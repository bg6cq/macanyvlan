/* MacAnyVlan: Mac in Any Vlan forward
	  by james@ustc.edu.cn 2019.01.24
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <fcntl.h>
#include <unistd.h>
#include <syslog.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <time.h>
#include <net/if.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/if_tun.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <stdarg.h>
#include <errno.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>

#define MAXLEN 			2048
#define MAX_PACKET_SIZE		2048
#define MAXFD   		64

#define MAXCLIENT		4096

#define MAXROUTER		100

#define HASHBKT			(MAXCLIENT*2)

#define VLAN_TAG_LEN   4
struct vlan_tag {
	u_int16_t vlan_tpid;	/* ETH_P_8021Q */
	u_int16_t vlan_tci;	/* VLAN TCI */
};

struct _EtherHeader {
	uint16_t destMAC1;
	uint32_t destMAC2;
	uint16_t srcMAC1;
	uint32_t srcMAC2;
	uint32_t VLANTag;
	uint16_t type;
	int32_t payload;
} __attribute__ ((packed));

typedef struct _EtherHeader EtherPacket;

int client_hash[HASHBKT];

volatile struct client_info {
	uint8_t mac[6];
	int hash_next;
	int new;
	time_t last_see;
	uint16_t vlano;
	uint16_t vlani;
	uint16_t rvlan;
	uint64_t send_pkts;
	uint64_t send_bytes;
	uint64_t recv_pkts;
	uint64_t recv_bytes;
} clients[MAXCLIENT];

volatile struct router_info {
	uint8_t mac[6];
	int new;
	uint16_t rvlan;
	uint64_t send_pkts;
	uint64_t send_bytes;
	uint64_t bcast_pkts;
	uint64_t bcast_bytes;
} routers[MAXROUTER];

volatile int total_router = 0;
volatile int total_client = 0;

volatile struct rvlan_client_info {
	uint16_t vlano[MAXCLIENT];
	uint16_t vlani[MAXCLIENT];
	uint16_t count[MAXCLIENT];
	uint16_t total_rvlan_client;
} rvlan_client[4096];

int daemon_proc;		/* set nonzero by daemon_init() */
int pid;
int debug = 0;
int forward_multicast = 0;
int client_timeout = 3600;
uint16_t qinq_tpid = 0x8100;

char client_config[MAXLEN], router_config[MAXLEN];
char dev_client[MAXLEN], dev_router[MAXLEN];

int32_t ifindex_client, ifindex_router;
int fdraw_client, fdraw_router;

void read_client_config(char *fname);
void read_router_config(char *fname);
void print_client_config();
void print_router_config();
void err_msg(const char *fmt, ...);

void sig_handler_hup(int signo)
{
	if (pid > 0) {
		kill(pid, SIGHUP);
		return;
	}
	if (pid != 0)
		return;
	err_msg("reread config file...");
	read_client_config(client_config);
	read_router_config(router_config);
	print_client_config();
	print_router_config();
}

void sig_handler_usr1(int signo)
{
	if (pid > 0) {
		kill(pid, SIGUSR1);
		return;
	}
	if (pid != 0)
		return;
	print_client_config();
	print_router_config();
}

void sig_handler_usr2(int signo)
{
	int i;
	if (pid > 0) {
		kill(pid, SIGUSR2);
		return;
	}
	if (pid != 0)
		return;
	for (i = 0; i < total_client; i++)
		clients[i].send_pkts = clients[i].send_bytes = clients[i].recv_pkts = clients[i].recv_bytes = 0;
	for (i = 0; i < total_router; i++)
		routers[i].send_pkts = routers[i].send_bytes = routers[i].bcast_pkts = routers[i].bcast_bytes = 0;
}

void err_doit(int errnoflag, int level, const char *fmt, va_list ap)
{
	int errno_save, n;
	char buf[MAXLEN];

	errno_save = errno;	/* value caller might want printed */
	vsnprintf(buf, sizeof(buf), fmt, ap);	/* this is safe */
	n = strlen(buf);
	if (errnoflag)
		snprintf(buf + n, sizeof(buf) - n, ": %s", strerror(errno_save));
	strcat(buf, "\n");

	if (daemon_proc) {
		syslog(level, "%s", buf);
	} else {
		fflush(stdout);	/* in case stdout and stderr are the same */
		fputs(buf, stderr);
		fflush(stderr);
	}
	return;
}

void err_msg(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	err_doit(0, LOG_INFO, fmt, ap);
	va_end(ap);
	return;
}

void inline Debug(const char *fmt, ...)
{
	va_list ap;
	if (debug) {
		va_start(ap, fmt);
		err_doit(0, LOG_INFO, fmt, ap);
		va_end(ap);
	}
	return;
}

void err_quit(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	err_doit(0, LOG_ERR, fmt, ap);
	va_end(ap);
	exit(1);
}

void err_sys(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	err_doit(1, LOG_ERR, fmt, ap);
	va_end(ap);
	exit(1);
}

void daemon_init(const char *pname, int facility)
{
	int i;
	pid_t pid;
	if ((pid = fork()) != 0)
		exit(0);	/* parent terminates */
	setsid();		/* become session leader */
	signal(SIGHUP, SIG_IGN);
	if ((pid = fork()) != 0)
		exit(0);	/* 1st child terminates */
	daemon_proc = 1;	/* for our err_XXX() functions */
	umask(0);		/* clear our file mode creation mask */
	for (i = 0; i < MAXFD; i++)
		close(i);
	openlog(pname, LOG_PID, facility);
}

char *mac_to_str(uint8_t * mac)
{

	static char t[16];
	sprintf(t, "%02X%02X%02X%02X%02X%02X", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
	return t;
}

unsigned char hex_digit(char ch)
{
	if (('0' <= ch) && (ch <= '9'))
		return ch - '0';
	if (('a' <= ch) && (ch <= 'f'))
		return ch + 10 - 'a';
	if (('A' <= ch) && (ch <= 'F'))
		return ch + 10 - 'A';
	return 16;
}

void str_to_mac(char *str, uint8_t * mac)
{
	int i;
	if (strlen(str) != 12) {
		Debug("mac %s len is not 12\n", str);
		for (i = 0; i < 6; i++)
			mac[i] = 0;
		return;
	}
	for (i = 0; i < 6; i++) {
		mac[i] = hex_digit(str[2 * i]) << 4;
		mac[i] |= hex_digit(str[1 + 2 * i]);
	}
}

int find_rvlan_client(uint16_t rvlan, uint16_t vlano, uint16_t vlani)
{
	int i;
	for (i = 0; i < rvlan_client[rvlan].total_rvlan_client; i++)
		if ((rvlan_client[rvlan].vlano[i] == vlano) && (rvlan_client[rvlan].vlani[i] == vlani))
			return i;
	return -1;
}

void add_rvlan_client(uint16_t rvlan, uint16_t vlano, uint16_t vlani)
{
	int i;
	rvlan = rvlan & 0xfff;
	vlano = vlano & 0xfff;
	vlani = vlani & 0xfff;
	if ((rvlan == 0) || (vlano == 0))
		return;
	i = find_rvlan_client(rvlan, vlano, vlani);
	if (i >= 0) {
		rvlan_client[rvlan].count[i]++;
		return;
	}
	rvlan_client[rvlan].vlano[rvlan_client[rvlan].total_rvlan_client] = vlano;
	rvlan_client[rvlan].vlani[rvlan_client[rvlan].total_rvlan_client] = vlani;
	rvlan_client[rvlan].count[rvlan_client[rvlan].total_rvlan_client] = 1;
	rvlan_client[rvlan].total_rvlan_client++;
}

void del_rvlan_client(uint16_t rvlan, uint16_t vlano, uint16_t vlani)
{
	int i;
	rvlan = rvlan & 0xfff;
	vlano = vlano & 0xfff;
	vlani = vlani & 0xfff;
	if ((rvlan == 0) || (vlano == 0))
		return;
	i = find_rvlan_client(rvlan, vlano, vlani);
	if (i >= 0) {
		rvlan_client[rvlan].count[i]--;
		if (rvlan_client[rvlan].count[i] == 0) {
			if (rvlan_client[rvlan].total_rvlan_client == 1) {
				rvlan_client[rvlan].total_rvlan_client = 0;
				return;
			}
			rvlan_client[rvlan].vlano[i] = rvlan_client[rvlan].vlano[rvlan_client[rvlan].total_rvlan_client - 1];
			rvlan_client[rvlan].vlani[i] = rvlan_client[rvlan].vlani[rvlan_client[rvlan].total_rvlan_client - 1];
			rvlan_client[rvlan].count[i] = rvlan_client[rvlan].count[rvlan_client[rvlan].total_rvlan_client - 1];
			rvlan_client[rvlan].total_rvlan_client--;
		}
		return;
	}
	err_msg("del_rvlan_client %d %d %d, not added", rvlan, vlano, vlani);
}

static inline uint16_t hash_key(uint8_t * mac)
{
	uint16_t k = 0;
	k = ((mac[0] + mac[2] + mac[4]) << 8) + mac[1] + mac[3] + mac[5];
	k = k % HASHBKT;
	return k;
}

int find_client(uint8_t * mac)
{
	int h;
	h = client_hash[hash_key(mac)];
	while (h != -1) {
		if (memcmp((void *)clients[h].mac, mac, 6) == 0)
			return h;
		h = clients[h].hash_next;
	}
	return -1;
}

int add_client(uint8_t * mac, uint16_t rvlan)
{
	int i;
	i = find_client(mac);
	if (i >= 0) {
		err_msg("%s in client table", mac_to_str(mac));
		del_rvlan_client(clients[i].rvlan, clients[i].vlano, clients[i].vlani);
		clients[i].rvlan = rvlan;
		clients[i].new = 1;
		add_rvlan_client(clients[i].rvlan, clients[i].vlano, clients[i].vlani);
		return -1;
	}
	if (total_client == MAXCLIENT - 1) {
		err_msg("Too many client\n");
		return -1;
	}
	memset((void *)&clients[total_client], 0, sizeof(struct client_info));
	memcpy((void *)clients[total_client].mac, mac, 6);
	clients[total_client].last_see = 0;
	clients[total_client].hash_next = -1;
	clients[total_client].rvlan = rvlan;
	clients[total_client].vlano = 0;
	clients[total_client].vlani = 0;
	clients[total_client].new = 1;
	int h = hash_key(mac);
	clients[total_client].hash_next = client_hash[h];
	client_hash[h] = total_client;
	total_client++;
	return 0;
}

void del_client(int idx)
{
	int k;
	if ((idx < 0) || (idx >= total_client)) {
		err_msg("error del client %d", idx);
		return;
	}
	del_rvlan_client(clients[idx].rvlan, clients[idx].vlano, clients[idx].vlani);
// del from hash
	k = hash_key((uint8_t *) clients[idx].mac);
	if (client_hash[k] == idx) {	// first hash
		client_hash[k] = clients[idx].hash_next;
	} else {
		int h;
		h = client_hash[k];
		while (h != -1) {
			if (clients[h].hash_next == idx) {
				clients[h].hash_next = clients[idx].hash_next;
				break;
			}
			h = clients[h].hash_next;
		}
	}
// if last client, just return  
	if (total_client == 1) {
		total_client = 0;
		err_msg("del last client");
		return;
	}
// move last client in array to idx
	memcpy((void *)&clients[idx], (void *)&clients[total_client - 1], sizeof(struct client_info));

// change hash
	k = hash_key((uint8_t *) clients[idx].mac);
	if (client_hash[k] == total_client - 1) {	// first hash
		client_hash[k] = idx;
	} else {
		int h;
		h = client_hash[k];
		while (h != -1) {
			if (clients[h].hash_next == total_client - 1) {
				clients[h].hash_next = idx;
				break;
			}
			h = clients[h].hash_next;
		}
	}
	total_client--;
	err_msg("del client %d", idx);
}

/* client_config file

client_dev eth?
MAC routervlan
MAC routervlan

*/

void read_client_config(char *fname)
{
	FILE *fp;
	char buf[MAXLEN];
	int i;
	fp = fopen(fname, "r");
	if (fp == NULL) {
		err_msg("open file %s error, exit.", fname);
		exit(0);
	}
	for (i = 0; i < total_client; i++)
		clients[i].new = 0;
	while (fgets(buf, MAXLEN, fp)) {
		char *p;
		uint8_t mac[6];
		p = buf;
		if (buf[0] == '#')
			continue;
		if (buf[strlen(buf) - 1] == '\n')
			buf[strlen(buf) - 1] = 0;
		if (memcmp(p, "client_dev", 10) == 0) {
			p += 10;
			while (isblank(*p))
				p++;
			strcpy(dev_client, p);
			p = dev_client;
			while (*p && (((*p >= 'a') && (*p <= 'z')) || ((*p >= '0') && (*p <= '9'))))
				p++;
			*p = 0;
			continue;
		}
		if (strlen(buf) < 13)
			continue;
		// Debug("read client :%s:\n", buf);
		buf[12] = 0;
		p = buf + 13;
		int rvlan = atoi(p);
		if ((rvlan <= 0) || (rvlan >= 4095)) {
			err_msg("client MAC %s routervlan %d invalid", buf, rvlan);
			continue;
		}
		str_to_mac(buf, mac);
		add_client(mac, rvlan);
	}
	fclose(fp);
	if (total_client == 0)
		return;
	for (i = total_client - 1; i >= 0; i--) {
		if (clients[i].new == 0)
			del_client(i);
	}
}

void print_client_config()
{
	int i;
	err_msg("===== client config file: %s, network dev: %s, timeout: %d", client_config, dev_client, client_timeout);
	err_msg("clients:");
	err_msg("idx MAC         rvlan vlan hash_next last_see send_pkts send_bytes recv_pkts recv_bytes");
	for (i = 0; i < total_client; i++)
		err_msg("%3d %s %4d %4d.%-4d %4d %4ld %ld %ld %ld %ld", i, mac_to_str((uint8_t *) clients[i].mac), clients[i].rvlan, clients[i].vlano,
			clients[i].vlani, clients[i].hash_next, clients[i].last_see == 0 ? -1 : (long)(time(NULL) - clients[i].last_see), clients[i].send_pkts,
			clients[i].send_bytes, clients[i].recv_pkts, clients[i].recv_bytes);
	err_msg("client hashtable:");
	int16_t h;
	for (i = 0; i < HASHBKT; i++)
		if (client_hash[i] != -1) {
			char buf[MAXLEN];
			int l;
			l = snprintf(buf, MAXLEN, "hash %d:", i);
			h = client_hash[i];
			while (h != -1) {
				if (l > MAXLEN - 10)
					break;
				l += snprintf(buf + l, MAXLEN - l, " %d", h);
				h = clients[h].hash_next;
			}
			err_msg("%s", buf);
		}
}

int find_router(uint8_t * mac, uint16_t rvlan)
{
	int i;
	for (i = 0; i < total_router; i++)
		if ((memcmp((void *)routers[i].mac, mac, 6) == 0) && (routers[i].rvlan == rvlan))
			return i;
	return -1;
}

void del_router(int idx)
{
	if ((idx < 0) || (idx >= total_router)) {
		err_msg("error del router %d", idx);
		return;
	}
// if last router, just return
	if (total_router == 1) {
		total_router = 0;
		err_msg("del last router");
		return;
	}
// move last router in array to idx
	memcpy((void *)&routers[idx], (void *)&routers[total_router - 1], sizeof(struct router_info));
	total_router--;
	err_msg("del router %d", idx);
}

int add_router(uint8_t * mac, uint16_t rvlan)
{
	int i;
	i = find_router(mac, rvlan);
	if (i >= 0) {
		routers[i].new = 1;
		err_msg("%s in router table", mac_to_str(mac));
		return -1;
	}
	if (total_router == MAXROUTER - 1) {
		err_msg("Too many router\n");
		return -1;
	}
	memset((void *)&routers[total_router], 0, sizeof(struct router_info));
	memcpy((void *)routers[total_router].mac, mac, 6);
	routers[total_router].rvlan = rvlan;
	routers[total_router].new = 1;
	total_router++;
	return 0;
}

/* router config file

router_dev eth?
MAC routervlan
MAC routervlan

*/

void read_router_config(char *fname)
{
	FILE *fp;
	char buf[MAXLEN];
	int i;
	for (i = 0; i < total_router; i++)
		routers[i].new = 0;
	fp = fopen(fname, "r");
	if (fp == NULL) {
		err_msg("open file %s error, exit.", fname);
		exit(0);
	}
	while (fgets(buf, MAXLEN, fp)) {
		char *p;
		uint8_t mac[6];
		p = buf;
		if (buf[0] == '#')
			continue;
		if (buf[strlen(buf) - 1] == '\n')
			buf[strlen(buf) - 1] = 0;
		if (memcmp(p, "router_dev", 10) == 0) {
			p += 10;
			while (isblank(*p))
				p++;
			strcpy(dev_router, p);
			p = dev_router;
			while (*p && (((*p >= 'a') && (*p <= 'z')) || ((*p >= '0') && (*p <= '9'))))
				p++;
			*p = 0;
			continue;
		}
		// Debug("read router :%s:\n", buf);
		if (strlen(buf) < 13)
			continue;
		buf[12] = 0;
		p = buf + 13;
		int rvlan = atoi(p);
		if ((rvlan <= 0) || (rvlan >= 4095)) {
			err_msg("router MAC %s routervlan %d invalid", buf, rvlan);
			continue;
		}
		str_to_mac(buf, mac);
		add_router(mac, rvlan);
	}
	fclose(fp);
	if (total_router == 0)
		return;
	for (i = total_router - 1; i >= 0; i--) {
		if (routers[i].new == 0)
			del_router(i);
	}
}

void print_router_config()
{
	int i;
	err_msg("===== router config file: %s, network dev: %s", router_config, dev_router);
	err_msg("forward multicast from router: %d", forward_multicast);
	err_msg("routers:");
	err_msg("idx MAC         rvlan send_pkt send_byte bcast_pkt bcast_byte");
	for (i = 0; i < total_router; i++)
		err_msg("%3d %s %4d %ld %ld %ld %ld", i, mac_to_str((uint8_t *) routers[i].mac), routers[i].rvlan,
			routers[i].send_pkts, routers[i].send_bytes, routers[i].bcast_pkts, routers[i].bcast_bytes);
	err_msg("rvlan client:");
	for (i = 0; i < 4096; i++) {
		int j;
		if (rvlan_client[i].total_rvlan_client) {
			err_msg("rvlan %d:", i);
			for (j = 0; j < rvlan_client[i].total_rvlan_client; j++)
				err_msg("    %4d.%-4d count=%d", rvlan_client[i].vlano[j], rvlan_client[i].vlani[j], rvlan_client[i].count[j]);
		}
	}
}

/**
 * Open a rawsocket for the network interface
 */
int32_t open_rawsocket(char *ifname, int32_t * rifindex)
{
	unsigned char buf[MAX_PACKET_SIZE];
	int32_t ifindex;
	struct ifreq ifr;
	struct sockaddr_ll sll;
	int n;

	int32_t fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (fd == -1)
		err_sys("socket %s - ", ifname);

	// get interface index
	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
	if (ioctl(fd, SIOCGIFINDEX, &ifr) == -1)
		err_sys("SIOCGIFINDEX %s - ", ifname);
	ifindex = ifr.ifr_ifindex;
	*rifindex = ifindex;

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
	ioctl(fd, SIOCGIFFLAGS, &ifr);
	ifr.ifr_flags |= IFF_PROMISC;
	ioctl(fd, SIOCSIFFLAGS, &ifr);

	memset(&sll, 0xff, sizeof(sll));
	sll.sll_family = AF_PACKET;
	sll.sll_protocol = htons(ETH_P_ALL);
	sll.sll_ifindex = ifindex;
	if (bind(fd, (struct sockaddr *)&sll, sizeof(sll)) == -1)
		err_sys("bind %s - ", ifname);

	/* flush all received packets. 
	 *
	 * raw-socket receives packets from all interfaces
	 * when the socket is not bound to an interface
	 */
	int32_t i, l = 0;
	do {
		fd_set fds;
		struct timeval t;
		FD_ZERO(&fds);
		FD_SET(fd, &fds);
		memset(&t, 0, sizeof(t));
		i = select(FD_SETSIZE, &fds, NULL, NULL, &t);
		if (i > 0) {
			recv(fd, buf, i, 0);
			l++;
		};
		Debug("interface %d flushed %d packets", ifindex, l);
	}
	while (i > 0);

	/* Enable auxillary data if supported and reserve room for
	 * reconstructing VLAN headers. */
	int val = 1;
	if (setsockopt(fd, SOL_PACKET, PACKET_AUXDATA, &val, sizeof(val)) == -1 && errno != ENOPROTOOPT) {
		err_sys("setsockopt(packet_auxdata): %s", strerror(errno));
	}

	Debug("%s opened (fd=%d interface=%d)", ifname, fd, ifindex);

	n = 10 * 1024 * 1024;
	setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &n, sizeof(n));
	if (debug) {
		socklen_t ln;
		if (getsockopt(fd, SOL_SOCKET, SO_RCVBUF, &n, &ln) == 0) {
			Debug("RAW socket RCVBUF setting to %d", n);
		}
	}

	return fd;
}

char *stamp(void)
{
	static char st_buf[200];
	struct timeval tv;
	struct timezone tz;
	struct tm *tm;
	gettimeofday(&tv, &tz);
	tm = localtime(&tv.tv_sec);
	snprintf(st_buf, 200, "%02d%02d %02d:%02d:%02d.%06ld", tm->tm_mon + 1, tm->tm_mday, tm->tm_hour, tm->tm_min, tm->tm_sec, tv.tv_usec);
	return st_buf;
}

void printPacket(EtherPacket * packet, ssize_t packetSize, char *message)
{
	int vlan_tags = 0;	// 0 no vlan, 1 single vlan, 2 qinq vlan
	struct vlan_tag *tag1, *tag2;
	printf("%s ", stamp());
	tag1 = (struct vlan_tag *)((uint8_t *) packet + 12);
	if ((tag1->vlan_tpid == htons(qinq_tpid)) || (tag1->vlan_tpid == 0x0081)) {
		tag2 = (struct vlan_tag *)((uint8_t *) packet + 16);
		if (tag2->vlan_tpid == 0x0081)
			vlan_tags = 2;
		else
			vlan_tags = 1;
	}
	if (vlan_tags == 2) {
		printf("%s #%04X/%04X (VLAN %d.%d) from %04X%08X to %04X%08X, len=%d\n",
		       message, ntohs(tag1->vlan_tpid), ntohs(tag2->vlan_tpid),
		       ntohs(tag1->vlan_tci) & 0xFFF, ntohs(tag2->vlan_tci) & 0xfff, ntohs(packet->srcMAC1),
		       ntohl(packet->srcMAC2), ntohs(packet->destMAC1), ntohl(packet->destMAC2), (int)packetSize);
	} else if (vlan_tags == 1)	// VLAN tag
		printf("%s #%04X (VLAN %d) from %04X%08X to %04X%08X, len=%d\n",
		       message, ntohs(tag1->vlan_tpid),
		       ntohs(tag1->vlan_tci) & 0xFFF, ntohs(packet->srcMAC1),
		       ntohl(packet->srcMAC2), ntohs(packet->destMAC1), ntohl(packet->destMAC2), (int)packetSize);
	else
		printf("%s #%04X (no VLAN) from %04X%08X to %04X%08X, len=%d\n",
		       message, ntohl(packet->VLANTag) >> 16,
		       ntohs(packet->srcMAC1), ntohl(packet->srcMAC2), ntohs(packet->destMAC1), ntohl(packet->destMAC2), (int)packetSize);
	fflush(stdout);
}

void process_client_to_router(void)
{
	u_int8_t buf[MAX_PACKET_SIZE + VLAN_TAG_LEN * 2];
	int len;
	int offset = 0;
	time_t last_check = 0, now_t;

	while (1) {		// read from eth rawsocket
		struct sockaddr from;
		struct iovec iov;
		struct msghdr msg;
		struct cmsghdr *cmsg;
		union {
			struct cmsghdr cmsg;
			char buf[CMSG_SPACE(sizeof(struct tpacket_auxdata))];
		} cmsg_buf;
		msg.msg_name = &from;
		msg.msg_namelen = sizeof(from);
		msg.msg_iov = &iov;
		msg.msg_iovlen = 1;
		msg.msg_control = &cmsg_buf;
		msg.msg_controllen = sizeof(cmsg_buf);
		msg.msg_flags = 0;

		offset = VLAN_TAG_LEN;
		iov.iov_len = MAX_PACKET_SIZE;
		iov.iov_base = buf + offset;
		len = recvmsg(fdraw_client, &msg, MSG_TRUNC);
		now_t = time(NULL);
		if ((client_timeout > 0) && (now_t - last_check > 5)) {	// check timeout for 5 seconds
			int i;
			for (i = 0; i < total_client; i++) {
				if (now_t - clients[i].last_see > client_timeout) {
					Debug("client %d idle for %d seconds > client_timeout %d", i, now_t - clients[i].last_see, client_timeout);
					del_rvlan_client(clients[i].rvlan, clients[i].vlano, clients[i].vlani);
					clients[i].vlano = clients[i].vlani = 0;
				}
			}
		}
		if (len <= 0)
			continue;
		if (len >= MAX_PACKET_SIZE) {
			err_msg("recv long pkt from raw, len=%d", len);
			len = MAX_PACKET_SIZE;
		}
		struct vlan_tag *tag, *tag1, *tag2;
		for (cmsg = CMSG_FIRSTHDR(&msg); cmsg; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
			struct tpacket_auxdata *aux;
			if (cmsg->cmsg_len < CMSG_LEN(sizeof(struct tpacket_auxdata))
			    || cmsg->cmsg_level != SOL_PACKET || cmsg->cmsg_type != PACKET_AUXDATA)
				continue;

			aux = (struct tpacket_auxdata *)CMSG_DATA(cmsg);

#if defined(TP_STATUS_VLAN_VALID)
			if ((aux->tp_vlan_tci == 0)
			    && !(aux->tp_status & TP_STATUS_VLAN_VALID))
#else
			if (aux->tp_vlan_tci == 0)	/* this is ambigious but without the */
#endif
				continue;

			//      Debug("len=%d, iov_len=%d, ", len, (int)iov.iov_len);

			len = len > iov.iov_len ? iov.iov_len : len;
			if (len < 12)	// MAC_len * 2
				break;
			// Debug("len=%d", len);

			memmove(buf, buf + VLAN_TAG_LEN, 12);
			offset = 0;

			/*
			 * Now insert the tag.
			 */
			tag = (struct vlan_tag *)(buf + 12);
			// Debug("insert vlan id, recv len=%d", len);

#ifdef TP_STATUS_VLAN_TPID_VALID
			tag->vlan_tpid = ((aux->tp_vlan_tpid || (aux->tp_status & TP_STATUS_VLAN_TPID_VALID)) ? aux->tp_vlan_tpid : 0x0081);
#else
			tag->vlan_tpid = 0x0081;
#endif
			tag->vlan_tci = htons(aux->tp_vlan_tci);

			/* Add the tag to the packet lengths.
			 */
			len += VLAN_TAG_LEN;
			break;
		}

		// tag.vlan_tpid shold be 0x0081

		if (len <= 0)
			continue;

		if (debug) {
			printPacket((EtherPacket *) (buf + offset), len, "from client :");
			//              if (offset)
			//              printf("offset=%d\n", offset);
		}
		int i = find_client(buf + offset + 6);
		if (i < 0) {
			Debug("unknow client, ignore\n");
			continue;
		}

		int vlan_tags = 0;
		tag1 = (struct vlan_tag *)(buf + offset + 12);
		tag2 = (struct vlan_tag *)(buf + offset + 16);
		if ((tag1->vlan_tpid == htons(qinq_tpid)) || (tag1->vlan_tpid == 0x0081)) {
			if (tag2->vlan_tpid == 0x0081)
				vlan_tags = 2;
			else
				vlan_tags = 1;
		}

		if (vlan_tags == 0) {	// not a 802.1Q packet?
			Debug("ignore tpid %04X packet\n", ntohs(tag1->vlan_tpid));
			continue;
		}

		if (debug) {
			if (vlan_tags == 2)
				Debug("client index %d, tpid: %04X/%04X, vlan: %d.%d, rvlan: %d", i, ntohs(tag1->vlan_tpid),
				      ntohs(tag2->vlan_tpid), ntohs(tag1->vlan_tci) & 0xfff, ntohs(tag2->vlan_tci) & 0xfff, clients[i].rvlan);
			else
				Debug("client index %d, tpid: %04X, vlan: %d.0, rvlan: %d", i, ntohs(tag1->vlan_tpid),
				      ntohs(tag1->vlan_tci) & 0xfff, clients[i].rvlan);
		}

		clients[i].last_see = now_t;
		uint16_t vlano, vlani;
		vlano = ntohs(tag1->vlan_tci) & 0xfff;
		if (vlan_tags == 2)
			vlani = ntohs(tag2->vlan_tci) & 0xfff;
		else
			vlani = 0;
		if ((vlano != clients[i].vlano) || (vlani != clients[i].vlani)) {
			del_rvlan_client(clients[i].rvlan, clients[i].vlano, clients[i].vlani);
			clients[i].vlano = vlano;
			clients[i].vlani = vlani;
			add_rvlan_client(clients[i].rvlan, vlano, vlani);
		}
		clients[i].send_pkts++;
		clients[i].send_bytes += len;
		// Debug("vlan: %d", clients[i].vlan);

		// change to router vlan
		tag->vlan_tci = htons(clients[i].rvlan & 0xfff);
		if (debug) {
			printPacket((EtherPacket *) (buf + offset), len, "sendto router:");
			//if (offset)
			//              printf("offset=%d\n", offset);
			printf("\n");
		}

		struct sockaddr_ll sll;
		memset(&sll, 0, sizeof(sll));
		sll.sll_family = AF_PACKET;
		sll.sll_protocol = htons(ETH_P_ALL);
		sll.sll_ifindex = ifindex_router;
		sendto(fdraw_router, buf + offset, len, 0, (struct sockaddr *)&sll, sizeof(sll));
	}
}

void process_router_to_client(void)
{
	u_int8_t buf[MAX_PACKET_SIZE + VLAN_TAG_LEN * 2];
	int len;
	int offset = 0;

	while (1) {		// read from router rawsocket
		struct sockaddr from;
		struct iovec iov;
		struct msghdr msg;
		struct cmsghdr *cmsg;
		union {
			struct cmsghdr cmsg;
			char buf[CMSG_SPACE(sizeof(struct tpacket_auxdata))];
		} cmsg_buf;
		msg.msg_name = &from;
		msg.msg_namelen = sizeof(from);
		msg.msg_iov = &iov;
		msg.msg_iovlen = 1;
		msg.msg_control = &cmsg_buf;
		msg.msg_controllen = sizeof(cmsg_buf);
		msg.msg_flags = 0;

		offset = VLAN_TAG_LEN * 2;
		iov.iov_len = MAX_PACKET_SIZE;
		iov.iov_base = buf + offset;
		len = recvmsg(fdraw_router, &msg, MSG_TRUNC);
		if (len <= 0)
			continue;
		if (len >= MAX_PACKET_SIZE) {
			err_msg("recv long pkt from raw, len=%d", len);
			len = MAX_PACKET_SIZE;
		}
		struct vlan_tag *tag;
		for (cmsg = CMSG_FIRSTHDR(&msg); cmsg; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
			struct tpacket_auxdata *aux;
			if (cmsg->cmsg_len < CMSG_LEN(sizeof(struct tpacket_auxdata))
			    || cmsg->cmsg_level != SOL_PACKET || cmsg->cmsg_type != PACKET_AUXDATA)
				continue;

			aux = (struct tpacket_auxdata *)CMSG_DATA(cmsg);

#if defined(TP_STATUS_VLAN_VALID)
			if ((aux->tp_vlan_tci == 0)
			    && !(aux->tp_status & TP_STATUS_VLAN_VALID))
#else
			if (aux->tp_vlan_tci == 0)	/* this is ambigious but without the */
#endif
				continue;

			// Debug("len=%d, iov_len=%d, ", len, (int)iov.iov_len);

			len = len > iov.iov_len ? iov.iov_len : len;
			if (len < 12)	// MAC_len * 2
				break;
			// Debug("len=%d", len);

			memmove(buf + VLAN_TAG_LEN, buf + VLAN_TAG_LEN + VLAN_TAG_LEN, 12);
			offset = VLAN_TAG_LEN;

			/*
			 * Now insert the tag.
			 */
			tag = (struct vlan_tag *)(buf + VLAN_TAG_LEN + 12);
			// Debug("insert vlan id, recv len=%d", len);

#ifdef TP_STATUS_VLAN_TPID_VALID
			tag->vlan_tpid = ((aux->tp_vlan_tpid || (aux->tp_status & TP_STATUS_VLAN_TPID_VALID)) ? aux->tp_vlan_tpid : 0x0081);
#else
			tag->vlan_tpid = 0x0081;
#endif
			tag->vlan_tci = htons(aux->tp_vlan_tci);

			/* Add the tag to the packet lengths.
			 */
			len += VLAN_TAG_LEN;
			break;
		}

		// tag.vlan_tpid shold be 0x0081

		if (len <= 0)
			continue;

		if (debug) {
			printPacket((EtherPacket *) (buf + offset), len, "from router :");
			// if (offset)
			//      printf("offset=%d\n", offset);
		}
		tag = (struct vlan_tag *)(buf + offset + 12);
		if (tag->vlan_tpid != 0x0081) {	// vlan 
			Debug("ignore tpid %04X packet\n", ntohs(tag->vlan_tpid));
			continue;
		}
		int rvlan = ntohs(tag->vlan_tci) & 0xfff;
		int i = find_router(buf + offset + 6, rvlan);
		if (i < 0) {
			Debug("unknow router, ignore\n");
			continue;
		}
		Debug("router index %d, tpid: %04X, rvlan: %d", i, ntohs(tag->vlan_tpid), ntohs(tag->vlan_tci) & 0xfff);

		if (!(forward_multicast && (buf[offset] & 1)) && (memcmp(buf + offset, "\xff\xff\xff\xff\xff\xff", 6) != 0)) {	// not a broadcast packet
			routers[i].send_pkts++;
			routers[i].send_bytes += len;
			i = find_client(buf + offset);
			if (i < 0) {
				Debug("unknow unicast packet, ignore");
				continue;
			}

			Debug("client index %d, vlan: %d.%d", i, clients[i].vlano, clients[i].vlani);

			if (rvlan != clients[i].rvlan) {
				Debug("routervlan %d is not the same as client rvlan %d, ignore", rvlan, clients[i].rvlan);
				continue;
			}

			if (clients[i].vlano == 0) {
				Debug("no client information now, ignore");
				continue;
			}
			// change to client vlan
			if (clients[i].vlani == 0)
				tag->vlan_tci = htons(clients[i].vlano & 0xfff);
			else {
				tag->vlan_tci = htons(clients[i].vlani & 0xfff);
				offset -= 4;
				memcpy(buf + offset, buf + offset + 4, 12);
				tag = (struct vlan_tag *)(buf + offset + 12);
				tag->vlan_tci = htons(clients[i].vlano & 0xfff);
				tag->vlan_tpid = htons(qinq_tpid);
				len += 4;
			}
			if (debug) {
				printPacket((EtherPacket *) (buf + offset), len, "sendto client:");
				//if (offset)
				//      printf("offset=%d\n", offset);
				printf("\n");
			}
			clients[i].recv_pkts++;
			clients[i].recv_bytes += len;

			struct sockaddr_ll sll;
			memset(&sll, 0, sizeof(sll));
			sll.sll_family = AF_PACKET;
			sll.sll_protocol = htons(ETH_P_ALL);
			sll.sll_ifindex = ifindex_client;
			sendto(fdraw_client, buf + offset, len, 0, (struct sockaddr *)&sll, sizeof(sll));
			continue;
		}
		// broadcast packet, flood to every vlan
		routers[i].bcast_pkts++;
		routers[i].bcast_bytes += len;
		u_int8_t buf2[MAX_PACKET_SIZE + VLAN_TAG_LEN * 2];
		int buf2_ready = 0;
		for (i = 0; i < rvlan_client[rvlan].total_rvlan_client; i++) {
			Debug("rvlan_client index %d, vlan: %d.%d, count=%d", i, rvlan_client[rvlan].vlano[i], rvlan_client[rvlan].vlani[i],
			      rvlan_client[rvlan].count[i]);
			if (rvlan_client[rvlan].vlani[i] == 0) {	// single VLAN
				// change to client vlan
				tag->vlan_tci = htons(rvlan_client[rvlan].vlano[i] & 0xfff);
				if (debug) {
					printPacket((EtherPacket *) (buf + offset), len, "sendto client:");
					//if (offset)
					//      printf("offset=%d\n", offset);
					printf("\n");
				}

				struct sockaddr_ll sll;
				memset(&sll, 0, sizeof(sll));
				sll.sll_family = AF_PACKET;
				sll.sll_protocol = htons(ETH_P_ALL);
				sll.sll_ifindex = ifindex_client;
				sendto(fdraw_client, buf + offset, len, 0, (struct sockaddr *)&sll, sizeof(sll));
			} else {	// QinQ vlan
				if (buf2_ready == 0) {
					memcpy(buf2, buf + offset, 12);	// packet header
					memcpy(buf2 + 16, buf + offset + 12, len - 12);	// pakcet
					tag = (struct vlan_tag *)(buf2 + 12);
					tag->vlan_tpid = ntohs(qinq_tpid);
					buf2_ready = 1;
				}
				tag = (struct vlan_tag *)(buf2 + 12);
				tag->vlan_tci = htons(rvlan_client[rvlan].vlano[i] & 0xfff);
				tag = (struct vlan_tag *)(buf2 + 16);
				tag->vlan_tci = htons(rvlan_client[rvlan].vlani[i] & 0xfff);
				if (debug) {
					printPacket((EtherPacket *) (buf + offset), len, "sendto client:");
					//if (offset)
					//      printf("offset=%d\n", offset);
					printf("\n");
				}

				struct sockaddr_ll sll;
				memset(&sll, 0, sizeof(sll));
				sll.sll_family = AF_PACKET;
				sll.sll_protocol = htons(ETH_P_ALL);
				sll.sll_ifindex = ifindex_client;
				sendto(fdraw_client, buf2, len + 4, 0, (struct sockaddr *)&sll, sizeof(sll));
			}
		}
	}
}

void usage(void)
{
	printf("MacAnyVlan Version: %s, by james@ustc.edu.cn (https://github.com/bg6cq/macanyvlan)\n", VERSION);
	printf("Usage:\n");
	printf("./MacAnyVlan [ options ] -c client_config -r router_config\n");
	printf(" options:\n");
	printf("    -d     enable debug\n");
	printf("    -m     forward multicast packet from router\n");
	printf("    -t client_timeout      default is 3600\n");
	printf("HUP  signal: reread config file\n");
	printf("USR1 signal: print information\n");
	printf("USR2 signal: reset statistics\n");
	exit(0);
}

int main(int argc, char *argv[])
{
	pthread_t tid;
	int i = 1;
	int got_one = 0;

	for (i = 0; i < HASHBKT; i++)
		client_hash[i] = -1;

	i = 1;
	do {
		got_one = 1;
		if (argc - i <= 0)
			break;
		if (strcmp(argv[i], "-d") == 0)
			debug = 1;
		else if (strcmp(argv[i], "-m") == 0)
			forward_multicast = 1;
		else if (strcmp(argv[i], "-t") == 0) {
			i++;
			if (argc - i <= 0)
				usage();
			client_timeout = atoi(argv[i]);
		} else if (strcmp(argv[i], "-c") == 0) {
			i++;
			if (argc - i <= 0)
				usage();
			strncpy(client_config, argv[i], MAXLEN);
			read_client_config(argv[i]);
		} else if (strcmp(argv[i], "-r") == 0) {
			i++;
			if (argc - i <= 0)
				usage();
			strncpy(router_config, argv[i], MAXLEN);
			read_router_config(argv[i]);
		} else
			got_one = 0;
		if (got_one)
			i++;
	}
	while (got_one);

	if (dev_client[0] == 0 || dev_router[0] == 0)
		usage();
	if (debug) {
		printf("         debug = 1\n");
		print_client_config();
		print_router_config();
		printf("\n");
	}

	if (debug == 0)
		daemon_init("MacAnyVlan", LOG_DAEMON);

	signal(SIGHUP, sig_handler_hup);
	signal(SIGUSR1, sig_handler_usr1);
	signal(SIGUSR2, sig_handler_usr2);

	if (debug == 0) {
		while (1) {
			pid = fork();
			if (pid == 0)	// child do the job
				break;
			else if (pid == -1)	// error
				exit(0);
			else {
				while (wait(NULL) < 0) ;	// parent wait for child
				pid = -1;
			}
			sleep(2);	// wait 2 second, and rerun
		}
	}

	fdraw_client = open_rawsocket(dev_client, &ifindex_client);
	fdraw_router = open_rawsocket(dev_router, &ifindex_router);

	if (pthread_create(&tid, NULL, (void *)process_client_to_router, NULL) != 0)
		err_sys("pthread_create client_to_router error");

	//  forward packets from router to client
	process_router_to_client();

	return 0;
}
