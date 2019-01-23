GIT_VERSION := $(shell git describe --abbrev=4 --dirty --always --tags)

MacAnyVlan:MacAnyVlan.c
	gcc -g -Wall -DVERSION=\"$(GIT_VERSION)\" -o MacAnyVlan MacAnyVlan.c -lpthread -lssl -llz4 -lcrypto -D_GNU_SOURCE

run:
	gcc -Wall -DVERSION=\"$(GIT_VERSION)-O3\" -fno-strict-aliasing -O2 -o MacAnyVlan MacAnyVlan.c -lpthread -lssl -llz4 -lcrypto -D_GNU_SOURCE

indent: MacAnyVlan.c
	indent MacAnyVlan.c  -nbad -bap -nbc -bbo -hnl -br -brs -c33 -cd33 -ncdb -ce -ci4  \
-cli0 -d0 -di1 -nfc1 -i8 -ip0 -l160 -lp -npcs -nprs -npsl -sai \
-saf -saw -ncs -nsc -sob -nfca -cp33 -ss -ts8 -il1
