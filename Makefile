all:
	gcc auth.c main.c ncp.c ssl.c tun.c -lssl -lcrypto -lz
