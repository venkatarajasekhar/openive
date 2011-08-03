all:
	gcc auth.c main.c ssl.c tun.c util.c -lssl -lcrypto -lz
