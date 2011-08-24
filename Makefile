all:
	gcc auth.c main.c ssl.c tun.c -lssl -lcrypto -lz
