all:
	gcc auth.c main.c ncp.c pac.c ssl.c tun.c -lssl
