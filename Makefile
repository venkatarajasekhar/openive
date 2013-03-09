CC=gcc
LIBS=-lssl
SOURCES=auth.c\
	main.c\
	ncp.c\
	pac.c\
	ssl.c\
	tun.c

openive:
	$(CC) $(LIBS) -o $@ $(SOURCES)
