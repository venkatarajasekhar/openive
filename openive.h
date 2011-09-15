#ifndef __OPENIVE_H__
#define __OPENIVE_H__

#include <openssl/ssl.h>
#include <zlib.h>

typedef struct {
	char *hvalue;
	char *uvalue;
	char *pvalue;
	char *rvalue;
	char *svalue;
	SSL *https_ssl;
	char *redirect_url;
	char *dsid;
	char *dsfa;
	z_stream inflate_strm;
	z_stream deflate_strm;
	unsigned long s_addr;
	int mtu;
} openive_info;

/* auth.c */
int auth_url(openive_info *vpninfo);
int openive_obtain_cookie(openive_info *vpninfo);
int make_ncp_connection(openive_info *vpninfo);
void send_hello(openive_info *vpninfo);
void parse_pac(openive_info *vpninfo);

/* ssl.c */
void openive_init_openssl();
int openive_open_https(openive_info *vpninfo);
int openive_SSL_printf(SSL *ssl, const char *fmt, ...);
int openive_SSL_gets(SSL *ssl, unsigned char *buf);

/* tun.c */
int tun_alloc();
int setup_tun(openive_info *vpninfo);

#endif
