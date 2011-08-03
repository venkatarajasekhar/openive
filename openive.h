#ifndef __OPENIVE_H__
#define __OPENIVE_H__

#include <openssl/ssl.h>
#include <zlib.h>

/* auth.c */
SSL *ive_login(char *hvalue, char *uvalue, char *pvalue, char *rvalue);

/* ssl.c */
SSL *open_https(const char *hostname);
int ive_printf(SSL *ssl, const char *fmt, ...);
int ive_getheader(SSL *ssl, unsigned char *buf);

/* tun.c */
int tun_alloc(char *dev);

/* util.c */
void replace_str(char *str, char *orig, char *rep);
z_stream def_init();
z_stream inf_init();

#endif
