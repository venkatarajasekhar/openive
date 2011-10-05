#include "openive.h"

int auth_url(openive_info *vpninfo)
{
	char buf[1024];
	char *redirect_url = NULL;

	char *request = "GET / HTTP/1.0\r\n"
			"Host: %s\r\n"
			"Accept: */*\r\n"
			"Accept-Language: en-us\r\n"
			"Connection: Keep-Alive\r\n"
			"User-Agent: DSClient; Linux\r\n"
			"Content-length: 0\r\n\r\n";

	if(openive_open_https(vpninfo))
	{
		printf("Failed to open HTTPS connection to %s\n", vpninfo->hvalue);
		return 1;
	}

	openive_SSL_printf(vpninfo->https_ssl, request, vpninfo->hvalue);
	
	openive_SSL_gets(vpninfo->https_ssl, buf);

	redirect_url = strstr(buf, "auth/") + 5;

	if((int)redirect_url == 5)
		return 1;

	strtok(redirect_url, "/");
	vpninfo->redirect_url = strdup(redirect_url);
	printf("%s\n", redirect_url);

	return 0;
}

int openive_obtain_cookie(openive_info *vpninfo)
{
	char buf[1024];
	char request_body[256];
	char *dsid = NULL;
	char *dsfa = NULL;

	char *request = "POST /dana-na/auth/%s/login.cgi HTTP/1.0\r\n"
			"Host: %s\r\n"
			"Accept: */*\r\n"
			"Accept-Language: en-us\r\n"
			"Connection: Keep-Alive\r\n"
			"User-Agent: DSClient; Linux\r\n"
			"Content-length: %d\r\n"
			"Cookie: DSSIGNIN=%s; DSSignInURL=/; DSIVS=\r\n\r\n"
			"%s";

	if(openive_open_https(vpninfo))
	{
		printf("Failed to open HTTPS connection to %s\n", vpninfo->hvalue);
		return 1;
	}

	if(!vpninfo->svalue)
		sprintf(request_body, "username=%s&password=%s&realm=%s", vpninfo->uvalue, vpninfo->pvalue, vpninfo->rvalue);
	else
		sprintf(request_body, "username=%s&password=%s&password#2=%s&realm=%s",
			vpninfo->uvalue, vpninfo->pvalue, vpninfo->svalue, vpninfo->rvalue);

	openive_SSL_printf(vpninfo->https_ssl, request, vpninfo->redirect_url, vpninfo->hvalue,
				strlen(request_body), vpninfo->redirect_url, request_body);
	
	openive_SSL_gets(vpninfo->https_ssl, buf);
	printf("%s\n", buf);

	dsid = strstr(buf, "DSID=") + 5;
	dsfa = strstr(buf, "DSFirstAccess=") + 14;

	if((int)dsid == 5 || (int)dsfa == 14)
		return 1;

	strtok(dsid, ";");
	strtok(dsfa, ";");
	vpninfo->dsid = strdup(dsid);
	vpninfo->dsfa = strdup(dsfa);

	return 0;
}

int make_ncp_connection(openive_info *vpninfo)
{
	char buf[1024];

	char *request = "POST /dana/js?prot=1&svc=4 HTTP/1.1\r\n"
			"Host: %s\r\n"
			"Cookie: DSLastAccess=%s;"
			"DSSIGNIN=%s;"
			"expires=Thu, 31-Dec-2037 00:00:00 GMT;"
			"DSFirstAccess=%s;"
			"DSSignInURL=/;"
			"DSID=%s;"
			"DSIVS=;\r\n"
			"Connection: close\r\n"
			"Content-Length: 256\r\n"
			"NCP-Version: 1\r\n"
			"Accept-encoding: gzip\r\n\r\n";

	if(openive_open_https(vpninfo))
	{
		printf("Failed to open HTTPS connection to %s\n", vpninfo->hvalue);
		return 1;
	}

	inflateInit2(&vpninfo->inflate_strm, 16+MAX_WBITS);
	deflateInit2(&vpninfo->deflate_strm, Z_DEFAULT_COMPRESSION, Z_DEFLATED, -15, 8, Z_DEFAULT_STRATEGY);

	openive_SSL_printf(vpninfo->https_ssl, request, vpninfo->hvalue, vpninfo->dsfa, vpninfo->redirect_url, vpninfo->dsfa, vpninfo->dsid);

	openive_SSL_gets(vpninfo->https_ssl, buf);
	printf("%s\n", buf);
	
	send_hello(vpninfo);

	return 0;
}

void send_hello(openive_info *vpninfo)
{
	char buf[1024];

	char hello[] = {0x00,0x04,0x00,0x00,0x00,0x06,0x00,'r',
			'r','_','i','v','e',0xbb,0x01,0x00,
			0x00, 0x00, 0x00};

	vpninfo->deflate_strm.avail_in = 19;
	vpninfo->deflate_strm.next_in = hello;
	vpninfo->deflate_strm.avail_out = 1024;
	vpninfo->deflate_strm.next_out = buf;

	deflate(&vpninfo->deflate_strm, Z_SYNC_FLUSH);

	unsigned char have = 1024 - vpninfo->deflate_strm.avail_out;
	unsigned char zero = 0x00;
	SSL_write(vpninfo->https_ssl, &have, 1);
	SSL_write(vpninfo->https_ssl, &zero, 1);
	SSL_write(vpninfo->https_ssl, buf, have);

	parse_pac(vpninfo);
}

void parse_pac(openive_info *vpninfo)
{
	int count;
	char buf[1024];
	char pac[1024];

	count = openive_SSL_gets(vpninfo->https_ssl, buf);
	
	vpninfo->inflate_strm.avail_in = count;
	vpninfo->inflate_strm.next_in = buf;
	vpninfo->inflate_strm.avail_out = 1024;
	vpninfo->inflate_strm.next_out = pac;

	inflate(&vpninfo->inflate_strm, Z_NO_FLUSH);

	FILE *f = fopen("debug", "w");
	fwrite(pac, 1024-vpninfo->inflate_strm.avail_out, 1, f);

	unsigned char type, size;
	int pos = 24, pos2;
	int len = 1024-vpninfo->inflate_strm.avail_out;
	printf("avail %d\n", len);
	printf("type %d\n", buf[pos]);

	while(pos < len)
	{
		type = buf[pos];

		/*IP MASK*/
		if(type == 1)
		{
			printf("%d\n", type);
			pos+=4;
			size = buf[pos];
			pos2 = pos+2;
			pos+=(size+2);

			while(pos2 < pos)
			{
				type = buf[pos2];

				if(type == 1)
				{
					printf("1 %d\n", type);
					pos2+=4;
					size = buf[pos2];
					unsigned int ip;
					memcpy(&ip, buf+pos2+1, 4);
					pos2+=(size+2);
				}
				else if(type == 2)
				{
					printf("1 %d\n", type);
					pos2+=4;
					size = buf[pos2];
					pos2+=(size+2);
				}
				else if(type == 3)
				{
					printf("1 %d\n", type);
					pos2+=4;
					size = buf[pos2];
					pos2+=(size+2);
				}
			}
		}
		/*DNS*/
		else if(type == 2)
		{
			printf("%d\n", type);
			pos+=4;
			size = buf[pos];
			pos+=(size+2);
		}
		/**/
		else if(type == 3)
		{
			printf("%d\n", type);
			pos+=4;
			size = buf[pos];
			pos+=(size+2);
		}
		/*WINS*/
		else if(type == 4)
		{
			printf("%d\n", type);
			pos+=4;
			size = buf[pos];
			pos+=(size+2);
		}
		/*PROXY*/
		else if(type == 5)
		{
			printf("%d\n", type);
			pos+=4;
			size = buf[pos];
			pos+=(size+2);
		}
		/*MTU*/
		else if(type == 6)
		{
			printf("%d\n", type);
			pos+=4;
			size = buf[pos];
			pos+=(size+2);
		}
		/**/
		else if(type == 7)
		{
			printf("%d\n", type);
			pos+=4;
			size = buf[pos];
			pos+=(size+2);
		}
		/**/
		else if(type == 8)
		{
			printf("%d\n", type);
			pos+=4;
			size = buf[pos];
			pos+=(size+2);
		}
	}
}
