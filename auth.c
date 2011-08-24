#include "openive.h"

int openive_obtain_cookie(openive_info *vpninfo)
{
	char buf[1024];
	char request_body[256];
	char *dsid = NULL;
	char *dsfa = NULL;

	char *request = "POST /dana-na/auth/url_default/login.cgi HTTP/1.0\r\n"
			"Host: %s\r\n"
			"Accept: */*\r\n"
			"Accept-Language: en-us\r\n"
			"Connection: Keep-Alive\r\n"
			"User-Agent: DSClient; Linux\r\n"
			"Content-length: %d\r\n"
			"Cookie: DSSIGNIN=url_default; DSSignInURL=/; DSIVS=\r\n\r\n"
			"%s";

	if(openive_open_https(vpninfo))
	{
		printf("Failed to open HTTPS connection to %s\n");
		return 1;
	}

	sprintf(request_body, "username=%s&password=%s&realm=%s", vpninfo->uvalue, vpninfo->pvalue, vpninfo->rvalue);

	openive_SSL_printf(vpninfo->https_ssl, request, vpninfo->hvalue, strlen(request_body), request_body);
	
	openive_SSL_gets(vpninfo->https_ssl, buf);

	dsid = strstr(buf, "DSID=") + 5;
	dsfa = strstr(buf, "DSFirstAccess=") + 14;
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
			"DSSIGNIN=url_default;"
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
		printf("Failed to open HTTPS connection to %s\n");
		return 1;
	}

	inflateInit2(&vpninfo->inflate_strm, 16+MAX_WBITS);
	deflateInit2(&vpninfo->deflate_strm, Z_DEFAULT_COMPRESSION, Z_DEFLATED, -15, 8, Z_DEFAULT_STRATEGY);

	openive_SSL_printf(vpninfo->https_ssl, request, vpninfo->hvalue, vpninfo->dsfa, vpninfo->dsfa, vpninfo->dsid);

	openive_SSL_gets(vpninfo->https_ssl, buf);

	return 0;
}
