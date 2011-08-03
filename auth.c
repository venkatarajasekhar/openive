#include "openive.h"

SSL *ive_login(char *hvalue, char *uvalue, char *pvalue, char *rvalue)
{
	SSL *ssl;
	char body[256];
	char response[1024];
	char *dsid = NULL;
	char *dsfa = NULL;
	time_t dsla;

	ssl = open_https(hvalue);

	char *request = "POST /dana-na/auth/url_default/login.cgi HTTP/1.0\r\n"
			"Host: %s\r\n"
			"Accept: */*\r\n"
			"Accept-Language: en-us\r\n"
			"Connection: Keep-Alive\r\n"
			"User-Agent: DSClient; Linux\r\n"
			"Content-length: %d\r\n"
			"Cookie: DSSIGNIN=url_default; DSSignInURL=/; DSIVS=\r\n\r\n"
			"%s";

	sprintf(body, "username=%s&password=%s&realm=%s", uvalue, pvalue, rvalue);
	replace_str(body, " ", "%20");
	ive_printf(ssl, request, hvalue, strlen(body), body);

	ive_getheader(ssl, response);
	dsid = strstr(response, "DSID=") + 5;
	dsfa = strstr(response, "DSFirstAccess=") + 14;
	strtok(dsid, ";");
	strtok(dsfa, ";");
	printf("%s\n", dsid);
	printf("%s\n", dsfa);

	ssl = open_https(hvalue);

	char *header = 	"POST /dana/js?prot=1&svc=4 HTTP/1.1\r\n"
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

	ive_printf(ssl, header, hvalue, dsfa, dsfa, dsid);

	ive_getheader(ssl, response);
	printf("%s\n", response);

	return ssl;
}
