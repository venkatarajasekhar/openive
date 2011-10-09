/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "openive.h"

static int openive_https_get(openive_info *vpninfo, char *url, char *response)
{
	char *request = "GET %s HTTP/1.1\r\n"
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

	openive_SSL_printf(vpninfo->https_ssl, request, url, vpninfo->hvalue);

	openive_SSL_gets(vpninfo->https_ssl, response);

	return 0;
}

static int openive_https_get_with_cookie(openive_info *vpninfo, char *url, char *cookie, char *response)
{
	char *request = "GET %s HTTP/1.0\r\n"
			"Host: %s\r\n"
			"Accept: */*\r\n"
			"Accept-Language: en-us\r\n"
			"Connection: Keep-Alive\r\n"
			"User-Agent: DSClient; Linux\r\n"
			"Cookie: DSCheckBrowser=java; %s\r\n"
			"Content-length: 0\r\n\r\n";

	if(openive_open_https(vpninfo))
	{
		printf("Failed to open HTTPS connection to %s\n", vpninfo->hvalue);
		return 1;
	}

	openive_SSL_printf(vpninfo->https_ssl, request, url, vpninfo->hvalue, cookie);

	openive_SSL_gets(vpninfo->https_ssl, response);

	return 0;
}

static int openive_https_post(openive_info *vpninfo, char *url, char *data, char *response)
{
	char *request = "POST /dana-na/auth/%s/login.cgi HTTP/1.0\r\n"
			"Host: %s\r\n"
			"Accept: */*\r\n"
			"Accept-Language: en-us\r\n"
			"Connection: Keep-Alive\r\n"
			"User-Agent: DSClient; Linux\r\n"
			"Content-length: %d\r\n\r\n"
			"%s";

	if(openive_open_https(vpninfo))
	{
		printf("Failed to open HTTPS connection to %s\n", vpninfo->hvalue);
		return 1;
	}

	openive_SSL_printf(vpninfo->https_ssl, request, url, vpninfo->hvalue, strlen(data), data);

	openive_SSL_gets(vpninfo->https_ssl, response);

	return 0;
}

int openive_obtain_cookie(openive_info *vpninfo)
{
	char buf[1024];
	char request_body[256];
	char *signinurl = NULL;
	char *redirect_url = NULL;
	char *location = NULL;
	char *cookie = NULL;
	char *dsid = NULL;
	char *dsfa = NULL;

	if(openive_https_get(vpninfo, "/", buf))
	{
		fprintf(stderr, "failed to obtain sign in url\n");
		return 1;
	}

	signinurl = strstr(buf, "auth/") + 5;

	if((int)signinurl == 5)
	{
		return 1;
	}

	strtok(signinurl, "/");
	signinurl = strdup(signinurl);

	if(!vpninfo->svalue)
		sprintf(request_body, "username=%s&password=%s&realm=%s",
			vpninfo->uvalue, vpninfo->pvalue, vpninfo->rvalue);
	else
		sprintf(request_body, "username=%s&password=%s&password#2=%s&realm=%s",
			vpninfo->uvalue, vpninfo->pvalue, vpninfo->svalue, vpninfo->rvalue);

	if(openive_https_post(vpninfo, signinurl, request_body, buf))
	{
		fprintf(stderr, "failed to obtain sign in url\n");
		return 1;
	}

	dsid = strstr(buf, "DSID=") + 5;
	dsfa = strstr(buf, "DSFirstAccess=") + 14;

	if((int)dsid == 5 || (int)dsfa == 14)
	{
		redirect_url = strstr(buf, vpninfo->hvalue) + strlen(vpninfo->hvalue);

		strtok(redirect_url, "\r");
		redirect_url = strdup(redirect_url);

		openive_https_get(vpninfo, redirect_url, buf);

		int i;

		for(i = 0; i < 5; i++)
		{
			cookie = strstr(buf, "DSPREAUTH=");
			strtok(cookie, ";");
			openive_https_get_with_cookie(vpninfo, redirect_url, cookie, buf);
		}

		location = strstr(buf, "location: ") + 10;
		strtok(location, "\r");

		cookie = strstr(buf, "DSPREAUTH=");
		strtok(cookie, ";");

		openive_https_get_with_cookie(vpninfo, location, cookie, buf);

		dsid = strstr(buf, "DSID=") + 5;
		dsfa = strstr(buf, "DSFirstAccess=") + 14;
	}

	printf("%s\n", buf);

	strtok(dsid, ";");
	strtok(dsfa, ";");
	vpninfo->dsid = strdup(dsid);
	vpninfo->dsfa = strdup(dsfa);

	return 0;
}
