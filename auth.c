/*
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "openive.h"

static int openive_https_get(openive_info * vpninfo, char *url, char *response)
{
	char *request = "GET %s HTTP/1.0\r\n"
	    "Host: %s\r\n"
	    "Accept: */*\r\n"
	    "Accept-Language: en-us\r\n"
	    "Connection: Keep-Alive\r\n"
	    "User-Agent: DSClient; Linux\r\n"
	    "Content-length: 0\r\n\r\n";

	if (openive_open_https(vpninfo)) {
		printf("Failed to open HTTPS connection to %s\n",
		       vpninfo->host);
		return 1;
	}

	printf("-> openive_https_get %s\n", url);
	openive_SSL_printf(vpninfo->https_ssl, request, url, vpninfo->host);

	openive_SSL_gets(vpninfo->https_ssl, response);
	//openive_close_https(vpninfo->https_ssl);

	return 0;
}

static int openive_https_post(openive_info * vpninfo, char *dssignin,
			      char *data, char *response)
{
	char *request = "POST /dana-na/auth/%s/login.cgi HTTP/1.0\r\n"
	    "Host: %s\r\n"
	    "Accept: */*\r\n"
	    "Accept-Language: en-us\r\n"
	    "Connection: Keep-Alive\r\n"
	    "User-Agent: DSClient; Linux\r\n" "Content-length: %d\r\n\r\n" "%s";

	if (openive_open_https(vpninfo)) {
		printf("Failed to open HTTPS connection to %s\n",
		       vpninfo->host);
		return 1;
	}

	printf("-> openive_https_post %s\n", dssignin);
	openive_SSL_printf(vpninfo->https_ssl, request, dssignin, vpninfo->host,
			   strlen(data), data);

	openive_SSL_gets(vpninfo->https_ssl, response);
	//openive_close_https(vpninfo->https_ssl);

	return 0;
}

int openive_obtain_cookie(openive_info * vpninfo)
{
	char buf[1024];
	char request_body[256];
	char *dssignin = NULL;
	char *failed = NULL;
	char *dsid = NULL;
	char *dsfa = NULL;

	if (openive_https_get(vpninfo, "/", buf)) {
		printf("failed to obtain sign in url\n");
		return 1;
	}

	dssignin = strstr(buf, "DSSIGNIN=") + 9;

	if ((intptr_t) dssignin == 9) {
		return 1;
	}

	strtok(dssignin, ";");
	dssignin = strdup(dssignin);

	sprintf(request_body, "username=%s&password=%s&realm=%s",
		vpninfo->user, vpninfo->pass, vpninfo->realm);

	if (openive_https_post(vpninfo, dssignin, request_body, buf)) {
		fprintf(stderr, "failed to obtain sign in url\n");
		return 1;
	}

	failed = strstr(buf, "?p=failed");

	if (failed) {
		printf("failed authenticate\n");
		return 1;
	}

	dsid = strstr(buf, "DSID=") + 5;
	dsfa = strstr(buf, "DSFirstAccess=") + 14;

	if ((intptr_t) dsid == 5 || (intptr_t) dsfa == 14) {
		return 1;
	}

	printf("cookie obtained\n");

	strtok(dsid, ";");
	strtok(dsfa, ";");
	vpninfo->dsid = strdup(dsid);
	vpninfo->dsfa = strdup(dsfa);

	return 0;
}
