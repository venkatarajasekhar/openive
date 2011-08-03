#include <stdio.h>
#include <string.h>
#include "openive.h"

#include <zlib.h>

void replace_str(char *str, char *orig, char *rep)
{
	char buffer[256];
	char *p;

	if(!(p = strstr(str, orig)))
		return;

	strncpy(buffer, str, p-str);
	buffer[p-str] = '\0';

	sprintf(buffer+(p-str), "%s%s", rep, p+strlen(orig));

	strcpy(str, buffer);
}

z_stream def_init()
{
	z_stream strm;
	strm.zalloc = Z_NULL;
	strm.zfree = Z_NULL;
	strm.opaque = Z_NULL;
	deflateInit2(&strm, Z_DEFAULT_COMPRESSION, Z_DEFLATED, -15, 8, Z_DEFAULT_STRATEGY);
	return strm;
}

z_stream inf_init()
{
	z_stream strm;
	strm.zalloc = Z_NULL;
	strm.zfree = Z_NULL;
	strm.opaque = Z_NULL;
	strm.avail_in = 0;
	strm.next_in = Z_NULL;
	inflateInit2(&strm, 16+MAX_WBITS);
	return strm;
}
