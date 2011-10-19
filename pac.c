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

char *read_uint8(char *buf, unsigned char *value)
{
	*value = *buf++;
	return buf;
}

char *read_uint16(char *buf, unsigned short *value)
{
	unsigned char lo, hi;

	buf = read_uint8(buf, &hi);
	buf = read_uint8(buf, &lo);
	*value = (hi << 8) | lo;
	return buf;
}

void *read_uint32(char *buf, unsigned int *value)
{
	unsigned short lo, hi;

	buf = read_uint16(buf, &hi);
	buf = read_uint16(buf, &lo);
	*value = (hi << 16) | lo;
	return buf;
}

void pac_parse(openive_info *vpninfo, char *buf)
{
	char *vptr = buf;
	int size;

	int insize;
	short type;

	vptr = read_uint32(vptr, &size);

	while(vptr - buf < size)
	{
		vptr = read_uint16(vptr, &type);
		printf("%d\n", type);
		vptr = read_uint32(vptr, &insize);
		vptr += insize;
	}
}
