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

char *read_uint32(char *buf, unsigned int *value)
{
	unsigned short lo, hi;

	buf = read_uint16(buf, &hi);
	buf = read_uint16(buf, &lo);
	*value = (hi << 16) | lo;
	return buf;
}

void pac_parse(openive_info * vpninfo, char *buf)
{
	char *vptr = buf;
	unsigned total;

	unsigned short type, subtype;
	unsigned size, subsize;

	vptr = read_uint32(vptr, &total);

	while (vptr - buf < total) {
		vptr = read_uint16(vptr, &type);
		vptr = read_uint32(vptr, &size);

		char *vvptr = vptr;

		while (vvptr - vptr < size) {
			vvptr = read_uint16(vvptr, &subtype);
			vvptr = read_uint32(vvptr, &subsize);
			printf("%d %d\n", type, subtype);

			if (type == 1 && subtype == 1)
				memcpy(&vpninfo->s_addr, vvptr, subsize);

			vvptr += subsize;
		}

		vptr += size;
	}
}
