#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main()
{
	FILE *fp;
	long len;
	char *buf;
	fp=fopen("debug","rb");
	fseek(fp,0,SEEK_END); //go to end
	len=ftell(fp); //get position at end (length)
	fseek(fp,0,SEEK_SET); //go to beg.
	buf=(char *)malloc(len); //malloc buffer
	fread(buf,len,1,fp); //read into buffer
	fclose(fp);

	unsigned char type, size;
	int pos = 24, pos2;

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
