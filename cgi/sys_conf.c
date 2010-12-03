/* sys_conf.c - system configuration file */

/* Copyright (c) 2008, Nissin Systems Co., Ltd. All rights reserved. */

/*
modification history
--------------------
01b,04sep08,nss  fixed sys_cgi.
01a,05aug08,nss  written.
*/

#include "cgi.h"
//#include "s2e_common.h"
#include "sys_conf.h"

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <termios.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/if.h>
#include <crypt.h>

char *sys_verison = "0.0.0.0";

HTTP_META sys_meta_conf[] = {
	{ "SYS_VER", 		sys_meta	} ,
	{ "SYS_MAC", 		sys_meta	} ,
	{ "SYS_RAM", 		sys_meta	} ,
	{ "SYS_FREE", 		sys_meta	} ,
	{ "SYS_IPADDR", 	sys_meta	} ,
	{ "SYS_PASS", 		sys_meta	} ,
	{ "SYS_PASS2", 		sys_meta	} ,
	{ NULL, 			NULL		}
};

static char *passwd_file = "/etc/passwd";
static char *fake_passwd = "\t\t\t\t\t\t\t\t";

static int ethaddr_get (unsigned char *ethaddr, int len);
static int ipaddr_get (unsigned char *ipaddr, unsigned char *netmask);
#ifdef INET6
static int ipaddr6_get (int index, unsigned char *ipaddr);
#endif
static unsigned long meminfo_get (char *key);
static int passwd_set (char *passwd);

int sys_start (void)
{
	return 0;
}

int sys_stop (void)
{
	return 0;
}

int sys_init (HTTP_INFO *info)
{
	return 0;
}

int sys_exit (HTTP_INFO *info)
{
	return 0;
}

int sys_clear (HTTP_INFO *info)
{
	passwd_set ("PASS");
	return 0;
}

int sys_meta (HTTP_INFO *info, char *name, char *buffer, int buflen)
{
	char *ptr = name;

	buffer[0] = '\0';

	if (strcmp (ptr, "SYS_VER") == 0) {
		sprintf (buffer, "%s", sys_verison);
	}
	else if (strcmp (ptr, "SYS_MAC") == 0) {
		unsigned char eaddr[6];
		ethaddr_get (eaddr, sizeof (eaddr));
		sprintf (buffer, "%02x:%02x:%02x:%02x:%02x:%02x",
			(int) eaddr[0] & 0xff,	(int) eaddr[1] & 0xff,
			(int) eaddr[2] & 0xff,	(int) eaddr[3] & 0xff,
			(int) eaddr[4] & 0xff,	(int) eaddr[5] & 0xff);
	}
	else if (strcmp (ptr, "SYS_RAM") == 0) {
		unsigned long value = meminfo_get ("MemTotal:");
		sprintf (buffer, "%lu bytes", value * 1024);
	}
	else if (strcmp (ptr, "SYS_FREE") == 0) {
		unsigned long value = meminfo_get ("MemFree:");
		sprintf (buffer, "%lu bytes", value * 1024);
	}
	else if (strcmp (ptr, "SYS_IPADDR") == 0) {
		unsigned char ipaddr[4];
		unsigned char netmask[4];
		ipaddr_get (ipaddr, netmask);
		sprintf (buffer, "%u.%u.%u.%u",
			(unsigned) ipaddr[0] & 0xff,
			(unsigned) ipaddr[1] & 0xff,
			(unsigned) ipaddr[2] & 0xff,
			(unsigned) ipaddr[3] & 0xff);
#ifdef INET6
	{
		unsigned char ipaddr6[16];
		char temp[64];
		int index = 0;
		while (ipaddr6_get (index++, ipaddr6) == 0) {
			if (inet_ntop (AF_INET6, ipaddr6, temp, sizeof (temp)) != NULL)
				sprintf (&buffer[strlen(buffer)], "<BR>\n%s",temp);
		}
	}
#endif
	}
	else if (strcmp (ptr, "SYS_PASS") == 0)
		strcpy (buffer, fake_passwd);
	else if (strcmp (ptr, "SYS_PASS2") == 0)
		strcpy (buffer, fake_passwd);

	return strlen (buffer);
}

int sys_cgi (HTTP_INFO *info)
{
	int i;
	int sys_clear = 0;
	int sys_reboot = 0;
	int ret = 0;
	char sys_pass[32];
	char sys_pass2[32];

	strcpy (sys_pass, fake_passwd);
	strcpy (sys_pass2, fake_passwd);

	for (i = 0; i < info->argc; i ++) {
		char *ptr = info->argv[i];

		if (strncmp (ptr, "SYS_CLEAR=", 10) == 0)
			sys_clear = atoi (ptr + 10);

		else if (strncmp (ptr, "SYS_REBOOT=", 11) == 0)
			sys_reboot = atoi (ptr + 11);

		else if (strncmp (ptr, "SYS_PASS=", 9) == 0)
			strncpy (sys_pass, ptr + 9, sizeof(sys_pass) - 1);

		else if (strncmp (ptr, "SYS_PASS2=", 10) == 0)
			strncpy (sys_pass2, ptr + 10, sizeof(sys_pass) - 1);
	}

	if (sys_clear) {
		extern int user_clear (HTTP_INFO *info);
		user_clear (info);
	}

	if (sys_reboot) {
		extern int user_reboot (HTTP_INFO *info);
		user_reboot (info);
	}

	if (strcmp (sys_pass, fake_passwd) != 0 ||
		strcmp (sys_pass2, fake_passwd) != 0) {
		if (strcmp (sys_pass, sys_pass2) == 0)
			passwd_set (sys_pass);
		else
			ret = -1;
	}

	return ret;
}

int ethaddr_get (unsigned char *ethaddr, int len)
{
	int s;
	struct ifreq ifr;

	memset (ethaddr, 0, 6);

	memset ((char *) &ifr, 0, sizeof (ifr));
	sprintf (ifr.ifr_name, "eth0");
    ifr.ifr_addr.sa_family = AF_INET;

	if (0 <= (s = socket (AF_INET, SOCK_DGRAM, 0))) {

		if (0 <= ioctl (s, SIOCGIFHWADDR, &ifr))
			memcpy ((char *)ethaddr, (char *)ifr.ifr_hwaddr.sa_data, len);

		close (s);
		return 0;
	} else
		return -1;
}

int ipaddr_get (unsigned char *ipaddr, unsigned char *netmask)
{
	int s;
	struct ifreq ifr;

	memset (ipaddr, 0, 4);
	memset (netmask, 0, 4);

	memset ((char *) &ifr, 0, sizeof (ifr));
	sprintf (ifr.ifr_name, "eth0");
    ifr.ifr_addr.sa_family = AF_INET;

	if (0 <= (s = socket (AF_INET, SOCK_DGRAM, 0))) {

		if (0 <= ioctl (s, SIOCGIFADDR, &ifr))
			memcpy (ipaddr, &(((struct sockaddr_in *)
				(&ifr.ifr_addr))->sin_addr), 4);

		if (0 <= ioctl (s, SIOCGIFNETMASK, &ifr))
			memcpy (netmask, &(((struct sockaddr_in *)
				(&ifr.ifr_addr))->sin_addr) , 4);

		close (s);
		return 0;

	} else
		return -1;
}

#ifdef INET6
int ipaddr6_get (int index, unsigned char *ipaddr)
{
	FILE *fp;
	char input[64];
	int count = 0;
	int ret = -1;

	memset (ipaddr, 0, 16);

	fp = fopen ("/proc/net/if_inet6", "r");
	if (fp == NULL)
		return -1;

	while (fgets(input, sizeof (input), fp)!=NULL){
		if (strstr (input, "eth0") != 0) {
			char temp[9];
			int i;
			unsigned long value;

			if (count++ == index) {
				temp[8] = 0;
				for (i = 0; i < 16; i += 4) {
					memcpy (temp, &input[i*2], 8);
					value = hatol(temp);
					memcpy (&ipaddr[i], (char *)&value, 4);
				}
				ret = 0;
				break;
			}
		}
	}
	fclose (fp);
	return ret;
}
#endif

unsigned long meminfo_get (char *key)
{
	FILE *fp;
	char input[64];
	unsigned long size = 0;

	fp = fopen ("/proc/meminfo", "r");
	if (fp == NULL)
		return 0;

	while (fgets(input, sizeof (input), fp)!=NULL){
		if (strncmp (input, key, strlen (key)) == 0) {
			char *ptr = input + strlen (key);
			while (*ptr == ' ' || *ptr == '\t') ptr ++;
			size = atoi (ptr);
			break;
		}
	}
	fclose (fp);
	return size;
}

int passwd_set (char *passwd)
{
	FILE *fp;
	char *cp;

	if ((cp = (char *)crypt(passwd, passwd)) == NULL)
		return -1;

	if ((fp = fopen (passwd_file, "w")) == NULL)
		return -1;

	fprintf (fp, "root:%s:0:0:Super User:/:/bin/sh\n", cp);
	fprintf (fp, "ftp::0:0:Ftp User:/:/bin/sh\n");

	fclose (fp);

	return 0;
}
