/* net_conf.c - net configuration file */

/* Copyright (c) 2008, Nissin Systems Co., Ltd. All rights reserved. */

/*
modification history
--------------------
01b,29aug08,nss  remove dhcpc_cachefile.
01a,05aug08,nss  written.
*/

#include "cgi.h"
//#include "s2e_common.h"
#include "net_conf.h"

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
#include <signal.h>


char *network_cfg_file 	= "/etc/netcfg";
#if 1	/* NSS */
char *network_cfg_file2 = "/usr/local/etc/netcfg";
#endif
char *network_restart_cmd = "/etc/netstart &";

struct net_t
{
	int dhcpc;				/* dhcp client <0:disable 1:enable> */
	unsigned char ipaddr[4];		/* host address */
	unsigned char netmask[4];		/* subnetmask */
	unsigned char gateway[4];		/* gateway address */
};

struct net_t net_conf[1];

HTTP_META net_meta_conf[] = {
	{ "NET_DHCP@", 	net_meta	} ,
	{ "NET_IPADDR", 	net_meta	} ,
	{ "NET_SUBNET", 	net_meta	} ,
	{ "NET_GATEWAY", 	net_meta	} ,
	{ NULL, 			NULL		}
};

static int read_config (int chan, struct net_t *conf);
static int write_config (int chan, struct net_t *conf);

int net_start (void)
{
	struct net_t *conf;
//	long zero = 0;

	conf = &net_conf[0];

	memset (conf, 0, sizeof (struct net_t));
	read_config (0, conf);

//	if (memcmp (conf->ipaddr, &zero, sizeof (zero)) != 0)
//		terminate_process (dhcpc_pidfile, 0);

	return 0;
}

int net_stop (void)
{
	return 0;
}

int net_init (HTTP_INFO *info)
{
	struct net_t *conf;

	conf = &net_conf[0];

	memset (conf, 0, sizeof (struct net_t));
	read_config (0, conf);

	return 0;
}

int net_exit (HTTP_INFO *info)
{
	return 0;
}

int net_clear (HTTP_INFO *info)
{
	struct net_t *conf;

	conf = &net_conf[0];

	memset (conf, 0, sizeof (struct net_t));
	conf->dhcpc = 1;
	write_config (0, conf);

	return 0;
}

int net_meta (HTTP_INFO *info, char *name, char *buffer, int buflen)
{
	char *ptr = name;
	struct net_t *conf;

	conf = &net_conf[0];

	buffer[0] = '\0';

	if (strncmp (ptr, "NET_DHCP@", 9) == 0) {
		if (atoi (ptr + 9) == conf->dhcpc)
			strcpy (buffer, "selected");
	} else if (strcmp (ptr, "NET_IPADDR") == 0) {
		unsigned long ipaddr = 0;
		buffer[0] = '\0';
		if (memcmp (conf->ipaddr, (char *)&ipaddr, sizeof (ipaddr)) != 0) {
			sprintf (buffer, "%u.%u.%u.%u",
				(unsigned) conf->ipaddr[0] & 0xff,
				(unsigned) conf->ipaddr[1] & 0xff,
				(unsigned) conf->ipaddr[2] & 0xff,
				(unsigned) conf->ipaddr[3] & 0xff);
		}
	}
	else if (strcmp (ptr, "NET_SUBNET") == 0) {
		unsigned long ipaddr = 0;
		buffer[0] = '\0';
		if (memcmp (conf->netmask, (char *)&ipaddr, sizeof (ipaddr)) != 0) {
			sprintf (buffer, "%u.%u.%u.%u",
				(unsigned) conf->netmask[0] & 0xff,
				(unsigned) conf->netmask[1] & 0xff,
				(unsigned) conf->netmask[2] & 0xff,
				(unsigned) conf->netmask[3] & 0xff);
		}
	}
	else if (strcmp (ptr, "NET_GATEWAY") == 0) {
		unsigned long ipaddr = 0;
		buffer[0] = '\0';
		if (memcmp (conf->gateway, (char *)&ipaddr, sizeof (ipaddr)) != 0) {
			sprintf (buffer, "%u.%u.%u.%u",
				(unsigned) conf->gateway[0] & 0xff,
				(unsigned) conf->gateway[1] & 0xff,
				(unsigned) conf->gateway[2] & 0xff,
				(unsigned) conf->gateway[3] & 0xff);
		}
	}

	return strlen (buffer);
}

int net_cgi (HTTP_INFO *info)
{
	int i;
	struct net_t *conf;
	struct net_t temp;
	int ret = 0;

	conf = &net_conf[0];

	memcpy (&temp, conf, sizeof (temp));

	for (i = 0; i < info->argc; i ++) {
		char *ptr = info->argv[i];

		if (strncmp (ptr, "NET_DHCP=", 9) == 0)
			temp.dhcpc = atoi (ptr + 9);
		else if (strncmp (ptr, "NET_IPADDR=", 11) == 0) {
			unsigned long ipaddr = 0;
			if (*(ptr + 11) != '\0') {
				ipaddr = inet_addr (ptr + 11);
				if (ipaddr == 0xffffffffL) {
					ret = -1;
					break;
				}
			}
			memcpy (temp.ipaddr, (char *)&ipaddr, 4);
		}
		else if (strncmp (ptr, "NET_SUBNET=", 11) == 0) {
			unsigned long ipaddr = 0;
			if (*(ptr + 11) != '\0') {
				ipaddr = inet_addr (ptr + 11);
				if (ipaddr == 0xffffffffL) {
					ret = -1;
					break;
				}
			}
			memcpy (temp.netmask, (char *)&ipaddr, 4);
		}
		else if (strncmp (ptr, "NET_GATEWAY=", 12) == 0) {
			unsigned long ipaddr = 0;
			if (*(ptr + 12) != '\0') {
				ipaddr = inet_addr (ptr + 12);
				if (ipaddr == 0xffffffffL) {
					ret = -1;
					break;
				}
			}
			memcpy (temp.gateway, (char *)&ipaddr, 4);
		}
	}

	if (ret == 0) {
		if (memcmp (conf, &temp, sizeof (temp)) != 0) {
			if (write_config (0, &temp) == 0)
				memcpy (conf, &temp, sizeof (temp));
		}
	}

	return ret;
}

static int read_config (int chan, struct net_t *conf)
{
	FILE *fp;
	char buffer[128];
	char *ptr;
	long addr = 0;
	(void) chan;

	conf->dhcpc = 0;
	memset (conf->ipaddr, 0, 4);
	memset (conf->netmask, 0, 4);
	memset (conf->gateway, 0, 4);

	if ((fp = fopen (network_cfg_file, "r")) != NULL) {

		while (fgets(buffer, sizeof (buffer), fp)!=NULL){
			ptr = buffer;
			if (!strncmp (buffer, "IPADDR=", 7)) {
				ptr = skip_brank(ptr + 7);
				addr = inet_addr(ptr);
				memcpy (conf->ipaddr, &addr, 4);
			} else 	if (!strncmp (buffer, "NETMASK=", 8)) {
					ptr = skip_brank(ptr + 8);
					addr = inet_addr(ptr);
					memcpy (conf->netmask, &addr, 4);
			} else if (!strncmp (buffer, "GATEWAY=", 8)) {
				ptr = skip_brank (ptr + 8);
				addr = inet_addr(ptr);
				memcpy (conf->gateway, &addr, 4);
			}

			if (buffer[0] != '#' && strstr (buffer, "dhcpcd") != NULL)
				conf->dhcpc = 1;
		}

		fclose (fp);
	}

	if (*(long*)conf->ipaddr == 0 || *(long*)conf->netmask == 0 || *(long*)conf->ipaddr == 0) {
		conf->dhcpc = 1;
		/* make sure all of them are 0 */
		memset (conf->ipaddr, 0, 4);
		memset (conf->netmask, 0, 4);
		memset (conf->gateway, 0, 4);
		if (fp) {

			fclose(fp);
			unlink(network_cfg_file); /* erase invalid netconf file */
		}
	}

	return 0;
}

static int write_config (int chan, struct net_t *conf)
{
	FILE *fp;
	unsigned long ipaddr;
	unsigned long netmask;
	unsigned long gateway;

	(void) chan;

	memcpy ((char *)&ipaddr, conf->ipaddr, 4);
	memcpy ((char *)&netmask, conf->netmask, 4);
	memcpy ((char *)&gateway, conf->gateway, 4);


	if (ipaddr == 0 || netmask == 0 || ipaddr == 0 || conf->dhcpc) {
		/* make sure dhcp is set */
		conf->dhcpc = 1;
		/* make sure all of them are 0 */
		memset (conf->ipaddr, 0, 4);
		memset (conf->netmask, 0, 4);
		memset (conf->gateway, 0, 4);

		unlink(network_cfg_file); /* erase netcfg file => DHCP */
		unlink(network_cfg_file2); /* erase alternate file */
		execute (network_restart_cmd);
		return 0;
	}

	if ((fp = fopen (network_cfg_file, "w")) != NULL) {

		fprintf (fp, "IPADDR=%u.%u.%u.%u\n",
				(unsigned) conf->ipaddr[0] & 0xff,
				(unsigned) conf->ipaddr[1] & 0xff,
				(unsigned) conf->ipaddr[2] & 0xff,
				(unsigned) conf->ipaddr[3] & 0xff);
		fprintf (fp, "NETMASK=%u.%u.%u.%u\n",
				(unsigned) conf->netmask[0] & 0xff,
				(unsigned) conf->netmask[1] & 0xff,
				(unsigned) conf->netmask[2] & 0xff,
				(unsigned) conf->netmask[3] & 0xff);
		fprintf (fp, "GATEWAY=%u.%u.%u.%u\n",
				(unsigned) conf->gateway[0] & 0xff,
				(unsigned) conf->gateway[1] & 0xff,
				(unsigned) conf->gateway[2] & 0xff,
				(unsigned) conf->gateway[3] & 0xff);

		fclose (fp);
		execute (network_restart_cmd);
		return 0;
	}

	return -1;
}

