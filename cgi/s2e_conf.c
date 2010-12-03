/* s2e_conf.c - s2e configuration file */

/* Copyright (c) 2008, Nissin Systems Co., Ltd. All rights reserved. */

/*
modification history
--------------------
01d,15jan10,nss  added SSH/SSL.
01c,05sep08,nss  fixed default_config.
01b,04sep08,nss  fixed write_config.
01a,05aug08,nss  written.
*/

#include "cgi.h"
#include "s2e_common.h"
#include "s2e_conf.h"

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
#include <errno.h>
#include <signal.h>

#ifdef	INET6
#include <netdb.h>
#endif	/* INET6 */

#ifdef USE_SSH
#define NET_MAX_AUTH_USER		8
#define NET_MAX_USER_LEN		32
#define NET_MAX_PASS_LEN		32
struct net_user
{
	char user[NET_MAX_USER_LEN];	/* username */
	char pass[NET_MAX_PASS_LEN];	/* password */
};
#endif	/* USE_SSH */

struct s2e_t
{
	char tty_device[16];		/* device name */
	long tty_baudrate;			/* baudrate */
	int tty_parity;				/* parity <0:none 1:odd 2: even> */
	int tty_stopbit;			/* stop bit <1 or 2> */
	int tty_length;				/* bit length <from 5 to 8> */
	int tty_flow;				/* flow control <0:none 1:soft 2: hard> */
	int tty_timeout;			/* receive timeout for transmition trigger */
	int tty_dma;				/* DMA transfer mode <0:disable 1:enable> */
	int tty_rs485;				/* RS-485 mode <0:disable 1:half 2:full 3:t-half 4:t-full> */

	int tty_size;				/* size for transmition trigger */
	char tty_delim_code[3];		/* delimiter code for transmition trigger */
	char tty_delim_len;			/* length of delimiter code */

	int net_mode;				/* network mode (0:server 1:client) */
	unsigned char net_host[4];	/* host address */
	int net_proto;				/* protcol (0:udp 1:tcp) */
	int net_port;				/* port number */
	int net_timeout;			/* connection timeout */

	int tty_fd;					/* tty descripter */
	int sock_fd;				/* socket descripter */
	int conn_fd;				/* connection descripter */

	char *net_buffer;			/* pointer to network buffer */
	int net_bufsz;				/* size of network buffer */
	char *tty_buffer;			/* pointer to tty buffer */
	int tty_bufsz;				/* size of tty buffer */

	unsigned char remote_host[4];	/* remote address */
	int remote_port;				/* remote port number */

#ifdef INET6
	int net_ipv6;					/* IPv6 mode (0:disable 1:enable) */
	unsigned char net_host6[16];	/* host IPv6 address */
	unsigned char remote_host6[16];	/* remote address */
	char have_net_host6;			/* have ipv6 addr */
#endif	/* INET6 */

	unsigned long tty_rcvd;		/* received data bytes */
	unsigned long tty_sent;		/* sent data bytes */

#ifdef USE_SSH
	struct net_user connect_user;	/* connect user for client */
	struct net_user auth_user[NET_MAX_AUTH_USER];
								/* authorized users for server */
#endif	/* USE_SSH */

#ifdef USE_VIP
	int net_vip;					/* VIP mode (0:disable 1:enable) */
	unsigned char net_vipname[16];	/* VIP name */
#endif	/* USE_SSH */

};

HTTP_META s2e_meta_conf[] = {
	{ "S2E_CHAN", 		s2e_meta	} ,
	{ "S2E_BAUD@", 		s2e_meta	} ,
	{ "S2E_PARITY@", 	s2e_meta	} ,
	{ "S2E_STOPB@", 	s2e_meta	} ,
	{ "S2E_LEN@", 		s2e_meta	} ,
	{ "S2E_FLOW@", 		s2e_meta	} ,
	{ "S2E_DMA@", 		s2e_meta	} ,
	{ "S2E_RS485@",		s2e_meta	} ,
	{ "S2E_TIMEOUT", 	s2e_meta	} ,
	{ "S2E_BUFSIZE", 	s2e_meta	} ,
	{ "S2E_DELIM_1",	s2e_meta	} ,
	{ "S2E_DELIM_2",	s2e_meta	} ,
	{ "S2E_MODE@", 		s2e_meta	} ,
	{ "S2E_IPVER@",		s2e_meta	} ,
	{ "S2E_HOST", 		s2e_meta	} ,
	{ "S2E_PROTO@", 	s2e_meta	} ,
	{ "S2E_PORT", 		s2e_meta	} ,
	{ "S2E_REMOTE",		s2e_meta	} ,
	{ "S2E_SEND", 		s2e_meta	} ,
	{ "S2E_RECV", 		s2e_meta	} ,
	{ "S2E_USE_SSH@", 	s2e_meta	} ,
	{ "S2E_USE_SSL@", 	s2e_meta	} ,
	{ "S2E_USE_VIP@", 	s2e_meta	} ,
#ifdef USE_SSH
	{ "S2E_SSH_CLIENT_USER", s2e_meta	} ,
	{ "S2E_SSH_CLIENT_PASS", s2e_meta	} ,
	{ "S2E_SSH_SERVER_USER_LIST_START", s2e_meta	} ,
	{ "S2E_SSH_SERVER_USER_LIST_END", s2e_meta	} ,
	{ "S2E_SSH_SERVER_USER_LIST@", s2e_meta	} ,
	{ "S2E_SSH_SERVER_RSA_PRIV", s2e_meta	} ,
	{ "S2E_SSH_SERVER_DSA_PRIV", s2e_meta	} ,
#endif	/* USE_SSH */
#ifdef USE_SSL
	{ "S2E_SSL_SERVER_CERT", s2e_meta	} ,
	{ "S2E_SSL_SERVER_KEY", s2e_meta	} ,
#endif	/* USE_SSL */
#ifdef USE_VIP
	{ "S2E_VIP_BOOTSTRAP", s2e_meta	} ,
#endif	/* USE_VIP */
	{ NULL, 			NULL		}
};

struct s2e_t s2e_conf[S2E_CHAN_MAX];
int info_flag = 0;
#ifdef USE_SSH
static char *fake_passwd = "\t\t\t\t\t\t\t\t";
#endif	/* USE_SSH */

#if (S2E_CHAN_MAX == 2)

#if 1
char *commands[2]   = {
	"/bin/s2e -0 -C /etc/s2e-ttyS0.conf",
	"/bin/s2e -1 -C /etc/s2e-ttyS1.conf"
};
char *conf_files[2] = {
	"/etc/s2e-ttyS0.conf",
	"/etc/s2e-ttyS1.conf"
};
#else
char *commands[2]   = {
	"${S2E_PREFIX}/bin/s2e -0 -C ${S2E_PREFIX}/etc/s2e-ttyS0.conf",
	"${S2E_PREFIX}/bin/s2e -1 -C ${S2E_PREFIX}/etc/s2e-ttyS1.conf"
};
char *conf_files[2] = {
	"${S2E_PREFIX}/etc/s2e-ttyS0.conf",
	"${S2E_PREFIX}/etc/s2e-ttyS1.conf"
};
#endif

char *pid_files[2]  = { "/var/run/s2e-ttyS0.pid", "/var/run/s2e-ttyS1.pid" };
char *info_files[2] = { "/tmp/s2e-ttyS0.info",    "/tmp/s2e-ttyS1.info"    };

#ifdef USE_VIP
int vip_net_port[2] = { 21000, 21001 };
#endif	/* USE_VIP */

#else

char *commands[1]   = { "/bin/s2e"		};
char *conf_files[1] = { "/etc/s2e.conf"	};
char *pid_files[1]  = { "/var/run/s2e.pid"				};
char *info_files[1] = { "/tmp/s2e.info"					};

#ifdef USE_VIP
int vip_net_port[1] = { 21000 };
#endif	/* USE_VIP */

#endif

#ifdef USE_SSH
char *ssh_rsa_priv_file = "/etc/ssh/ssh_host_rsa_key";
char *ssh_dsa_priv_file = "/etc/ssh/ssh_host_dsa_key";
char *ssh_conf_file = "/etc/ssh/auth_users";
#endif	/* USE_SSH */

#ifdef USE_SSL
char *ssl_cert_file = "/etc/ssl/ssl_server.crt";
char *ssl_key_file = "/etc/ssl/ssl_server.key";
#endif	/* USE_SSH */

#ifdef USE_VIP
char *vip_command1 = 
	"/bin/vipaccess --conf=/etc/vipaccess.conf /usr/local/etc/bootstrap.xml";
char *vip_command2 = "/bin/vipproxy &";
char *vip_command3 = 
	"/bin/vipportd --conf=/etc/vipaccess.conf /usr/local/etc/bootstrap.xml";
char *vip_pid_file1 = "/var/run/vipaccess.pid";
char *vip_pid_file2 = "/var/run/vipproxy.pid";
char *vip_pid_file3 = "/var/run/vipportd.pid";
char *vip_conf_file = "/etc/vipaccess.conf";
char *vip_bootstrap_file = "/usr/local/etc/bootstrap.xml";
#endif	/* USE_SSH */

static void default_config (int chan, struct s2e_t *conf_data);
static int read_config (int chan, struct s2e_t *conf_data);
static int write_config (int chan, struct s2e_t *conf_data);
static int read_info (int chan, struct s2e_t *conf_data);
#ifdef USE_SSH
static int read_ssh_config (int chan, struct s2e_t *conf_data);
static int write_ssh_config (int chan, struct s2e_t *conf_data);
static int add_user (struct s2e_t *conf_data, char *user, char *pass);
static int del_user (struct s2e_t *conf_data, int index);
static int list_user_start (struct s2e_t *conf_data, char *buffer, int buflen);
static int list_user_end (struct s2e_t *conf_data, char *buffer, int buflen);
static int list_user (struct s2e_t *conf_data, int index, char *buffer, int buflen);
#endif	/* USE_SSH */
#ifdef USE_VIP
#ifdef USE_VIP
static int vip_start (void);
static int vip_stop (void);
#endif	/* USE_VIP */
static int read_vip_config (int chan, struct s2e_t *conf_data);
static int write_vip_config (int chan, struct s2e_t *conf_data);
#endif	/* USE_VIP */

int s2e_stop_chan (int chan)
{
    if (chan < 0 || chan >= S2E_CHAN_MAX)
    {
        return -1;
    }

    terminate_process (pid_files[chan], 1000, S2E_CMD_NAME);

    return 0;
}

int s2e_start_chan (int chan)
{
    int rc = 0;

    if (chan < 0 || chan >= S2E_CHAN_MAX)
    {
        return -1;
    }

	default_config (chan, &s2e_conf[chan]);
	read_config (chan, &s2e_conf[chan]);
	if (s2e_conf[chan].net_mode != 0)
	{
		rc = execute (commands[chan]);
    }

	return rc;
}

int s2e_start (void)
{
	int chan;

	s2e_stop ();

	for (chan = 0; chan < S2E_CHAN_MAX; chan ++)
		s2e_start_chan (chan);

#ifdef USE_VIP
	vip_start ();
#endif

	return 0;
}

int s2e_stop (void)
{
	int chan;

	for (chan = 0; chan < S2E_CHAN_MAX; chan ++)
		s2e_stop_chan (chan);

#ifdef USE_VIP
	vip_stop ();
#endif

	return 0;
}

int s2e_init (HTTP_INFO *info)
{
	int chan;

	for (chan = 0; chan < S2E_CHAN_MAX; chan ++) {
		default_config (chan, &s2e_conf[chan]);
		read_config (chan, &s2e_conf[chan]);
	}

	return 0;
}

int s2e_exit (HTTP_INFO *info)
{
	return 0;
}

int s2e_clear (HTTP_INFO *info)
{
	int chan;

	for (chan = 0; chan < S2E_CHAN_MAX; chan ++) {
		default_config (chan, &s2e_conf[chan]);
		write_config (chan, &s2e_conf[chan]);
	}

	return 0;
}

int s2e_meta (HTTP_INFO *info, char *name, char *buffer, int buflen)
{
	char *ptr = name;
	struct s2e_t *conf;
	int chan = info->chan ? info->chan - 1 : 0;

	conf = &s2e_conf[chan];

	buffer[0] = '\0';

	if (strcmp (ptr, "S2E_CHAN") == 0) {
		sprintf (buffer, "%d", chan + 1);
	}
	else if (strncmp (ptr, "S2E_BAUD@",9) == 0) {
		if (atoi (ptr + 9) == conf->tty_baudrate)
			strcpy (buffer, "selected");
	}
	else if (strncmp (ptr, "S2E_PARITY@", 11) == 0) {
		if (atoi (ptr + 11) == conf->tty_parity)
			strcpy (buffer, "selected");
	}
	else if (strncmp (ptr, "S2E_STOPB@", 10) == 0) {
		if (atoi (ptr + 10) == conf->tty_stopbit)
			strcpy (buffer, "selected");
	}
	else if (strncmp (ptr, "S2E_LEN@", 8) == 0) {
		if (atoi (ptr + 8) == conf->tty_length)
			strcpy (buffer, "selected");
	}
	else if (strncmp (ptr, "S2E_FLOW@", 9) == 0) {
		if (atoi (ptr + 9) == conf->tty_flow)
			strcpy (buffer, "selected");
	}
	else if (strncmp (ptr, "S2E_DMA@", 8) == 0) {
		if (atoi (ptr + 8) == conf->tty_dma)
			strcpy (buffer, "selected");
	}
	else if (strncmp (ptr, "S2E_RS485@", 10) == 0) {
		if (atoi (ptr + 10) == conf->tty_rs485)
			strcpy (buffer, "selected");
	}
	else if (strcmp (ptr, "S2E_TIMEOUT") == 0) {
		sprintf (buffer, "%d", conf->tty_timeout);
	}
	else if (strcmp (ptr, "S2E_BUFSIZE") == 0) {
		sprintf (buffer, "%d", conf->tty_size);
	}
	else if (strcmp (ptr, "S2E_DELIM_1") == 0) {
		if (0 < conf->tty_delim_len)
			sprintf (buffer, "%02x",
				(unsigned)conf->tty_delim_code[0] & 0xff);
	} else if (strcmp (ptr, "S2E_DELIM_2") == 0) {
		if (1 < conf->tty_delim_len)
			sprintf (buffer, "%02x",
				(unsigned)conf->tty_delim_code[1] & 0xff);
	}
	else if (strncmp (ptr, "S2E_MODE@", 9) == 0) {
		if (atoi (ptr + 9) == conf->net_mode)
			strcpy (buffer, "selected");
	}
#ifdef	INET6
	else if (strncmp (ptr, "S2E_IPVER@", 10) == 0) {
		if (atoi (ptr + 10) == conf->net_ipv6)
			strcpy (buffer, "selected");
	}
#endif
	else if (strcmp (ptr, "S2E_HOST") == 0) {
#ifdef	USE_VIP
	if (conf->net_vip) {
		sprintf (buffer, "[%s]", conf->net_vipname);
	} else {
#endif	/* USE_VIP */
#ifdef	INET6
	if (conf->net_ipv6) {
		char ipaddr6[16];
		buffer[0] = '\0';
		memset (ipaddr6, 0, sizeof (ipaddr6));
		if (memcmp (conf->net_host6,
			(char *)&ipaddr6, sizeof (ipaddr6)) != 0) {
			inet_ntop (AF_INET6, conf->net_host6, buffer, buflen);
		}
	} else {
#endif
		long ipaddr = 0;
		buffer[0] = '\0';
		if (memcmp (conf->net_host, (char *)&ipaddr, sizeof (ipaddr)) != 0) {
			sprintf (buffer, "%u.%u.%u.%u",
				(unsigned)conf->net_host[0] & 0xff,
				(unsigned)conf->net_host[1] & 0xff,
				(unsigned)conf->net_host[2] & 0xff,
				(unsigned)conf->net_host[3] & 0xff);
		}
#ifdef	INET6
	}
#endif
#ifdef	USE_VIP
	}
#endif	/* USE_VIP */
	}
	else if (strncmp (ptr, "S2E_PROTO@", 10) == 0) {
		if (atoi (ptr + 10) == conf->net_proto)
			strcpy (buffer, "selected");
	}
	else if (strcmp (ptr, "S2E_PORT") == 0)
		sprintf (buffer, "%u", (unsigned)conf->net_port & 0xffff);

	else if (strcmp (ptr, "S2E_REMOTE") == 0) {
		if (info_flag == 0) { read_info (chan, conf); info_flag = 1; }
#ifdef	INET6
	if (conf->net_ipv6) {
		inet_ntop (AF_INET6, conf->remote_host6, buffer, buflen);
		sprintf (&buffer[strlen(buffer)], "/%u",
			(unsigned)conf->remote_port);
	} else
#endif
		sprintf (buffer, "%u.%u.%u.%u:%u",
			(unsigned)conf->remote_host[0] & 0xff,
			(unsigned)conf->remote_host[1] & 0xff,
			(unsigned)conf->remote_host[2] & 0xff,
			(unsigned)conf->remote_host[3] & 0xff,
			(unsigned)conf->remote_port);
	}
	else if (strcmp (ptr, "S2E_SEND") == 0) {
		if (info_flag == 0) { read_info (chan, conf); info_flag = 1; }
		sprintf (buffer, "%lu", conf->tty_sent);
	}
	else if (strcmp (ptr, "S2E_RECV") == 0) {
		if (info_flag == 0) { read_info (chan, conf); info_flag = 1; }
		sprintf (buffer, "%lu", conf->tty_rcvd);
	}
#ifdef USE_SSH
	else if (strcmp (ptr, "S2E_SSH_CLIENT_USER") == 0) {
		strcpy (buffer, conf->connect_user.user);
	}
	else if (strcmp (ptr, "S2E_SSH_CLIENT_PASS") == 0) {
		strcpy (buffer, fake_passwd);
	}
	else if (strcmp (ptr, "S2E_SSH_SERVER_USER_LIST_START") == 0) {
		list_user_start(conf, buffer, buflen);
	}
	else if (strcmp (ptr, "S2E_SSH_SERVER_USER_LIST_END") == 0) {
		list_user_end(conf, buffer, buflen);
	}
	else if (strncmp (ptr, "S2E_SSH_SERVER_USER_LIST@", 25) == 0) {
		list_user(conf, atoi (ptr + 25), buffer, buflen);
	}
	else if (strcmp (ptr, "S2E_SSH_SERVER_RSA_PRIV") == 0) {
		struct stat s;
		if (lstat(ssh_rsa_priv_file, &s) == 0 && S_ISREG(s.st_mode))
			strcpy (buffer, "(Available)");
		else
			strcpy (buffer, "(Not Available)");
	}
	else if (strcmp (ptr, "S2E_SSH_SERVER_DSA_PRIV") == 0) {
		struct stat s;
		if (lstat(ssh_dsa_priv_file, &s) == 0 && S_ISREG(s.st_mode))
			strcpy (buffer, "(Available)");
		else
			strcpy (buffer, "(Not Available)");
	}
#endif
#ifdef USE_SSL
	else if (strcmp (ptr, "S2E_SSL_SERVER_CERT") == 0) {
		struct stat s;
		if (lstat(ssl_cert_file, &s) == 0 && S_ISREG(s.st_mode))
			strcpy (buffer, "(Available)");
		else
			strcpy (buffer, "(Not Available)");
	}
	else if (strcmp (ptr, "S2E_SSL_SERVER_KEY") == 0) {
		struct stat s;
		if (lstat(ssl_key_file, &s) == 0 && S_ISREG(s.st_mode))
			strcpy (buffer, "(Available)");
		else
			strcpy (buffer, "(Not Available)");
	}
#endif
#ifdef USE_VIP
	else if (strcmp (ptr, "S2E_VIP_BOOTSTRAP") == 0) {
		struct stat s;
		if (lstat(vip_bootstrap_file, &s) == 0 && S_ISREG(s.st_mode))
			strcpy (buffer, "(Available)");
		else
			strcpy (buffer, "(Not Available)");
	}
#endif
#ifndef USE_SSH
	else if (strncmp (ptr, "S2E_USE_SSH@", 12) == 0) {
		if (atoi (ptr + 12) == 0)
			strcpy (buffer, "<!--");
		else
			strcpy (buffer, "-->");
	}
#endif
#ifndef USE_SSL
	else if (strncmp (ptr, "S2E_USE_SSL@", 12) == 0) {
		if (atoi (ptr + 12) == 0)
			strcpy (buffer, "<!--");
		else
			strcpy (buffer, "-->");
	}
#endif
#ifndef USE_VIP
	else if (strncmp (ptr, "S2E_USE_VIP@", 12) == 0) {
		if (atoi (ptr + 12) == 0)
			strcpy (buffer, "<!--");
		else
			strcpy (buffer, "-->");
	}
#endif

	return strlen (buffer);
}

int s2e_cgi (HTTP_INFO *info)
{
	int chan = info->chan ? info->chan - 1 : 0;
	int i;
	struct s2e_t *conf;
	struct s2e_t temp;
	int ret = 0;

#ifdef USE_SSH
	if (strncmp (info->func, "ssh", 3) == 0) {
		extern int ssh_cgi (HTTP_INFO *info);
		return ssh_cgi (info);
	}
#endif	/* USE_SSH */

	conf = &s2e_conf[chan];

	memcpy (&temp, conf, sizeof (temp));

	for (i = 0; i < info->argc; i ++) {
		char *ptr = info->argv[i];

		if (strncmp (ptr, "S2E_BAUD=", 9) == 0)
			temp.tty_baudrate = atol (ptr + 9);
		else if (strncmp (ptr, "S2E_PARITY=", 11) == 0)
			temp.tty_parity = atoi (ptr + 11);
		else if (strncmp (ptr, "S2E_STOPB=", 10) == 0)
			temp.tty_stopbit = atoi (ptr + 10);
		else if (strncmp (ptr, "S2E_LEN=", 8) == 0)
			temp.tty_length = atoi (ptr + 8);
		else if (strncmp (ptr, "S2E_FLOW=", 9) == 0)
			temp.tty_flow = atoi (ptr + 9);
		else if (strncmp (ptr, "S2E_DMA=", 8) == 0)
			temp.tty_dma = atoi (ptr + 8);
		else if (strncmp (ptr, "S2E_RS485=", 10) == 0)
			temp.tty_rs485 = atoi (ptr + 10);
		else if (strncmp (ptr, "S2E_TIMEOUT=", 12) == 0) {
			temp.tty_timeout = atoi (ptr + 12);
			if (temp.tty_timeout < 0 || 65535 < temp.tty_timeout) {
				ret = -1;
				break;
			}
		}
		else if (strncmp (ptr, "S2E_BUFSIZE=", 12) == 0) {
			temp.tty_size = atoi (ptr + 12);
			if (temp.tty_size < 64 || 2048 < temp.tty_size) {
				ret = -1;
				break;
			}
		}
		else if (strncmp (ptr, "S2E_DELIM_1=", 12) == 0) {
			if (*(ptr + 12)) {
				temp.tty_delim_code[0] =  hatol (ptr + 12);
				temp.tty_delim_len = 1;
			} else {
				temp.tty_delim_len = 0;
			}
		}
		else if (strncmp (ptr, "S2E_DELIM_2=", 12) == 0) {
			if (*(ptr + 12)) {
				temp.tty_delim_code[1] =  hatol (ptr + 12);
				temp.tty_delim_len = 2;
			}
		}
		else if (strncmp (ptr, "S2E_MODE=", 9) == 0)
			temp.net_mode = atoi (ptr + 9);
#ifdef	INET6
		else if (strncmp (ptr, "S2E_IPVER=", 10) == 0)
			temp.net_ipv6 = atoi (ptr + 10);
#endif
		else if (strncmp (ptr, "S2E_HOST=", 9) == 0) {
#ifdef	USE_VIP
		if (strncmp (ptr + 9, "[vip", 4) == 0 &&
			ptr[strlen (ptr) - 1] == ']') {
			int len;
			temp.net_vip = 1;
			len = strlen (ptr + 10) - 1;
			memcpy (temp.net_vipname, ptr + 10,
				len < sizeof (temp.net_vipname) - 1 ?
				len : sizeof (temp.net_vipname) - 1);
		} else {
			temp.net_vip = 0;
#endif	/* USE_VIP */
#ifdef	INET6
		if (temp.net_ipv6) {
			char ipaddr6[16];
			memset (ipaddr6, 0, sizeof (ipaddr6));
			if (*(ptr + 9) != '\0') {
				if (inet_pton (AF_INET6, ptr + 9, ipaddr6) <= 0){
					ret = -1;
					break;
				}
			}
			memcpy (temp.net_host6, ipaddr6, sizeof (ipaddr6));
		} else {
#endif
			unsigned long ipaddr = 0;
			if (*(ptr + 9) != '\0') {
				ipaddr = inet_addr (ptr + 9);
				if (ipaddr == 0xffffffffL) {
					ret = -1;
					break;
				}
			}
			memcpy (temp.net_host, (char *)&ipaddr, sizeof (ipaddr));
#ifdef	INET6
		}
#endif
#ifdef	USE_VIP
		}
#endif	/* USE_VIP */
		}
		else if (strncmp (ptr, "S2E_PROTO=", 10) == 0)
			temp.net_proto = atoi (ptr + 10);
		else if (strncmp (ptr, "S2E_PORT=", 9) == 0) {
			temp.net_port = atoi (ptr + 9);
			if (temp.net_port <= 0 || 65535 < temp.net_port) {
				ret = -1;
				break;
			}
		}
#ifdef USE_SSH
		else if (strncmp (ptr, "S2E_SSH_CLIENT_USER=", 20) == 0) {
			strncpy (temp.connect_user.user, ptr + 20,
					sizeof(temp.connect_user.user));
			temp.connect_user.user[sizeof(temp.connect_user.user)-1] = '\0';
		}
		else if (strncmp (ptr, "S2E_SSH_CLIENT_PASS=", 20) == 0) {
			if (strcmp (ptr + 20, fake_passwd) != 0) {
				strncpy (temp.connect_user.user, ptr + 20,
						sizeof(temp.connect_user.user));
				temp.connect_user.user[sizeof(temp.connect_user.user)-1] = '\0';
			}
		}
#endif	/* USE_SSH */
	}

	if (ret == 0) {
		if (memcmp (conf, &temp, sizeof (temp)) != 0) {
#ifdef USE_VIP
			write_vip_config (chan, &temp);
			vip_stop ();
			vip_start ();
#endif	/* USE_SSH */
			if (write_config (chan, &temp) == 0) {
				memcpy (conf, &temp, sizeof (temp));
                s2e_stop_chan (chan);
                s2e_start_chan (chan);
            }
		}
	}

	return ret;
}

void
default_config (int chan, struct s2e_t *conf_data)
{
	memset (&s2e_conf[chan], 0, sizeof (struct s2e_t));

	sprintf (conf_data->tty_device, "/dev/ttyS%d", chan);
	conf_data->tty_baudrate = 115200;
	conf_data->tty_parity = 0;
	conf_data->tty_stopbit = 1;
	conf_data->tty_length = 8;
	conf_data->tty_flow = 0;
	conf_data->tty_timeout = 1000;
	conf_data->tty_size = 2048;
	conf_data->tty_delim_len = 1;
	conf_data->tty_delim_code[0] = 0x0a;

	conf_data->net_mode = chan ? 1 : 0;
	conf_data->net_proto = 1;
	conf_data->net_port = 5000 + chan;
	conf_data->net_timeout = 10;
}

int
read_config (int chan, struct s2e_t *conf_data)
{
	FILE *fp = NULL;
	char input[128];
	char token[64];
	int line = 0;

/* move to default_config()
	conf_data->tty_baudrate = 115200;
	conf_data->tty_parity = 0;
	conf_data->tty_stopbit = 1;
	conf_data->tty_length = 8;
	conf_data->tty_flow = 0;
	conf_data->tty_timeout = 1000;
	conf_data->tty_size = 2048;
	conf_data->tty_delim_len = 1
	conf_data->tty_delim_code[0] = 0x0a;

	conf_data->net_mode = chan ? 1 : 0;
	conf_data->net_proto = 1;
	conf_data->net_port = 5000 + chan;
	conf_data->net_timeout = 10;
*/

#ifdef USE_SSH
	read_ssh_config (chan, conf_data);
#endif

	fp = fopen (conf_files[chan], "r");
	if (fp == NULL) {
//		fprintf(stderr, "can't open %s: %s\n", conf_files[chan], strerror(errno));
		return (-1);
	}

	while (fgets(input, sizeof (input), fp)!=NULL){
		char *ptr = input;
		line ++;

		ptr = get_token (ptr, token, sizeof (token));
		if (token[0] == '#')
			continue;

		if (strcasecmp (token, "tty") == 0) {

			ptr = get_token (ptr, token, sizeof (token));
			if (strcmp (token, "{") != 0)
				goto err;

			while (fgets(input, sizeof (input), fp)!=NULL){
				char *ptr = input;
				line++;

				ptr = get_token (ptr, token, sizeof (token));
				if (token[0] == '#')
					continue;

				if (strcmp (token, "}") == 0) {
					break;
				}
				else if (strcasecmp (token, "device") == 0) {
					ptr = get_token (ptr, token, sizeof (token));
					strncpy (conf_data->tty_device,
						token, sizeof (conf_data->tty_device) - 1);
				}
				else if (strcasecmp (token, "baudrate") == 0) {
					long value;
					ptr = get_token (ptr, token, sizeof (token));
					switch (atol (token)) {
#ifdef CONFIG_DEFAULTS_LANTRONIX_XPORT_PRO
					case 921600:    value = 921600; break;
#endif
					case 230400:	value = 230400;	break;
					case 115200:	value = 115200;	break;
					case 57600:		value = 57600;	break;
					case 38400:		value = 38400;	break;
					case 19200:		value = 19200;	break;
					case 9600:		value = 9600;	break;
					case 4800:		value = 4800;	break;
					case 2400:		value = 2400;	break;
					case 1200:		value = 1200;	break;
					case 600:		value = 600;	break;
					case 300:		value = 300;	break;
					default:		goto err;		break;
					}
					conf_data->tty_baudrate = value;
				}
				else if  (strcasecmp (token, "parity") == 0) {
					ptr = get_token (ptr, token, sizeof (token));
					if (strcasecmp(token, "none") == 0)
						conf_data->tty_parity = 0;
					else if (strcasecmp(token, "odd") == 0)
						conf_data->tty_parity = 1;
					else if (strcasecmp(token, "even") == 0)
						conf_data->tty_parity = 2;
					else
						goto err;
				}
				else if  (strcasecmp (token, "stopbit") == 0) {
					int value;
					ptr = get_token (ptr, token, sizeof (token));
					value = atoi (token);
					if (value < 1 || 2 < value)
						goto err;
					conf_data->tty_stopbit = value;
				}
				else if  (strcasecmp (token, "length") == 0) {
					int value;
					ptr = get_token (ptr, token, sizeof (token));
					value = atoi (token);
					if (value < 5 || 8 < value)
						goto err;
					conf_data->tty_length = value;
				}
				else if  (strcasecmp (token, "flow") == 0) {
					ptr = get_token (ptr, token, sizeof (token));
					if (strcasecmp(token, "none") == 0)
						conf_data->tty_flow = 0;
					else if (strcasecmp(token, "soft") == 0)
						conf_data->tty_flow = 1;
					else if (strcasecmp(token, "hard") == 0)
						conf_data->tty_flow = 2;
					else
						goto err;
				}
				else if  (strcasecmp (token, "timeout") == 0) {
					int value;
					ptr = get_token (ptr, token, sizeof (token));
					value = atol (token);
					conf_data->tty_timeout = value;
				}
				else if  (strcasecmp (token, "dma") == 0) {
					ptr = get_token (ptr, token, sizeof (token));
					if (strcasecmp(token, "disable") == 0)
						conf_data->tty_dma = 0;
					else if (strcasecmp(token, "enable") == 0)
						conf_data->tty_dma = 1;
					else
						goto err;
				}
				else if  (strcasecmp (token, "rs485") == 0) {
					ptr = get_token (ptr, token, sizeof (token));
					if (strcasecmp(token, "disable") == 0)
						conf_data->tty_rs485 = 0;
					else if (strcasecmp(token, "enable") == 0)
						conf_data->tty_rs485 = 1;
					else if (strcasecmp(token, "half") == 0)
						conf_data->tty_rs485 = 1;
					else if (strcasecmp(token, "full") == 0)
						conf_data->tty_rs485 = 2;
					else if (strcasecmp(token, "t-half") == 0)
						conf_data->tty_rs485 = 3;
					else if (strcasecmp(token, "t-full") == 0)
						conf_data->tty_rs485 = 4;
					else
						goto err;
				}
				else if  (strcasecmp (token, "size") == 0) {
					int value;
					ptr = get_token (ptr, token, sizeof (token));
					value = atol (token);
					conf_data->tty_size = value;
				}
				else if  (strcasecmp (token, "delim") == 0) {
					long value;
					ptr = get_token (ptr, token, sizeof (token));
					if (strcasecmp(token, "none") == 0) {
						conf_data->tty_delim_len = 0;
						break;
					}
					value = hatol (token);
					if (value < 0)
						goto err;
					switch (strlen (token)) {
					case 1:
					case 2:
						conf_data->tty_delim_code[0] = value & 0xff;
						conf_data->tty_delim_len = 1;
						break;
					case 3:
					case 4:
						conf_data->tty_delim_code[0] = (value >> 8 ) & 0xff;
						conf_data->tty_delim_code[1] = value & 0xff;
						conf_data->tty_delim_len = 2;
						break;
					default:	goto err;	break;
					}
				}
			}
		}

		else if (strcasecmp (token, "net") == 0) {

			ptr = get_token (ptr, token, sizeof (token));
			if (strcmp (token, "{") != 0)
				goto err;

			while (fgets(input, sizeof (input), fp)!=NULL){
				char *ptr = input;
				line++;

				ptr = get_token (ptr, token, sizeof (token));
				if (token[0] == '#')
					continue;

				if (strcmp (token, "}") == 0) {
					break;
				}
				else if (strcasecmp (token, "mode") == 0) {
					ptr = get_token (ptr, token, sizeof (token));
					if (strcasecmp(token, "disable") == 0)
						conf_data->net_mode = 0;
					else if (strcasecmp(token, "server") == 0)
						conf_data->net_mode = 1;
					else if (strcasecmp(token, "client") == 0)
						conf_data->net_mode = 2;
					else
						goto err;
				}
				else if (strcasecmp (token, "host") == 0) {
					unsigned long value;
					ptr = get_token (ptr, token, sizeof (token));

					value = (unsigned long) inet_addr(token);
					if (value == 0xffffffff)
						goto err;

					memcpy (conf_data->net_host, &value, 4);
				}
#ifdef INET6
				else if  (strcasecmp (token, "ipv6") == 0) {
					ptr = get_token (ptr, token, sizeof (token));
					if (strcasecmp(token, "disable") == 0)
						conf_data->net_ipv6 = 0;
					else if (strcasecmp(token, "enable") == 0)
						conf_data->net_ipv6 = 1;
					else
						goto err;
				}
				else if (strcasecmp (token, "host6") == 0) {
					unsigned char value[16];

					ptr = get_token (ptr, token, sizeof (token));

					if (inet_pton (AF_INET6, token, (char *)value) <= 0)
						goto err;

					memcpy (conf_data->net_host6, value, 16);
				}
#endif	/* INET6 */
				else if  (strcasecmp (token, "port") == 0) {
					int value;
					ptr = get_token (ptr, token, sizeof (token));
					value = atoi (token);
					if (value <= 0 || 0xffff < value)
						goto err;
					conf_data->net_port = value;
				}
				else if (strcasecmp (token, "proto") == 0) {
					ptr = get_token (ptr, token, sizeof (token));
					if (strcasecmp(token, "udp") == 0)
						conf_data->net_proto = 0;
					else if (strcasecmp(token, "tcp") == 0)
						conf_data->net_proto = 1;
#ifdef USE_SSH
					else if (strcasecmp(token, "ssh") == 0)
						conf_data->net_proto = 2;
#endif	/* USE_SSH */
#ifdef USE_SSL
					else if (strcasecmp(token, "ssl") == 0)
						conf_data->net_proto = 3;
#endif	/* USE_SSL */
					else
						goto err;
				}
#ifdef USE_SSH
				else if (strcasecmp (token, "user") == 0) {
					ptr = get_token (ptr, token, sizeof (token));
					strncpy (conf_data->connect_user.user, token,
							sizeof(conf_data->connect_user.user) - 1);
					ptr = get_token (ptr, token, sizeof (token));
					strncpy (conf_data->connect_user.pass, token,
							sizeof(conf_data->connect_user.pass) - 1);
				}
#endif	/* USE_SSH */
			}
		}
	}

	fclose (fp);
#ifdef USE_VIP
	read_vip_config (chan, conf_data);
#endif
	return 0;

err:
//	fprintf(stderr, "Error %s in %d\n", &conf_files[chan], line);
	if (fp)	fclose (fp);
	return -1;
}

int
write_config (int chan, struct s2e_t *conf_data)
{
	FILE *fp = NULL;
	char *tty_parity[] = {"none", "odd", "even"};
	char *tty_flow[] = {"none", "soft", "hard"};
	char *tty_rs485[] = {"disable", "half", "full", "t-half", "t-full"};
	char *net_mode[] = {"disable", "server", "client"};
	char *net_proto[] = {"udp", "tcp", "ssh", "ssl"};
	char *disable_enable[] = {"disable", "enable"};

#ifdef USE_SSH
	write_ssh_config (chan, conf_data);
#endif	/* USE_SSH */

	fp = fopen (conf_files[chan], "w");
	if (fp == NULL) {
//		fprintf(stderr, "can't open %s: %s\n", conf_files[chan], strerror(errno));
		return (-1);
	}

	fprintf (fp, "# %s (Automatically generated) \n", conf_files[chan]);
	fprintf (fp, "tty {\n");
	fprintf (fp, "\tdevice\t%s\n", conf_data->tty_device);
	fprintf (fp, "\tbaudrate\t%ld\n", conf_data->tty_baudrate);
	fprintf (fp, "\tparity\t%s\n", tty_parity[conf_data->tty_parity]);
	fprintf (fp, "\tstopbit\t%d\n", conf_data->tty_stopbit);
	fprintf (fp, "\tlength\t%d\n", conf_data->tty_length);
	fprintf (fp, "\tflow\t%s\n", tty_flow[conf_data->tty_flow]);
	fprintf (fp, "\tdma\t%s\n", disable_enable[conf_data->tty_dma]);
	fprintf (fp, "\trs485\t%s\n", tty_rs485[conf_data->tty_rs485]);
	fprintf (fp, "\ttimeout\t%d\n", conf_data->tty_timeout);
	fprintf (fp, "\tsize\t%d\n", conf_data->tty_size);
	if (conf_data->tty_delim_len == 1)
		fprintf (fp, "\tdelim\t%02x\n",
			(unsigned)conf_data->tty_delim_code[0] & 0xff);
	if (conf_data->tty_delim_len == 2)
		fprintf (fp, "\tdelim\t%02x%02x\n",
			(unsigned)conf_data->tty_delim_code[0] & 0xff,
			(unsigned)conf_data->tty_delim_code[1] & 0xff);
	fprintf (fp, "}\n");
	fprintf (fp, "\n");
	fprintf (fp, "net {\n");
	fprintf (fp, "\tmode\t%s\n", net_mode[conf_data->net_mode]);
#ifdef USE_VIP
	if (conf_data->net_vip && conf_data->net_mode == 2) /* client */
		fprintf (fp, "\thost\t127.0.0.1\n");
	else
#endif
	fprintf (fp, "\thost\t%u.%u.%u.%u\n",
			(unsigned)conf_data->net_host[0] & 0xff,
			(unsigned)conf_data->net_host[1] & 0xff,
			(unsigned)conf_data->net_host[2] & 0xff,
			(unsigned)conf_data->net_host[3] & 0xff);
#ifdef INET6
	if (conf_data->net_ipv6) {
		char temp[64];
		fprintf (fp, "\tipv6\t%s\n", disable_enable[conf_data->net_ipv6]);
		inet_ntop (AF_INET6, conf_data->net_host6, temp, sizeof(temp));
		fprintf (fp, "\thost6\t%s\n", temp);
	}
#endif	/* INET6 */
	fprintf (fp, "\tproto\t%s\n", net_proto[conf_data->net_proto]);
#ifdef USE_VIP
	if (conf_data->net_vip && conf_data->net_mode == 2) /* client */
		fprintf (fp, "\tport\t%u\n", vip_net_port[chan]);
	else
#endif
	fprintf (fp, "\tport\t%u\n", conf_data->net_port);
#ifdef USE_SSH
	fprintf (fp, "\tuser\t%s\t%s\n", conf_data->connect_user.user,
			conf_data->connect_user.pass);
#endif	/* USE_SSH */
	fprintf (fp, "}\n");

	fclose (fp);
	return 0;
}

static int
read_info (int chan, struct s2e_t *conf_data)
{
	FILE *fp;
	char buffer[128];
	int i;
	int pid = 0;

    if (chan < 0 || chan >= S2E_CHAN_MAX)
    {
        printf("Invalid chan %d\n", chan);
        return -1;
    }

	unlink (info_files[chan]);

	if ((pid = getpid_by_file (pid_files[chan])) < 0)
		return -1;

    if (!is_active_proc(pid, S2E_CMD_NAME))
    {
        unlink(pid_files[chan]);
        return -1;
    }

	kill (pid, SIGUSR1);

	for (i = 0; i < 30; i ++) {
		msleep (100);
		if ((fp = fopen (info_files[chan], "r")) != NULL) {

			while (fgets(buffer, sizeof (buffer), fp)!=NULL){
				char *ptr = buffer;
				if (strncmp (ptr , "tty_sent:", 9) == 0) {
					ptr += 9;
					ptr = skip_brank(ptr);
					conf_data->tty_sent = atol (ptr);
				}
				if (strncmp (ptr , "tty_rcvd:", 9) == 0) {
					ptr += 9;
					ptr = skip_brank(ptr);
					conf_data->tty_rcvd = atol (ptr);
				}
				if (strncmp (ptr , "remote_host:", 12) == 0) {
					unsigned long value;
					ptr += 12;
					ptr = skip_brank(ptr);
					value = (unsigned long) inet_addr(ptr);
					memcpy (conf_data->remote_host, &value, 4);
				}
#ifdef	INET6
				if (strncmp (ptr , "remote_host6:", 13) == 0) {
					ptr += 13;
					ptr = skip_brank(ptr);
					if (ptr[strlen (ptr) - 1] == '\n')
						ptr[strlen (ptr) - 1] = '\0';
					inet_pton (AF_INET6, ptr, (char *)conf_data->remote_host6);
				}
#endif
				if (strncmp (ptr , "remote_port:", 12) == 0) {
					ptr += 12;
					ptr = skip_brank(ptr);
					conf_data->remote_port = atol (ptr);
				}
			}
			fclose (fp);
			unlink (info_files[chan]);
			break;
		}
	}
	return 0;
}

#ifdef USE_SSH
int ssh_cgi (HTTP_INFO *info)
{
	int chan = info->chan ? info->chan - 1 : 0;
	int i;
	int ret = 0;
	struct s2e_t *conf;
	struct s2e_t temp;
	char *user = NULL;
	char *pass = NULL;

	conf = &s2e_conf[chan];

	memcpy (&temp, conf, sizeof (temp));

	for (i = 0; i < info->argc; i ++) {
		char *ptr = info->argv[i];


		if (strncmp (ptr, "S2E_SSH_SERVER_USER=", 20) == 0) {
			user = ptr + 20;
			if (user != NULL && pass != 0) {
				if (add_user(&temp, user, pass) < 0) {
					ret = -1;
					break;
				}
			}
		}
		else if (strncmp (ptr, "S2E_SSH_SERVER_PASS=", 20) == 0) {
			pass = ptr + 20;
			if (user != NULL && pass != NULL) {
				if (add_user(&temp, user, pass) < 0) {
					ret = -1;
					break;
				}
			}
		}
		else if (strncmp (ptr, "S2E_SSH_SERVER_USER_DEL@", 24) == 0) {
			int index = atoi (ptr + 24);
			if (del_user(&temp, index) < 0) {
				ret = -1;
				break;
			}
		}
	}
	if (ret == 0) {
		if (memcmp (conf, &temp, sizeof (temp)) != 0) {
			if (write_ssh_config (chan, &temp) == 0) {
				memcpy (conf, &temp, sizeof (temp));
				s2e_stop_chan (chan);
				s2e_start_chan (chan);
			}
		}
	}
	return ret;
}

static int
read_ssh_config (int chan, struct s2e_t *conf_data)
{
	FILE *fp = NULL;
	char input[128];
	char token[64];
	int count = 0;
	struct net_user *userp;

	fp = fopen (ssh_conf_file, "r");
	if (fp == NULL) {
//		fprintf(stderr, "can't open %s: %s\n", ssh_conf_file, strerror(errno));
		return (-1);
	}

	memset(conf_data->auth_user, 0,
			sizeof(struct net_user) * NET_MAX_AUTH_USER);

	while (fgets(input, sizeof (input), fp)!=NULL){
		char *ptr = input;

		if (NET_MAX_AUTH_USER <= count)
			break;

		ptr = get_token (ptr, token, sizeof (token));
		if (token[0] == '#')
			continue;

		if (token[0]) {
			userp = &conf_data->auth_user[count];
			strncpy(userp->user, token, NET_MAX_USER_LEN - 1);
			ptr = get_token (ptr, token, sizeof (token));
			strncpy(userp->pass, token, NET_MAX_PASS_LEN - 1);
			count ++;
		}
	}

	return 0;
}

static int
write_ssh_config (int chan, struct s2e_t *conf_data)
{
	FILE *fp = NULL;
	int i;

	fp = fopen (ssh_conf_file, "w");
	if (fp == NULL) {
//		fprintf(stderr, "can't open %s: %s\n", ssh_conf_file, strerror(errno));
		return (-1);
	}

	fprintf (fp, "# %s (Automatically generated) \n", ssh_conf_file);
	for (i = 0; i < NET_MAX_AUTH_USER; i++) {
		if (conf_data->auth_user[i].user[0]) {
			fprintf (fp, "%s\t%s\n", conf_data->auth_user[i].user,
					conf_data->auth_user[i].pass);
		}
	}

	fclose (fp);

	chmod(ssh_conf_file, 0600);

	return 0;
}

static int add_user (struct s2e_t *conf_data, char *user, char *pass)
{
	int i;
	struct net_user *userp;

	if (user == NULL || pass == NULL || user[0] == '\0')
		return -1;

	/* Error if already registered */
	for (i = 0; i < NET_MAX_AUTH_USER; i++) {
		userp = &conf_data->auth_user[i];
		if (strcmp (userp->user, user) == 0) {
			return -1;
		}
	}

	for (i = 0; i < NET_MAX_AUTH_USER; i++) {
		userp = &conf_data->auth_user[i];
		if (userp->user[0] == '\0') {
			strncpy (userp->user, user, NET_MAX_USER_LEN - 1);
			strncpy (userp->pass, pass, NET_MAX_USER_LEN - 1);
			return 0;
		}
	}

	return -1;
}

static int del_user (struct s2e_t *conf_data, int index)
{
	struct net_user *userp;

	if (index < 0 || NET_MAX_AUTH_USER <= index)
		return -1;

	userp = &conf_data->auth_user[index];
	memset (userp, 0, sizeof (struct net_user));

	return 0;
}

static int list_user_start (struct s2e_t *conf_data, char *buffer, int buflen)
{
	int i;
	int len = 0;
	int count = 0;
	struct net_user *userp;

	for (i = 0; i < NET_MAX_AUTH_USER; i++) {
		userp = &conf_data->auth_user[i];
		if (userp->user[0] != '\0') {
			count++;
		}
	}

	if (count == 0) {
		strcpy (&buffer[len], "No entry.");
		return 0;
	}

	len += snprintf (&buffer[len], buflen - len,
			"<TABLE width=\"100%%\" border=\"1\">\n");

	len += snprintf (&buffer[len], buflen - len, "<TR>\n");
	len += snprintf (&buffer[len], buflen - len,
			"<TD width=\"1\">&nbsp</TD>\n");
	len += snprintf (&buffer[len], buflen - len, "<TD>Username</TD>\n");
	len += snprintf (&buffer[len], buflen - len, "<TD>Password</TD>\n");
	len += snprintf (&buffer[len], buflen - len, "</TR>\n");

	return 0;
}

static int list_user_end (struct s2e_t *conf_data, char *buffer, int buflen)
{
	int i;
	int len = 0;
	int count = 0;
	struct net_user *userp;

	for (i = 0; i < NET_MAX_AUTH_USER; i++) {
		userp = &conf_data->auth_user[i];
		if (userp->user[0] != '\0') {
			count++;
		}
	}

	if (count == 0) {
		return 0;
	}

	len += snprintf (&buffer[len], buflen - len, "</TABLE>\n");
	len += snprintf (&buffer[len], buflen - len, "<TR>\n");
	len += snprintf (&buffer[len], buflen - len, "  <TD colspan=\"2\">\n");
	len += snprintf (&buffer[len], buflen - len, "    <INPUT type=\"submit\" "
			"name=\"del\" value=\"Delete\">\n");
	len += snprintf (&buffer[len], buflen - len, "  </TD>\n");
	len += snprintf (&buffer[len], buflen - len, "</TR>\n");

	return 0;
}

static int list_user (struct s2e_t *conf_data, int index, char *buffer, int buflen)
{
	int len = 0;
	struct net_user *userp;

	if (index < 0 || NET_MAX_AUTH_USER <= index)
		return -1;

	userp = &conf_data->auth_user[index];

	if (userp->user[0] == '\0')
		return 0;

	len += snprintf (&buffer[len], buflen - len, "<TR>\n");
	len += snprintf (&buffer[len], buflen - len, "<TD width=\"1\">"
			"<INPUT type=checkbox name=\"S2E_SSH_SERVER_USER_DEL@%d\"></TD>\n",
			index);
	len += snprintf (&buffer[len], buflen - len,
			"<TD>%s</TD>\n", userp->user);
	len += snprintf (&buffer[len], buflen - len, "<TD>********</TD>\n");
	len += snprintf (&buffer[len], buflen - len, "</TR>\n");

	return 0;
}
#endif	/* USE_SSH */

#ifdef USE_VIP
static int vip_start (void)
{
	int pid;

	if (0 < (pid = getpid_by_file (vip_pid_file1)))
		kill (pid, SIGHUP);
	else
		execute (vip_command1);

	if (0 < (pid = getpid_by_file (vip_pid_file2)))
		kill (pid, SIGHUP);
	else
		execute (vip_command2);

	if (0 < (pid = getpid_by_file (vip_pid_file3)))
		kill (pid, SIGHUP);
	else
		execute (vip_command3);

	return 0;
}

static int vip_stop (void)
{
	return 0;
}

static int
read_vip_config (int chan, struct s2e_t *conf_data)
{
	FILE *fp = NULL;
	char input[128];
	char token[64];

	fp = fopen (vip_conf_file, "r");
	if (fp == NULL) {
//		fprintf(stderr, "can't open %s: %s\n", vip_conf_file, strerror(errno));
		return (-1);
	}

	while (fgets(input, sizeof (input), fp)!=NULL){
		char *ptr = input;
		char *ptr2;

		ptr = get_token (ptr, token, sizeof (token));
		if (token[0] == '#')
			continue;

		if (strcmp (token, "connect") == 0) {
			ptr = get_token (ptr, token, sizeof (token));
			if ((ptr2 = strrchr (token, ':')) != 0) {
				if (atoi(ptr2 + 1) == vip_net_port[chan]) {
					if ((ptr2 = strchr (token, ':')) != 0) {
						unsigned long value;
						*ptr2 = '\0';
						strncpy ((char *)conf_data->net_vipname, token,
								sizeof(conf_data->net_vipname) - 1);
						conf_data->net_vip = 1;
						value = 0x7f000001; /* 127.0.0.1 */
						memcpy (conf_data->net_host, &value, 4);
						if ((ptr2 = strchr (ptr2 + 1, '/')) != 0) {
							conf_data->net_port = atoi (ptr2 + 1);
						}
					}
				}
			}
		}
	}

	return 0;
}

static int
write_vip_config (int chan, struct s2e_t *conf_data)
{
	FILE *fp1 = NULL;
	FILE *fp2 = NULL;
	char file[256];
	char input[128];
	char token[64];
	char *ptr;

	ptr = strrchr (vip_conf_file, '/');
	ptr = ptr ? ptr + 1 : vip_conf_file;

	snprintf (file, sizeof(file), "/tmp/%s", ptr);

	fp1 = fopen (vip_conf_file, "r");
	fp2 = fopen (file, "w");
	if (fp2== NULL) {
//		fprintf(stderr, "can't open %s: %s\n", ssh_conf_file, strerror(errno));
		fclose (fp1);
		return (-1);
	}

	if (fp1) {
		while (fgets(input, sizeof (input), fp1) != NULL) {
			char *ptr = input;
			char *ptr2;

			ptr = get_token (ptr, token, sizeof (token));
			if (strcmp (token, "connect") == 0) {
				ptr = get_token (ptr, token, sizeof (token));
				if ((ptr2 = strrchr (token, ':')) != 0) {
					if (atoi(ptr2 + 1) == vip_net_port[chan])
						continue;
				}
			}

			if (fputs (input, fp2) < 0)
				break;
		}
	} else {
		/* write default configuration */
		fprintf (fp2, "client\t/bin/dbclient\n");
		fprintf (fp2, "remote-port\t20000\n");
		fprintf (fp2, "local-port\t20001\n");
		fprintf (fp2, "bootstrap\t%s\n", vip_bootstrap_file);
		fprintf (fp2, "extend\n");
		fprintf (fp2, "replication\n");
		fprintf (fp2, "connect\t*:tcp/80:20010\n");
		fprintf (fp2, "connect\t*:tcp/443:20020\n");
		fprintf (fp2, "connect\t*:tcp/23:20030\n");
	}

	fprintf (fp2, "connect\t%s:tcp/%d:%d\n", conf_data->net_vipname,
			conf_data->net_port, vip_net_port[chan]);

	if (fp1)
		fclose (fp1);
	if (fp2)
		fclose (fp2);

	fp1 = fopen (file, "r");
	fp2 = fopen (vip_conf_file, "w");
	if (fp1 && fp2) {
		while (fgets (input, sizeof (input), fp1) != NULL) {
			fputs (input, fp2);
		}
	}
	if (fp1)
		fclose (fp1);
	if (fp2)
		fclose (fp2);
	unlink (file);

	chmod(vip_conf_file, 0600);

	return 0;
}
#endif	/* USE_VIP */
