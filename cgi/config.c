/* config.c - http cgi user configutation */

/* Copyright (c) 2008, Nissin Systems Co., Ltd. All rights reserved. */

/*
modification history
--------------------
01c,15jan10,nss  added SSH/SSL.
01b,29aug08,nss  fixed boa path..
01a,05aug08,nss  written.
*/

#include "cgi.h"
//#include "s2e_common.h"
#include "sys_conf.h"
#include "net_conf.h"
//#include "s2e_conf.h"
#include "io_conf.h"
#include "pm_conf.h"


HTTP_META_TABLE user_meta_table[] = {
	{ "SYS_",	sys_meta_conf	},
	{ "NET_",	net_meta_conf	},
	{ "S2E_",	io_meta_conf	},
	{ "PM_",	pm_meta_conf	},
	{ NULL, 	NULL			}
};

int user_startup (void)
{
	sys_start ();
	net_start ();
	io_start ();
	pm_start ();

	return 0;
}

int user_stop (void)
{
//	terminate_process (httpd_pidfile, 0);

	sys_stop ();
	net_stop ();
	io_stop ();
	pm_stop ();

	return 0;
}

/*USER INIT FUNCTION, called in main.c*/
int user_init (HTTP_INFO *info)
{
	sys_init (info);
	net_init (info);
	io_init (info); //init variables from conf file
	pm_init (info);
	return 0;
}

int user_result (HTTP_INFO *info, int result)
{
	html_header (info);
	html_body (info, "Result");
	if (result == 0)
    {
        printf ("Successful<BR>\n");
	}
	else
		printf ("Fail<BR>\n");

	printf ("<A HREF=\"javaScript:history.back();\">Back</A>\n");
	html_footer (info);
	return 0;
}

int user_cgi (HTTP_INFO *info)
{
	int ret = 0;

	if (info->boundary) {
		extern int user_multi (HTTP_INFO *info);
		if ((ret = user_multi (info)) != 0) {
			user_result (info, ret);
			return ret;
		}
	}

	if (strncmp (info->func, "system", 6) == 0 ||
	    strncmp (info->func, "admin", 5) == 0) {
		ret = sys_cgi (info);
		user_result (info, ret);
	}
	else if (strncmp (info->func, "network", 7) == 0) {
		ret = net_cgi (info);
		user_result (info, ret);
	}
	else if (strncmp (info->func, "io", 2) == 0) {
		ret = io_cgi (info);
		user_result (info, ret);
	}
	else if (strncmp (info->func, "pm", 2) == 0) {
		ret = pm_cgi (info);
		user_result (info, ret);
	}
	else {
		html_file_output (info);
	}

	return ret;
}

int user_clear (HTTP_INFO *info)
{
	sys_clear(info);
	net_clear(info);
	io_clear(info);
	pm_clear(info);
	return 0;
}

int user_reboot (HTTP_INFO *info)
{
	child (NULL, 0, "/bin/reboot");
	child (NULL, 0, "/sbin/reboot");	/* just in case */
	return 0;
}

int user_multi (HTTP_INFO *info)
{
	int sys_update = 0;
	int ret = 0;

	while (html_multipart (info) == 0) {
		int n = info->argc - 1;
		if (info->func && strncmp (info->func, "system", 6) == 0) {
			if (strncmp (info->argv[n], "SYS_UPDATE=", 11) == 0) {
				sys_update = atoi (info->argv[n] + 11);
			}
			else if (strncmp (info->argv[n], "SYS_FIRMWARE=", 13) == 0) {
				extern int user_update (HTTP_INFO *info, int mode);
				ret = user_update (info, sys_update);
				if (ret != 0)
					return ret;
			}
		}
	}

	return ret;
}

#include <sys/types.h> 
#include <sys/stat.h> 
#include <unistd.h> 

unsigned long user_multi_write (HTTP_INFO *info, FILE *fp)
{
	char *temp = NULL;
	unsigned long total = 0;
	int crlf_flag = 0;
	int dlen = 0;
	int blen = strlen(info->boundary);

	if ((temp = malloc (513)) == NULL) {
		goto abort;
	}

	while (1) {
		int n;

		if (crlf_flag) {
			crlf_flag = 0;
			temp[dlen++] = 0x0d;
			temp[dlen++] = 0x0a;
		}

		n = html_multipart_read (info, &temp[dlen], 512 - dlen);
		if (n < 0) {
			goto abort;
		}
		if (n == 0)
			break;

		dlen += n;

		if (2 <= dlen && temp[dlen - 2] == 0x0d && temp[dlen - 1] == 0x0a) {
			crlf_flag = 1;
			dlen -= 2;
			if (dlen == 0)
				continue;
		}

		if (2 <= dlen && temp[0] == 0x0d && temp[1] == 0x0a) {
			if (memcmp (&temp[2], "--", 2) == 0 &&
				memcmp (&temp[4], info->boundary, blen) == 0)
				break;
		}

		if (fp) {
			if (fwrite (temp, 1, dlen, fp) <= 0) {
				goto abort;
			}
		}

		total += dlen;
		dlen = 0;
	}

abort:
	if (temp)
		free (temp);

	return total;
}

int user_update (HTTP_INFO *info, int mode)
{
	char *firmware = "/var/firmware.img";	/* using fw-upgrade */
	FILE *fp = NULL;
	int ret = 0;

	if (mode) {
		struct stat s;
		if (lstat (firmware, &s) != 0 || !S_ISFIFO(s.st_mode)) {
			ret = -1;
			goto abort;
		}
		fp = fopen (firmware, "wb");
		if (fp == NULL)  {
			ret = -1;
			goto abort;
		}
	}

	if (user_multi_write (info, fp) == 0)
		ret = -1;

abort:

	if (fp)
		fclose (fp);

	return ret;
}

int user_update_file (HTTP_INFO *info, char *file)
{
	FILE *fp = NULL;
	int ret = 0;
	char temp[256];
	char *ptr;

	ptr = strrchr (file, '/');
	ptr = ptr ? ptr + 1 : file;

	snprintf (temp, sizeof(temp), "/tmp/%s", ptr);
	fp = fopen (temp, "wb");
	if (fp == NULL)  {
		ret = -1;
		goto abort;
	}

	if (user_multi_write (info, fp) == 0) {
		ret = -1;
	}

abort:

	if (fp)
		fclose (fp);

	if (ret == 0) {
		FILE *fp2 = NULL;
		char buf[256];
		fp  = fopen (temp, "r");
		fp2 = fopen (file, "w");
		if (fp && fp2) {
			while (fgets(buf, sizeof (buf), fp) != NULL) {
				fputs(buf, fp2);
			}
		}
		if (fp)
			fclose (fp);
		if (fp2)
			fclose (fp2);
	}

	unlink (temp);

	return ret;
}
