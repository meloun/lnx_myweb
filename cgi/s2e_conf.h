/* s2e_conf.h - s2e configuration header */

/* Copyright (c) 2008, Nissin Systems Co., Ltd. All rights reserved. */

/*
modification history
--------------------
01a,05aug08,nss  written.
*/

#ifndef _S2E_CONF_H
#define _S2E_CONF_H

#define	S2E_CHAN_MAX	2

extern int s2e_start (void);
extern int s2e_stop (void);
extern int s2e_init (HTTP_INFO *info);
extern int s2e_exit (HTTP_INFO *info);
extern int s2e_meta (HTTP_INFO *info, char *name, char *buffer, int buflen);
extern int s2e_cgi (HTTP_INFO *info);
extern int s2e_clear (HTTP_INFO *info);
extern HTTP_META s2e_meta_conf[];

#endif	/* _S2E_CONF_H */
