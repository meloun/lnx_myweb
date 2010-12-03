/* net_conf.h - network configuration header */

/* Copyright (c) 2008, Nissin Systems Co., Ltd. All rights reserved. */

/*
modification history
--------------------
01a,05aug08,nss  written.
*/

#ifndef _NET_CONF_H
#define _NET_CONF_H

extern int net_start (void);
extern int net_stop (void);
extern int net_init (HTTP_INFO *info);
extern int net_exit (HTTP_INFO *info);
extern int net_meta (HTTP_INFO *info, char *name, char *buffer, int buflen);
extern int net_cgi (HTTP_INFO *info);
extern int net_clear (HTTP_INFO *info);
extern HTTP_META net_meta_conf[];

#endif	/* _NET_CONF_H */
