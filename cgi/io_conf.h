/* s2e_conf.h - s2e configuration header */

/* Copyright (c) 2008, Nissin Systems Co., Ltd. All rights reserved. */

/*
modification history
--------------------
01a,05aug08,nss  written.
*/

#ifndef _IO_CONF_H
#define _IO_CONF_H

#define	IO_CHAN_MAX	2

extern int io_start (void);
extern int io_stop (void);
extern int io_init (HTTP_INFO *info);
extern int io_exit (HTTP_INFO *info);
extern int io_meta (HTTP_INFO *info, char *name, char *buffer, int buflen);
extern int io_cgi (HTTP_INFO *info);
extern int io_clear (HTTP_INFO *info);
extern HTTP_META io_meta_conf[];

#endif	/* _IO_CONF_H */
