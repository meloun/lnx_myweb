/* sys_conf.h - system configuration header */

/* Copyright (c) 2008, Nissin Systems Co., Ltd. All rights reserved. */

/*
modification history
--------------------
01a,05aug08,nss  written.
*/

#ifndef _SYS_CONF_H
#define _SYS_CONF_H

extern int sys_start (void);
extern int sys_stop (void);
extern int sys_init (HTTP_INFO *info);
extern int sys_exit (HTTP_INFO *info);
extern int sys_meta (HTTP_INFO *info, char *name, char *buffer, int buflen);
extern int sys_cgi (HTTP_INFO *info);
extern int sys_clear (HTTP_INFO *info);
extern HTTP_META sys_meta_conf[];

#endif	/* _SYS_CONF_H */
