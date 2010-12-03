/* pm_conf.h */

#ifndef _PM_CONF_H
#define _PM_CONF_H

extern int pm_start (void);
extern int pm_stop (void);
extern int pm_init (HTTP_INFO *info);
extern int pm_exit (HTTP_INFO *info);
extern int pm_meta (HTTP_INFO *info, char *name, char *buffer, int buflen);
extern int pm_meta (HTTP_INFO *info, char *name, char *buffer, int buflen);
extern int pm_cgi (HTTP_INFO *info);
extern int pm_clear (HTTP_INFO *info);
extern HTTP_META pm_meta_conf[];

#endif	/* _PM_CONF_H */
