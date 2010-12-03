/* main.c - main */

/* Copyright (c) 2008, Nissin Systems Co., Ltd. All rights reserved. */

/*
modification history
--------------------
02b,16dec09,nss  fixed for compiler bugs.
01a,05aug08,nss  written.
*/

#include "cgi.h"

extern int user_init(HTTP_INFO *info);
extern int user_cgi(HTTP_INFO *info);
extern HTTP_META_TABLE user_meta_table[];

int main (int argc, char *argv[])
{
	html_init = user_init;
	html_cgi = user_cgi;
	html_meta_table = user_meta_table;

	(void) html_main (argc, argv);

	return 0;
}
