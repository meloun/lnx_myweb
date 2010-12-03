# Makefile - makefile for ~/cgi
#
# Copyright (c) 2008, Nissin Systems Co., Ltd. All rights reserved.
#
# modification history
# --------------------
# 01a,05aug08,nss  written.
#

TOP_DIR := $(shell cd ../../../../; pwd)
include $(TOP_DIR)/config/config.make

FLTFLAGS = -s 6144

OFLAGS:=-static -lcrypt

INS_DIR := $(TOP_DIR)/romfs

##

LIBCGI	:= ../../cgi/libcgi
#LIBS2E	:= ../libs2e
CFLAGS	+= -I$(LIBCGI) #-I$(LIBS2E)
ifneq ($(CONFIG_IPV6),)
CFLAGS	+=-DINET6
endif
OFLAGS	+= -L$(LIBCGI) -lcgi #-L$(LIBS2E) -ls2e
#LIBS	+= $(LIBCGI)/libcgi.a $(LIBS2E)/libs2e.a

##

HDRS =
OBJS = main.o config.o
EXES = myweb.cgi
HTMS =

HDRS += sys_conf.h net_conf.h io_conf.h pm_conf.h ../../my_libc/s2e_common.h ../../my_libc/io_common.h  ../../my_libc/pm_common.h #s2e_conf.h
OBJS += sys_conf.o net_conf.o  io_conf.o pm_conf.o ../../my_libc/s2e_common.o ../../my_libc/io_common.o  ../../my_libc/pm_common.o#s2e_conf.o
#HDRS += sys_conf.h net_conf.h pm_conf.h  ../../my_libc/pm_common.h #s2e_conf.h
#OBJS += sys_conf.o net_conf.o  pm_conf.o ../../my_libc/pm_common.o#s2e_conf.o


HTMS = 	html/admin.html		\
	html/cond.html		\
	html/index.html		\
	html/main.html		\
	html/network.html	\
	html/stat.html

##

#####################################################################
# We need to conditionally set the install arguments for menu.html
# based on the number of serial port configured for our target.
#####################################################################
INSTALL_MENU_ARGS = html/menu.html $(INS_DIR)/www/.
ifeq ($(CONFIG_USER_LANTRONIX_S2E_CON2),)
 ifeq ($(CONFIG_USER_LANTRONIX_S2E_CON_BOTH),)
   INSTALL_MENU_ARGS = html/menu.html.port1_only $(INS_DIR)/www/menu.html
 endif
endif

#####################################################################
# We need to conditionally set the install arguments for menu.html
# based on the number of serial port configured for our target.
#####################################################################
INSTALL_SERIAL_ARGS = html/serial.html $(INS_DIR)/www/.
ifneq ($(CONFIG_XPORT_PRO),)
   INSTALL_SERIAL_ARGS = html/serial.html.xpp $(INS_DIR)/www/serial.html
endif
ifneq ($(CONFIG_EDS1100),)
   INSTALL_SERIAL_ARGS = html/serial.html.eds $(INS_DIR)/www/serial.html
endif

INSTALL_SYSTEM_ARGS = html/system.html $(INS_DIR)/www/.
ifneq ($(CONFIG_USER_LANTRONIX_S2E_UPDATE),)
  INSTALL_SYSTEM_ARGS = html/system2.html $(INS_DIR)/www/system.html
endif

all:  $(EXES)

$(EXES):  $(OBJS) $(HDRS) $(LIBS)
	$(CC) -o $(EXES) $(OBJS) $(OFLAGS) $(LDFLAGS) $(EXTRALIBS) $(LDLIBS)

.c.o:
	$(CC) $(CFLAGS) -c $<

clean:
	-@rm -f $(EXES) $(EXES).gdb $(OBJS)
	-@rm -f $(INS_DIR)/home/httpd/cgi-bin/$(EXES)
	-@rm -f $(INS_DIR)/home/httpd/*.html

romfs: all
	[ -d $(INS_DIR)/www/cgi-bin ] || mkdir -p $(INS_DIR)/www/cgi-bin
ifneq ($(FLTFLAGS),)
	$(CROSS)flthdr $(FLTFLAGS) $(EXES)
endif
	install -m 0755 $(EXES) 	$(INS_DIR)/www/cgi-bin/.
	install -m 0644 $(HTMS) 	$(INS_DIR)/www/.
	install -m 0644 $(INSTALL_MENU_ARGS)
	install -m 0644 $(INSTALL_SERIAL_ARGS)
	install -m 0644 $(INSTALL_SYSTEM_ARGS)
ifneq ($(CONFIG_USER_LANTRONIX_S2E_SSH),)
	install -m 0644 html/ssh.html $(INS_DIR)/www/ssh.html
endif
ifneq ($(CONFIG_USER_LANTRONIX_S2E_SSL),)
	install -m 0644 html/ssl.html $(INS_DIR)/www/ssl.html
endif
ifneq ($(CONFIG_USER_LANTRONIX_S2E_VIP),)
	install -m 0644 html/vip.html $(INS_DIR)/www/vip.html
endif

##

main.o			: main.c			$(HDRS)
config.o		: config.c			$(HDRS)
sys_conf.c.o		: sys_conf.c.c		$(HDRS)
net_conf.c.o		: net_conf.c.c		$(HDRS)
#s2e_conf.c.o		: s2e_conf.c.c		$(HDRS)
io_conf.c.o		: io_conf.c.c	$(HDRS)
pm_conf.c.o		: pm_conf.c.c		$(HDRS)

