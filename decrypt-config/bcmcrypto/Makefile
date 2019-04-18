#
# Assorted cryptographic algorithms
#
# Copyright (C) 2002 Broadcom Corporation
#
# $Id: Makefile 241182 2011-02-17 21:50:03Z $
#

SRCBASE	:= ..

CC	:= gcc
CFLAGS	+= -I. -I$(SRCBASE)/include -Wall
CFLAGS	+= -g -DDEBUG -ffunction-sections
#CFLAGS	+= -O2
CFLAGS	+= -Wall -Werror

#CC	:= cl
#CFLAGS	+= -I. -I../include -Ic:/tools/msdev/2600ddk/inc/crt
#LDFLAGS	+= -link -LIBPATH:c:/tools/msdev/2600ddk/lib/wxp/i386

PROGS	:= prf



all: $(PROGS)

clean:
	rm -f *.o *.obj $(PROGS) *.exe

prf:	prf.c hmac.c sha1.c md5.c
	$(CC) $(CFLAGS) -DBCMPRF_TEST -DBCMCCX -o $@ $^ $(LDFLAGS)
