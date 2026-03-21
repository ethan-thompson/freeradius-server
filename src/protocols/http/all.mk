#
# Makefile
#
# Version:	$Id$
#
TARGET		:= libfreeradius-http$(L)

SOURCES		:= base.c decode.c encode.c

SRC_CFLAGS	:= -I$(top_builddir)/src -DNO_ASSERT
TGT_PREREQS	:= libfreeradius-util$(L)
