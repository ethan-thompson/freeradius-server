TARGETNAME	:= process_http

TARGET		:= $(TARGETNAME)$(L)

SOURCES		:= base.c
TGT_PREREQS	:= libfreeradius-http$(L)
