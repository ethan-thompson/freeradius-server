TARGETNAME	:= proto_http_tcp

ifneq "$(TARGETNAME)" ""
TARGET		:= $(TARGETNAME)$(L)
endif

SOURCES		:= proto_http_tcp.c

TGT_PREREQS	:= libfreeradius-http$(L)
