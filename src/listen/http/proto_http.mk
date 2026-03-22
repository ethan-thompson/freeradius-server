TARGETNAME	:= proto_http

ifneq "$(TARGETNAME)" ""
TARGET		:= $(TARGETNAME)$(L)
endif

SOURCES		:= proto_http.c

TGT_PREREQS	:= $(LIBFREERADIUS_SERVER) libfreeradius-http$(L) libfreeradius-io$(L)
