TARGETNAME	:= rlm_pkcs10

ifneq "$(TARGETNAME)" ""
TARGET		:= $(TARGETNAME)$(L)
endif

SOURCES		:= $(TARGETNAME).c

# SRC_CFLAGS	:= -I/Users/ethanthompson/devel/openssl/apps/include -I/opt/homebrew/Cellar/openssl@3/3.3.1/include -I/Users/ethanthompson/devel/freeradius-server/src/protocols
SRC_CFLAGS	:= -I/opt/homebrew/Cellar/openssl@3/3.3.1/include
# TGT_LDLIBS	:= -L
LOG_ID_LIB	= 61
