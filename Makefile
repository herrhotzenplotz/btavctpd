PROG=	btavctpd
SRCS=	btavctpd.c
LDADD=	-lbluetooth -lsdp
MAN=	btavctpd.8

CFLAGS_PLAYERCTL != pkg-config --cflags playerctl
LIBS_PLAYERCTL != pkg-config --libs playerctl

CFLAGS += $(CFLAGS_PLAYERCTL) -DHAVE_LIBPLAYERCTL=1
LDADD += $(LIBS_PLAYERCTL)
SRCS += playerctl.c

.include <bsd.prog.mk>
