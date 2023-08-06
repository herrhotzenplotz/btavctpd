PROG=	btavctpd
SRCS=	btavctpd.c
LDADD=	-lbluetooth -lsdp
MAN=

.include <bsd.prog.mk>
