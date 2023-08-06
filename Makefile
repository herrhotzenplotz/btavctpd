PROG=	btavctpd
SRCS=	btavctpd.c
LDADD=	-lbluetooth -lsdp
MAN=	btavctpd.8

.include <bsd.prog.mk>
