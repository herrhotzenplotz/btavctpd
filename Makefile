PROG=		btavctpd
SRCS=		btavctpd.c
LDADD=		-lbluetooth -lsdp
MAN=		btavctpd.8
VERSION=	1.0.0

CFLAGS_PLAYERCTL != pkg-config --cflags playerctl
LIBS_PLAYERCTL != pkg-config --libs playerctl

CFLAGS += $(CFLAGS_PLAYERCTL) -DHAVE_LIBPLAYERCTL=1
LDADD += $(LIBS_PLAYERCTL)
SRCS += playerctl.c

CPPFLAGS+=	-DPACKAGE_VERSION=\"$(VERSION)\"
CFLAGS+=	$(CPPFLAGS)

DESTDIR?=	/
PREFIX?=	/usr/local

bindir=$(DESTDIR)$(PREFIX)/bin
mandir=$(DESTDIR)$(PREFIX)/share/man

.PHONY: all install clean
all: $(PROG) $(MAN:=.gz)

$(PROG): $(SRCS:.c=.o)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) \
		-o $(PROG) \
		$(SRCS:.c=.o) $(LDADD)

.SUFFIXES: .8 .8.gz
.8.8.gz:
	gzip < $< > $@

clean:
	rm -f $(PROG) $(MAN:=.gz)

install: $(PROG) $(MAN:=.gz)
	strip $(PROG)
	install -d $(bindir)
	install $(PROG) $(bindir)
	install -d $(mandir)/man8
	install $(MAN:=.gz) $(mandir)/man8
