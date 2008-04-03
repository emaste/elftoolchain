# $FreeBSD: src/usr.bin/ar/Makefile,v 1.20 2008/02/25 16:16:17 ru Exp $

PROG=	ar
SRCS=	ar.c acplex.l acpyacc.y read.c util.c write.c y.tab.h

WARNS?=	5

DPADD=	${LIBARCHIVE} ${LIBBZ2} ${LIBZ} ${LIBELF}
LDADD=	-larchive -lbz2 -lz -lelf

NO_SHARED?=	yes
LINKS=	${BINDIR}/ar ${BINDIR}/ranlib
MLINKS= ar.1 ranlib.1

.include <bsd.prog.mk>
