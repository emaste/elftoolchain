PROG=	elfcopy
NO_MAN=
VERSION=	1.0.0
SRCS=	main.c sections.c segments.c symbols.c utils.c
WARNS?=	5
DPADD=	${LIBELF}
LDADD=	-lelf
CFLAGS+=	-g -DELFCOPY_VERSION=\"${VERSION}\"
LINKS=	${BINDIR}/elfcopy ${BINDIR}/strip

.include <bsd.prog.mk>
