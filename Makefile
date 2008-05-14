# $FreeBSD$

PROG=	nm
SRCS=	nm.c vector_str.c cpp_demangle.c dwarf_line_number.c
LDADD=	-lelf
CSTD=	c99
NO_SHARED?= yes

.include <bsd.prog.mk>
