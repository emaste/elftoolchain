# $FreeBSD$

PROG=	nm
SRCS=	nm.c nm_aout.c vector_str.c cpp_demangle.c dwarf_line_number.c
LDADD=	-lelf

.include <bsd.prog.mk>
