# $FreeBSD: src/lib/libdwarf/Makefile,v 1.1 2008/05/22 02:14:23 jb Exp $

LIB=	dwarf

SRCS=	\
	dwarf_abbrev.c		\
	dwarf_attr.c		\
	dwarf_attrval.c		\
	dwarf_cu.c		\
	dwarf_dealloc.c		\
	dwarf_die.c		\
	dwarf_dump.c		\
	dwarf_errmsg.c		\
	dwarf_errno.c		\
	dwarf_finish.c		\
	dwarf_form.c		\
	dwarf_init.c		\
	dwarf_lineno.c		\
	dwarf_loclist.c		\
	libdwarf_abbrev.c	\
	libdwarf_attr.c		\
	libdwarf_die.c		\
	libdwarf_init.c		\
	libdwarf_lineno.c	\
	libdwarf_loc.c		\
	libdwarf_loclist.c	\
	libdwarf_nametbl.c	\
	libdwarf_rw.c

INCS=	dwarf.h libdwarf.h

CFLAGS+=	-I. -I${.CURDIR} -g

SHLIB_MAJOR=	2

WARNS?=	6

WITHOUT_MAN=	yes

.include <bsd.lib.mk>
