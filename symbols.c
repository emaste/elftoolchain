/*-
 * Copyright (c) 2007,2008 Kai Wang
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer
 *    in this position and unchanged.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR(S) ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR(S) BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <err.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>

#include "elfcopy.h"

static int	is_debug_symbol(GElf_Sym *s);
static int	is_global_symbol(GElf_Sym *s);
static int	is_needed_symbol(struct elfcopy *ecp, int i, GElf_Sym *s);
static int	is_remove_symbol(struct elfcopy *ecp, size_t sc, int i,
		    GElf_Sym *s, const char *name);
static int	is_weak_symbol(GElf_Sym *s);
static int	lookup_keep_symlist(struct elfcopy *ecp, const char *name);
static int	lookup_strip_symlist(struct elfcopy *ecp, const char *name);
static void	mark_symbols(struct elfcopy *ecp, size_t sc);

#define BIT_SET(v, n) (v[(n)>>3] |= 1U << ((n) & 7))
#define BIT_CLR(v, n) (v[(n)>>3] &= ~(1U << ((n) & 7)))
#define BIT_ISSET(v, n) (v[(n)>>3] & (1U << ((n) & 7)))

static int
is_debug_symbol(GElf_Sym *s)
{

	if (GELF_ST_TYPE(s->st_info) == STT_SECTION ||
	    GELF_ST_TYPE(s->st_info) == STT_FILE)
		return (1);

	return (0);
}

static int
is_global_symbol(GElf_Sym *s)
{

	if (GELF_ST_BIND(s->st_info) == STB_GLOBAL &&
	    s->st_shndx != SHN_UNDEF &&
	    s->st_shndx != SHN_COMMON)
		return (1);

	return (0);
}

static int
is_remove_symbol(struct elfcopy *ecp, size_t sc, int i, GElf_Sym *s,
    const char *name)
{

	if (ecp->strip == STRIP_ALL)
		return (1);

	if (ecp->v_rel == NULL)
		mark_symbols(ecp, sc);

	if (is_needed_symbol(ecp, i, s))
		return (0);

	if (ecp->strip == STRIP_UNNEEDED)
		return (1);

	if (ecp->strip == STRIP_DEBUG && is_debug_symbol(s))
		return (1);

	if (lookup_keep_symlist(ecp, name) != 0)
		return (0);

	if (lookup_strip_symlist(ecp, name) != 0)
		return (1);

	return (0);
}

/*
 * Mark symbols refered by relocation entries.
 */
static void
mark_symbols(struct elfcopy *ecp, size_t sc)
{
	Elf_Data *d;
	Elf_Scn *s;
	GElf_Rel r;
	GElf_Rela ra;
	GElf_Shdr sh;
	size_t n;
	int elferr, i, len;

	ecp->v_rel = malloc((sc + 7) / 8);
	if (ecp->v_rel == NULL)
		err(EX_SOFTWARE, "malloc failed");

	s = NULL;
	while ((s = elf_nextscn(ecp->ein, s)) != NULL) {
		if (gelf_getshdr(s, &sh) != &sh)
			errx(EX_SOFTWARE, "elf_getshdr failed: %s",
			    elf_errmsg(-1));

		if (sh.sh_type != SHT_REL && sh.sh_type != SHT_RELA)
			continue;

		d = NULL;
		n = 0;
		while (n < sh.sh_size && (d = elf_getdata(s, d)) != NULL) {
			len = d->d_size / sh.sh_entsize;
			for (i = 0; i < len; i++) {
				if (sh.sh_type == SHT_REL) {
					if (gelf_getrel(d, i, &r) != &r)
						errx(EX_SOFTWARE,
						    "elf_getrel failed: %s",
						     elf_errmsg(-1));
					n = GELF_R_SYM(r.r_info);
				} else {
					if (gelf_getrela(d, i, &ra) != &ra)
						errx(EX_SOFTWARE,
						    "elf_getrela failed: %s",
						     elf_errmsg(-1));
					n = GELF_R_SYM(ra.r_info);
				}
				if (n > 0 && n < sc)
					BIT_SET(ecp->v_rel, n);
				else if (n != 0)
					warnx("invalid symbox index");
			}
		}
		elferr = elf_errno();
		if (elferr != 0)
			errx(EX_SOFTWARE, "elf_getdata failed: %s",
			    elf_errmsg(elferr));
	}
	elferr = elf_errno();
	if (elferr != 0)
		errx(EX_SOFTWARE, "elf_nextscn failed: %s",
		    elf_errmsg(elferr));
}

/*
 * Symbols related to relocation are needed.
 */
static int
is_needed_symbol(struct elfcopy *ecp, int i, GElf_Sym *s)
{

	/* If symbol involves relocation, it is needed. */
	if (BIT_ISSET(ecp->v_rel, i))
		return (1);

	/*
	 * For relocatable files (.o files), global and weak symbols
	 * are needed.
	 */
	if (ecp->flags & RELOCATABLE) {
		if (is_global_symbol(s) || is_weak_symbol(s))
			return (1);
	}

	return (0);
}

#define	ALLOCSYM(SZ) do {					\
	if (sy_buf##SZ == NULL) {				\
		sy_buf##SZ = malloc(sy_cap *			\
		    sizeof(Elf##SZ##_Sym));			\
		if (sy_buf##SZ == NULL)				\
			err(EX_SOFTWARE, "malloc failed");	\
	} else {						\
		sy_cap *= 2;					\
		sy_buf##SZ = realloc(sy_buf##SZ,		\
		    sy_cap * sizeof(Elf##SZ##_Sym));		\
		if (sy_buf##SZ == NULL)				\
			err(EX_SOFTWARE, "realloc failed");	\
	}							\
} while (0)

#define	COPYSYM(SZ) do {					\
	if ((dup_pos = find_duplicate(st_buf, name,		\
	    st_sz)) > -1)					\
		sy_buf##SZ[j].st_name = dup_pos;		\
	else {							\
		if (strlen(name) > 0)				\
			st_sz++;				\
		sy_buf##SZ[j].st_name = st_sz;			\
	}							\
	sy_buf##SZ[j].st_info = sym.st_info;			\
	sy_buf##SZ[j].st_other = sym.st_other;			\
	sy_buf##SZ[j].st_shndx = sym.st_shndx;			\
	sy_buf##SZ[j].st_value = sym.st_value;			\
	sy_buf##SZ[j].st_size = sym.st_size;			\
} while (0)

static int
is_weak_symbol(GElf_Sym *s)
{

	if (GELF_ST_BIND(s->st_info) == STB_WEAK)
		return (1);

	return (0);
}

static void
generate_symbols(struct elfcopy *ecp)
{
	GElf_Shdr ish;
	GElf_Sym sym;
	Elf_Data* id;
	Elf_Scn *is;
	Elf32_Sym *sy_buf32;
	Elf64_Sym *sy_buf64;
	size_t ishstrndx, n, nsyms, sc, symndx, sy_cap, st_sz, st_cap;
	char *name, *st_buf;
	int ec, elferr, i, j, dup_pos;

	if (elf_getshstrndx(ecp->ein, &ishstrndx) == 0)
		errx(EX_SOFTWARE, "elf_getshstrndx failed: %s",
		    elf_errmsg(-1));
	if ((ec = gelf_getclass(ecp->eout)) == ELFCLASSNONE)
		errx(EX_SOFTWARE, "gelf_getclass failed: %s",
		    elf_errmsg(-1));

	/* Allocate storage for symbol table and string table. */
	nsyms = 0;
	sy_cap = 64;
	sy_buf32 = NULL;
	sy_buf64 = NULL;
	if (ec == ELFCLASS32)
		ALLOCSYM(32);
	else
		ALLOCSYM(64);
	st_sz = 0;
	st_cap = 512;
	st_buf = malloc(st_cap);
	if (st_buf == NULL)
		err(EX_SOFTWARE, "malloc failed");
	st_buf[0] = '\0';

	symndx = 0;
	is = NULL;
	while ((is = elf_nextscn(ecp->ein, is)) != NULL) {
		if (gelf_getshdr(is, &ish) != &ish)
			errx(EX_SOFTWARE, "elf_getshdr failed: %s",
			    elf_errmsg(-1));
		if ((name = elf_strptr(ecp->ein, ishstrndx, ish.sh_name)) == NULL)
			errx(EX_SOFTWARE, "elf_strptr failed: %s",
			    elf_errmsg(-1));
		if (strcmp(name, ".strtab") == 0) {
			symndx = elf_ndxscn(is);
			break;
		}
	}
	elferr = elf_errno();
	if (elferr != 0)
		errx(EX_SOFTWARE, "elf_nextscn failed: %s",
		    elf_errmsg(elferr));
	/* FIXME don't panic if can't find .strtab */
	if (symndx == 0)
		errx(EX_DATAERR, "can't find .strtab section");

	is = NULL;
	while ((is = elf_nextscn(ecp->ein, is)) != NULL) {
		if (gelf_getshdr(is, &ish) != &ish)
			errx(EX_SOFTWARE, "elf_getshdr failed: %s",
			    elf_errmsg(-1));
		if ((name = elf_strptr(ecp->ein, ishstrndx, ish.sh_name)) ==
		    NULL)
			errx(EX_SOFTWARE, "elf_strptr failed: %s",
			    elf_errmsg(-1));
		if (strcmp(name, ".symtab") == 0)
			break;
	}
	elferr = elf_errno();
	if (elferr != 0)
		errx(EX_SOFTWARE, "elf_nextscn failed: %s",
		    elf_errmsg(elferr));
	if (is == NULL)
		errx(EX_DATAERR, "can't find .strtab section");

	id = NULL;
	n = 0;
	while (n < ish.sh_size && (id = elf_getdata(is, id)) != NULL) {
		sc = id->d_size / ish.sh_entsize;
		for (i = 0; (size_t)i < sc; i++) {
			if (gelf_getsym(id, i, &sym) != &sym)
				errx(EX_SOFTWARE, "gelf_getsym failed: %s",
				     elf_errmsg(-1));
			if ((name = elf_strptr(ecp->ein, symndx,
					       sym.st_name)) == NULL)
				errx(EX_SOFTWARE, "elf_strptr failed: %s",
				     elf_errmsg(-1));

			/* symbol filtering. */
			if (is_remove_symbol(ecp, sc, i, &sym, name) != 0)
				continue;

			/* increase storage if need */
			if (nsyms >= sy_cap) {
				if (ec == ELFCLASS32)
					ALLOCSYM(32);
				else
					ALLOCSYM(64);
			}

			j = nsyms;

			/* FIXME: st_shndx may change. */
			if (ec == ELFCLASS32)
				COPYSYM(32);
			else
				COPYSYM(64);

			nsyms++;

			if (dup_pos > -1)
				continue;

			while (st_sz + strlen(name) >= st_cap - 1) {
				st_cap *= 2;
				st_buf = realloc(st_buf, st_cap);
				if (st_buf == NULL)
					err(EX_SOFTWARE, "realloc failed");
			}

			strncpy(&st_buf[st_sz], name, strlen(name));
			st_buf[st_sz + strlen(name)] = '\0';
			st_sz += strlen(name) + 1;
		}
		n += id->d_size;
	}
	elferr = elf_errno();
	if (elferr != 0)
		errx(EX_SOFTWARE, "elf_getdata failed: %s",
		     elf_errmsg(elferr));

	ecp->symtab->sz = nsyms *
	    (ec == ELFCLASS32 ? sizeof(Elf32_Sym) : sizeof(Elf64_Sym));
	if (ec == ELFCLASS32)
		ecp->symtab->buf = sy_buf32;
	else
		ecp->symtab->buf = sy_buf64;
	ecp->strtab->sz = st_sz;
	ecp->strtab->buf = st_buf;
}

void
create_symtab(struct elfcopy *ecp)
{
	struct section *sy, *st;
	Elf_Data *sydata, *stdata;
	GElf_Shdr shy, sht;

	sy = ecp->symtab;
	st = ecp->strtab;

	copy_shdr(ecp, sy->is, sy->os, ".symtab");
	copy_shdr(ecp, st->is, st->os, ".strtab");

	if (gelf_getshdr(sy->os, &shy) == NULL)
		errx(EX_SOFTWARE, "gelf_getshdr() failed: %s",
		    elf_errmsg(-1));
	if (gelf_getshdr(st->os, &sht) == NULL)
		errx(EX_SOFTWARE, "gelf_getshdr() failed: %s",
		    elf_errmsg(-1));

	if (ecp->flags & SYMTAB_INTACT) {
		copy_data(sy->is, sy->os);
		copy_data(st->is, st->os);
		goto update_symtab;
	}

	generate_symbols(ecp);

	if ((sydata = elf_newdata(sy->os)) == NULL)
		errx(EX_SOFTWARE, "elf_newdata() failed: %s.",
		    elf_errmsg(-1));
	if ((stdata = elf_newdata(st->os)) == NULL)
		errx(EX_SOFTWARE, "elf_newdata() failed: %s.",
		    elf_errmsg(-1));

	/* FIXME support format conversion. */
	sydata->d_align		= 4;
	sydata->d_off		= 0;
	sydata->d_buf		= sy->buf;
	sydata->d_size		= sy->sz;
	sydata->d_type		= ELF_T_SYM;
	sydata->d_version	= EV_CURRENT;

	stdata->d_align		= 1;
	stdata->d_off		= 0;
	stdata->d_buf		= st->buf;
	stdata->d_size		= st->sz;
	stdata->d_type		= ELF_T_BYTE;
	stdata->d_version	= EV_CURRENT;

	shy.sh_addr		= 0;
	shy.sh_addralign	= 4; /* FIXME */
	shy.sh_size		= sy->sz;
	shy.sh_type		= SHT_SYMTAB;
	shy.sh_flags		= 0;
	shy.sh_entsize		= gelf_fsize(ecp->eout, ELF_T_SYM, 1,
	    EV_CURRENT);
	/*
	 * FIXME sh_info has special meanings here:
	 * SYSV abi manual: One greater than the symbol
	 * table index of the last local symbol(binding
	 * STB_LOCAL).
	 * GNU utils:
	 */
	shy.sh_info		= 0;

	sht.sh_addr		= 0;
	sht.sh_addralign	= 1;
	sht.sh_size		= st->sz;
	sht.sh_type		= SHT_STRTAB;
	sht.sh_flags		= 0;
	sht.sh_entsize		= 0;
	sht.sh_info		= 0;
	sht.sh_link		= 0;

update_symtab:

	/* Link .symtab and .strtab */
	shy.sh_link = elf_ndxscn(st->os);

	if (!gelf_update_shdr(sy->os, &shy))
		errx(EX_SOFTWARE, "gelf_update_shdr() failed: %s",
		    elf_errmsg(-1));
	if (!gelf_update_shdr(st->os, &sht))
		errx(EX_SOFTWARE, "gelf_update_shdr() failed: %s",
		    elf_errmsg(-1));
}

void
add_to_keep_list(struct elfcopy *ecp, const char *name)
{
	struct symlist *s;

	if ((s = malloc(sizeof(*s))) == NULL)
		errx(EX_SOFTWARE, "not enough memory");
	memset(s, 0, sizeof(*s));
	s->name = name;
	STAILQ_INSERT_TAIL(&ecp->v_sym_keep, s, sym_list);
}

void
add_to_strip_list(struct elfcopy *ecp, const char *name)
{
	struct symlist *s;

	if ((s = malloc(sizeof(*s))) == NULL)
		errx(EX_SOFTWARE, "not enough memory");
	memset(s, 0, sizeof(*s));
	s->name = name;
	STAILQ_INSERT_TAIL(&ecp->v_sym_strip, s, sym_list);
}

static int
lookup_keep_symlist(struct elfcopy *ecp, const char *name)
{
	struct symlist *s;

	STAILQ_FOREACH(s, &ecp->v_sym_keep, sym_list) {
		if (strcmp(name, s->name) == 0)
			return 1;
	}

	return (0);
}

static int
lookup_strip_symlist(struct elfcopy *ecp, const char *name)
{
	struct symlist *s;

	STAILQ_FOREACH(s, &ecp->v_sym_strip, sym_list) {
		if (strcmp(name, s->name) == 0)
			return 1;
	}

	return (0);
}
