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
 * Symbols related with relocation are needed.
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

#define	ALLOCSYM(SZ) do {						\
	if (ecp->st.symtab##SZ == NULL) {				\
		ecp->st.symtab##SZ = malloc(ecp->symtab_cap *		\
		    sizeof(Elf##SZ##_Sym));				\
		if (ecp->st.symtab##SZ == NULL)				\
			err(EX_SOFTWARE, "malloc failed");		\
	} else {							\
		ecp->symtab_cap *= 2;					\
		ecp->st.symtab##SZ = realloc(ecp->st.symtab##SZ,	\
		    ecp->symtab_cap * sizeof(Elf##SZ##_Sym));		\
		if (ecp->st.symtab##SZ == NULL)				\
			err(EX_SOFTWARE, "realloc failed");		\
	}								\
} while (0)

#define	COPYSYM(SZ) do {						\
	if ((dup_pos = find_duplicate(ecp->strtab, name,		\
	    ecp->strtab_size)) > -1)					\
		ecp->st.symtab##SZ[j].st_name = dup_pos;		\
	else {								\
		if (strlen(name) > 0)					\
			ecp->strtab_size++;				\
		ecp->st.symtab##SZ[j].st_name = ecp->strtab_size;	\
	}								\
	ecp->st.symtab##SZ[j].st_info = sym.st_info;			\
	ecp->st.symtab##SZ[j].st_other = sym.st_other;			\
	ecp->st.symtab##SZ[j].st_shndx = sym.st_shndx;			\
	ecp->st.symtab##SZ[j].st_value = sym.st_value;			\
	ecp->st.symtab##SZ[j].st_size = sym.st_size;			\
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
	GElf_Shdr ishdr;
	GElf_Sym sym;
	Elf_Data* idata;
	Elf_Scn *iscn;
	size_t ishstrndx, n, sc, symndx;
	char *name;
	int ec, elferr, i, j, dup_pos;

	if (elf_getshstrndx(ecp->ein, &ishstrndx) == 0)
		errx(EX_SOFTWARE, "elf_getshstrndx failed: %s",
		    elf_errmsg(-1));
	if ((ec = gelf_getclass(ecp->eout)) == ELFCLASSNONE)
		errx(EX_SOFTWARE, "gelf_getclass failed: %s",
		    elf_errmsg(-1));

	/*
	 * Allocate storage for symbol table and string table.
	 */
	ecp->symtab_cnt = 0;
	ecp->symtab_cap = 64;
	if (ec == ELFCLASS32)
		ALLOCSYM(32);
	else
		ALLOCSYM(64);
	ecp->strtab_size = 0;
	ecp->strtab_cap = 512;
	ecp->strtab = malloc(ecp->strtab_cap);
	if (ecp->strtab == NULL)
		err(EX_SOFTWARE, "malloc failed");
	ecp->strtab[0] = '\0';

	symndx = 0;
	iscn = NULL;
	while ((iscn = elf_nextscn(ecp->ein, iscn)) != NULL) {
		if (gelf_getshdr(iscn, &ishdr) != &ishdr)
			errx(EX_SOFTWARE, "elf_getshdr failed: %s",
			    elf_errmsg(-1));
		if ((name = elf_strptr(ecp->ein, ishstrndx, ishdr.sh_name)) == NULL)
			errx(EX_SOFTWARE, "elf_strptr failed: %s",
			    elf_errmsg(-1));
		if (strcmp(name, ".strtab") == 0) {
			symndx = elf_ndxscn(iscn);
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

	iscn = NULL;
	while ((iscn = elf_nextscn(ecp->ein, iscn)) != NULL) {
		if (gelf_getshdr(iscn, &ishdr) != &ishdr)
			errx(EX_SOFTWARE, "elf_getshdr failed: %s",
			    elf_errmsg(-1));
		if ((name = elf_strptr(ecp->ein, ishstrndx, ishdr.sh_name)) == NULL)
			errx(EX_SOFTWARE, "elf_strptr failed: %s",
			    elf_errmsg(-1));
		if (strcmp(name, ".symtab") == 0)
			break;
	}
	elferr = elf_errno();
	if (elferr != 0)
		errx(EX_SOFTWARE, "elf_nextscn failed: %s",
		    elf_errmsg(elferr));
	if (iscn == NULL)
		errx(EX_DATAERR, "can't find .strtab section");

	idata = NULL;
	n = 0;
	while (n < ishdr.sh_size && (idata = elf_getdata(iscn, idata)) !=
	    NULL) {
		sc = idata->d_size / ishdr.sh_entsize;
		for (i = 0; (size_t)i < sc; i++) {
			if (gelf_getsym(idata, i, &sym) != &sym)
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
			if (ecp->symtab_cnt >= ecp->symtab_cap) {
				if (ec == ELFCLASS32)
					ALLOCSYM(32);
				else
					ALLOCSYM(64);
			}

			j = ecp->symtab_cnt;

			/* FIXME: st_shndx may change. */
			if (ec == ELFCLASS32)
				COPYSYM(32);
			else
				COPYSYM(64);

			ecp->symtab_cnt++;

			if (dup_pos > -1)
				continue;

			while (ecp->strtab_size + strlen(name) >=
			    ecp->strtab_cap - 1) {
				ecp->strtab_cap *= 2;
				ecp->strtab = realloc(ecp->strtab,
				    ecp->strtab_cap);
				if (ecp->strtab == NULL)
					err(EX_SOFTWARE, "realloc failed");
			}

			strncpy(&ecp->strtab[ecp->strtab_size], name,
				strlen(name));
			ecp->strtab_size += strlen(name);
			ecp->strtab[ecp->strtab_size] = '\0';
		}
		n += idata->d_size;
	}
	elferr = elf_errno();
	if (elferr != 0)
		errx(EX_SOFTWARE, "elf_getdata failed: %s",
		     elf_errmsg(elferr));

	/* Compute symbol table size. */
	ecp->symtab_size = ecp->symtab_cnt *
	    (ec == ELFCLASS32 ? sizeof(Elf32_Sym) : sizeof(Elf64_Sym));
}

size_t
create_symtab(struct elfcopy *ecp, size_t off)
{
	Elf_Scn *sy, *st;
	Elf_Data *sydata, *stdata;
	GElf_Shdr shy, sht;

	if ((sy = elf_newscn(ecp->eout)) == NULL)
		errx(EX_SOFTWARE, "elf_newscn() failed: %s",
		    elf_errmsg(-1));
	if ((st = elf_newscn(ecp->eout)) == NULL)
		errx(EX_SOFTWARE, "elf_newscn() failed: %s",
		    elf_errmsg(-1));

	create_shdr(ecp, ecp->symscn, sy, ".symtab");
	create_shdr(ecp, ecp->strscn, st, ".strtab");

	if (gelf_getshdr(sy, &shy) == NULL)
		errx(EX_SOFTWARE, "gelf_getshdr() failed: %s",
		    elf_errmsg(-1));
	if (gelf_getshdr(st, &sht) == NULL)
		errx(EX_SOFTWARE, "gelf_getshdr() failed: %s",
		    elf_errmsg(-1));

	if (ecp->flags & SYMTAB_INTACT) {
		copy_data(ecp->symscn, sy);
		copy_data(ecp->strscn, st);
		goto update_symtab;
	}

	generate_symbols(ecp);

	if ((sydata = elf_newdata(sy)) == NULL)
		errx(EX_SOFTWARE, "elf_newdata() failed: %s.",
		    elf_errmsg(-1));
	if ((stdata = elf_newdata(st)) == NULL)
		errx(EX_SOFTWARE, "elf_newdata() failed: %s.",
		    elf_errmsg(-1));

	/* FIXME support format conversion. */
	sydata->d_align		= 4;
	sydata->d_off		= 0;
	sydata->d_buf		= ecp->st.symtab32;
	sydata->d_size		= ecp->symtab_size;
	sydata->d_type		= ELF_T_SYM;
	sydata->d_version	= EV_CURRENT;

	stdata->d_align		= 1;
	stdata->d_off		= 0;
	stdata->d_buf		= ecp->strtab;
	stdata->d_size		= ecp->strtab_size;
	stdata->d_type		= ELF_T_BYTE;
	stdata->d_version	= EV_CURRENT;

	shy.sh_addr		= 0;
	shy.sh_addralign	= 4; /* FIXME */
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
	sht.sh_type		= SHT_STRTAB;
	sht.sh_flags		= 0;
	sht.sh_entsize		= 0;
	sht.sh_info		= 0;
	sht.sh_link		= 0;

update_symtab:
	shy.sh_offset = off = roundup(off, shy.sh_addralign);

	if (ecp->symtab_size) {
		shy.sh_size = ecp->symtab_size;
		off += ecp->symtab_size;
	} else
		off += shy.sh_size;

	sht.sh_offset = off;

	if (ecp->strtab_size) {
		sht.sh_size = ecp->strtab_size;
		off += ecp->strtab_size;
	} else
		off += sht.sh_size;

	/* Link .symtab and .strtab */
	shy.sh_link	 = elf_ndxscn(st);

	if (!gelf_update_shdr(sy, &shy))
		errx(EX_SOFTWARE, "gelf_update_shdr() failed: %s",
		    elf_errmsg(-1));
	if (!gelf_update_shdr(st, &sht))
		errx(EX_SOFTWARE, "gelf_update_shdr() failed: %s",
		    elf_errmsg(-1));

	return (off);
}

void
add_to_keep_list(struct elfcopy *ecp, const char *name)
{
	struct symlist *s;

	if ((s = malloc(sizeof(*s))) == NULL)
		errx(EX_SOFTWARE, "not enough memory");
	memset(s, 0, sizeof(*s));
	s->name = name;
	STAILQ_INSERT_TAIL(&ecp->v_sym_keep, s, syms);
}

void
add_to_strip_list(struct elfcopy *ecp, const char *name)
{
	struct symlist *s;

	if ((s = malloc(sizeof(*s))) == NULL)
		errx(EX_SOFTWARE, "not enough memory");
	memset(s, 0, sizeof(*s));
	s->name = name;
	STAILQ_INSERT_TAIL(&ecp->v_sym_strip, s, syms);
}

static int
lookup_keep_symlist(struct elfcopy *ecp, const char *name)
{
	struct symlist *s;

	STAILQ_FOREACH(s, &ecp->v_sym_keep, syms) {
		if (strcmp(name, s->name) == 0)
			return 1;
	}

	return (0);
}

static int
lookup_strip_symlist(struct elfcopy *ecp, const char *name)
{
	struct symlist *s;

	STAILQ_FOREACH(s, &ecp->v_sym_strip, syms) {
		if (strcmp(name, s->name) == 0)
			return 1;
	}

	return (0);
}

