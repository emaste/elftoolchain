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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>

#include "elfcopy.h"

static void	add_to_shstrtab(struct elfcopy *ecp, const char *name);
static void	filter_reloc(struct elfcopy *ecp, struct section *s);
static void	insert_to_sec_list(struct elfcopy *ecp, struct section *sec);
static int	is_append_section(struct elfcopy *ecp, const char *name);
static int	is_compress_section(struct elfcopy *ecp, const char *name);
static int	is_debug_section(const char *name);
static int	is_modify_section(struct elfcopy *ecp, const char *name);
static int	is_print_section(struct elfcopy *ecp, const char *name);
static void	modify_section(struct elfcopy *ecp, struct section *s);
static void	print_data(const char *d, size_t sz);
static void	print_section(struct section *s);
static void	*read_section(struct section *s, size_t *size);
static void	update_reloc(struct elfcopy *ecp, struct section *s);

int
is_remove_section(struct elfcopy *ecp, const char *name)
{

	/* Always keep section name table */
	if (strcmp(name, ".shstrtab") == 0)
		return 0;
	if (strcmp(name, ".symtab") == 0 ||
	    strcmp(name, ".strtab") == 0) {
		if (ecp->strip == STRIP_ALL)
			return (1);
		else
			return (0);
	}

	if (is_debug_section(name))
		if (ecp->strip == STRIP_ALL ||
		    ecp->strip == STRIP_DEBUG ||
		    ecp->strip == STRIP_UNNEEDED)
			return (1);

	if (ecp->sections_to_remove != 0 ||
	    ecp->sections_to_copy != 0) {
		struct sec_action *sac;

		sac = lookup_sec_act(ecp, name, 0);
		if (ecp->sections_to_remove != 0 &&
		    sac != NULL && sac->remove != 0)
			return (1);
		if (ecp->sections_to_copy != 0 &&
		    (sac == NULL || sac->copy == 0))
			return (1);
	}

	return (0);
}

/*
 * Relocation section need to be remove if the section it applies will
 * be removed.
 */
int
is_remove_reloc_sec(struct elfcopy *ecp, uint32_t sh_info)
{
	const char *name;
	GElf_Shdr ish;
	Elf_Scn *is;
	size_t indx;
	int elferr;

	if (elf_getshstrndx(ecp->ein, &indx) == 0)
		errx(EX_SOFTWARE, "elf_getshstrndx failed: %s",
		    elf_errmsg(-1));

	is = NULL;
	while ((is = elf_nextscn(ecp->ein, is)) != NULL) {
		if (sh_info == elf_ndxscn(is)) {
			if (gelf_getshdr(is, &ish) == NULL)
				errx(EX_SOFTWARE, "gelf_getshdr failed: %s",
				    elf_errmsg(-1));
			if ((name = elf_strptr(ecp->ein, indx, ish.sh_name)) ==
			    NULL)
				errx(EX_SOFTWARE, "elf_strptr failed: %s",
				    elf_errmsg(-1));
			if (is_remove_section(ecp, name))
				return (1);
			else
				return (0);
		}
	}
	elferr = elf_errno();
	if (elferr != 0)
		errx(EX_SOFTWARE, "elf_nextscn failed: %s",
		    elf_errmsg(elferr));

	/* Remove reloc section if we can't find the target section. */
	return (1);
}

static int
is_append_section(struct elfcopy *ecp, const char *name)
{
	struct sec_action *sac;

	sac = lookup_sec_act(ecp, name, 0);
	if (sac != NULL && sac->append != 0 && sac->string != NULL)
		return (1);

	return (0);
}

static int
is_compress_section(struct elfcopy *ecp, const char *name)
{
	struct sec_action *sac;

	sac = lookup_sec_act(ecp, name, 0);
	if (sac != NULL && sac->compress != 0)
		return (1);

	return (0);
}

/*
 * Determine whether the section are debugging section.
 * According to libbfd, debugging sections are recognized
 * only by name.
 */
static int
is_debug_section(const char *name)
{
	const char *dbg_sec[] = {
		".debug",
		".gnu.linkonce.wi.",
		".line",
		".stab",
		NULL
	};
	const char **p;

	for(p = dbg_sec; *p; p++) {
		if (strncmp(name, *p, strlen(*p)) == 0)
			return (1);
	}

	return (0);
}

static int
is_print_section(struct elfcopy *ecp, const char *name)
{
	struct sec_action *sac;

	sac = lookup_sec_act(ecp, name, 0);
	if (sac != NULL && sac->print != 0)
		return (1);

	return (0);
}

static int
is_modify_section(struct elfcopy *ecp, const char *name)
{

	if (is_append_section(ecp, name) ||
	    is_compress_section(ecp, name))
		return (1);

	return (0);
}

struct sec_action*
lookup_sec_act(struct elfcopy *ecp, const char *name, int add)
{
	struct sec_action *sac;

	STAILQ_FOREACH(sac, &ecp->v_sac, sac_list) {
		if (strcmp(name, sac->name) == 0)
			return sac;
	}

	if (add == 0)
		return NULL;

	if ((sac = malloc(sizeof(*sac))) == NULL)
		errx(EX_SOFTWARE, "not enough memory");
	memset(sac, 0, sizeof(*sac));
	sac->name = name;
	STAILQ_INSERT_TAIL(&ecp->v_sac, sac, sac_list);

	return (sac);
}

static void
insert_to_sec_list(struct elfcopy *ecp, struct section *sec)
{
	struct section *s;

	TAILQ_FOREACH(s, &ecp->v_sec, sec_list) {
		if (sec->off < s->off) {
			TAILQ_INSERT_BEFORE(s, sec, sec_list);
			goto inc_nos;
		}
	}

	TAILQ_INSERT_TAIL(&ecp->v_sec, sec, sec_list);

inc_nos:
	if (sec->pseudo == 0)
		ecp->nos++;
}

/*
 * First step of section creation: create scn and internal section
 * structure, discard sections to be removed.
 */
void
create_scn(struct elfcopy *ecp)
{
	struct section *s;
	const char *name;
	Elf_Scn *is;
	GElf_Shdr ish;
	size_t indx;
	uint64_t oldndx, newndx;
	int elferr;

	/* Create internal .shstrtab section. */
	if ((ecp->shstrtab = calloc(1, sizeof(*ecp->shstrtab))) == NULL)
		err(EX_SOFTWARE, "calloc failed");
	s = ecp->shstrtab;
	s->name = ".shstrtab";
	s->is = NULL;
	s->sz = 0;
	s->align = 1;
	s->loadable = 0;
	s->type = SHT_STRTAB;
	s->vma = 0;

	if (elf_getshstrndx(ecp->ein, &indx) == 0)
		errx(EX_SOFTWARE, "elf_getshstrndx failed: %s",
		    elf_errmsg(-1));

	is = NULL;
	while ((is = elf_nextscn(ecp->ein, is)) != NULL) {
		if (gelf_getshdr(is, &ish) == NULL)
			errx(EX_SOFTWARE, "219 gelf_getshdr failed: %s",
			    elf_errmsg(-1));
		if ((name = elf_strptr(ecp->ein, indx, ish.sh_name)) == NULL)
			errx(EX_SOFTWARE, "elf_strptr failed: %s",
			    elf_errmsg(-1));

		/* Skip sections to be removed. */
		if (is_remove_section(ecp, name))
			continue;

		/*
		 * Relocation section need to be remove if the section
		 * it applies will be removed.
		 */
		if (ish.sh_type == SHT_REL || ish.sh_type == SHT_RELA)
			if (ish.sh_info != 0 &&
			    is_remove_reloc_sec(ecp, ish.sh_info))
				continue;

		/* Create internal section object. */
		if (strcmp(name, ".shstrtab") != 0) {
			if ((s = calloc(1, sizeof(*s))) == NULL)
				err(EX_SOFTWARE, "calloc failed");
			s->name		= name;
			s->is		= is;
			s->off		= ish.sh_offset;
			s->sz		= ish.sh_size;
			s->align	= ish.sh_addralign;
			s->type		= ish.sh_type;
			s->vma		= ish.sh_addr;
			s->loadable	= add_to_inseg_list(ecp, s);
		} else {
			/* Assuming .shstrtab is "unloadable". */
			s		= ecp->shstrtab;
			s->off		= ish.sh_offset;
		}

		if ((s->os = elf_newscn(ecp->eout)) == NULL)
			errx(EX_SOFTWARE, "elf_newscn failed: %s",
			    elf_errmsg(-1));

		if ((oldndx = elf_ndxscn(is)) == SHN_UNDEF ||
		    (newndx = elf_ndxscn(s->os)) == SHN_UNDEF)
			errx(EX_SOFTWARE, "elf_scnndx failed: %s",
			    elf_errmsg(-1));
		ecp->secndx[oldndx] = newndx;

		/* create section header based on input object. */
		if (strcmp(name, ".shstrtab") != 0)
			copy_shdr(ecp, s->is, s->os, s->name);

		if (strcmp(name, ".symtab") == 0) {
			ecp->flags |= SYMTAB_EXIST;
			ecp->symtab = s;
		}
		if (strcmp(name, ".strtab") == 0)
			ecp->strtab = s;

		insert_to_sec_list(ecp, s);
	}
	elferr = elf_errno();
	if (elferr != 0)
		errx(EX_SOFTWARE, "elf_nextscn failed: %s",
		    elf_errmsg(elferr));
}

struct section *
insert_shtab(struct elfcopy *ecp)
{
	struct section *s, *shtab;
	GElf_Ehdr ieh;
	int nsecs;

	/*
	 * Treat section header table as a "pseudo" section, insert it
	 * into section list, so later it will get sorted and resynced
	 * just as normal sections.
	 */
	if (gelf_getehdr(ecp->ein, &ieh) == NULL)
		errx(EX_SOFTWARE, "gelf_getehdr() failed: %s",
		    elf_errmsg(-1));
	if ((shtab = calloc(1, sizeof(*shtab))) == NULL)
		errx(EX_SOFTWARE, "calloc failed");
	/* shoff of input object is used as a hint. */
	shtab->off = ieh.e_shoff;
	/* Calculate number of sections in the output object. */
	nsecs = 0;
	TAILQ_FOREACH(s, &ecp->v_sec, sec_list) {
		if (!s->pseudo)
			nsecs++;
	}
	/* Remember there is always a null section, so we +1 here. */
	shtab->sz = gelf_fsize(ecp->eout, ELF_T_SHDR, nsecs + 1, EV_CURRENT);
	if (shtab->sz == 0)
		errx(EX_SOFTWARE, "gelf_fsize() failed: %s", elf_errmsg(-1));
	shtab->align = (ecp->oec == ELFCLASS32 ? 4 : 8);
	shtab->loadable = 0;
	shtab->pseudo = 1;
	insert_to_sec_list(ecp, shtab);

	return (shtab);
}

void
copy_content(struct elfcopy *ecp)
{
	struct section *s;

	TAILQ_FOREACH(s, &ecp->v_sec, sec_list) {
		/* Skip pseudo section. */
		if (s->pseudo)
			continue;

		/* Skip special sections. */
		if (strcmp(s->name, ".symtab") == 0 ||
		    strcmp(s->name, ".strtab") == 0 ||
		    strcmp(s->name, ".shstrtab") == 0)
			continue;

		/*
		 * If strip action is STRIP_ALL, relocation info need
		 * to be stripped. Skip filtering otherwisw.
		 */
		if (ecp->strip == STRIP_ALL &&
		    (s->type == SHT_REL || s->type == SHT_RELA))
			filter_reloc(ecp, s);

		/* Add check for whether change section name here */

		if (is_modify_section(ecp, s->name))
			modify_section(ecp, s);

		copy_data(s);

		/*
		 * If symbol table is modified, relocation info might
		 * need update, as symbol index may have changed.
		 */
		if ((ecp->flags & SYMTAB_INTACT) == 0 &&
		    (ecp->flags & SYMTAB_EXIST) &&
		    (s->type == SHT_REL || s->type == SHT_RELA))
			update_reloc(ecp, s);

		if (is_print_section(ecp, s->name))
			print_section(s);
	}
}

/*
 * Filter relocation entries, only keep those entries whose
 * symbol is in the keep list.
 */
static void
filter_reloc(struct elfcopy *ecp, struct section *s)
{
	const char *name;
	GElf_Shdr ish;
	GElf_Rel rel;
	GElf_Rela rela;
	Elf32_Rel *rel32;
	Elf64_Rel *rel64;
	Elf32_Rela *rela32;
	Elf64_Rela *rela64;
	Elf_Data *id;
	uint64_t cap, n, nrels;
	int elferr, i;

	if (gelf_getshdr(s->is, &ish) == NULL)
		errx(EX_SOFTWARE, "gelf_getehdr() failed: %s",
		    elf_errmsg(-1));

	/* We don't want to touch relocation info for dynamic symbols. */
	if ((ecp->flags & SYMTAB_EXIST) == 0) {
		if (ish.sh_link == 0 || ecp->secndx[ish.sh_link] == 0) {
			/*
			 * This reloc section applies to the symbol table
			 * that was stripped, so discard whole section.
			 */
			s->nocopy = 1;
			s->sz = 0;
		}
		return;
	} else {
		/* Symbol table exist, check if index equals. */
		if (ish.sh_link != elf_ndxscn(ecp->symtab->is))
			return;
	}

#define	COPYREL(REL, SZ) do {					\
	if (nrels == 0) {					\
		if ((REL##SZ = malloc(cap *			\
		    sizeof(Elf##SZ##_Rel))) == NULL)		\
			err(EX_SOFTWARE, "malloc failed");	\
	}							\
	if (nrels >= cap) {					\
		cap *= 2;					\
		if ((REL##SZ = realloc(REL##SZ, cap *		\
		    sizeof(Elf##SZ##_Rel))) == NULL)		\
			err(EX_SOFTWARE, "realloc failed");	\
	}							\
	REL##SZ[nrels].r_offset = REL.r_offset;			\
	REL##SZ[nrels].r_info	= REL.r_info;			\
	if (s->type == SHT_RELA)				\
		rela##SZ[nrels].r_addend = rela.r_addend;	\
	nrels++;						\
} while (0)

	nrels = 0;
	cap = 4;		/* keep list is usually small. */
	rel32 = NULL;
	rel64 = NULL;
	rela32 = NULL;
	rela64 = NULL;
	if ((id = elf_getdata(s->is, NULL)) == NULL)
		errx(EX_SOFTWARE, "elf_getdata() failed: %s",
		    elf_errmsg(-1));
	n = ish.sh_size / ish.sh_entsize;
	for(i = 0; (uint64_t)i < n; i++) {
		if (s->type == SHT_REL) {
			if (gelf_getrel(id, i, &rel) != &rel)
				errx(EX_SOFTWARE, "gelf_getrel failed: %s",
				    elf_errmsg(-1));
		} else {
			if (gelf_getrela(id, i, &rela) != &rela)
				errx(EX_SOFTWARE, "gelf_getrel failed: %s",
				    elf_errmsg(-1));
		}
		name = elf_strptr(ecp->ein, elf_ndxscn(ecp->strtab->is),
		    GELF_R_SYM(rel.r_info));
		if (name == NULL)
			errx(EX_SOFTWARE, "elf_strptr failed: %s",
			    elf_errmsg(-1));
		if (lookup_keep_symlist(ecp, name) != 0) {
			if (ecp->oec == ELFCLASS32) {
				if (s->type == SHT_REL)
					COPYREL(rel, 32);
				else
					COPYREL(rela, 32);
			} else {
				if (s->type == SHT_REL)
					COPYREL(rel, 64);
				else
					COPYREL(rela, 64);
			}
		}
	}
	elferr = elf_errno();
	if (elferr != 0)
		errx(EX_SOFTWARE, "elf_getdata() failed: %s",
		    elf_errmsg(elferr));

	if (ecp->oec == ELFCLASS32) {
		if (s->type == SHT_REL)
			s->buf = rel32;
		else
			s->buf = rela32;
	} else {
		if (s->type == SHT_REL)
			s->buf = rel64;
		else
			s->buf = rela64;
	}
	s->sz = gelf_fsize(ecp->eout, (s->type == SHT_REL ? ELF_T_REL :
	    ELF_T_RELA), nrels, EV_CURRENT);
	s->nocopy = 1;
}

static void
update_reloc(struct elfcopy *ecp, struct section *s)
{
	GElf_Shdr osh;
	GElf_Rel rel;
	GElf_Rela rela;
	Elf_Data *od;
	uint64_t n;
	int i;

#define UPDATEREL(REL) do {						\
	if (gelf_get##REL(od, i, &REL) != &REL)				\
		errx(EX_SOFTWARE, "gelf_get##REL failed: %s",		\
		    elf_errmsg(-1));					\
	REL.r_info = GELF_R_INFO(ecp->symndx[GELF_R_SYM(REL.r_info)],	\
	    GELF_R_TYPE(REL.r_info));					\
	if (!gelf_update_##REL(od, i, &REL))				\
		errx(EX_SOFTWARE, "gelf_update_##REL failed: %s",	\
		    elf_errmsg(-1));					\
} while(0)

	if (s->sz == 0)
		return;
	if (gelf_getshdr(s->os, &osh) == NULL)
		errx(EX_SOFTWARE, "gelf_getehdr() failed: %s",
		    elf_errmsg(-1));
	/* Only process .symtab reloc info. */
	if (osh.sh_link != elf_ndxscn(ecp->symtab->is))
		return;
	if ((od = elf_getdata(s->os, NULL)) == NULL)
		errx(EX_SOFTWARE, "elf_newdata() failed: %s",
		    elf_errmsg(-1));
	n = osh.sh_size / osh.sh_entsize;
	for(i = 0; (uint64_t)i < n; i++) {
		if (s->type == SHT_REL)
			UPDATEREL(rel);
		else
			UPDATEREL(rela);
	}
}

void
resync_sections(struct elfcopy *ecp)
{
	struct section *s;
	GElf_Shdr osh;
	uint64_t off;

	off = 0;
	TAILQ_FOREACH(s, &ecp->v_sec, sec_list) {
		if (off == 0) {
			off = s->off + s->sz;
			continue;
		}

		if (off <= s->off) {
			if (s->loadable)
				off = s->off;
			else
				s->off = roundup(off, s->align);
		} else {
			if (s->loadable)
				warnx("moving loadable section,"
				    "is this intentional?");
			s->off = roundup(off, s->align);
		}

		if (s->pseudo || (s->type != SHT_NOBITS && s->type != SHT_NULL))
			off = s->off + s->sz;

		if (s->pseudo)
			continue;

		/* Update section header accordingly. */
		if (gelf_getshdr(s->os, &osh) == NULL)
			errx(EX_SOFTWARE, "365 gelf_getshdr() failed: %s",
			    elf_errmsg(-1));
		osh.sh_offset = s->off;
		osh.sh_size = s->sz;
		if (!gelf_update_shdr(s->os, &osh))
			errx(EX_SOFTWARE, "elf_update_shdr failed: %s",
			    elf_errmsg(-1));
	}
}

static void
modify_section(struct elfcopy *ecp, struct section *s)
{
	struct sec_action *sac;
	size_t srcsz, dstsz, p, len;
	char *b, *c, *d, *src, *end;
	int dupe;

	src = read_section(s, &srcsz);
	if (src == NULL || srcsz == 0) {
		/* For empty section, we proceed if we need to append. */
		if (!is_append_section(ecp, s->name))
			return;
	}

	/* Allocate buffer needed for new section data. */
	dstsz = srcsz;
	if (is_append_section(ecp, s->name)) {
		sac = lookup_sec_act(ecp, s->name, 0);
		dstsz += strlen(sac->string) + 1;
	}
	if ((b = malloc(dstsz)) == NULL)
		err(EX_SOFTWARE, "malloc failed");
	s->buf = b;

	/* Compress section. */
	p = 0;
	if (is_compress_section(ecp, s->name)) {
		end = src + srcsz;
		for(c = src; c < end;) {
			len = 0;
			while(c + len < end && c[len] != '\0')
				len++;
			if (c + len == end) {
				/* XXX should we warn here? */
				strncpy(&b[p], c, len);
				p += len;
				break;
			}
			dupe = 0;
			for (d = b; d < b + p; ) {
				if (strcmp(d, c) == 0) {
					dupe = 1;
					break;
				}
				d += strlen(d) + 1;
			}
			if (!dupe) {
				strncpy(&b[p], c, len);
				b[p + len] = '\0';
				p += len + 1;
			}
			c += len + 1;
		}
	} else {
		memcpy(b, src, srcsz);
		p += srcsz;
	}

	/* Append section. */
	if (is_append_section(ecp, s->name)) {
		sac = lookup_sec_act(ecp, s->name, 0);
		len = strlen(sac->string);
		strncpy(&b[p], sac->string, len);
		b[p + len] = '\0';
		p += len + 1;
	}

	s->sz = p;
	s->nocopy = 1;
}

static void
print_data(const char *d, size_t sz)
{
	const char *c;

	for (c = d; c < d + sz; c++) {
		if (*c == '\0')
			putchar('\n');
		else
			putchar(*c);
	}
}

static void
print_section(struct section *s)
{
	Elf_Data *id;
	int elferr;

	if (s->buf != NULL && s->sz > 0) {
		print_data(s->buf, s->sz);
	} else {
		id = NULL;
		while ((id = elf_getdata(s->is, id)) != NULL)
			print_data(id->d_buf, id->d_size);
		elferr = elf_errno();
		if (elferr != 0)
			errx(EX_SOFTWARE, "elf_getdata() failed: %s",
			    elf_errmsg(elferr));
	}
	putchar('\n');
}

static void *
read_section(struct section *s, size_t *size)
{
	Elf_Data *id;
	char *b;
	size_t sz;
	int elferr;

	sz = 0;
	b = NULL;
	id = NULL;
	while ((id = elf_getdata(s->is, id)) != NULL) {
		if (b == NULL)
			b = malloc(id->d_size);
		else
			b = malloc(sz + id->d_size);
		if (b == NULL)
			err(EX_SOFTWARE, "malloc or realloc failed");

		memcpy(&b[sz], id->d_buf, id->d_size);
		sz += id->d_size;
	}
	elferr = elf_errno();
	if (elferr != 0)
		errx(EX_SOFTWARE, "elf_getdata() failed: %s",
		    elf_errmsg(elferr));

	*size = sz;

	return (b);
}

void
copy_shdr(struct elfcopy *ecp, Elf_Scn *is, Elf_Scn *os, const char *name)
{
	GElf_Shdr ish, osh;

	if (gelf_getshdr(is, &ish) == NULL)
		errx(EX_SOFTWARE, "526 gelf_getshdr() failed: %s",
		    elf_errmsg(-1));
	if (gelf_getshdr(os, &osh) == NULL)
		errx(EX_SOFTWARE, "529 gelf_getshdr() failed: %s",
		    elf_errmsg(-1));

	(void) memcpy(&osh, &ish, sizeof(ish));
	add_to_shstrtab(ecp, name);

	if (!gelf_update_shdr(os, &osh))
		errx(EX_SOFTWARE, "elf_update_shdr failed: %s",
		    elf_errmsg(-1));
}

void
copy_data(struct section *s)
{
	Elf_Data *id, *od;
	int elferr;

	if (s->nocopy && s->buf == NULL)
		return;

	id = NULL;
	while ((id = elf_getdata(s->is, id)) != NULL) {
		if ((od = elf_newdata(s->os)) == NULL)
			errx(EX_SOFTWARE, "elf_newdata() failed: %s",
			    elf_errmsg(-1));
		/* Use s->buf as content if s->nocopy is set. */
		if (s->nocopy) {
			od->d_align	= id->d_align;
			od->d_off	= 0;
			od->d_buf	= s->buf;
			od->d_type	= id->d_type;
			od->d_size	= s->sz;
			od->d_version	= id->d_version;
			return;
		}
		od->d_align	= id->d_align;
		od->d_off	= id->d_off;
		od->d_buf	= id->d_buf;
		od->d_type	= id->d_type;
		od->d_size	= id->d_size;
		od->d_version	= id->d_version;
	}
	elferr = elf_errno();
	if (elferr != 0)
		errx(EX_SOFTWARE, "elf_getdata() failed: %s",
		    elf_errmsg(elferr));
}

void
add_unloadables(struct elfcopy *ecp)
{
	struct sec_add *sa;
	struct section *shstr, *s;
	Elf_Data *od;
	Elf_Scn *os;
	GElf_Shdr osh;

	/* Put unloadable sections before .shstrtab section. */
	TAILQ_FOREACH(shstr, &ecp->v_sec, sec_list) {
		if (strcmp(shstr->name, ".shstrtab") == 0)
			break;
	}

	STAILQ_FOREACH(sa, &ecp->v_sadd, sadd_list) {
		if ((os = elf_newscn(ecp->eout)) == NULL)
			errx(EX_SOFTWARE, "elf_newscn() failed: %s",
			    elf_errmsg(-1));
		if ((s = calloc(1, sizeof(*s))) == NULL)
			err(EX_SOFTWARE, "calloc failed");
		s->name = sa->name;
		s->off = shstr->off;
		s->sz = sa->size;
		s->loadable = 0;
		s->is = NULL;
		s->os = os;
		TAILQ_INSERT_BEFORE(shstr, s, sec_list);

		if ((od = elf_newdata(os)) == NULL)
			errx(EX_SOFTWARE, "elf_newdata() failed: %s",
			    elf_errmsg(-1));
		od->d_align = 1;
		od->d_off = 0;
		od->d_buf = sa->content;
		od->d_size = sa->size;
		od->d_type = ELF_T_BYTE;
		od->d_version = EV_CURRENT;

		if (gelf_getshdr(os, &osh) == NULL)
			errx(EX_SOFTWARE, "607 gelf_getshdr() failed: %s",
			    elf_errmsg(-1));
		osh.sh_type = SHT_PROGBITS;
		add_to_shstrtab(ecp, sa->name);

		/* Add section header vma/lma, flag changes here */

		if (!gelf_update_shdr(os, &osh))
			errx(EX_SOFTWARE, "gelf_update_shdr() failed: %s",
			    elf_errmsg(-1));
	}
}

static void
add_to_shstrtab(struct elfcopy *ecp, const char *name)
{
	struct section *s;

	s = ecp->shstrtab;
	if (s->buf == NULL) {
		insert_to_strtab(s, "");
		insert_to_strtab(s, ".symtab");
		insert_to_strtab(s, ".strtab");
		insert_to_strtab(s, ".shstrtab");
	}
	insert_to_strtab(s, name);
}

void
update_shdr(struct elfcopy *ecp)
{
	struct section *s;
	GElf_Shdr osh;
	int elferr;

	TAILQ_FOREACH(s, &ecp->v_sec, sec_list) {
		if (gelf_getshdr(s->os, &osh) == NULL)
			errx(EX_SOFTWARE, "668 gelf_getshdr failed: %s",
			    elf_errmsg(-1));

		/* Find section name in string table and set sh_name. */
		osh.sh_name = lookup_string(ecp->shstrtab, s->name);

		/* 
		 * sh_link needs to be updated, since the index of the
		 * linked section might have changed.
		 */
		if (osh.sh_link != 0)
			osh.sh_link = ecp->secndx[osh.sh_link];

		/*
		 * sh_info of relocation section links to the section to which
		 * its relocation info applies. So it may need update as well.
		 */
		if ((s->type == SHT_REL || s->type == SHT_RELA) &&
		    osh.sh_info != 0)
			osh.sh_info = ecp->secndx[osh.sh_info];

		if (!gelf_update_shdr(s->os, &osh))
			errx(EX_SOFTWARE, "gelf_update_shdr() failed: %s",
			    elf_errmsg(-1));
	}
	elferr = elf_errno();
	if (elferr != 0)
		errx(EX_SOFTWARE, "elf_nextscn failed: %s",
		    elf_errmsg(elferr));
}

void
set_shstrtab(struct elfcopy *ecp)
{
	struct section *s;
	Elf_Data *data;
	GElf_Shdr sh;

	s = ecp->shstrtab;

	if (gelf_getshdr(s->os, &sh) == NULL)
		errx(EX_SOFTWARE, "692 gelf_getshdr() failed: %s",
		    elf_errmsg(-1));
	sh.sh_addr	= 0;
	sh.sh_addralign	= 1;
	sh.sh_offset	= s->off;
	sh.sh_type	= SHT_STRTAB;
	sh.sh_flags	= 0;
	sh.sh_entsize	= 0;
	sh.sh_info	= 0;
	sh.sh_link	= 0;

	if ((data = elf_newdata(s->os)) == NULL)
		errx(EX_SOFTWARE, "elf_newdata() failed: %s",
		    elf_errmsg(-1));

	/*
	 * If we don't have a symbol table, skip those a few bytes
	 * which are reserved for this in the beginning of shstrtab.
	 */
	if (!(ecp->flags & SYMTAB_EXIST)) {
		s->sz -= sizeof(".symtab\0.strtab");
		memmove(s->buf, (char *)s->buf + sizeof(".symtab\0.strtab"),
		    s->sz);
	}

	sh.sh_size	= s->sz;
	if (!gelf_update_shdr(s->os, &sh))
		errx(EX_SOFTWARE, "gelf_update_shdr() failed: %s",
		    elf_errmsg(-1));

	data->d_align	= 1;
	data->d_buf	= s->buf;
	data->d_size	= s->sz;
	data->d_off	= 0;
	data->d_type	= ELF_T_BYTE;
	data->d_version	= EV_CURRENT;

	if (!elf_setshstrndx(ecp->eout, elf_ndxscn(s->os)))
		errx(EX_SOFTWARE, "elf_setshstrndx() failed: %s",
		     elf_errmsg(-1));
}
