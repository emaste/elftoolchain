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

static int	add_to_shstrtab(struct elfcopy *ecp, const char *name);
static int	is_remove_section(struct elfcopy *ecp, const char *name);

static int
is_remove_section(struct elfcopy *ecp, const char *name)
{
	/* Always keep section name table */
	if (strcmp(name, ".shstrtab") == 0)
		return 0;
	if (strcmp(name, ".symtab") == 0 ||
	    strcmp(name, ".strtab") == 0) {
		if (ecp->strip == STRIP_ALL)
			return 1;
		else
			return 0;
	}

	if (ecp->sections_to_remove != 0 ||
	    ecp->sections_to_copy != 0) {
		struct sec_action *sac;

		sac = lookup_sec_act(ecp, name, 0);
		if (ecp->sections_to_remove != 0 &&
		    sac != NULL && sac->remove != 0)
			return 1;
		if (ecp->sections_to_copy != 0 &&
		    (sac == NULL || sac->copy == 0))
			return 1;
	}

	return 0;
}

void
add_to_sec_list(struct segment *seg, struct section *sec)
{
	struct section *s;

	TAILQ_FOREACH(s, &seg->v_sec, sec_next) {
		if (sec->off < s->off) {
			TAILQ_INSERT_BEFORE(s, sec, sec_next);
			return;
		}
	}

	TAILQ_INSERT_TAIL(&seg->v_sec, sec, sec_next);
}

struct sec_action*
lookup_sec_act(struct elfcopy *ecp, const char *name, int add)
{
	struct sec_action *sac;

	STAILQ_FOREACH(sac, &ecp->v_sac, sacs) {
		if (strcmp(name, sac->name) == 0)
			return sac;
	}

	if (add == 0)
		return NULL;

	if ((sac = malloc(sizeof(*sac))) == NULL)
		errx(EX_SOFTWARE, "not enough memory");
	memset(sac, 0, sizeof(*sac));
	sac->name = name;
	STAILQ_INSERT_TAIL(&ecp->v_sac, sac, sacs);

	return sac;
}

#define	_INIT_SHSTR "\0.symtab\0.strtab\0.shstrtab"

static int
add_to_shstrtab(struct elfcopy *ecp, const char *name)
{
	int t;

	if (ecp->shstrtab == NULL) {
		ecp->shstrtab_cap = 512;
		ecp->shstrtab = malloc(ecp->shstrtab_cap);
		if (ecp->shstrtab == NULL)
			err(EX_SOFTWARE, "malloc failed");
		(void) memcpy(ecp->shstrtab, _INIT_SHSTR, sizeof(_INIT_SHSTR));
		ecp->shstrtab_size = sizeof(_INIT_SHSTR);
	}

	if ((t = find_duplicate(ecp->shstrtab, name, ecp->shstrtab_size)) > -1)
		return t;

	t = ecp->shstrtab_size;
	while (t + strlen(name) >= ecp->shstrtab_cap - 1) {
		ecp->shstrtab_cap *= 2;
		if ((ecp->shstrtab = realloc(ecp->shstrtab,
		    ecp->shstrtab_cap)) == NULL)
			err(EX_SOFTWARE, "realloc failed");
	}
	strncpy(&ecp->shstrtab[t], name, strlen(name));
	ecp->shstrtab[t + strlen(name)] ='\0';

	if (strlen(name) > 0)
		ecp->shstrtab_size += strlen(name) + 1;

	return t;
}

size_t
create_sections(struct elfcopy *ecp, size_t off)
{
	Elf_Scn *is, *os;
	GElf_Shdr ish;
	size_t indx, sz;
	const char *name;
	int elferr;

	if (elf_getshstrndx(ecp->ein, &indx) == 0)
		errx(EX_SOFTWARE, "elf_getshstrndx failed: %s",
		     elf_errmsg(-1));

	is = NULL;
	while ((is = elf_nextscn(ecp->ein, is)) != NULL) {
		if (gelf_getshdr(is, &ish) == NULL)
			errx(EX_SOFTWARE, "gelf_getshdr failed: %s",
			    elf_errmsg(-1));
		if ((name = elf_strptr(ecp->ein, indx, ish.sh_name)) == NULL)
			errx(EX_SOFTWARE, "elf_strptr failed: %s",
			    elf_errmsg(-1));

		/* Add check for whether change section name here */

		if (is_remove_section(ecp, name)) {
			remove_section(ecp, &ish, name);
			continue;
		}

		if (strcmp(name, ".symtab") == 0) {
			ecp->flags |= SYMTAB_EXIST;
			ecp->symscn = is;
			continue;
		}
		if (strcmp(name, ".strtab") == 0) {
			ecp->strscn = is;
			continue;
		}
		if (strcmp(name, ".shstrtab") == 0)
			continue;

		if ((os = elf_newscn(ecp->eout)) == NULL)
			errx(EX_SOFTWARE, "elf_newscn() failed: %s",
			    elf_errmsg(-1));

		create_shdr(ecp, is, os, name);
		copy_data(is, os);

		/* size of SHT_NOBITS section doesn't count */
		if (ish.sh_type != SHT_NOBITS && ish.sh_type != SHT_NULL) {
			sz = ish.sh_offset + ish.sh_size;
			if (sz > off)
				off = sz;
		}

		ecp->os_cnt++;
	}
	elferr = elf_errno();
	if (elferr != 0)
		errx(EX_SOFTWARE, "elf_nextscn failed: %s",
		    elf_errmsg(elferr));

	return (off);
}

void
create_shdr(struct elfcopy *ecp, Elf_Scn *is, Elf_Scn *os, const char *name)
{
	GElf_Shdr ish, osh;

	if (gelf_getshdr(is, &ish) == NULL)
		errx(EX_SOFTWARE, "gelf_getshdr() failed: %s",
		    elf_errmsg(-1));
	if (gelf_getshdr(os, &osh) == NULL)
		errx(EX_SOFTWARE, "gelf_getshdr() failed: %s",
		    elf_errmsg(-1));

	(void) memcpy(&osh, &ish, sizeof(ish));
	osh.sh_name = add_to_shstrtab(ecp, name);

	if (!gelf_update_shdr(os, &osh))
		errx(EX_SOFTWARE, "elf_update_shdr failed: %s",
		    elf_errmsg(-1));
}

void
copy_data(Elf_Scn *is, Elf_Scn *os)
{
	Elf_Data *idata, *odata;
	int elferr;

	idata = NULL;
	while ((idata = elf_getdata(is, idata)) != NULL) {
		if ((odata = elf_newdata(os)) == NULL)
			errx(EX_SOFTWARE, "elf_newdata() failed: %s",
			    elf_errmsg(-1));

		odata->d_align		= idata->d_align;
		odata->d_off		= idata->d_off;
		odata->d_buf		= idata->d_buf;
		odata->d_type		= idata->d_type;
		odata->d_size		= idata->d_size;
		odata->d_version	= idata->d_version;
	}
	elferr = elf_errno();
	if (elferr != 0)
		errx(EX_SOFTWARE, "elf_getdata() failed: %s",
		    elf_errmsg(elferr));
}

size_t
add_sections(struct elfcopy *ecp, size_t off)
{
	struct sec_add *sa;
	Elf_Data *odata;
	Elf_Scn *oscn;
	GElf_Shdr oshdr;

	STAILQ_FOREACH(sa, &ecp->v_sadd, sadds) {
		if ((oscn = elf_newscn(ecp->eout)) == NULL)
			errx(EX_SOFTWARE, "elf_newscn() failed: %s",
			    elf_errmsg(-1));
		if ((odata = elf_newdata(oscn)) == NULL)
			errx(EX_SOFTWARE, "elf_newdata() failed: %s",
			    elf_errmsg(-1));
		odata->d_align = 1;
		odata->d_off = 0;
		odata->d_buf = sa->content;
		odata->d_size = sa->size;
		odata->d_type = ELF_T_BYTE;
		odata->d_version = EV_CURRENT;

		if (gelf_getshdr(oscn, &oshdr) == NULL)
			errx(EX_SOFTWARE, "gelf_getshdr() failed: %s",
			    elf_errmsg(-1));
		oshdr.sh_type = SHT_PROGBITS;
		oshdr.sh_name = add_to_shstrtab(ecp, sa->name);
		oshdr.sh_offset = off;
		oshdr.sh_size = sa->size;

		/* Add section header vma/lma, flag changes here */

		if (!gelf_update_shdr(oscn, &oshdr))
			errx(EX_SOFTWARE, "gelf_update_shdr() failed: %s",
			    elf_errmsg(-1));

		off += sa->size;
		ecp->os_cnt++;
	}

	return (off);
}

void
resync_shname(struct elfcopy *ecp)
{
	Elf_Scn *os;
	GElf_Shdr osh;
	int elferr;

	os = NULL;
	while ((os = elf_nextscn(ecp->eout, os)) != NULL) {
		if (gelf_getshdr(os, &osh) == NULL)
			errx(EX_SOFTWARE, "gelf_getshdr failed: %s",
			    elf_errmsg(-1));

		osh.sh_name -= sizeof(".symtab\0.strtab");

		if (!gelf_update_shdr(os, &osh))
			errx(EX_SOFTWARE, "gelf_update_shdr() failed: %s",
			    elf_errmsg(-1));
	}
	elferr = elf_errno();
	if (elferr != 0)
		errx(EX_SOFTWARE, "elf_nextscn failed: %s",
		    elf_errmsg(elferr));
}

size_t
create_shstrtab(struct elfcopy *ecp, size_t off)
{
	Elf_Scn *ss;
	Elf_Data *data;
	GElf_Shdr sh;

	if ((ss = elf_newscn(ecp->eout)) == NULL)
		errx(EX_SOFTWARE, "elf_newscn() failed: %s",
		    elf_errmsg(-1));

	if (gelf_getshdr(ss, &sh) == NULL)
		errx(EX_SOFTWARE, "gelf_getshdr() failed: %s",
		    elf_errmsg(-1));

	if ((data = elf_newdata(ss)) == NULL)
		errx(EX_SOFTWARE, "elf_newdata() failed: %s",
		    elf_errmsg(-1));

	data->d_align	= 1;
	data->d_off	= 0;
	data->d_buf	= ecp->shstrtab;
	data->d_size	= ecp->shstrtab_size;
	data->d_type	= ELF_T_BYTE;
	data->d_version	= EV_CURRENT;

	sh.sh_name	= add_to_shstrtab(ecp, ".shstrtab");
	sh.sh_addr	= 0;
	sh.sh_addralign	= 1;
	sh.sh_offset	= off;
	sh.sh_size	= data->d_size;
	sh.sh_type	= SHT_STRTAB;
	sh.sh_flags	= 0;
	sh.sh_entsize	= 0;
	sh.sh_info	= 0;
	sh.sh_link	= 0;

	if (!gelf_update_shdr(ss, &sh))
		errx(EX_SOFTWARE, "gelf_update_shdr() failed: %s",
		    elf_errmsg(-1));

	/* Set section name string table index */
	if (!elf_setshstrndx(ecp->eout, elf_ndxscn(ss)))
		errx(EX_SOFTWARE, "elf_setshstrndx() failed: %s",
		     elf_errmsg(-1));

	off += data->d_size;

	return (off);
}
