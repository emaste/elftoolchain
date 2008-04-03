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

static int	is_append_section(struct elfcopy *ecp, const char *name);
static int	is_compress_section(struct elfcopy *ecp, const char *name);
static int	is_print_section(struct elfcopy *ecp, const char *name);
static void	mcs_operations(struct elfcopy *ecp, Elf_Scn *oscn);

static int
is_append_section(struct elfcopy *ecp, const char *name)
{
	struct sec_action *sac;

	sac = lookup_sec_act(ecp, name, 0);
	if (sac != NULL && sac->append != 0 && sac->string != NULL)
		return 1;

	return 0;
}

static int
is_compress_section(struct elfcopy *ecp, const char *name)
{
	struct sec_action *sac;

	sac = lookup_sec_act(ecp, name, 0);
	if (sac != NULL && sac->compress != 0)
		return 1;

	return 0;
}

static int
is_print_section(struct elfcopy *ecp, const char *name)
{
	struct sec_action *sac;

	sac = lookup_sec_act(ecp, name, 0);
	if (sac != NULL && sac->print != 0)
		return 1;

	return 0;
}

static void
mcs_operations(struct elfcopy *ecp, Elf_Scn *oscn)
{
	struct sec_action *sac;
	GElf_Shdr oshdr;
	Elf_Data *odata;
	char *name, *c, *d, *start, *end;
	size_t len;
	int dupe, elferr;

	if (gelf_getshdr(oscn, &oshdr) == NULL)
		errx(EX_SOFTWARE, "gelf_getshdr failed: %s",
		    elf_errmsg(-1));

	name = &ecp->shstrtab[oshdr.sh_name];

	/*
	 * There should not be more than one Elf_Data for this Scn.
	 */
	odata = NULL;
	if ((odata = elf_getdata(oscn, odata)) == NULL) {
		elferr = elf_errno();
		if (elferr != 0)
			errx(EX_SOFTWARE, "elf_getdata failed: %s",
			    elf_errmsg(elferr));

		/* For empty section, we proceed if we need to append. */
		if (!is_append_section(ecp, name))
			return;
	}

	/* If we only print, no need to copy verbatim. */
	if (is_print_section(ecp, name) && !is_append_section(ecp, name) &&
	    !is_compress_section(ecp, name))
		goto print;

	/* Allocate buffer for new section data. */
	ecp->mcsbuf_size = 0;
	ecp->mcsbuf_cap = 512;
	ecp->mcsbuf = malloc(ecp->mcsbuf_cap);
	if (ecp->mcsbuf == NULL)
		err(EX_SOFTWARE, "malloc failed");

	start = odata->d_buf;
	end = start + odata->d_size;
	for(c = start; c < end;) {
		len = strlen(c);
		dupe = 0;
		if (is_compress_section(ecp, name)) {
			for (d = ecp->mcsbuf; d < ecp->mcsbuf +
			    ecp->mcsbuf_size;) {
				if (strcmp(d, c) == 0) {
					dupe = 1;
					break;
				}
				d += strlen(d) + 1;
			}
		}
		if (!dupe) {
			if (ecp->mcsbuf_size + len >= ecp->mcsbuf_cap) {
				ecp->mcsbuf_cap *= 2;
				ecp->mcsbuf = realloc(ecp->mcsbuf,
				    ecp->mcsbuf_cap);
				if (ecp->mcsbuf == NULL)
					err(EX_SOFTWARE, "realloc failed");
			}
			strncpy(&ecp->mcsbuf[ecp->mcsbuf_size], c, len);
			ecp->mcsbuf[ecp->mcsbuf_size + len] = '\0';
			ecp->mcsbuf_size += len + 1;
		}

		c += len + 1;
	}

	if (is_append_section(ecp, name)) {
		sac = lookup_sec_act(ecp, name, 0);
		len = strlen(sac->string);
		ecp->mcsbuf_cap = ecp->mcsbuf_size + len + 1;
		ecp->mcsbuf = realloc(ecp->mcsbuf, ecp->mcsbuf_cap);
		if (ecp->mcsbuf == NULL)
			err(EX_SOFTWARE, "realloc failed");
		strncpy(&ecp->mcsbuf[ecp->mcsbuf_size], sac->string, len);
		ecp->mcsbuf[ecp->mcsbuf_size + len] = '\0';
		ecp->mcsbuf_size = ecp->mcsbuf_cap;
	}

	odata->d_buf  = ecp->mcsbuf;
	odata->d_size = ecp->mcsbuf_size;

	/* Update sh_size as well */
	if (gelf_getshdr(oscn, &oshdr) == NULL)
		errx(EX_SOFTWARE, "gelf_getshdr failed: %s",
		    elf_errmsg(-1));
	oshdr.sh_size = ecp->mcsbuf_size;
	if (!gelf_update_shdr(oscn, &oshdr))
		errx(EX_SOFTWARE, "gelf_update_shdr failed: %s",
		    elf_errmsg(-1));

print:
	if (is_print_section(ecp, name)) {
		start = odata->d_buf;
		end = start + odata->d_size;
		for (c = start; c < end;) {
			/* output empty line for "extra" \0 */
			if (c == '\0') {
				printf("\n");
				c++;
				continue;
			}
			printf("%s\n", c);
			c += strlen(c) + 1;
		}
		printf("\n");
	}
}

void
mcs_sections(struct elfcopy *ecp)
{
	GElf_Shdr oshdr;
	GElf_Ehdr oehdr;
	Elf_Scn *oscn;
	size_t rc, shtab_size;
	char *name;
	int elferr;

	rc = 0;
	oscn = NULL;
	while ((oscn = elf_nextscn(ecp->eout, oscn)) != NULL) {
		if (gelf_getshdr(oscn, &oshdr) == NULL)
			errx(EX_SOFTWARE, "gelf_getshdr failed: %s",
			    elf_errmsg(-1));

		/*
		 * Note that here we can't use elf_strptr to retrieve
		 * names because the internal e->e_u.e_elf.e_strndx
		 * won't get updated in ELF_C_WRITE mode.
		 */
		name = &ecp->shstrtab[oshdr.sh_name];
		
		/* Check if we need to adjust sh_offset. */
		if (rc == 0)
			rc = oshdr.sh_offset;
		else {
			rc = roundup(rc, oshdr.sh_addralign);
			if (rc > oshdr.sh_offset) {
				oshdr.sh_offset = rc;
				if (!gelf_update_shdr(oscn, &oshdr))
					errx(EX_SOFTWARE,
					    "gelf_update_shdr failed: %s",
					     elf_errmsg(-1));
			} else
				/* We don't care about gaps between sections */
				rc = oshdr.sh_offset;
		}

		/* SHT_NOBITS section does not have content. */
		if (oshdr.sh_type == SHT_NOBITS || oshdr.sh_type == SHT_NULL)
			continue;

		if (is_append_section(ecp, name) ||
		    is_compress_section(ecp, name) ||
		    is_print_section(ecp, name))
			mcs_operations(ecp, oscn);

		/* Regain oshdr here since sh_size possibly has been updated. */
		if (gelf_getshdr(oscn, &oshdr) == NULL)
			errx(EX_SOFTWARE, "gelf_getshdr failed: %s",
			    elf_errmsg(-1));

		rc += oshdr.sh_size;

		/*
		 * If this section is .shstrtab, sync the section header table
		 * that follows it.
		 */
		if (strcmp(name, ".shstrtab") == 0) {
			rc = roundup(rc, 4); /* FIXME always 4? */
			if (gelf_getehdr(ecp->eout, &oehdr) == NULL)
				errx(EX_SOFTWARE, "gelf_getehdr failed: %s",
				    elf_errmsg(-1));
			if (rc > oehdr.e_shoff) {
				oehdr.e_shoff = rc;
				if (!gelf_update_ehdr(ecp->eout, &oehdr))
					errx(EX_SOFTWARE,
					    "gelf_update_shdr failed: %s",
					     elf_errmsg(-1));
			} else
				rc = oshdr.sh_offset;

			shtab_size = gelf_fsize(ecp->eout, ELF_T_SHDR,
			    ecp->os_cnt + 1, EV_CURRENT);
			if (shtab_size == 0)
				errx(EX_SOFTWARE, "gelf_fsize failed: %s",
				    elf_errmsg(-1));

			rc += shtab_size;
		}

	}
	elferr = elf_errno();
	if (elferr != 0)
		errx(EX_SOFTWARE, "elf_nextscn failed: %s",
		    elf_errmsg(elferr));
}
