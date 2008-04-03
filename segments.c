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

#include <sys/queue.h>
#include <err.h>
#include <gelf.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>

#include "elfcopy.h"

void
setup_phdr(struct elfcopy *ecp)
{
	struct segment *seg;
	struct section *sec;
	GElf_Shdr ishdr;
	GElf_Phdr iphdr;
	Elf_Scn *iscn;
	char *name;
	size_t ishstrndx;
	int iphnum;
	int elferr;
	int i;

	if (elf_getshstrndx(ecp->ein, &ishstrndx) == 0)
		errx(EX_SOFTWARE, "elf_getshstrndx failed: %s",
		     elf_errmsg(-1));
	if (elf_getphnum(ecp->ein, &iphnum) == 0)
		errx(EX_DATAERR, "elf_getphnum failed: %s",
		    elf_errmsg(-1));

	ecp->ophnum = ecp->iphnum = iphnum;
	if (iphnum == 0)
		return;

	if ((ecp->v_seg = malloc(sizeof(*ecp->v_seg) * iphnum)) == NULL)
		err(EX_SOFTWARE, "malloc failed");
	memset(ecp->v_seg, 0, sizeof(*ecp->v_seg) * iphnum);

	for (i = 0; i < iphnum; i++) {
		if (gelf_getphdr(ecp->ein, i, &iphdr) != &iphdr)
			errx(EX_SOFTWARE, "gelf_getphdr failed: %s",
			    elf_errmsg(-1));
		seg = &ecp->v_seg[i];
		seg->off = iphdr.p_offset;
		seg->fsize = iphdr.p_filesz;
		seg->msize = iphdr.p_memsz;
		TAILQ_INIT(&seg->v_sec);
	}

	/*
	 * Some of the sections are included in one or more segments.
	 * Find these sections and keep a record in their containing
	 * segments' v_sec queues. These information are later used to
	 * recalculate the extents of segments, when sections are removed,
	 * for example.
	 */
	iscn = NULL;
	while ((iscn = elf_nextscn(ecp->ein, iscn)) != NULL) {
		if (gelf_getshdr(iscn, &ishdr) != &ishdr)
			errx(EX_SOFTWARE, "elf_getshdr failed: %s",
			    elf_errmsg(-1));
		if ((name = elf_strptr(ecp->ein, ishstrndx, ishdr.sh_name)) ==
		    NULL)
			errx(EX_SOFTWARE, "elf_strptr failed: %s",
			    elf_errmsg(-1));

		for (i = 0; i < iphnum; i++) {
			seg = &ecp->v_seg[i];
			if (ishdr.sh_offset < seg->off)
				continue;
			if (ishdr.sh_offset + ishdr.sh_size > seg->off +
			    seg->fsize && ishdr.sh_type != SHT_NOBITS)
				continue;
			if (ishdr.sh_offset + ishdr.sh_size > seg->off +
			    seg->msize)
				continue;

			if ((sec = malloc(sizeof(*sec))) == NULL)
				errx(EX_SOFTWARE, "malloc failed");
			sec->name = name;
			sec->off = ishdr.sh_offset;
			sec->size = ishdr.sh_size;
			add_to_sec_list(seg, sec);
		}
	}
	elferr = elf_errno();
	if (elferr != 0)
		errx(EX_SOFTWARE, "elf_nextscn failed: %s",
		    elf_errmsg(elferr));


}

void
copy_phdr(struct elfcopy *ecp)
{
	struct segment *seg;
	struct section *lsec;
	GElf_Phdr iphdr, ophdr;
	size_t t;
	int i;

	for (i = 1; i < ecp->iphnum; i++) {
		seg = &ecp->v_seg[i];
		if (!TAILQ_EMPTY(&seg->v_sec)) {
			lsec = TAILQ_LAST(&seg->v_sec, sec_head);
			t = lsec->off + lsec->size - seg->off;
			/*
			 * XXX Here we check whether need to "Shrink"
			 * fsize and msize by comparing the extend of
			 * the last section to the mem size field.
			 * This is so because alloc sections (e.g.
			 * '.bss') are positioned at last of loadable
			 * segment. And if that alloc section is
			 * removed, we assume file size and mem size
			 * become the same. This might not be right.
			 */
			if (seg->msize != t)
				seg->fsize = seg->msize = t;
		} else
			seg->fsize = seg->msize = 0;
	}

	/*
	 * Allocate space for program headers, note that libelf keep
	 * track of the number in internal variable, and a call to
	 * elf_update is needed to update e_phnum of ehdr.
	 */
	if (gelf_newphdr(ecp->eout, ecp->ophnum) == NULL)
		errx(EX_SOFTWARE, "gelf_newphdr() failed: %s", elf_errmsg(-1));

	/*
	 * This elf_update() call is to update the e_phnum field in
	 * ehdr. It's necessary because later we will call gelf_getphdr(),
	 * which does sanity check by comparing ndx argument with e_phnum.
	 */
	if (elf_update(ecp->eout, ELF_C_NULL) < 0)
		errx(EX_SOFTWARE, "elf_update() failed: %s", elf_errmsg(-1));

	/*
	 * XXX iphnum == ophnum, since we don't remove program
	 * headers even if they no longer contain sections.
	 * Need more observation of objcopy's behaviour.
	 */
	for (i = 0; i < ecp->iphnum; i++) {
		if (gelf_getphdr(ecp->ein, i, &iphdr) != &iphdr)
			errx(EX_SOFTWARE, "gelf_getphdr failed: %s",
			    elf_errmsg(-1));
		if (gelf_getphdr(ecp->eout, i, &ophdr) != &ophdr)
			errx(EX_SOFTWARE, "gelf_getphdr failed: %s",
			    elf_errmsg(-1));

		seg = &ecp->v_seg[i];
		ophdr.p_type = iphdr.p_type;
		ophdr.p_vaddr = iphdr.p_vaddr;
		ophdr.p_paddr = iphdr.p_paddr;
		ophdr.p_flags = iphdr.p_flags;
		ophdr.p_align = iphdr.p_align;
		ophdr.p_offset = iphdr.p_offset;
		ophdr.p_filesz = seg->fsize;
		ophdr.p_memsz = seg->msize;

		if (!gelf_update_phdr(ecp->eout, i, &ophdr))
			err(EX_SOFTWARE, "gelf_update_phdr failed :%s",
			    elf_errmsg(-1));
	}
}

void
remove_section(struct elfcopy *ecp, GElf_Shdr *sh, const char *name)
{
	struct section *s, *s_temp;
	struct segment *seg;
	int i;

	for(i = 0; i < ecp->iphnum; i++) {
		seg = &ecp->v_seg[i];
		TAILQ_FOREACH_SAFE(s, &seg->v_sec, sec_next, s_temp) {
			if (strcmp(name, s->name) == 0 &&
			    sh->sh_offset == s->off &&
			    sh->sh_size == s->size) {
				TAILQ_REMOVE(&seg->v_sec, s, sec_next);
				free(s);
				break;
			}
		}
	}
}

