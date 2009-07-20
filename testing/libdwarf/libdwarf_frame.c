/*-
 * Copyright (c) 2009 Kai Wang
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include "_libdwarf.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

static int
frame_find_cie(Dwarf_FrameSec fs, Dwarf_Unsigned offset, Dwarf_Cie *ret_cie)
{
	Dwarf_Cie cie;

	STAILQ_FOREACH(cie, &fs->fs_cielist, cie_next) {
		if (cie->cie_offset == offset)
			break;
	}

	if (cie == NULL)
		return (DWARF_E_NO_ENTRY);

	if (ret_cie != NULL)
		*ret_cie = cie;

	return (DWARF_E_NONE);
}

static int
frame_add_cie(Dwarf_Debug dbg, Dwarf_FrameSec fs, Elf_Data *d,
    Dwarf_Unsigned *off, Dwarf_Cie *ret_cie, Dwarf_Error *error)
{
	Dwarf_Cie cie;
	uint64_t length;
	int dwarf_size;
	char *p;

	/* Check if we already added this CIE. */
	if (frame_find_cie(fs, *off, NULL) != DWARF_E_NO_ENTRY)
		return (DWARF_E_NONE);

	if ((cie = calloc(1, sizeof(struct _Dwarf_Cie))) == NULL) {
		DWARF_SET_ERROR(error, DWARF_E_MEMORY);
		return (DWARF_E_MEMORY);
	}
	STAILQ_INSERT_TAIL(&fs->fs_cielist, cie, cie_next);

	cie->cie_index = fs->fs_cielen;
	cie->cie_offset = *off;

	length = dbg->read(&d, off, 4);
	if (length == 0xffffffff) {
		dwarf_size = 8;
		length = dbg->read(&d, off, 8);
	} else
		dwarf_size = 4;

	if (length > d->d_size - *off) {
		DWARF_SET_ERROR(error, DWARF_E_INVALID_FRAME);
		return (DWARF_E_INVALID_FRAME);
	}

	(void) dbg->read(&d, off, dwarf_size); /* Skip CIE id. */
	cie->cie_length = length;
	cie->cie_version = dbg->read(&d, off, 2); /* FIXME: verify version */
	cie->cie_augment = (uint8_t *)d->d_buf + *off;
	p = (char *)d->d_buf;
	while (p[(*off)++] != '\0')
		;

#if 0
	/* We only recognize CIE with empty augmentation. */
	if (*cie->cie_augment != 0) {
		*off = cie->cie_offset + ((dwarf_size == 4) ? 4 : 12) +
		    cie->cie_length;
		return (DWARF_E_NONE);
	}
#endif

	cie->cie_caf = read_uleb128(&d, off);
	cie->cie_daf = read_sleb128(&d, off);
	cie->cie_ra = read_uleb128(&d, off);
	cie->cie_initinst = (uint8_t *)d->d_buf + *off;
	if (dwarf_size == 4)
		cie->cie_instlen = cie->cie_offset + 4 + length - *off;
	else
		cie->cie_instlen = cie->cie_offset + 12 + length - *off;

	*off += cie->cie_instlen;

	printf("cie:\n");
	printf("\tcie_offset=%ju cie_length=%ju cie_augment=%u cie_instlen=%ju off=%ju\n",
	    cie->cie_offset, cie->cie_length, *cie->cie_augment, cie->cie_instlen, *off);

	if (ret_cie != NULL)
		*ret_cie = cie;

	fs->fs_cielen++;

	return (DWARF_E_NONE);
}

static int
frame_add_fde(Dwarf_Debug dbg, Dwarf_FrameSec fs, Elf_Data *d,
    Dwarf_Unsigned *off, Dwarf_Error *error)
{
	Dwarf_Cie cie;
	Dwarf_Fde fde;
	uint64_t length;
	int dwarf_size, ret;

	if ((fde = calloc(1, sizeof(struct _Dwarf_Fde))) == NULL) {
		DWARF_SET_ERROR(error, DWARF_E_MEMORY);
		return (DWARF_E_MEMORY);
	}
	STAILQ_INSERT_TAIL(&fs->fs_fdelist, fde, fde_next);

	fde->fde_addr = (uint8_t *)d->d_buf + *off;
	fde->fde_offset = *off;

	length = dbg->read(&d, off, 4);
	if (length == 0xffffffff) {
		dwarf_size = 8;
		length = dbg->read(&d, off, 8);
	} else
		dwarf_size = 4;

	if (length > d->d_size - *off) {
		DWARF_SET_ERROR(error, DWARF_E_INVALID_FRAME);
		return (DWARF_E_INVALID_FRAME);
	}

	fde->fde_length = length;
	fde->fde_cieoff = dbg->read(&d, off, dwarf_size);
	if (frame_find_cie(fs, fde->fde_cieoff, &cie) == DWARF_E_NO_ENTRY) {
		ret = frame_add_cie(dbg, fs, d, &fde->fde_cieoff, &cie, error);
		if (ret != DWARF_E_NONE)
			return (ret);
	}
	fde->fde_cieoff = cie->cie_offset;
	fde->fde_cie = cie;
	fde->fde_initloc = dbg->read(&d, off, dbg->dbg_pointer_size);
	fde->fde_adrange = dbg->read(&d, off, dbg->dbg_pointer_size);
	fde->fde_inst = (uint8_t *)d->d_buf + *off;
	if (dwarf_size == 4)
		fde->fde_instlen = fde->fde_offset + 4 + length - *off;
	else
		fde->fde_instlen = fde->fde_offset + 12 + length - *off;

	*off += fde->fde_instlen;

	printf("fde:\n");
	printf("\tfde_offset=%ju fde_length=%ju fde_cieoff=%ju fde_instlen=%ju off=%ju\n",
	    fde->fde_offset, fde->fde_length, fde->fde_cieoff, fde->fde_instlen, *off);

	fs->fs_fdelen++;

	return (DWARF_E_NONE);
}

void
frame_cleanup(Dwarf_FrameSec fs)
{
	Dwarf_Cie cie, tcie;
	Dwarf_Fde fde, tfde;

	STAILQ_FOREACH_SAFE(cie, &fs->fs_cielist, cie_next, tcie) {
		STAILQ_REMOVE(&fs->fs_cielist, cie, _Dwarf_Cie, cie_next);
		free(cie);
	}

	STAILQ_FOREACH_SAFE(fde, &fs->fs_fdelist, fde_next, tfde) {
		STAILQ_REMOVE(&fs->fs_fdelist, fde, _Dwarf_Fde, fde_next);
		free(fde);
	}

	if (fs->fs_ciearray != NULL)
		free(fs->fs_ciearray);
	if (fs->fs_fdearray != NULL)
		free(fs->fs_fdearray);

	free(fs);
}

int
frame_init(Dwarf_Debug dbg, Dwarf_FrameSec *frame_sec, Elf_Data *d,
    Dwarf_Error *error)
{
	Dwarf_FrameSec fs;
	Dwarf_Cie cie;
	Dwarf_Fde fde;
	uint64_t length, offset, cie_id, entry_off;
	int dwarf_size, i, ret;

	assert(frame_sec != NULL);
	assert(*frame_sec == NULL);

	if ((fs = calloc(1, sizeof(struct _Dwarf_FrameSec))) == NULL) {
		DWARF_SET_ERROR(error, DWARF_E_MEMORY);
		return (DWARF_E_MEMORY);
	}
	STAILQ_INIT(&fs->fs_cielist);
	STAILQ_INIT(&fs->fs_fdelist);

	offset = 0;
	while (offset < d->d_size) {
		entry_off = offset;
		length = dbg->read(&d, &offset, 4);
		if (length == 0xffffffff) {
			dwarf_size = 8;
			length = dbg->read(&d, &offset, 8);
		} else
			dwarf_size = 4;

		if (length > d->d_size - offset) {
			DWARF_SET_ERROR(error, DWARF_E_INVALID_FRAME);
			return (DWARF_E_INVALID_FRAME);
		}

		cie_id = dbg->read(&d, &offset, dwarf_size);
		if ((dwarf_size == 4 && cie_id == ~0U) ||
		    (dwarf_size == 8 && cie_id == ~0ULL))
			ret = frame_add_cie(dbg, fs, d, &entry_off, NULL,
			    error);
		else
			ret = frame_add_fde(dbg, fs, d, &entry_off, error);

		if (ret != DWARF_E_NONE)
			goto fail_cleanup;

		offset = entry_off;
	}

	/* Create CIE array. */
	if (fs->fs_cielen > 0) {
		if ((fs->fs_ciearray = malloc(sizeof(Dwarf_Cie) *
		    fs->fs_cielen)) == NULL) {
			ret = DWARF_E_MEMORY;
			DWARF_SET_ERROR(error, ret);
			goto fail_cleanup;
		}
		i = 0;
		STAILQ_FOREACH(cie, &fs->fs_cielist, cie_next) {
			fs->fs_ciearray[i++] = cie;
		}
		assert((Dwarf_Unsigned)i == fs->fs_cielen);
	}

	/* Create FDE array. */
	if (fs->fs_fdelen > 0) {
		if ((fs->fs_fdearray = malloc(sizeof(Dwarf_Fde) *
		    fs->fs_fdelen)) == NULL) {
			ret = DWARF_E_MEMORY;
			DWARF_SET_ERROR(error, ret);
			goto fail_cleanup;
		}
		i = 0;
		STAILQ_FOREACH(fde, &fs->fs_fdelist, fde_next) {
			fs->fs_fdearray[i++] = fde;
		}
		assert((Dwarf_Unsigned)i == fs->fs_fdelen);
	}

	*frame_sec = fs;

	return (DWARF_E_NONE);

fail_cleanup:

	frame_cleanup(fs);

	return (ret);
}
