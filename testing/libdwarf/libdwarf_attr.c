/*-
 * Copyright (c) 2007 John Birrell (jb@freebsd.org)
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

#include <stdlib.h>
#include <string.h>
#include "_libdwarf.h"

static int
attr_add(Dwarf_Die die, Dwarf_Attribute atref, Dwarf_Attribute *atp,
    Dwarf_Error *error)
{
	Dwarf_Attribute at;

	if ((at = malloc(sizeof(struct _Dwarf_Attribute))) == NULL) {
		DWARF_SET_ERROR(error, DWARF_E_MEMORY);
		return (DWARF_E_MEMORY);
	}

	memcpy(at, atref, sizeof(struct _Dwarf_Attribute));

	/* Add the attribute value to the list in the die. */
	STAILQ_INSERT_TAIL(&die->die_attr, at, at_next);

	/* Save a pointer to the attribute name if this is one. */
	if (at->at_attrib == DW_AT_name)
		switch (at->at_form) {
		case DW_FORM_strp:
			die->die_name = at->u[1].s;
			break;
		case DW_FORM_string:
			die->die_name = at->u[0].s;
			break;
		default:
			break;
		}

	if (atp != NULL)
		*atp = at;

	return (DWARF_E_NONE);
}

Dwarf_Attribute
attr_find(Dwarf_Die die, Dwarf_Half attr)
{
	Dwarf_Attribute at;

	STAILQ_FOREACH(at, &die->die_attr, at_next) {
		if (at->at_attrib == attr)
			break;
	}

	return at;
}

int
attr_init(Dwarf_Debug dbg, Elf_Data **dp, uint64_t *offsetp,
    Dwarf_CU cu, Dwarf_Die die, Dwarf_AttrDef ad, uint64_t form,
    int indirect, Dwarf_Error *error)
{
	int ret;
	struct _Dwarf_Attribute atref;

	ret = DWARF_E_NONE;
	memset(&atref, 0, sizeof(atref));
	atref.at_cu = cu;
	atref.at_ad = ad;
	atref.at_indirect = indirect;

	switch (form) {
	case DW_FORM_addr:
		atref.u[0].u64 = dbg->read(dp, offsetp, cu->cu_pointer_size);
		break;
	case DW_FORM_block:
		atref.u[0].u64 = read_uleb128(dp, offsetp);
		atref.u[1].u8p = read_block(dp, offsetp, atref.u[0].u64);
		break;
	case DW_FORM_block1:
		atref.u[0].u64 = dbg->read(dp, offsetp, 1);
		atref.u[1].u8p = read_block(dp, offsetp, atref.u[0].u64);
		break;
	case DW_FORM_block2:
		atref.u[0].u64 = dbg->read(dp, offsetp, 2);
		atref.u[1].u8p = read_block(dp, offsetp, atref.u[0].u64);
		break;
	case DW_FORM_block4:
		atref.u[0].u64 = dbg->read(dp, offsetp, 4);
		atref.u[1].u8p = read_block(dp, offsetp, atref.u[0].u64);
		break;
	case DW_FORM_data1:
	case DW_FORM_flag:
	case DW_FORM_ref1:
		atref.u[0].u64 = dbg->read(dp, offsetp, 1);
		break;
	case DW_FORM_data2:
	case DW_FORM_ref2:
		atref.u[0].u64 = dbg->read(dp, offsetp, 2);
		break;
	case DW_FORM_data4:
	case DW_FORM_ref4:
		atref.u[0].u64 = dbg->read(dp, offsetp, 4);
		break;
	case DW_FORM_data8:
	case DW_FORM_ref8:
		atref.u[0].u64 = dbg->read(dp, offsetp, 8);
		break;
	case DW_FORM_indirect:
		form = read_uleb128(dp, offsetp);
		return (attr_init(dbg, dp, offsetp, cu, die, ad, form, 1,
		    error));
	case DW_FORM_ref_addr:
		if (cu->cu_version == 2)
			atref.u[0].u64 = dbg->read(dp, offsetp, cu->cu_pointer_size);
		else if (cu->cu_version == 3)
			atref.u[0].u64 = dbg->read(dp, offsetp, dbg->dbg_offsize);
		break;
	case DW_FORM_ref_udata:
	case DW_FORM_udata:
		atref.u[0].u64 = read_uleb128(dp, offsetp);
		break;
	case DW_FORM_sdata:
		atref.u[0].s64 = read_sleb128(dp, offsetp);
		break;
	case DW_FORM_string:
		atref.u[0].s = read_string(dp, offsetp);
		break;
	case DW_FORM_strp:
		atref.u[0].u64 = dbg->read(dp, offsetp, dbg->dbg_offsize);
		atref.u[1].s = elf_strptr(dbg->dbg_elf,
		    dbg->dbg_s[DWARF_debug_str].s_shnum, atref.u[0].u64);
		break;
	default:
		DWARF_SET_ERROR(error, DWARF_E_NOT_IMPLEMENTED);
		ret = DWARF_E_NOT_IMPLEMENTED;
		break;
	}

	if (ret == DWARF_E_NONE)
		ret = attr_add(die, &atref, NULL, error);

	return (ret);
}
