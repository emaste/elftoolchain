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

int
dwarf_get_fde_list(Dwarf_Debug dbg, Dwarf_Cie **cie_list,
    Dwarf_Signed *cie_count, Dwarf_Fde **fde_list, Dwarf_Signed *fde_count,
    Dwarf_Error *error)
{

	if (dbg == NULL || cie_list == NULL || cie_count == NULL ||
	    fde_list == NULL || fde_count == NULL) {
		DWARF_SET_ERROR(error, DWARF_E_ARGUMENT);
		return (DW_DLV_ERROR);
	}

	if (dbg->dbg_frame == NULL) {
		DWARF_SET_ERROR(error, DWARF_E_NO_ENTRY);
		return (DW_DLV_NO_ENTRY);
	}

	if (dbg->dbg_frame->fs_ciearray == NULL ||
	    dbg->dbg_frame->fs_fdearray == NULL) {
		DWARF_SET_ERROR(error, DWARF_E_NO_ENTRY);
		return (DW_DLV_NO_ENTRY);
	}

	*cie_list = dbg->dbg_frame->fs_ciearray;
	*cie_count = dbg->dbg_frame->fs_cielen;
	*fde_list = dbg->dbg_frame->fs_fdearray;
	*fde_count = dbg->dbg_frame->fs_fdelen;

	return (DW_DLV_OK);
}

int
dwarf_get_cie_of_fde(Dwarf_Fde fde, Dwarf_Cie *ret_cie, Dwarf_Error *error)
{

	if (fde == NULL || ret_cie == NULL) {
		DWARF_SET_ERROR(error, DWARF_E_ARGUMENT);
		return (DW_DLV_ERROR);
	}

	*ret_cie = fde->fde_cie;

	return (DW_DLV_OK);
}

int
dwarf_get_fde_range(Dwarf_Fde fde, Dwarf_Addr *low_pc, Dwarf_Unsigned *func_len,
    Dwarf_Ptr *fde_bytes, Dwarf_Unsigned *fde_byte_len, Dwarf_Off *cie_offset,
    Dwarf_Signed *cie_index, Dwarf_Off *fde_offset, Dwarf_Error *error)
{

	if (fde == NULL || low_pc == NULL || func_len == NULL ||
	    fde_bytes == NULL || fde_byte_len == NULL || cie_offset == NULL ||
	    cie_index == NULL || fde_offset == NULL) {
		DWARF_SET_ERROR(error, DWARF_E_ARGUMENT);
		return (DW_DLV_ERROR);
	}

	*low_pc = fde->fde_initloc;
	*func_len = fde->fde_adrange;
	*fde_bytes = fde->fde_addr;

	/*
	 * XXX should we return a real length, or length excluding
	 * initial length?
	 */
	*fde_byte_len = fde->fde_length;
	*cie_offset = fde->fde_cieoff;
	*cie_index = fde->fde_cie->cie_index;
	*fde_offset = fde->fde_offset;

	return (DW_DLV_OK);
}

int
dwarf_get_cie_info(Dwarf_Cie cie, Dwarf_Unsigned *bytes_in_cie,
    Dwarf_Small *version, char **augmenter, Dwarf_Unsigned *caf,
    Dwarf_Unsigned *daf, Dwarf_Half *ra, Dwarf_Ptr *initinst,
    Dwarf_Unsigned *inst_len, Dwarf_Error *error)
{

	if (cie == NULL || bytes_in_cie == NULL || version == NULL ||
	    augmenter == NULL || caf == NULL || daf == NULL || ra == NULL ||
	    initinst == NULL || inst_len == NULL) {
		DWARF_SET_ERROR(error, DWARF_E_ARGUMENT);
		return (DW_DLV_ERROR);
	}

	/* XXX probably wrong, see above. */
	*bytes_in_cie = cie->cie_length;
	*version = cie->cie_version;
	*augmenter = cie->cie_augment;
	*caf = cie->cie_caf;
	*daf = cie->cie_daf;
	*ra = cie->cie_ra;
	*initinst = cie->cie_initinst;
	*inst_len = cie->cie_instlen;

	return (DW_DLV_OK);
}

int
dwarf_get_fde_instr_bytes(Dwarf_Fde fde, Dwarf_Ptr *ret_inst,
    Dwarf_Unsigned *ret_len, Dwarf_Error *error)
{

	if (fde == NULL || ret_inst == NULL || ret_len == NULL) {
		DWARF_SET_ERROR(error, DWARF_E_ARGUMENT);
		return (DW_DLV_ERROR);
	}

	*ret_inst = fde->fde_inst;
	*ret_len = fde->fde_instlen;

	return (DW_DLV_OK);
}
