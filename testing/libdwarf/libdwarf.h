/*-
 * Copyright (c) 2009 Kai Wang
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
 *
 * $FreeBSD$
 */

#ifndef	_LIBDWARF_H_
#define	_LIBDWARF_H_

#include <libelf.h>

typedef int		Dwarf_Bool;
typedef off_t		Dwarf_Off;
typedef uint64_t	Dwarf_Unsigned;
typedef uint16_t	Dwarf_Half;
typedef uint8_t		Dwarf_Small;
typedef int64_t		Dwarf_Signed;
typedef uint64_t	Dwarf_Addr;
typedef void		*Dwarf_Ptr;

/* Forward definitions. */
typedef struct _Dwarf_Abbrev	*Dwarf_Abbrev;
typedef struct _Dwarf_Arange	*Dwarf_Arange;
typedef struct _Dwarf_Attribute	*Dwarf_Attribute;
typedef struct _Dwarf_AttrDef	*Dwarf_AttrDef;
typedef struct _Dwarf_CU	*Dwarf_CU;
typedef struct _Dwarf_Cie	*Dwarf_Cie;
typedef struct _Dwarf_Debug	*Dwarf_Debug;
typedef struct _Dwarf_Die	*Dwarf_Die;
typedef struct _Dwarf_Fde	*Dwarf_Fde;
typedef struct _Dwarf_Func	*Dwarf_Func;
typedef struct _Dwarf_Line	*Dwarf_Line;
typedef struct _Dwarf_LineFile	*Dwarf_LineFile;
typedef struct _Dwarf_LineInfo	*Dwarf_LineInfo;
typedef struct _Dwarf_Loclist	*Dwarf_Loclist;
typedef struct _Dwarf_NamePair	*Dwarf_NamePair;
typedef struct _Dwarf_NamePair	*Dwarf_Global;
typedef struct _Dwarf_NamePair	*Dwarf_Type;
typedef struct _Dwarf_NameTbl	*Dwarf_NameTbl;
typedef struct _Dwarf_NameSec	*Dwarf_NameSec;
typedef struct _Dwarf_Var	*Dwarf_Var;
typedef struct _Dwarf_Weak	*Dwarf_Weak;

typedef struct {
        Dwarf_Small	lr_atom;
        Dwarf_Unsigned	lr_number;
	Dwarf_Unsigned	lr_number2;
	Dwarf_Unsigned	lr_offset;
} Dwarf_Loc;

typedef struct {
	Dwarf_Addr      ld_lopc;
	Dwarf_Addr      ld_hipc;
	Dwarf_Half      ld_cents;
	Dwarf_Loc	*ld_s;
} Dwarf_Locdesc;

typedef struct {
	Dwarf_Unsigned	bl_len;
	Dwarf_Ptr	bl_data;
} Dwarf_Block;

/*
 * Frame operation only for DWARF 2.
 */
typedef struct {
	Dwarf_Small	fp_base_op;
	Dwarf_Small	fp_extended_op;
	Dwarf_Half	fp_register;
	Dwarf_Signed	fp_offset;
	Dwarf_Off	fp_instr_offset;
} Dwarf_Frame_Op;

#ifndef	DW_REG_TABLE_SIZE
#define	DW_REG_TABLE_SIZE	66
#endif

typedef struct {
	struct {
		Dwarf_Small	dw_offset_relevant;
		Dwarf_Half	dw_regnum;
		Dwarf_Addr	dw_offset;
	} rules[DW_REG_TABLE_SIZE];
} Dwarf_Regtable;

/*
 * Frame operation for DWARF 3 and DWARF 2.
 */
typedef struct {
	Dwarf_Small	fp_base_op;
	Dwarf_Small	fp_extended_op;
	Dwarf_Half	fp_register;
	Dwarf_Unsigned	fp_offset_or_block_len;
	Dwarf_Small	*fp_expr_block;
	Dwarf_Off	fp_instr_offset;
} Dwarf_Frame_Op3;

typedef struct {
	Dwarf_Small	dw_offset_relevant;
	Dwarf_Small	dw_value_type;
	Dwarf_Half	dw_regnum;
	Dwarf_Unsigned	dw_offset_or_block_len;
	Dwarf_Ptr	dw_block_ptr;
} Dwarf_Regtable_Entry3;

typedef struct {
	Dwarf_Regtable_Entry3	rt3_cfa_rule;
	Dwarf_Half		rt3_reg_table_size;
	Dwarf_Regtable_Entry3	*rt3_rules;
} Dwarf_Regtable3;

typedef struct {
	Dwarf_Off	dmd_offset;
	Dwarf_Small	dmd_type;
	Dwarf_Signed	dmd_lineno;
	Dwarf_Signed	dmd_fileindex;
	char		*dmd_macro;
} Dwarf_Macro_Details;

/*
 * Error numbers which are specific to this implementation.
 */
enum {
	DWARF_E_NONE,			/* No error. */
	DWARF_E_ERROR,			/* An error! */
	DWARF_E_NO_ENTRY,		/* No entry. */
	DWARF_E_ARGUMENT,		/* Invalid argument. */
	DWARF_E_DEBUG_INFO,		/* Debug info NULL. */
	DWARF_E_MEMORY,			/* Insufficient memory. */
	DWARF_E_ELF,			/* ELF error. */
	DWARF_E_INVALID_CU,		/* Invalid compilation unit data. */
	DWARF_E_CU_VERSION,		/* Wrong CU version. */
	DWARF_E_MISSING_ABBREV,		/* Abbrev not found. */
	DWARF_E_NOT_IMPLEMENTED,	/* Not implemented. */
	DWARF_E_CU_CURRENT,		/* No current compilation unit. */
	DWARF_E_BAD_FORM,		/* Wrong form type for attribute value. */
	DWARF_E_INVALID_EXPR,		/* Invalid DWARF expression. */
	DWARF_E_INVALID_LOCLIST,	/* Invalid loclist data. */
	DWARF_E_INVALID_ATTR,		/* Invalid attribute. */
	DWARF_E_INVALID_LINE,		/* Invalid line info data. */
	DWARF_E_NUM			/* Max error number. */
};

typedef struct _Dwarf_Error {
	int		err_error;	/* DWARF error. */
	int		elf_error;	/* ELF error. */
	const char	*err_func;	/* Function name where error occurred. */
	int		err_line;	/* Line number where error occurred. */
	char		err_msg[1024];	/* Formatted error message. */
} Dwarf_Error;

/*
 * Return values which have to be compatible with other
 * implementations of libdwarf.
 */
#define DW_DLV_NO_ENTRY		-1
#define DW_DLV_OK		0
#define	DW_DLV_ERROR		1
#define DW_DLE_DEBUG_INFO_NULL	DWARF_E_DEBUG_INFO

#define DW_DLC_READ        	0	/* read only access */

/* Function prototype definitions. */
__BEGIN_DECLS
const char	*dwarf_errmsg(Dwarf_Error *);
const char	*get_sht_desc(uint32_t);
const char	*get_attr_desc(uint32_t);
const char	*get_form_desc(uint32_t);
const char	*get_tag_desc(uint32_t);
int		dwarf_arrayorder(Dwarf_Die, Dwarf_Unsigned *, Dwarf_Error *);
int		dwarf_attr(Dwarf_Die, Dwarf_Half, Dwarf_Attribute *,
		    Dwarf_Error *);
int		dwarf_attrlist(Dwarf_Die, Dwarf_Attribute **,
		    Dwarf_Signed *, Dwarf_Error *);
int		dwarf_attrval_flag(Dwarf_Die, uint64_t, Dwarf_Bool *,
		    Dwarf_Error *);
int		dwarf_attrval_signed(Dwarf_Die, uint64_t, Dwarf_Signed *,
		    Dwarf_Error *);
int		dwarf_attrval_string(Dwarf_Die, uint64_t, const char **,
		    Dwarf_Error *);
int		dwarf_attrval_unsigned(Dwarf_Die, uint64_t, Dwarf_Unsigned *,
		    Dwarf_Error *);
int		dwarf_bitoffset(Dwarf_Die, Dwarf_Unsigned *, Dwarf_Error *);
int		dwarf_bitsize(Dwarf_Die, Dwarf_Unsigned *, Dwarf_Error *);
int		dwarf_bytesize(Dwarf_Die, Dwarf_Unsigned *, Dwarf_Error *);
int		dwarf_child(Dwarf_Die, Dwarf_Die *, Dwarf_Error *);
int		dwarf_diename(Dwarf_Die, const char **, Dwarf_Error *);
int		dwarf_dieoffset(Dwarf_Die, Dwarf_Off *, Dwarf_Error *);
int		dwarf_die_abbrev_code(Dwarf_Die);
int		dwarf_die_CU_offset(Dwarf_Die, Dwarf_Off *, Dwarf_Error *);
int		dwarf_die_CU_offset_range(Dwarf_Die, Dwarf_Off *, Dwarf_Off *,
		    Dwarf_Error *);
int		dwarf_elf_init(Elf *, int, Dwarf_Debug *, Dwarf_Error *);
int		dwarf_errno(Dwarf_Error *);
int		dwarf_finish(Dwarf_Debug *, Dwarf_Error *);
int		dwarf_formref(Dwarf_Attribute, Dwarf_Off *, Dwarf_Error *);
int		dwarf_global_formref(Dwarf_Attribute, Dwarf_Off *,
		    Dwarf_Error *);
int		dwarf_formaddr(Dwarf_Attribute, Dwarf_Addr *, Dwarf_Error *);
int		dwarf_formblock(Dwarf_Attribute, Dwarf_Block *, Dwarf_Error *);
int		dwarf_formflag(Dwarf_Attribute, Dwarf_Bool *, Dwarf_Error *);
int		dwarf_formstring(Dwarf_Attribute, const char **, Dwarf_Error *);
int		dwarf_formsdata(Dwarf_Attribute, Dwarf_Unsigned *,
		    Dwarf_Error *);
int		dwarf_formudata(Dwarf_Attribute, Dwarf_Unsigned *,
		    Dwarf_Error *);
int		dwarf_get_abbrev(Dwarf_Debug, Dwarf_Unsigned, Dwarf_Abbrev *,
		    Dwarf_Unsigned *, Dwarf_Unsigned *, Dwarf_Error *);
int		dwarf_get_abbrev_children_flag(Dwarf_Abbrev, Dwarf_Signed *,
		    Dwarf_Error *);
int		dwarf_get_abbrev_code(Dwarf_Abbrev, Dwarf_Unsigned *,
		    Dwarf_Error *);
int		dwarf_get_abbrev_entry(Dwarf_Abbrev, Dwarf_Signed, Dwarf_Half *,
		    Dwarf_Signed *, Dwarf_Off *, Dwarf_Error *);
int		dwarf_get_abbrev_tag(Dwarf_Abbrev, Dwarf_Half *, Dwarf_Error *);
int		dwarf_get_cu_die_offset_given_cu_header_offset(Dwarf_Debug,
		    Dwarf_Off, Dwarf_Off *, Dwarf_Error *);
int		dwarf_get_globals(Dwarf_Debug, Dwarf_Global **, Dwarf_Signed *,
		    Dwarf_Error *);
int		dwarf_global_cu_offset(Dwarf_Global, Dwarf_Off *, Dwarf_Error *);
int		dwarf_global_die_offset(Dwarf_Global, Dwarf_Off *,
		    Dwarf_Error *);
int		dwarf_global_name_offsets(Dwarf_Global, const char **,
		    Dwarf_Off *, Dwarf_Off *, Dwarf_Error *);
int		dwarf_globname(Dwarf_Global, const char **, Dwarf_Error *);
int		dwarf_hasattr(Dwarf_Die, Dwarf_Half, Dwarf_Bool *,
		    Dwarf_Error *);
int		dwarf_hasform(Dwarf_Attribute, Dwarf_Half, Dwarf_Bool *,
		    Dwarf_Error *);
int		dwarf_highpc(Dwarf_Die, Dwarf_Addr *, Dwarf_Error *);
int		dwarf_line_srcfileno(Dwarf_Line, Dwarf_Unsigned *,
		    Dwarf_Error *);
int		dwarf_lineaddr(Dwarf_Line, Dwarf_Addr *, Dwarf_Error *);
int		dwarf_linebeginstatement(Dwarf_Line, Dwarf_Bool *,
		    Dwarf_Error *);
int		dwarf_lineblock(Dwarf_Line, Dwarf_Bool *, Dwarf_Error *);
int		dwarf_lineendsequence(Dwarf_Line, Dwarf_Bool *, Dwarf_Error *);
int		dwarf_lineno(Dwarf_Line, Dwarf_Unsigned *, Dwarf_Error *);
int		dwarf_lineoff(Dwarf_Line, Dwarf_Signed *, Dwarf_Error *);
int		dwarf_linesrc(Dwarf_Line, const char **, Dwarf_Error *);
int		dwarf_locdesc(Dwarf_Die, uint64_t, Dwarf_Locdesc **, Dwarf_Signed *,
		    Dwarf_Error *);
int		dwarf_locdesc_free(Dwarf_Locdesc *, Dwarf_Error *);
int		dwarf_loclist(Dwarf_Attribute, Dwarf_Locdesc **, Dwarf_Signed *,
		    Dwarf_Error *);
int		dwarf_loclist_n(Dwarf_Attribute, Dwarf_Locdesc **,
		    Dwarf_Signed *, Dwarf_Error *);
int		dwarf_loclist_from_expr(Dwarf_Debug, Dwarf_Ptr, Dwarf_Unsigned,
		    Dwarf_Locdesc **, Dwarf_Signed *, Dwarf_Error *);
int		dwarf_loclist_from_expr_a(Dwarf_Ptr, Dwarf_Unsigned, Dwarf_Half,
		    Dwarf_Locdesc **, Dwarf_Signed *, Dwarf_Error *);
int		dwarf_loclist_from_expr_free(Dwarf_Locdesc *, Dwarf_Error *);
int		dwarf_lowpc(Dwarf_Die, Dwarf_Addr *, Dwarf_Error *);
int		dwarf_init(int, int, Dwarf_Debug *, Dwarf_Error *);
int		dwarf_next_cu_header(Dwarf_Debug, Dwarf_Unsigned *, Dwarf_Half *,
		    Dwarf_Unsigned *, Dwarf_Half *, Dwarf_Unsigned *, Dwarf_Error *);
int		dwarf_offdie(Dwarf_Debug, Dwarf_Off, Dwarf_Die *,
		    Dwarf_Error *);
int		dwarf_siblingof(Dwarf_Debug, Dwarf_Die, Dwarf_Die *, Dwarf_Error *);
int		dwarf_srcfiles(Dwarf_Die, const char ***, Dwarf_Signed *,
		    Dwarf_Error *);
int		dwarf_srclang(Dwarf_Die, Dwarf_Unsigned *, Dwarf_Error *);
int		dwarf_srclines(Dwarf_Die, Dwarf_Line **, Dwarf_Signed *,
		    Dwarf_Error *);
int		dwarf_tag(Dwarf_Die, Dwarf_Half *, Dwarf_Error *);
int		dwarf_whatattr(Dwarf_Attribute, Dwarf_Half *, Dwarf_Error *);
int		dwarf_whatform(Dwarf_Attribute, Dwarf_Half *, Dwarf_Error *);
int		dwarf_whatform_direct(Dwarf_Attribute, Dwarf_Half *,
		    Dwarf_Error *);
void		dwarf_dealloc(Dwarf_Debug, Dwarf_Ptr, Dwarf_Unsigned);
void		dwarf_dump(Dwarf_Debug);
void		dwarf_dump_abbrev(Dwarf_Debug);
void		dwarf_dump_at(Dwarf_Die, Dwarf_Attribute);
void		dwarf_dump_dbgstr(Dwarf_Debug);
void		dwarf_dump_die(Dwarf_Die);
void		dwarf_dump_die_at_offset(Dwarf_Debug, Dwarf_Off);
void		dwarf_dump_info(Dwarf_Debug);
void		dwarf_dump_shstrtab(Dwarf_Debug);
void		dwarf_dump_strtab(Dwarf_Debug);
void		dwarf_dump_symtab(Dwarf_Debug);
void		dwarf_dump_raw(Dwarf_Debug);
void		dwarf_dump_tree(Dwarf_Debug);
__END_DECLS

#endif /* !_LIBDWARF_H_ */
