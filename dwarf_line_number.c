/*-
 * Copyright (c) 2008 Hyogeol Lee <hyogeollee@gmail.com>
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
 * THIS SOFTWARE IS PROVIDED BY THE AUTHORS ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "vector_str.h"
#include "dwarf_line_number.h"

/**
 * @file dwarf_line_number.c
 * @brief Decode line number information from DWARF debug information.
 *
 * DWARF debug information from http://dwarfstd.org/Dwarf3.pdf
 */

/**
 * @brief Common header for CU, line number program for 32-bit DWARF
 */
struct header_32 {
	/**
	 * address size for CU.
	 * min instruction length for line number program
	 */
	unsigned char	addr_size;
	/** version of DWARF */
	uint16_t	ver;
	/** unit length for CU */
	uint32_t	unit_len;
	/** abbrev offset for CU, header length for line number program */
	uint32_t	len;
};

/**
 * @brief Common header for CU, line number program for 64-bit DWARF
 */
struct header_64 {
	/**
	 * address size for CU.
	 * min instruction length for line number program
	 */
	unsigned char	addr_size;
	/** version of DWARF */
	uint16_t	ver;
	/** unit length for CU */
	uint64_t	unit_len;
	/** abbrev offset for CU, header length for line number program */
	uint64_t	len;
};

/**
 * @brief Register of line number information state machine.
 */
struct state_register {
	uint64_t	addr;
	uint64_t	file;
	uint64_t	line;
	uint64_t	col;
};

/* line number program specific header */
struct LNP_header {
	char		line_base;
	unsigned char	min_inst_len, line_range, opcode_base;
	unsigned char	std_opcode_length[255];
};

#define	DW_AT_name			0x03
#define	DW_AT_comp_dir			0x1b

#define	DW_FORM_addr			0x01 /* machine dependent */
#define	DW_FORM_block2			0x03 /* 2 bytes */
#define	DW_FORM_block4			0x04 /* 4 bytes */
#define	DW_FORM_data2			0x05 /* 2 bytes */
#define	DW_FORM_data4			0x06 /* 4 bytes */
#define	DW_FORM_data8			0x07 /* 8 bytes */
#define	DW_FORM_string			0x08
#define	DW_FORM_block			0x09 /* ULEB128 */
#define	DW_FORM_block1			0x0a /* 1 byte */
#define	DW_FORM_data1			0x0b /* 1 byte */
#define	DW_FORM_flag			0x0c /* 1 byte */
#define	DW_FORM_sdata			0x0d /* LEB128 */
#define	DW_FORM_strp			0x0e /* uint32, uint64 */
#define	DW_FORM_udata			0x0f /* ULEB128 */
#define	DW_FORM_ref_addr		0x10 /* uint32, uint64 */
#define	DW_FORM_ref1			0x11 /* 1 byte */
#define	DW_FORM_ref2			0x12 /* 2 bytes */
#define	DW_FORM_ref4			0x13 /* 4 bytes */
#define	DW_FORM_ref8			0x14 /* 8 bytes */
#define	DW_FORM_ref_udata		0x15 /* ULEB128 */
#define	DW_FORM_indirect		0x16 /* LEB128 */

/* Standard opcodes */
#define	DW_LNS_copy			0x01
#define	DW_LNS_advance_pc		0x02
#define	DW_LNS_advance_line		0x03
#define	DW_LNS_set_file			0x04
#define	DW_LNS_set_column		0x05
#define	DW_LNS_negate_stmt		0x06
#define	DW_LNS_set_basic_block		0x07
#define	DW_LNS_const_add_pc		0x08
#define	DW_LNS_fixed_advance_pc		0x09
#define	DW_LNS_set_prologue_end		0x0a
#define	DW_LNS_set_epilogue_begin	0x0b
#define	DW_LNS_set_isa			0x0c

/* Extened opcodes */
#define	DW_LNE_end_sequence		0x01
#define	DW_LNE_set_address		0x02
#define	DW_LNE_define_file		0x03
#define	DW_LNE_lo_user			0x80
#define	DW_LNE_hi_user			0xff

#define VECTOR_LINE_INFO_DEF_CAPACITY	2048

static int	ULEB128_len(unsigned char *);
static int	decode_LEB128(unsigned char *, int64_t *);
static int	decode_ULEB128(unsigned char *, uint64_t *);
static int	vector_line_info_grow(struct vector_line_info *);
static int	vector_line_info_push(struct state_register *,
		    struct vector_str *, struct vector_line_info *);
static int	vector_comp_dir_grow(struct vector_comp_dir *);
static int	vector_comp_dir_push(struct vector_comp_dir *, const char *,
		    const char *);
static void	vector_str_reset(struct vector_str *);
static int	find_current_path(struct vector_comp_dir *, const char *,
		    size_t);
static int	get_LNP_header(unsigned char *, struct LNP_header *);
static int	get_current_path(struct vector_comp_dir *, const char *,
		    size_t *, char **);
static int	get_file_names(char *, struct vector_comp_dir *,
		    struct vector_str *, struct vector_str *);
static int	get_header(unsigned char *, struct header_32 *,
		    struct header_64 *, bool *);
static int	get_include_dir(char *, struct vector_str *);
static int	duplicate_str(const char *, char **);
static int	read_abbrev_table(unsigned char *, unsigned char *, char *, bool,
		    char **, char **);
static void	state_register_init(struct state_register *);
static int	state_op_ext(unsigned char *, struct state_register *,
		    struct vector_comp_dir *, struct vector_str *,
		    struct vector_str *, struct vector_line_info *);
static int	state_op_sp(unsigned char, struct state_register *,
		    struct LNP_header *, struct vector_str *,
		    struct vector_line_info *);
static int	state_op_std(unsigned char, unsigned char *,
		    struct state_register *, struct LNP_header *,
		    struct vector_str *, struct vector_line_info *);

/*
 * Get length of ULEB128.
 *
 * Return 0 at fail or length of ULEB128 in bytes.
 */
static int
ULEB128_len(unsigned char *in)
{
	unsigned int i;

	if (in == NULL)
		return (0);

	for (i = 0; i < 16; ++i) {
		if ((*in & 0x80) == 0x00) {
			++i;

			break;
		}

		++in;
	}

	return (i);
}

/*
 * Get decoded signed LEB128.
 *
 * Decoded result assigned to 'out' when success.
 * Return 0 at fail or length of LEB128 in bytes.
 */
static int
decode_LEB128(unsigned char *in, int64_t *out)
{
	int64_t rst;
	int shift, i;

	if (in == NULL || out == NULL)
		return (0);

	rst = 0;
	shift = 0;
	for (i = 0; i < 16; ++i) {
		if (i > 7)
			return (0);

		rst |= (*in & 0x7f) << shift;
		shift += 7;

		if ((*in & 0x80) == 0x00) {
			++in;
			++i;

			break;
		}

		++in;
	}

	if ((shift < 64) && (*(in - 1) & 0x40) == 0x40)
		rst |= - (1 << shift);

	*out = rst;

	return (i);
}

/*
 * Get decoded unsigned LEB128.
 *
 * Decoded result assigned to 'out' when success.
 * Return 0 at fail or length of ULEB128 in bytes.
 */
static int
decode_ULEB128(unsigned char *in, uint64_t *out)
{
	uint64_t rst;
	int i, shift;

	if (in == NULL || out == NULL)
		return (0);

	rst = 0;
	shift = 0;
	for (i = 0; i < 16; ++i) {
		if (i > 7)
			return (0);

		rst |= (*in & 0x7f) << shift;
		if ((*in & 0x80) == 0x00) {
			++i;

			break;
		}

		shift += 7;
		++in;
	}

	*out = rst;

	return (i);
}

void
vector_line_info_dest(struct vector_line_info *vec)
{

	if (vec == NULL)
		return;

	for (size_t i = 0; i < vec->size; ++i)
		free(vec->info[i].file);

	free(vec->info);
}

int
vector_line_info_init(struct vector_line_info *vec)
{

	if (vec == NULL)
		return (0);

	vec->size = 0;
	vec->capacity = VECTOR_LINE_INFO_DEF_CAPACITY;

	if ((vec->info = malloc(sizeof(struct line_info) * vec->capacity))
	    == NULL)
		return (0);

	return (1);
}

static int
vector_line_info_grow(struct vector_line_info *v)
{
	size_t cap;
	struct line_info *info;

	if (v == NULL)
		return (0);

	cap = v->capacity * BUFFER_GROWFACTOR;

	if ((info = malloc(sizeof(struct line_info) * cap)) == NULL)
		return (0);

	for (size_t i = 0; i < v->size; ++i)
		info[i] = v->info[i];

	free(v->info);

	v->capacity = cap;
	v->info = info;

	return (1);
}

/*
 * Push back data to 'vec'.
 *
 * Return 0 at fail or 1.
 */
static int
vector_line_info_push(struct state_register *regi, struct vector_str *v_file,
    struct vector_line_info *v)
{
	const char *filename;
	size_t len;

	if (regi == NULL || v_file == NULL || v == NULL)
		return (0);

	if (regi->file - 1 > v_file->size)
		return (0);
	
	if (v->size == v->capacity && vector_line_info_grow(v) == 0)
		return (0);

	filename = v_file->container[regi->file - 1];
	len = strlen(filename);

	if ((v->info[v->size].file =
		malloc(sizeof(char) * (len + 1))) == NULL)
		return (0);

	snprintf(v->info[v->size].file, len + 1, "%s", filename);

	v->info[v->size].addr = regi->addr;
	v->info[v->size].line = regi->line;

	++v->size;

	return (1);
}

int
vector_comp_dir_init(struct vector_comp_dir *v)
{

	if (v == NULL)
		return (0);

	v->size = 0;
	v->capacity = VECTOR_DEF_CAPACITY;

	if ((v->info = malloc(sizeof(struct comp_dir) * v->capacity))
	    == NULL)
		return (0);

	return (1);
}

void
vector_comp_dir_dest(struct vector_comp_dir *v)
{

	if (v == NULL)
		return;

	for (size_t i = 0; i < v->size; ++i) {
		free(v->info[i].dir);
		free(v->info[i].src);
	}

	free(v->info);
}

static int
vector_comp_dir_grow(struct vector_comp_dir *v)
{
	size_t cap;
	struct comp_dir *comp_dir;

	if (v == NULL)
		return (0);

	cap = v->capacity * BUFFER_GROWFACTOR;

	if ((comp_dir = malloc(sizeof(struct comp_dir) * cap)) == NULL)
		return (0);

	for (size_t i = 0; i < v->size; ++i)
		comp_dir[i] = v->info[i];

	free(v->info);

	v->capacity = cap;
	v->info = comp_dir;

	return (0);
}

static int
vector_comp_dir_push(struct vector_comp_dir *v, const char *s, const char *d)
{
	size_t s_len, d_len;

	if (v == NULL || s == NULL || d == NULL)
		return (0);

	if (v->size == v->capacity && vector_comp_dir_grow(v) == 0)
		return (0);

	s_len = strlen(s);
	if ((v->info[v->size].src = malloc(sizeof(char) * (s_len + 1))) == NULL)
		return (0);

	d_len = strlen(d);
	if ((v->info[v->size].dir =
		malloc(sizeof(char) * (d_len + 1))) == NULL) {
		free(v->info[v->size].src);

		return (0);
	}

	snprintf(v->info[v->size].src, s_len + 1, "%s", s);
	snprintf(v->info[v->size].dir, d_len + 1, "%s", d);

	++v->size;

	return (1);
}

static void
vector_str_reset(struct vector_str *v)
{

	if (v == NULL)
		return;

	vector_str_dest(v);
	v->container = NULL;
	v->capacity = 0;
	v->size = 0;
}

/*
 * Find current path index from 'v'.
 *
 * Return -1 at failed, index at success.
 */ 
static int
find_current_path(struct vector_comp_dir *v, const char *cur, size_t len)
{

	if (v == NULL || cur == NULL || len == 0)
		return (-1);

	for (size_t i = 0; i < v->size; ++i)
		if (strncmp(v->info[i].src, cur, len) == 0)
			return (i);

	return (-1);
}

static int
get_LNP_header(unsigned char *p, struct LNP_header *h)
{
	int rtn = 0;

	if (p == NULL || h == NULL)
		return (0);

	/* def_is_stmt */
	++p;
	++rtn;

	memcpy(&h->line_base, p, 1);
	++p;
	++rtn;

	memcpy(&h->line_range, p, 1);
	++p;
	++rtn;

	memcpy(&h->opcode_base, p, 1);
	++p;
	++rtn;

	memcpy(h->std_opcode_length, p, h->opcode_base - 1);
	rtn += h->opcode_base - 1;

	return (rtn);
}

/*
 * Get current path from 'v'.
 *
 * Find correspoding dir in 'v' and assign new allocated dir/cur string
 * to 'out'.
 *
 * Return 0 at failed or 1 at success.
 * Return 'out' length in 'len' variable.
 */
static int
get_current_path(struct vector_comp_dir *v, const char *cur, size_t *len,
    char **out)
{

	if (len == NULL || out == NULL)
		return (0);

	if (v != NULL && v->size > 0) {
		const int idx = find_current_path(v, cur, *len);

		if (idx >= 0) {
			*len = *len + strlen(v->info[idx].dir) + 1;
				
			if ((*out = malloc(sizeof(char) * (*len + 1))) == NULL)
				return (0);
					
			snprintf(*out, *len + 1, "%s/%s", v->info[idx].dir,
			    cur);

			return (1);
		}
	}

	if ((*out = malloc(sizeof(char) * (*len + 1))) == NULL)
		return (0);
			
	snprintf(*out, *len + 1, "%s", cur);

	return (1);
}

static int
get_file_names(char *p, struct vector_comp_dir *c_dir, struct vector_str *dir,
    struct vector_str *f)
{
	char *cur_file_name, *full_file_name;
	size_t len;
	size_t rtn = 0;
	int i;
	uint64_t dir_idx;

	if (p == NULL || dir == NULL || f == NULL)
		return (0);

	for (;;) {
		if (*p == 0) {
			++rtn;

			break;
		}

		/* file name */
		cur_file_name = p;
		len = strlen(p);
		p += len + 1;
		rtn += len + 1;

		/* dir index unsigned LEB128 */
		if ((i = decode_ULEB128((unsigned char *)p, &dir_idx)) == 0)
			return (0);

		p += i;
		rtn += i;

		if (dir_idx > dir->size)
			return (0);

		/* current dir */
		if (dir_idx == 0) {
			if (get_current_path(c_dir, cur_file_name, &len,
				&full_file_name) == 0)
				return (0);
		} else {
			len += strlen(dir->container[dir_idx - 1]) + 1;
			if ((full_file_name =
				malloc(sizeof(char) * (len + 1))) == NULL)
				return (0);

			snprintf(full_file_name, len + 1, "%s/%s",
			    dir->container[dir_idx - 1], cur_file_name);
		}

		if (vector_str_push(f, full_file_name, len) == 0) {
			free(full_file_name);

			return (0);
		}

		free(full_file_name);

		/* mod time ULEB128 */
		if ((i = ULEB128_len((unsigned char *)p)) == 0)
			return (0);

		p += i;
		rtn += i;

		/* file length ULEB128 */
		if ((i = ULEB128_len((unsigned char *)p)) == 0)
			return (0);

		p += i;
		rtn += i;
	}

	return (rtn);
}

/* Return 0 at fail or 1 at success */
static int
get_header(unsigned char *p, struct header_32 *h32, struct header_64 *h64,
    bool *is_64)
{
	uint32_t tmp;

	if (p == NULL || h32 == NULL || h64 == NULL || is_64 == NULL)
		return (0);

	memcpy(&tmp, p, 4);
	p += 4;

	if (tmp == 0xffffffff) {
		memcpy(&h64->unit_len, p, 8);
		p += 8;

		memcpy(&h64->ver, p, 2);
		p += 2;

		memcpy(&h64->len, p, 8);
		p += 8;

		memcpy(&h64->addr_size, p, 1);

		*is_64 = true;
	} else if (tmp >= 0xffffff00)
		return (0);
	else {
		h32->unit_len = tmp;

		memcpy(&h32->ver, p, 2);
		p += 2;

		memcpy(&h32->len, p, 4);
		p += 4;

		memcpy(&h32->addr_size, p, 1);

		*is_64 = false;
	}

	return (1);
}

static int
get_include_dir(char *p, struct vector_str *v)
{
	size_t rtn = 0;

	if (p == NULL || v == NULL)
		return (0);

	for (;;) {
		const size_t len = strlen(p);
		if (vector_str_push(v, p, len) == 0)
			return (0);

		p += len + 1;
		rtn += len + 1;

		if (*p == 0) {
			++rtn;

			break;
		}
	}

	return (rtn);
}

/* Read first abbrev table and find src, dir */
static int
read_abbrev_table(unsigned char *i_ptr, unsigned char *a_ptr, char *str,
    bool is_64, char **src, char **dir)
{
	int i;
	size_t len;
	uint32_t str_offset_32;
	int64_t stmp_64;
	uint64_t attr, form, str_offset_64, tmp_64;

	if (i_ptr == NULL || a_ptr == NULL || str == NULL || src == NULL ||
	    dir == NULL)
		return (0);

	for (;;) {
		/* attr */
		if ((i = decode_ULEB128(a_ptr, &attr)) == 0)
			return (0);

		a_ptr += i;

		/* form */
		if ((i = decode_ULEB128(a_ptr, &form)) == 0)
			return (0);

		a_ptr += i;

		/* end with 0, 0 */
		if (attr == 0 && form == 0)
			break;

		switch(form) {
		case DW_FORM_addr:
			i_ptr += is_64 == false ? 4 : 8;

			break;
		case DW_FORM_block2:
			i_ptr += 2;

			break;
		case DW_FORM_block4:
			i_ptr += 4;

			break;
		case DW_FORM_data2:
			i_ptr += 2;

			break;
		case DW_FORM_data8:
			i_ptr += 8;

			break;
		case DW_FORM_string:
			if (attr == DW_AT_name) {
				if ((len = duplicate_str((char *)i_ptr, src))
				    == 0)
					return (0);

				i_ptr += len + 1;
			} else if (attr == DW_AT_comp_dir) {
				if ((len = duplicate_str((char *)i_ptr, dir))
				    == 0)
					return (0);

				i_ptr += len + 1;
			} else {
				while (*i_ptr != '\0')
					++i_ptr;

				++i_ptr;
			}

			break;
		case DW_FORM_block:
			if ((i = decode_ULEB128(i_ptr, &tmp_64)) == 0)
				return (0);

			i_ptr += i;

			break;
		case DW_FORM_block1:
			/* FALLTHROUGH */
		case DW_FORM_data1:
			/* FALLTHROUGH */
		case DW_FORM_flag:
			++i_ptr;

			break;
		case DW_FORM_sdata:
			if ((i = decode_LEB128(i_ptr, &stmp_64)) == 0)
				return (0);

			i_ptr += i;

			break;
		case DW_FORM_strp:
			if (str == NULL)
				return (0);

			if (attr == DW_AT_name) {
				if (is_64 == false) {
					memcpy(&str_offset_32, i_ptr, 4);

					i_ptr += 4;

					if (duplicate_str((char *)str +
						str_offset_32, src) == 0)
						return (0);
				} else {
					memcpy(&str_offset_64, i_ptr, 8);

					i_ptr += 8;

					if (duplicate_str((char *)str +
						str_offset_64, src) == 0)
						return (0);
				}
			} else if (attr == DW_AT_comp_dir) {
				if (is_64 == false) {
					memcpy(&str_offset_32, i_ptr, 4);

					i_ptr += 4;

					if (duplicate_str((char *)str +
						str_offset_32, dir) == 0)
						return (0);
				} else {
					memcpy(&str_offset_64, i_ptr, 8);

					i_ptr += 8;

					if (duplicate_str((char *)str +
						str_offset_64, dir) == 0)
						return (0);
				}
			} else
				i_ptr += is_64 == false ? 4 : 8;

			break;
		case DW_FORM_udata:
			if ((i = decode_ULEB128(i_ptr, &tmp_64)) == 0)
				return (0);

			i_ptr += i;

			break;
		case DW_FORM_ref_addr:
			i_ptr += is_64 == false ? 4 : 8;

			break;
		case DW_FORM_ref1:
			++i_ptr;

			break;
		case DW_FORM_ref2:
			i_ptr += 2;

			break;
		case DW_FORM_ref4:
			i_ptr += 4;

			break;
		case DW_FORM_ref8:
			i_ptr += 8;

			break;
		case DW_FORM_ref_udata:
			if ((i = decode_ULEB128(i_ptr, &tmp_64)) == 0)
				return (0);

			i_ptr += i;

			break;
		case DW_FORM_indirect:
			if ((i = decode_LEB128(i_ptr, &stmp_64)) == 0)
				return (0);

			i_ptr += i;
		};
	}

	return (1);
}

/*
 * Duplicate string orig to dest.
 *
 * Return 0 at fail or length of string.
 */
static int
duplicate_str(const char *orig, char **dest)
{
	size_t len;

	if (orig == NULL || dest == NULL)
		return (0);

	len = strlen(orig);

	if (*dest != NULL)
		free(*dest);

	if ((*dest = malloc(sizeof(char) * (len + 1))) == NULL)
		return (0);

	snprintf(*dest, len + 1, "%s", orig);

	return (len);
}

static void
state_register_init(struct state_register *r)
{

	if (r == NULL)
		return;

	r->addr = 0;
	r->file = 1;
	r->line = 1;
	r->col = 0;
}

/* Return 0 at failed, -1 at end seq, advanced ptr at success */
static int
state_op_ext(unsigned char *p, struct state_register *regi,
    struct vector_comp_dir *comp_dir, struct vector_str *dir,
    struct vector_str *file, struct vector_line_info *out)
{
	unsigned char opcode;
	int i, rtn = 0;
	uint64_t op_len;

	if (p == NULL || regi == NULL || comp_dir == NULL || dir == NULL ||
	    file == NULL || out == NULL)
		return (0);

	if ((i = decode_ULEB128(p, &op_len)) == 0)
		return (0);

	p += i;
	rtn += i;

	memcpy(&opcode, p, 1);
	++p;
	++rtn;

	if (opcode == DW_LNE_end_sequence) {
		if (vector_line_info_push(regi, file, out) == 0)
			return (0);

		return (-1);
	} else if (opcode == DW_LNE_set_address)
		memcpy(&regi->addr, p, op_len - 1);
	else if (opcode == DW_LNE_define_file) {
		/* file name */
		if ((i = get_file_names((char *)p, comp_dir, dir, file)) == 0)
			return (0);

		rtn += i;
	}

	return (rtn + op_len - 1);
}

static int
state_op_sp(unsigned char op, struct state_register *regi, struct LNP_header *h,
    struct vector_str *file, struct vector_line_info *out)
{
	unsigned char adj_opcode;

	if (regi == NULL || h == NULL || file == NULL || out == NULL)
		return (0);

	adj_opcode = op - h->opcode_base;
	regi->addr += (adj_opcode / h->line_range) * h->min_inst_len;
	regi->line += h->line_base + (adj_opcode % h->line_range);

	if (vector_line_info_push(regi, file, out) == 0)
		return (0);

	return (1);
}

/* Return -1 at failed */
static int
state_op_std(unsigned char op, unsigned char *p, struct state_register *regi,
    struct LNP_header *h, struct vector_str *file, struct vector_line_info *out)
{
	unsigned char adj;
	uint16_t oper_16;
	int i;
	int64_t s_oper;
	uint64_t oper;

	if (p == NULL || regi == NULL || h == NULL || file == NULL ||
	    out == NULL)
		return (-1);

	switch (op) {
	case DW_LNS_copy:
		if (vector_line_info_push(regi, file, out) == 0)
			return (-1);

		return (0);
	case DW_LNS_advance_pc:
		if ((i = decode_ULEB128(p, &oper)) == 0)
			return (-1);

		regi->addr += oper * h->min_inst_len;

		return (i);
	case DW_LNS_advance_line:
		if ((i = decode_LEB128(p, &s_oper)) == 0)
			return (-1);

		regi->line += s_oper;

		return (i);
	case DW_LNS_set_file:
		if ((i = decode_ULEB128(p, &oper)) == 0)
			return (-1);

		regi->file = oper;

		return (i);
	case DW_LNS_set_column:
		if ((i = decode_ULEB128(p, &oper)) == 0)
			return (0);

		regi->col = oper;

		return (i);
	case DW_LNS_const_add_pc:
		adj = 255 - h->opcode_base;

		regi->addr += (adj / h->line_range) * h->min_inst_len;

		return (0);
	case DW_LNS_fixed_advance_pc:
		memcpy(&oper_16, p, 2);

		regi->addr += oper_16;

		return (2);
	case DW_LNS_set_isa:
		if ((i = ULEB128_len(p)) == 0)
			return (-1);

		return (i);
	};

	return (0);
}

int
get_dwarf_line_info(void *buf, uint64_t size, struct vector_comp_dir *comp_dir,
    struct vector_line_info *out)
{
	unsigned char *ptr, *this_cu;
	unsigned char opcode;
	int i, rtn;
	bool is_64;
	struct vector_str file_names, dir_names;
	struct header_32 h32;
	struct header_64 h64;
	struct LNP_header lnp_header;
	struct state_register regi;

	/* comp_dir not always exist */
	if (buf == NULL || size == 0 || out == NULL)
		return (0);

	ptr = (unsigned char *)buf;
	this_cu = (unsigned char *)buf;
	rtn = 1;

	file_names.container = NULL;
	dir_names.container = NULL;

	lnp_header.min_inst_len = 1;
	memset(lnp_header.std_opcode_length, 0, 255);
start:
	/* min is 11 for 32DWARF */
	if ((unsigned char *)buf - ptr + size < 11)
		return (0);

	if (get_header(ptr, &h32, &h64, &is_64) == 0)
		return (0);

	if (is_64 == false) {
		if (h32.ver != 2 && h32.ver != 3)
			return (0);

		lnp_header.min_inst_len = h32.addr_size;

		ptr += 11;
	} else {
		if (h64.ver != 2 && h64.ver != 3)
			return (0);

		lnp_header.min_inst_len = h64.addr_size;

		ptr += 23;
	}

	if ((i = get_LNP_header(ptr, &lnp_header)) == 0)
		return (0);
	
	ptr += i;

	/* include_directory */
	if (vector_str_init(&dir_names) == 0)
		return (0);

	if ((i = get_include_dir((char *)ptr, &dir_names)) == 0) {
		rtn = 0;

		goto clean;
	}

	ptr += i;

	/* file_names */
	if (vector_str_init(&file_names) == 0) {
		rtn = 0;

		goto clean;
	}

	if ((i = get_file_names((char *)ptr, comp_dir, &dir_names,
		    &file_names)) == 0) {
		rtn = 0;

		goto clean;
	}

	ptr += i;

	state_register_init(&regi);

	for (;;) {
		memcpy(&opcode, ptr, 1);
		ptr += 1;

		if (opcode == 0) {
			i = state_op_ext(ptr, &regi, comp_dir, &dir_names,
			    &file_names, out);
			if (i == -1)
				break;
			else if (i == 0) {
				rtn = 0;

				goto clean;
			} else
				ptr += i;
		} else if (opcode <= lnp_header.opcode_base) {
			i = state_op_std(opcode, ptr, &regi, &lnp_header,
			    &file_names, out);
			if (i < 0) {
				rtn = 0;

				goto clean;
			}

			ptr += i;
		} else {
			if (state_op_sp(opcode, &regi, &lnp_header, &file_names,
				out) == 0) {
				rtn = 0;

				goto clean;
			}
		}
	}

	vector_str_reset(&file_names);
	vector_str_reset(&dir_names);

	/* skip to match unit length */
	this_cu = ptr = this_cu +
	    (is_64 == false ? h32.unit_len + 4 : h64.unit_len + 12);

	if (ptr - (unsigned char *)buf < size)
		goto start;
clean:
	if (dir_names.container != NULL)
		vector_str_dest(&dir_names);

	if (file_names.container != NULL)
		vector_str_dest(&file_names);

	return (rtn);
}

int
get_dwarf_info(void *info, size_t info_len, void *abbrev, size_t abbrev_len,
    void *str, size_t str_len, struct vector_comp_dir *v)
{
	char *src, *dir;
	unsigned char *i_ptr, *a_ptr, *this_cu;
	int rtn, i;
	bool is_64;
	uint64_t tmp_64, i_idx, a_idx;
	struct header_32 h32;
	struct header_64 h64;

	/* .debug_str not always exist */
	if (info == NULL || info_len == 0 || abbrev == NULL ||
	    abbrev_len == 0 || v == NULL)
		return (0);

	src = dir = NULL;

	i_ptr = info;
	a_ptr = NULL;
	this_cu = info;

	rtn = 1;
start:
	if ((unsigned char *)info - i_ptr + info_len < 11)
		return (0);

	if (get_header(i_ptr, &h32, &h64, &is_64) == 0)
		return (0);

	if (is_64 == false) {
		if (h32.ver != 2 && h32.ver != 3)
			return (0);

		i_ptr += 11;

		a_ptr = (unsigned char *)abbrev + h32.len;
	} else {
		if (h64.ver != 2 && h64.ver != 3)
			return (0);

		i_ptr += 23;

		a_ptr = (unsigned char *)abbrev + h64.len;
	}

	/* index */
	if ((i = decode_ULEB128(i_ptr, &i_idx)) == 0) {
		rtn = 0;

		goto clean;
	}
	i_ptr += i;

	if ((i = decode_ULEB128(a_ptr, &a_idx)) == 0) {
		rtn = 0;

		goto clean;
	}
	a_ptr += i;

	assert(i_idx == a_idx && "index mismatch");

	/* TAG */
	if ((i = decode_ULEB128(a_ptr, &tmp_64)) == 0) {
		rtn = 0;

		goto clean;
	}
	a_ptr += i;

	/* child */
	++a_ptr;

	if (read_abbrev_table(i_ptr, a_ptr, str, is_64, &src, &dir) == 0) {
		rtn = 0;

		goto clean;
	}

	if (src != NULL && dir != NULL)
		if (vector_comp_dir_push(v, src, dir) == 0)
			goto clean;

	/* skip to next cu, because need only comp_dir */
	this_cu = i_ptr = this_cu +
	    (is_64 == false ? h32.unit_len + 4 : h64.unit_len + 12);

	if (i_ptr - (unsigned char *)info < info_len) {
		free(dir);
		free(src);
		src = dir = NULL;

		goto start;
	}
clean:
	free(dir);
	free(src);

	return (rtn);
}
