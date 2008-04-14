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

#define	DW_AT_name		0x03
#define	DW_AT_comp_dir		0x1b

#define	DW_FORM_addr		0x01 /* machine dependent */
#define	DW_FORM_block2		0x03 /* 2 bytes */
#define	DW_FORM_block4		0x04 /* 4 bytes */
#define	DW_FORM_data2		0x05 /* 2 bytes */
#define	DW_FORM_data4		0x06 /* 4 bytes */
#define	DW_FORM_data8		0x07 /* 8 bytes */
#define	DW_FORM_string		0x08
#define	DW_FORM_block		0x09 /* ULEB128 */
#define	DW_FORM_block1		0x0a /* 1 byte */
#define	DW_FORM_data1		0x0b /* 1 byte */
#define	DW_FORM_flag		0x0c /* 1 byte */
#define	DW_FORM_sdata		0x0d /* LEB128 */
#define	DW_FORM_strp		0x0e /* uint32 at 32DWARF, uint64 at 64DWARF */
#define	DW_FORM_udata		0x0f /* ULEB128 */
#define	DW_FORM_ref_addr	0x10 /* uint32 at 32DWARF, uint64 at 64DWARF */
#define	DW_FORM_ref1		0x11 /* 1 byte */
#define	DW_FORM_ref2		0x12 /* 2 bytes */
#define	DW_FORM_ref4		0x13 /* 4 bytes */
#define	DW_FORM_ref8		0x14 /* 8 bytes */
#define	DW_FORM_ref_udata	0x15 /* ULEB128 */
#define	DW_FORM_indirect	0x16 /* LEB128 */

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

static int		ULEB128_len(unsigned char *);
static int		decode_LEB128(unsigned char *, int64_t *);
static int		decode_ULEB128(unsigned char *, uint64_t *);
static int		vector_line_info_push(struct vector_line_info *, uint64_t, uint64_t, const char *, size_t);
static int		vector_comp_dir_push(struct vector_comp_dir *, const char *, const char *);
static void		vector_str_reset(struct vector_str *);
static int		get_current_path(struct vector_comp_dir *, const char *, size_t *, char **);
static int		get_header(unsigned char *, struct header_32 *, struct header_64 *, int *);
static int		duplicate_str(const char *, char **);

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

        if ((shift < 64) &&
            (*(in - 1) & 0x40) == 0x40) {
                rst |= - (1 << shift);
        }

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
        size_t i;

        if (vec == NULL)
                return;

        for (i = 0; i < vec->size; ++i) {
                free(vec->info[i].file);
        }

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

/*
 * Push back data to 'vec'.
 *
 * Return 0 at fail or 1.
 */
static int
vector_line_info_push(struct vector_line_info *vec, uint64_t addr, uint64_t line, const char *info, size_t info_len)
{
        size_t i, tmp_cap;
        struct line_info *tmp_info;

        if (vec == NULL || info == NULL || info_len == 0)
                return (0);

        if (vec->size == vec->capacity) {
                tmp_cap = vec->capacity * BUFFER_GROWFACTOR;

                if ((tmp_info = malloc(sizeof(struct line_info) * tmp_cap))
                    == NULL)
                        return (0);

                for (i = 0; i < vec->size; ++i)
                        tmp_info[i] = vec->info[i];

                free(vec->info);

                vec->info = tmp_info;
                vec->capacity = tmp_cap;
        }

        if ((vec->info[vec->size].file =
                malloc(sizeof(char) * (info_len + 1))) == NULL)
                return (0);

        snprintf(vec->info[vec->size].file, info_len + 1, "%s", info);

        vec->info[vec->size].addr = addr;
        vec->info[vec->size].line = line;

        ++vec->size;

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
        size_t i;

        if (v == NULL)
                return;

        for (i = 0; i < v->size; ++i) {
                free(v->info[i].dir);
                free(v->info[i].src);
        }

        free(v->info);
}

static int
vector_comp_dir_push(struct vector_comp_dir *v, const char *s, const char *d)
{
        size_t i, tmp_cap, s_len, d_len;
        struct comp_dir *tmp_comp_dir;

        if (v == NULL || s == NULL || d == NULL)
                return (0);

        if (v->size == v->capacity) {
                tmp_cap = v->capacity * BUFFER_GROWFACTOR;

                if ((tmp_comp_dir = malloc(sizeof(struct comp_dir) * tmp_cap))
                    == NULL)
                        return (0);

                for (i = 0; i < v->size; ++i)
                        tmp_comp_dir[i] = v->info[i];

                free(v->info);

                v->info = tmp_comp_dir;
                v->capacity = tmp_cap;
        }

        s_len = strlen(s);
        if ((v->info[v->size].src = malloc(sizeof(char) * (s_len + 1)))
            == NULL)
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
 * Get current path from 'v'.
 *
 * Find correspoding dir in 'v' and assign new allocated dir/cur string
 * to 'out'.
 *
 * Return 0 at failed or 1 at success.
 * Return 'out' length in 'len' variable.
 */
static int
get_current_path(struct vector_comp_dir *v, const char *cur, size_t *len, char **out)
{
        size_t i;

        if (len == NULL || out == NULL)
                return (0);

        if (v != NULL && v->size > 0) {
                for (i = 0; i < v->size; ++i) {
                        if (strncmp(v->info[i].src, cur, *len) == 0) {
                                *len = *len + strlen(v->info[i].dir) + 1;
                                
                                if ((*out = malloc(sizeof(char) * (*len + 1)))
                                    == NULL)
                                        return (0);
                                        
                                snprintf(*out, *len + 1,
                                    "%s/%s", v->info[i].dir, cur);

                                return (1);
                        }
                }
        }

        if ((*out = malloc(sizeof(char) * (*len + 1))) == NULL)
                return (0);
                        
        snprintf(*out, *len + 1, "%s", cur);

        return (1);
}

/* Return 0 at fail or 1 at success */
static int
get_header(unsigned char *p, struct header_32 *h32, struct header_64 *h64, int *is_64)
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

                *is_64 = 1;
        } else if (tmp >= 0xffffff00) {
                return (0);
        } else {
                h32->unit_len = tmp;

                memcpy(&h32->ver, p, 2);
                p += 2;

                memcpy(&h32->len, p, 4);
                p += 4;

                memcpy(&h32->addr_size, p, 1);

                *is_64 = 0;
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

int
get_dwarf_line_info(void *buf, uint64_t size, struct vector_comp_dir *comp_dir, struct vector_line_info *out)
{
        char line_base;
        char *cur_file_name, *full_file_name;
        unsigned char *ptr, *this_cu;
        unsigned char min_inst_length, line_range, opcode_base;
        unsigned char std_opcode_lengths[255] = { 0, };
        unsigned char opcode, adj_opcode;
        unsigned char ex_opcode;
        uint16_t operand_16;
        uint64_t file, line, address_64, column, ex_op_len, operand, dir_index;
        int64_t s_operand;
        int is_64, i, rtn;
        size_t len;
        struct vector_str file_names, dir_names;
        struct header_32 h32;
        struct header_64 h64;

        /* comp_dir not always exist */
        if (buf == NULL || size == 0 || out == NULL)
                return (0);

        ptr = (unsigned char *)buf;
        this_cu = (unsigned char *)buf;
        min_inst_length = 1;
        rtn = 1;

        file_names.container = NULL;
        dir_names.container = NULL;
start:
        /* min is 11 for 32DWARF */
        if ((unsigned char *)buf - ptr + size < 11)
                return (0);

        if (get_header(ptr, &h32, &h64, &is_64) == 0)
                return (0);

        assert(is_64 == 0 || is_64 == 1);
        if (is_64 == 0) {
                if (h32.ver != 2 && h32.ver != 3)
                        return (0);

                min_inst_length = h32.addr_size;

                ptr += 11;
        } else if (is_64 == 1) {
                if (h64.ver != 2 && h64.ver != 3)
                        return (0);

                min_inst_length = h64.addr_size;

                ptr += 23;
        }
        
        /* def_is_stmt */
        ++ptr;

        memcpy(&line_base, ptr, 1);
        ++ptr;

        memcpy(&line_range, ptr, 1);
        ++ptr;

        memcpy(&opcode_base, ptr, 1);
        ++ptr;

        memcpy(&std_opcode_lengths, ptr, opcode_base - 1);
        ptr += opcode_base - 1;

        /* include_directory */
        if (vector_str_init(&dir_names) == 0)
                return (0);

        for (;;) {
                len = strlen((char *)ptr);
                if (vector_str_push(&dir_names, (char *)ptr, len) == 0) {
                        rtn = 0;

                        goto clean;
                }

                ptr += len + 1;

                if (*ptr == 0) {
                        ++ptr;

                        break;
                }
        }

        /* file_names */
        if (vector_str_init(&file_names) == 0) {
                rtn = 0;

                goto clean;
        }

        for (;;) {
                if (*ptr == 0) {
                        ++ptr;

                        break;
                }

                /* file name */
                cur_file_name = (char *)ptr;
                len = strlen((char *)ptr);
                ptr += len + 1;

                /* dir index unsigned LEB128 */
                if ((i = decode_ULEB128(ptr, &dir_index)) == 0) {
                        rtn = 0;

                        goto clean;
                } else
                        ptr += i;

                if (dir_index > dir_names.size) {
                        rtn = 0;

                        goto clean;
                }

                /* current dir */
                if (dir_index == 0) {
                        if (get_current_path(comp_dir, cur_file_name, &len,
                                &full_file_name) == 0) {
                                rtn = 0;

                                goto clean;
                        }
                } else {
                        len += strlen(dir_names.container[dir_index - 1]) + 1;
                        if ((full_file_name =
                                malloc(sizeof(char) * (len + 1))) == NULL) {
                                rtn = 0;

                                goto clean;
                        }

                        snprintf(full_file_name, len + 1, "%s/%s",
                            dir_names.container[dir_index - 1], cur_file_name);
                }

                if (vector_str_push(&file_names, full_file_name, len) == 0) {
                        free(full_file_name);
                        rtn = 0;
                        
                        goto clean;
                }

                free(full_file_name);

                /* mod time ULEB128 */
                if ((i = ULEB128_len(ptr)) == 0) {
                        rtn = 0;

                        goto clean;
                }

                ptr += i;

                /* file length ULEB128 */
                if ((i = ULEB128_len(ptr)) == 0) {
                        rtn = 0;

                        goto clean;
                }

                ptr += i;
        }

        address_64 = 0;
        file = 1;
        line = 1;
        column = 0;

        for (;;) {
                memcpy(&opcode, ptr, 1);
                ptr += 1;

                if (opcode == 0) {
                        /* extened */
                        if ((i = decode_ULEB128(ptr, &ex_op_len)) == 0) {
                                rtn = 0;

                                goto clean;
                        } else
                                ptr += i;

                        memcpy(&ex_opcode, ptr, 1);
                        ++ptr;

                        if (ex_opcode == DW_LNE_end_sequence) {
                                if (file > file_names.size) {
                                        rtn = 0;

                                        goto clean;
                                }

                                cur_file_name = file_names.container[file - 1];

                                if (vector_line_info_push(out, address_64, line,
                                        cur_file_name,
                                        strlen(cur_file_name)) == 0) {
                                        rtn = 0;

                                        goto clean;
                                }

                                break;
                        } else if (ex_opcode == DW_LNE_set_address) {
                                memcpy(&address_64, ptr, ex_op_len - 1);
                        } else if (ex_opcode == DW_LNE_define_file) {
                                /* file name */
                                cur_file_name = (char *)ptr;
                                len = strlen((char *)ptr);
                                ptr += len + 1;

                                /* dir index unsigned LEB128 */
                                if ((i = decode_ULEB128(ptr, &dir_index))
                                    == 0) {
                                        rtn = 0;

                                        goto clean;
                                } else
                                        ptr += i;

                                if (dir_index > dir_names.size) {
                                        rtn = 0;

                                        goto clean;
                                }

                                /* current dir */
                                if (dir_index == 0) {
                                        if (get_current_path(comp_dir,
                                                cur_file_name, &len,
                                                &full_file_name) == 0) {
                                                rtn = 0;

                                                goto clean;
                                        }
                                } else {
                                        len += strlen(dir_names.container[dir_index - 1]) + 1;
                                        if ((full_file_name =
                                                malloc(sizeof(char) * (len + 1))) == NULL) {
                                                rtn = 0;

                                                goto clean;
                                        }

                                        snprintf(full_file_name, len + 1, "%s/%s",
                                            dir_names.container[dir_index - 1], cur_file_name);

                                }

                                if (vector_str_push(&file_names, full_file_name, len) == 0) {
                                        free(full_file_name);
                                        rtn = 0;
                        
                                        goto clean;
                                }

                                free(full_file_name);

                                /* mod time unsigned LEB128(skip) */
                                if ((i = ULEB128_len(ptr)) == 0) {
                                        rtn = 0;

                                        goto clean;
                                }

                                ptr += i;

                                /* file length unsigned LEB128(skip) */
                                if ((i = ULEB128_len(ptr)) == 0) {
                                        rtn = 0;

                                        goto clean;
                                }

                                ptr += i;
                        } else {
                                /* unknown extened */
                        }

                        ptr += ex_op_len - 1;

                } else if (opcode <= opcode_base) {
                        /* standard */
                        if (opcode == DW_LNS_copy) {
                                if (file - 1 > file_names.size)
                                        goto clean;

                                cur_file_name = file_names.container[file - 1];

                                if (vector_line_info_push(out, address_64, line,
                                        cur_file_name,
                                        strlen(cur_file_name)) == 0) {
                                        rtn = 0;

                                        goto clean;
                                }
                        } else if (opcode == DW_LNS_advance_pc) {
                                /* unsigned LEB128 */
                                if ((i = decode_ULEB128(ptr, &operand))
                                    == 0) {
                                        rtn = 0;

                                        goto clean;
                                } else
                                        ptr += i;

                                address_64 += operand * min_inst_length;
                        } else if (opcode == DW_LNS_advance_line) {
                                /* signed LEB128 */
                                if ((i = decode_LEB128(ptr, &s_operand))
                                    == 0) {
                                        rtn = 0;
                                        goto clean;
                                } else
                                        ptr += i;

                                line += s_operand;
                        } else if (opcode == DW_LNS_set_file) {
                                /* unsigned LEB128 */
                                if ((i = decode_ULEB128(ptr, &operand))
                                    == 0) {
                                        rtn = 0;

                                        goto clean;
                                } else
                                        ptr += i;

                                file = operand;
                        } else if (opcode == DW_LNS_set_column) {
                                /* unsigned LEB128 */
                                if ((i = decode_ULEB128(ptr, &operand))
                                    == 0) {
                                        rtn = 0;

                                        goto clean;
                                } else
                                        ptr += i;

                                column = operand;
                        } else if (opcode == DW_LNS_negate_stmt) {
                                /* is_stmt = is_stmt == 1 ? 0 : 1; */
                        } else if (opcode == DW_LNS_set_basic_block) {

                        } else if (opcode == DW_LNS_const_add_pc) {
                                adj_opcode = 255 - opcode_base;

                                address_64 += (adj_opcode / line_range)
                                    * min_inst_length;
                        } else if (opcode == DW_LNS_fixed_advance_pc) {
                                memcpy(&operand_16, ptr, 2);
                                ptr += 2;

                                address_64 += operand_16;
                        } else if (opcode == DW_LNS_set_prologue_end) {

                        } else if (opcode == DW_LNS_set_epilogue_begin) {

                        } else if (opcode == DW_LNS_set_isa) {
                                /* unsigned LEB128(skip) */
                                if ((i = ULEB128_len(ptr)) == 0) {
                                        rtn = 0;

                                        goto clean;
                                }

                                ptr += i;
                        }
                } else {
                        /* special */
                        adj_opcode = opcode - opcode_base;
                        address_64 += (adj_opcode / line_range) * min_inst_length;
                        line += line_base + (adj_opcode % line_range);

                        if (file - 1 > file_names.size) {
                                rtn = 0;

                                goto clean;
                        }

                        cur_file_name = file_names.container[file - 1];

                        if (vector_line_info_push(out, address_64, line,
                                cur_file_name,
                                strlen(cur_file_name)) == 0) {
                                rtn = 0;

                                goto clean;
                        }
                }
        }

        vector_str_reset(&file_names);
        vector_str_reset(&dir_names);

        /* skip to match unit length */
        this_cu = ptr = this_cu +
            (is_64 == 0 ? h32.unit_len + 4 : h64.unit_len + 12);

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
get_dwarf_info(void *info, size_t info_len, void *abbrev, size_t abbrev_len, void *str, size_t str_len, struct vector_comp_dir *v)
{
        char *src, *dir;
        unsigned char *i_ptr, *a_ptr, *this_cu;
        int is_64, rtn, i;
        size_t len;
        uint32_t str_offset_32;
        uint64_t str_offset_64, tmp_64, attr, form, i_idx, a_idx;
        int64_t stmp_64;
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

        assert(is_64 == 0 || is_64 == 1);
        if (is_64 == 0) {
                if (h32.ver != 2 && h32.ver != 3)
                        return (0);

                i_ptr += 11;

                a_ptr = (unsigned char *)abbrev + h32.len;
        } else if (is_64 == 1) {
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

        /* read first abbrev table */
        for (;;) {
                /* attr */
                if ((i = decode_ULEB128(a_ptr, &attr)) == 0) {
                        rtn = 0;

                        goto clean;
                }
                a_ptr += i;

                /* form */
                if ((i = decode_ULEB128(a_ptr, &form)) == 0) {
                        rtn = 0;

                        goto clean;
                }
                a_ptr += i;

                /* end with 0, 0 */
                if (attr == 0 && form == 0)
                        break;

                switch(form) {
                case DW_FORM_addr:
                        i_ptr += is_64 == 0 ? 4 : 8;

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
                                if ((len = duplicate_str((char *)i_ptr, &src))
                                    == 0)
                                        goto clean;

                                i_ptr += len + 1;
                        } else if (attr == DW_AT_comp_dir) {
                                if ((len = duplicate_str((char *)i_ptr, &dir))
                                    == 0)
                                        goto clean;

                                i_ptr += len + 1;
                        } else {
                                while (*i_ptr != '\0')
                                        ++i_ptr;

                                ++i_ptr;
                        }

                        break;
                case DW_FORM_block:
                        if ((i = decode_ULEB128(i_ptr, &tmp_64)) == 0) {
                                rtn = 0;

                                goto clean;
                        }
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
                        if ((i = decode_LEB128(i_ptr, &stmp_64)) == 0) {
                                rtn = 0;

                                goto clean;
                        }
                        i_ptr += i;

                        break;
                case DW_FORM_strp:
                        if (str == NULL)
                                goto clean;

                        assert(is_64 == 1 || is_64 == 0);
                        if (attr == DW_AT_name) {
                                if (is_64 == 0) {
                                        memcpy(&str_offset_32, i_ptr, 4);

                                        i_ptr += 4;

                                        if (duplicate_str((char *)str +
                                                str_offset_32, &src) == 0)
                                                goto clean;
                                } else if (is_64 == 1) {
                                        memcpy(&str_offset_64, i_ptr, 8);

                                        i_ptr += 8;

                                        if (duplicate_str((char *)str +
                                                str_offset_64, &src) == 0)
                                                goto clean;
                                }
                        } else if (attr == DW_AT_comp_dir) {
                                if (is_64 == 0) {
                                        memcpy(&str_offset_32, i_ptr, 4);

                                        i_ptr += 4;

                                        if (duplicate_str((char *)str +
                                                str_offset_32, &dir) == 0)
                                                goto clean;
                                } if (is_64 == 1) {
                                        memcpy(&str_offset_64, i_ptr, 8);

                                        i_ptr += 8;

                                        if (duplicate_str((char *)str +
                                                str_offset_64, &dir) == 0)
                                                goto clean;
                                }
                        } else
                                i_ptr += is_64 == 0 ? 4 : 8;

                        break;
                case DW_FORM_udata:
                        if ((i = decode_ULEB128(i_ptr, &tmp_64)) == 0) {
                                rtn = 0;

                                goto clean;
                        }
                        i_ptr += i;

                        break;
                case DW_FORM_ref_addr:
                        i_ptr += is_64 == 0 ? 4 : 8;

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
                        if ((i = decode_ULEB128(i_ptr, &tmp_64)) == 0) {
                                rtn = 0;

                                goto clean;
                        }
                        i_ptr += i;

                        break;
                case DW_FORM_indirect:
                        if ((i = decode_LEB128(i_ptr, &stmp_64)) == 0) {
                                rtn = 0;

                                goto clean;
                        }
                        i_ptr += i;
                };
        }

        if (src != NULL && dir != NULL) {
                if (vector_comp_dir_push(v, src, dir) == 0)
                        goto clean;
        }

        /* skip to next cu, because need only comp_dir */
        this_cu = i_ptr = this_cu +
            (is_64 == 0 ? h32.unit_len + 4 : h64.unit_len + 12);

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
