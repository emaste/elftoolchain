/*-
 * Copyright (c) 2007 Hyogeol Lee <hyogeollee@gmail.com>
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

#include <sys/queue.h>
#include <netinet/in.h>

#include <ar.h>
#include <assert.h>
#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <gelf.h>
#include <getopt.h>
#include <inttypes.h>
#include <libelf.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <unistd.h>

#include "cpp_demangle.h"
#include "dwarf_line_number.h"
#include "nm_aout.h"

/* symbol information list */
TAILQ_HEAD(sym_head, sym_entry);

struct sym_entry {
	char		*name;
	GElf_Sym	*sym;
	TAILQ_ENTRY(sym_entry) sym_entries;
};

typedef int (*fn_sort)(const struct sym_entry *, const struct sym_entry *, const char *);
typedef void (*fn_elem_print)(char, const char *, const GElf_Sym *, const char *);
typedef void (*fn_sym_print)(const GElf_Sym *);
typedef int (*fn_filter)(char, const GElf_Sym *, const char *);

/* output filter list */
SLIST_HEAD(filter_head, filter_entry) g_filter =
SLIST_HEAD_INITIALIZER(g_filter);

struct filter_entry {
	fn_filter	fn;
	SLIST_ENTRY(filter_entry) filter_entries;
};

struct sym_print_data {
	struct sym_head	*headp;
	size_t		sh_num;
	const char	*t_table, **s_table, *filename, *objname;
};

/* output numric type */
enum radix {
	RADIX_DEFAULT, RADIX_OCT, RADIX_HEX, RADIX_DEC
};

/* output symbol type, PRINT_SYM_DYN for dynamic symbol only */
enum print_symbol {
	PRINT_SYM_SYM, PRINT_SYM_DYN
};

/* output name type */
enum print_name {
	PRINT_NAME_NONE, PRINT_NAME_FULL, PRINT_NAME_MULTI
};

enum demangle {
	DEMANGLE_NONE, DEMANGLE_AUTO, DEMANGLE_GV3
};

/* input taget type */
enum target {
	TARGET_ERROR, TARGET_UNKNOWN, TARGET_DEFAULT, TARGET_ELF, TARGET_AOUT
};

#define CHECK_SYM_PRINT_DATA(p)	(p->headp == NULL || p->sh_num == 0 ||	      \
p->t_table == NULL || p->s_table == NULL || p->filename == NULL)
#define IS_SYM_TYPE(t)		(t == '?' || isalpha(t) != 0)
#define	IS_UNDEF_SYM_TYPE(t)	(t == 'U' || t == 'u' || t == 'w')
#define	FASTLOWER(t)		(t + 32)
#define	STDLOWER(t)		(tolower(t))
#define	TOLOWER(t)		(STDLOWER(t))
#define	TAILQ_HINIT_AFTER(l)	{l.tqh_first = NULL; \
l.tqh_last = &(l).tqh_first;}
#define	UNUSED(p)		((void)p)

static int		cmp_name(const struct sym_entry *,
			    const struct sym_entry *, const char *);
static int		cmp_none(const struct sym_entry *,
			    const struct sym_entry *, const char *);
static int		cmp_size(const struct sym_entry *,
			    const struct sym_entry *, const char *);
static int		cmp_value(const struct sym_entry *,
			    const struct sym_entry *, const char *);
static void		filter_dest(void);
static int		filter_insert(fn_filter);
static enum demangle	get_demangle_type(const char *);
static enum demangle	get_demangle_option(const char *);
static int		get_sym(Elf *, struct sym_head *, int,
			    const Elf_Data *, const Elf_Data *);
static char		get_sym_type(const GElf_Sym *, const char *);
static enum target	get_target(const char *);
static enum target	get_target_option(const char *);
static void		global_init(void);
static bool		is_sec_bss(GElf_Shdr *);
static bool		is_sec_data(GElf_Shdr *);
static bool		is_sec_debug(GElf_Shdr *);
static bool		is_sec_readonly(GElf_Shdr *);
static bool		is_sec_text(GElf_Shdr *);
static void		print_ar_index(int fd, Elf *);
static void		print_version(void);
static int		read_elf(const char *);
static int		readfile(const char *, const char *);
static unsigned char	*relocate_sec(Elf_Data *, Elf_Data *, int);
static int		search_addr(struct vector_line_info *, GElf_Sym *);
static void		set_g_value_print_fn(enum radix);
static int		sym_elem_def(char, const GElf_Sym *, const char *);
static int		sym_elem_global(char, const GElf_Sym *, const char *);
static int		sym_elem_nondebug(char, const GElf_Sym *, const char *);
static int		sym_elem_nonzero_size(char, const GElf_Sym *,
			    const char *);
static void		sym_elem_print_all(char, const char *,
			    const GElf_Sym *, const char *);
static void		sym_elem_print_all_portable(char, const char *,
			    const GElf_Sym *, const char *);
static void		sym_elem_print_all_sysv(char, const char *,
			    const GElf_Sym *, const char *);
static int		sym_elem_undef(char, const GElf_Sym *, const char *);
static void		sym_list_dest(struct sym_head *);
static int		sym_list_insert(struct sym_head *, const char *,
			    const GElf_Sym *);
static void		sym_list_print(struct sym_print_data *,
			    struct vector_line_info *);
static void		sym_list_print_each(struct sym_entry *,
			    struct sym_print_data *, struct vector_line_info *);
static void		sym_list_sort(struct sym_head *, const char *, fn_sort);
static int		sym_section_filter(const GElf_Shdr *);
static void		sym_size_oct_print(const GElf_Sym *);
static void		sym_size_hex_print(const GElf_Sym *);
static void		sym_size_dec_print(const GElf_Sym *);
static void		sym_value_oct_print(const GElf_Sym *);
static void		sym_value_hex_print(const GElf_Sym *);
static void		sym_value_dec_print(const GElf_Sym *);
static void		usage(int);

const char		*g_program_name;
const char		*g_program_version;
const char		*g_default_filename;
enum print_symbol	g_print_symbol;
enum print_name		g_print_name;
enum demangle		g_demangle_type;
bool			g_print_debug;
bool			g_print_armap;
int			g_print_size;
bool			g_debug_line;
int			g_def_only;
bool			g_undef_only;
int			g_sort_size;
bool			g_sort_reverse;
int			g_no_demangle;
int			g_target;

/*
 * function pointer to sort symbol list.
 * possible function - cmp_name, cmp_none, cmp_size, cmp_value
 */
fn_sort			g_sort_fn;

/*
 * function pointer to print symbol elem.
 * possible function - sym_elem_print_all
 *		       sym_elem_print_all_portable
 *		       sym_elem_print_all_sysv
 */
fn_elem_print		g_elem_print_fn;

fn_sym_print		g_value_print_fn;
fn_sym_print		g_size_print_fn;

static const struct option nm_longopts[] = {
	{ "debug-syms",		no_argument,		NULL,		'a'},
	{ "defined-only",	no_argument,		&g_def_only,	1   },
	{ "demangle",		optional_argument,	NULL,		'C' },
	{ "dynamic",		no_argument,		NULL,		'D' },
	{ "format",		required_argument,	NULL,		'F' },
	{ "line-numbers",	no_argument,		NULL,		'l' },
	{ "no-demangle",	no_argument,		&g_no_demangle,	1   },
	{ "no-sort",		no_argument,		NULL,		'p' },
	{ "numeric-sort",	no_argument,		NULL,		'v' },
	{ "print-armap",	no_argument,		NULL,		's' },
	{ "print-file-name",	no_argument,		NULL,		'A' },
	{ "print-size",		no_argument,		NULL,		'S' },
	{ "radix",		required_argument,	NULL,		't' },
	{ "reverse-sort",	no_argument,		NULL,		'r' },
	{ "size-sort",		no_argument,		&g_sort_size,	1   },
	{ "target",		required_argument,	&g_target,	1   },
	{ "undefined-only",	no_argument,		NULL,		'u' },
	{ "version",		no_argument,		NULL,		'V' },
	{ NULL,			0,			NULL,		0   }
};

static int
cmp_name(const struct sym_entry *l, const struct sym_entry *r,
    const char *ttable)
{

	assert(l != NULL);
	assert(r != NULL);
	assert(l->name != NULL);
	assert(r->name != NULL);
	
	UNUSED(ttable);

	return (strcmp(l->name, r->name));
}

static int
cmp_none(const struct sym_entry *l, const struct sym_entry *r,
    const char *ttable)
{

	UNUSED(l);
	UNUSED(r);
	UNUSED(ttable);

	return (0);
}

/* Size comparison. If l and r have same size, compare their name. */
static int
cmp_size(const struct sym_entry *l, const struct sym_entry *r,
    const char *ttable)
{

	assert(l != NULL);
	assert(l->name != NULL);
	assert(l->sym != NULL);
	assert(r != NULL);
	assert(r->name != NULL);
	assert(r->sym != NULL);

	UNUSED(ttable);

	if (l->sym->st_size == r->sym->st_size)
		return (strcmp(l->name, r->name));

	return (l->sym->st_size > r->sym->st_size);
}

/* Value comparison. Undefined symbols come first. */
static int
cmp_value(const struct sym_entry *l, const struct sym_entry *r,
    const char *ttable)
{
	int l_is_undef, r_is_undef;

	assert(l != NULL);
	assert(l->name != NULL);
	assert(l->sym != NULL);
	assert(r != NULL);
	assert(r->name != NULL);
	assert(r->sym != NULL);
	assert(ttable != NULL);

	l_is_undef = IS_UNDEF_SYM_TYPE(get_sym_type(l->sym, ttable)) ? 1 : 0;
	r_is_undef = IS_UNDEF_SYM_TYPE(get_sym_type(r->sym, ttable)) ? 1 : 0;

	assert(l_is_undef + r_is_undef >= 0);
	assert(l_is_undef + r_is_undef <= 2);

	switch (l_is_undef + r_is_undef) {
	case 0:
		/* Both defined */
		return (l->sym->st_value > r->sym->st_value);
	case 1:
		/* One undefined */
		return (l_is_undef == 0);
	case 2:
		/* Both undefined */
		return (strcmp(l->name, r->name));
	}
	/* NOTREACHED */

	return (l->sym->st_value > r->sym->st_value);
}

static void
filter_dest(void)
{
	struct filter_entry *e;

	while (!SLIST_EMPTY(&g_filter)) {
		e = SLIST_FIRST(&g_filter);
		SLIST_REMOVE_HEAD(&g_filter, filter_entries);
		free(e);
	}
}

static int
filter_insert(fn_filter filter_fn)
{
	struct filter_entry *e;

	assert(filter_fn != NULL);

	if ((e = malloc(sizeof(struct filter_entry))) == NULL)
		return (0);

	e->fn = filter_fn;

	SLIST_INSERT_HEAD(&g_filter, e, filter_entries);

	return (1);
}

static enum demangle
get_demangle_type(const char *org)
{

	if (org == NULL)
		return (DEMANGLE_NONE);

	if (is_cpp_mangled_ia64(org))
		return (DEMANGLE_GV3);

	return (DEMANGLE_NONE);
}

static enum demangle
get_demangle_option(const char *opt)
{

	if (opt == NULL)
		return (DEMANGLE_AUTO);

	if (strncasecmp(opt, "gnu-v3", 6) == 0)
		return (DEMANGLE_GV3);

	errx(EX_USAGE, "unknown demangling style '%s'", opt);

	/* NOTREACHED */
	return (DEMANGLE_NONE);
}

/*
 * Get symbol information from elf.
 * param shnum Total section header number(ehdr.e_shnum).
 */
static int
get_sym(Elf *elf, struct sym_head *headp, int shnum,
    const Elf_Data *dynstr_data, const Elf_Data *strtab_data)
{
	Elf_Scn *scn;
	Elf_Data *data;
	const Elf_Data *table;
	GElf_Shdr shdr;
	GElf_Sym sym;
	const char *sym_name;

	assert(elf != NULL);
	assert(headp != NULL);

	for (int i = 1; i < shnum; ++i) {
		if ((scn = elf_getscn(elf, i)) == NULL)
			return (0);

		if (gelf_getshdr(scn, &shdr) == NULL)
			return (0);

		if (sym_section_filter(&shdr) != 1)
			continue;

		if (shdr.sh_type == SHT_DYNSYM && dynstr_data != NULL)
			table = dynstr_data;
		else if (shdr.sh_type == SHT_SYMTAB && strtab_data != NULL)
			table = strtab_data;
		else
			table = NULL;

		data = NULL;
		while ((data = elf_getdata(scn, data)) != NULL) {
			int j = 1;
			while (gelf_getsym(data, j++, &sym) != NULL) {
				sym_name = table == NULL ? "(null)" :
				    (char *)((char *)(table->d_buf) +
					sym.st_name);

				if (sym_list_insert(headp, sym_name, &sym) == 0)
					return (0);
			}
		}
	}

	return (1);
}

static char
get_sym_type(const GElf_Sym *sym, const char *type_table)
{
	bool is_local;
	unsigned char type;

	if (sym == NULL || type_table == NULL)
		return ('?');

	is_local = sym->st_info >> 4 == STB_LOCAL;
	type = sym->st_info & 0xf;

	if (sym->st_shndx == SHN_ABS) /* absolute */
		return (is_local ? 'a' : 'A');

	if (sym->st_shndx == SHN_COMMON) /* common */
		return (is_local ? 'c' : 'C');

	if ((sym->st_info) >> 4 == STB_WEAK) /* weak */
		return (sym->st_value == 0 ? 'w' : 'W');

	if (sym->st_shndx == SHN_UNDEF) /* undefined */
		return (is_local ? 'u' : 'U');

	return (is_local == true ?
	    TOLOWER(type_table[sym->st_shndx]) :
	    type_table[sym->st_shndx]);
}

static enum target
get_target(const char *filename)
{
	int fd;
	Elf_Cmd cmd;
	Elf* elf;

	if (filename == NULL)
		return (TARGET_UNKNOWN);

	if ((fd = open(filename, O_RDONLY)) == -1) {
		warn("'%s'", filename);

		return (TARGET_ERROR);
	}

	/* try elf */
	cmd = ELF_C_READ;
	if ((elf = elf_begin(fd, cmd, (Elf *) NULL)) != NULL &&
	    elf_kind(elf) != ELF_K_NONE) {
		elf_end(elf);
		close(fd);

		return (TARGET_ELF);
	}

	if (lseek(fd, 0, SEEK_SET) != 0)
		return (TARGET_ERROR);

	/* try a.out */
	if (is_aout_file(fd)) {
		close(fd);

		return (TARGET_AOUT);
	}

	close(fd);

	return (TARGET_UNKNOWN);
}

static enum target
get_target_option(const char *t)
{

	if (t == NULL)
		return (TARGET_DEFAULT);

	if (strncasecmp(t, "elf", 3) == 0)
		return (TARGET_ELF);
	else if (strncasecmp(t, "aout", 4) == 0)
		return (TARGET_AOUT);

	return (TARGET_UNKNOWN);
}

static void
global_init(void)
{

	if (elf_version(EV_CURRENT) == EV_NONE)
		errx(1, "elf_version error");

	g_program_name = "nm";
	g_program_version = "1.0";
	g_default_filename = "a.out";

	g_print_symbol = PRINT_SYM_SYM;
	g_print_name = PRINT_NAME_NONE;
	g_demangle_type = DEMANGLE_NONE;
	g_print_debug = false;
	g_print_armap = false;
	g_print_size = 0;

	g_debug_line = false;

	g_def_only = 0;
	g_undef_only = false;

	g_sort_size = 0;
	g_sort_reverse = false;
	g_no_demangle = 0;
	g_target = 0;

	g_sort_fn = &cmp_name;
	g_elem_print_fn = &sym_elem_print_all;
	g_value_print_fn = &sym_value_dec_print;
	g_size_print_fn = &sym_size_dec_print;

	SLIST_INIT(&g_filter);
}

static bool
is_sec_bss(GElf_Shdr *s)
{

	assert(s != NULL && "shdr is NULL");

	return (s->sh_type == SHT_NOBITS &&
	    s->sh_flags == (SHF_ALLOC + SHF_WRITE));
}

static bool
is_sec_data(GElf_Shdr *s)
{

	assert(s != NULL && "shdr is NULL");

	return ((s->sh_type == SHT_PROGBITS &&
		s->sh_flags == (SHF_ALLOC + SHF_WRITE)) ||
	    s->sh_type == SHT_DYNAMIC);
}

static bool
is_sec_debug(GElf_Shdr *s)
{

	assert(s != NULL && "shdr is NULL");

	return (s->sh_type == SHT_PROGBITS && s->sh_flags == 0);
}

static bool
is_sec_readonly(GElf_Shdr *s)
{

	assert(s != NULL && "shdr is NULL");

	return ((s->sh_type == SHT_PROGBITS &&
		(s->sh_flags == SHF_ALLOC ||
		    s->sh_flags == (SHF_ALLOC + SHF_MERGE) ||
		    s->sh_flags == (SHF_ALLOC + SHF_MERGE + SHF_STRINGS))) ||
	    s->sh_type == SHT_NOTE);
}

static bool
is_sec_text(GElf_Shdr *s)
{

	assert(s != NULL && "shdr is NULL");

	return (s->sh_type == SHT_PROGBITS &&
	    s->sh_flags == (SHF_ALLOC + SHF_EXECINSTR));
}

static void
print_ar_index(int fd, Elf *arf)
{
	Elf_Arsym *arsym;
	Elf_Cmd cmd;
	size_t arsym_size;

	if (arf == NULL)
		return;

	if ((arsym = elf_getarsym(arf, &arsym_size)) == NULL)
		return;

	printf("\nArchive index:\n");

	cmd = ELF_C_READ;
	while (arsym_size > 1) {
		Elf *elf;
		Elf_Arhdr *arhdr;

		if (elf_rand(arf, arsym->as_off) == arsym->as_off &&
		    (elf = elf_begin(fd, cmd, arf)) != NULL) {
			if ((arhdr = elf_getarhdr(elf)) != NULL)
				printf("%s in %s\n",
				    arsym->as_name,
				    arhdr->ar_name != NULL ?
				    arhdr->ar_name : arhdr->ar_rawname);

			elf_end(elf);
		}
		++arsym;
		--arsym_size;
	}
	printf("\n");

	elf_rand(arf, SARMAG);
}

static void
print_version(void)
{

	printf("%s %s\n", g_program_name, g_program_version);

	exit(EX_OK);
}

/*
 * return -1 at error. 0 at false, 1 at true.
 */
static int
sym_section_filter(const GElf_Shdr *shdr)
{

	if (shdr == NULL)
		return (-1);

	if (g_print_debug == false &&
	    shdr->sh_type == SHT_PROGBITS &&
	    shdr->sh_flags == 0)
		return (1);

	if (g_print_symbol == PRINT_SYM_SYM &&
	    shdr->sh_type == SHT_SYMTAB)
		return (1);

	if (g_print_symbol == PRINT_SYM_DYN &&
	    shdr->sh_type == SHT_DYNSYM)
		return (1);

	/* In manual page, SHT_GNU_versym is also symbol section */
	return (0);
}

/*
 * Read elf file and collect symbol information, sort them, print.
 * Return 1 at failed, 0 at success.
 */
static int
read_elf(const char *filename)
{
	int fd, rtn, e_err;
	GElf_Half i;
	const char *shname, *objname;
	char *type_table, **sec_table;
	void *dbg_info_buf, *dbg_str_buf, *dbg_line_buf;
	size_t strndx, shnum, dbg_info_size, dbg_str_size, dbg_line_size;
	struct sym_head list_head;
	Elf_Cmd elf_cmd;
	Elf *arf, *elf;
	Elf_Kind kind;
	struct sym_print_data p_data;
	Elf_Arhdr *arhdr;
	Elf_Scn *scn;
	Elf_Data *dynstr_data, *strtab_data, *dbg_info, *dbg_rela_info;
	Elf_Data *dbg_abbrev, *dbg_str, *dbg_line, *dbg_rela_line;
	GElf_Shdr shdr;
	struct vector_comp_dir *v_comp_dir;
	struct vector_line_info *v_line_info;

	assert(filename != NULL && "filename is null");

	if ((fd = open(filename, O_RDONLY)) == -1) {
		warn("'%s'", filename);

		return (1);
	}

	elf_cmd = ELF_C_READ;
	if ((arf = elf_begin(fd, elf_cmd, (Elf *) NULL)) == NULL) {
		if ((e_err = elf_errno()) != 0)
			warnx("elf_begin error : %s", elf_errmsg(e_err));
		else
			warnx("elf_begin error");

		close(fd);

		return (1);
	}

	assert(arf != NULL && "arf is null.");

	rtn = 0;

	if ((kind = elf_kind(arf)) == ELF_K_NONE) {
		warnx("%s: File format not recognized", filename);

		rtn = 1;

		goto end_read_elf;
	}

	if (g_print_armap == true && kind == ELF_K_AR)
		print_ar_index(fd, arf);

	objname = NULL;

	/* Instead of TAILQ_HEAD_INITIALIZER to avoid warning */
	TAILQ_HINIT_AFTER(list_head);

	while ((elf = elf_begin(fd, elf_cmd, arf)) != NULL) {
		type_table = NULL;
		sec_table = NULL;
		dbg_info_buf = NULL;
		dbg_str_buf = NULL;
		dbg_line_buf = NULL;
		dynstr_data = NULL;
		strtab_data = NULL;
		dbg_info = NULL;
		dbg_rela_info = NULL;
		dbg_abbrev = NULL;
		dbg_str = NULL;
		dbg_line = NULL;
		dbg_rela_line = NULL;
		v_comp_dir = NULL;
		v_line_info = NULL;

		if (kind == ELF_K_AR) {
			if ((arhdr = elf_getarhdr(elf)) == NULL)
				goto next_cmd;

			objname = arhdr->ar_name != NULL ?
			    arhdr->ar_name : arhdr->ar_rawname;
		}

		if (elf_getshnum(elf, &shnum) == 0) {
			if ((e_err = elf_errno()) != 0)
				warnx("%s: %s",
				    objname == NULL ? filename : objname,
				    elf_errmsg(e_err));
			else
				warnx("%s: cannot get section number",
				    objname == NULL ? filename : objname);

			rtn = 1;

			goto next_cmd;
		}

		if (shnum == 0) {
			warnx("%s: has no section", objname == NULL ?
			    filename : objname);

			rtn = 1;

			goto next_cmd;
		}

		if (elf_getshstrndx(elf, &strndx) == 0) {
			warnx("%s: cannot get str index", objname == NULL ?
			    filename : objname);

			rtn = 1;

			goto next_cmd;
		}

		/* type_table for type determine */
		if ((type_table = malloc(sizeof(char) * shnum)) == NULL) {
			warn("%s", objname == NULL ? filename : objname);

			rtn = 1;

			goto next_cmd;
		}

		/* sec_table for section name to display in sysv format */
		if ((sec_table = malloc(sizeof(char *) * shnum)) == NULL) {
			warn("%s", objname == NULL ? filename : objname);

			rtn = 1;

			goto next_cmd;
		}

		/*
		 * Need to set NULL separately to free safely when failed in
		 * loop and goto cleaning area.
		 */
		for (i = 1; i< shnum; ++i)
			sec_table[i] = NULL;

		type_table[0] = 'U';
		if ((sec_table[0] = strdup("*UND*")) == NULL)
			goto next_cmd;

		for (i = 1; i < shnum; ++i) {
			type_table[i] = 'U';

			if ((scn = elf_getscn(elf, i)) == NULL) {
				if ((e_err = elf_errno()) != 0)
					warnx("%s: %s",
					    objname == NULL ?
					    filename : objname,
					    elf_errmsg(e_err));
				else
					warnx("%s: cannot get section",
					    objname == NULL ?
					    filename : objname);

				rtn = 1;

				goto next_cmd;
			}

			if (gelf_getshdr(scn, &shdr) == NULL)
				goto next_cmd;

			/*
			 * cannot test by type and attribute for dynstr,
			 * strtab
			 */
			if ((shname = elf_strptr(elf, strndx,
				 (size_t)shdr.sh_name)) != NULL) {
				if ((sec_table[i] = strdup(shname)) == NULL)
					goto next_cmd;

				if (strncmp(shname, ".dynstr", 7) == 0) {
					if ((dynstr_data = elf_getdata(scn,
						 NULL)) == NULL)
						goto next_cmd;
				}

				if (strncmp(shname, ".strtab", 7) == 0) {
					if ((strtab_data = elf_getdata(scn,
						 NULL)) == NULL)
						goto next_cmd;
				}

				/* not in SysV special sections,
				 * but has .debug_ stuff in DWARF.
				 */
				if (g_debug_line == true) {
					if (strncmp(shname, ".debug_info",
						11) == 0) {
						if ((dbg_info =
							elf_getdata(scn, NULL))
						    == NULL)
							goto next_cmd;
					}

					if (strncmp(shname, ".rela.debug_info",
						16) == 0) {
						if ((dbg_rela_info =
							elf_getdata(scn, NULL))
						    == NULL)
							goto next_cmd;
					}

					if (strncmp(shname, ".debug_abbrev",
						11) == 0) {
						if ((dbg_abbrev =
							elf_getdata(scn, NULL))
						    == NULL)
							goto next_cmd;
					}

					if (strncmp(shname, ".debug_str", 11) ==
					    0) {
						if ((dbg_str =
							elf_getdata(scn, NULL))
						    == NULL)
							goto next_cmd;
					}

					if (strncmp(shname, ".debug_line",
						11) == 0) {
						if ((dbg_line =
							elf_getdata(scn, NULL))
						    == NULL)
							goto next_cmd;
					}

					if (strncmp(shname, ".rela.debug_line",
						16) == 0) {
						if ((dbg_rela_line =
							elf_getdata(scn, NULL))
						    == NULL)
							goto next_cmd;
					}
				}
			} else if ((sec_table[i] = strdup("*UND*")) == NULL)
				goto next_cmd;

			if (is_sec_bss(&shdr) == true)
				type_table[i] = 'B';
			else if (is_sec_data(&shdr) == true)
				type_table[i] = 'D';
			else if (is_sec_text(&shdr) == true)
				type_table[i] = 'T';
			else if (is_sec_readonly(&shdr) == true)
				type_table[i] = 'R';
			else if (is_sec_debug(&shdr) == true)
				type_table[i] = 'N';
		}

		if ((dynstr_data == NULL && g_print_symbol == PRINT_SYM_DYN) ||
		    (strtab_data == NULL && g_print_symbol == PRINT_SYM_SYM)) {
			warnx("%s: no symbols", objname == NULL ?
			    filename : objname);

			/* this is not error case */

			goto next_cmd;
		}

		TAILQ_INIT(&list_head);

		if (g_debug_line == true && dbg_info != NULL &&
		    dbg_abbrev != NULL && dbg_line != NULL) {

			if ((v_comp_dir =
				malloc(sizeof(struct vector_comp_dir)))
			    != NULL) {
				vector_comp_dir_init(v_comp_dir);

				if (dbg_rela_info == NULL) {
					dbg_info_buf = dbg_info->d_buf;
					dbg_info_size = dbg_info->d_size;
				} else {
					dbg_info_buf = relocate_sec(dbg_info,
					    dbg_rela_info, gelf_getclass(elf));
					dbg_info_size = dbg_info->d_size;
				}

				if (dbg_str == NULL) {
					dbg_str_buf = NULL;
					dbg_str_size = 0;
				} else {
					dbg_str_buf =
					    dbg_str->d_buf;
					dbg_str_size =
					    dbg_str->d_size;
				}

				if (dbg_info_buf == NULL ||
				    get_dwarf_info(dbg_info_buf, dbg_info_size,
					dbg_abbrev->d_buf, dbg_abbrev->d_size,
					dbg_str_buf, dbg_str_size,
					v_comp_dir) == 0) {
					vector_comp_dir_dest(v_comp_dir);
					free(v_comp_dir);
					v_comp_dir = NULL;
				}
			}

			if ((v_line_info =
				malloc(sizeof(struct vector_line_info)))
			    != NULL) {

				vector_line_info_init(v_line_info);

				if (dbg_rela_line == NULL) {
					dbg_line_buf = dbg_line->d_buf;
					dbg_line_size = dbg_line->d_size;
				} else {
					dbg_line_buf = relocate_sec(dbg_line,
					    dbg_rela_line, gelf_getclass(elf));
					dbg_line_size = dbg_line->d_size;
				}

				if (dbg_line_buf == NULL ||
				    get_dwarf_line_info(dbg_line_buf,
					dbg_line_size,
					v_comp_dir,
					v_line_info) == 0) {

					vector_line_info_dest(v_line_info);
					free(v_line_info);
					v_line_info = NULL;
				}
			}
		}

		get_sym(elf, &list_head, shnum, dynstr_data, strtab_data);

		sym_list_sort(&list_head, type_table, g_sort_fn);

		p_data.headp = &list_head;
		p_data.sh_num = shnum;
		p_data.t_table = type_table;
		p_data.s_table = (const char **)sec_table;
		p_data.filename = filename;
		p_data.objname = objname;

		sym_list_print(&p_data, v_line_info);
next_cmd:
		if (g_debug_line == true) {
			if (v_comp_dir != NULL) {
				vector_comp_dir_dest(v_comp_dir);
				free(v_comp_dir);
				v_comp_dir = NULL;
			}

			if (v_line_info != NULL) {
				vector_line_info_dest(v_line_info);
				free(v_line_info);
				v_line_info = NULL;
			}

			if (dbg_rela_line != NULL)
				free(dbg_line_buf);

			if (dbg_rela_info != NULL)
				free(dbg_info_buf);
		}

		sym_list_dest(&list_head);

		if (sec_table != NULL)
			for (i = 0; i < shnum; ++i)
				free(sec_table[i]);

		free(sec_table);
		free(type_table);

		/*
		 * If file is not archive, elf_next return ELF_C_NULL and
		 * stop the loop.
		 */
		elf_cmd = elf_next(elf);
		elf_end(elf);
	}
end_read_elf:
	elf_end(arf);

	if (close(fd) == -1) {
		warn("%s: close error", filename);

		rtn |= 1;
	}

	return (rtn);
}

/*
 * Read file for specific target.
 * Return 1 at failed, 0 at success.
 */
static int
readfile(const char *filename, const char *topt)
{
	enum target t;

	if ((t = get_target_option(topt)) == TARGET_DEFAULT)
		t = get_target(filename);

	switch (t) {
	case TARGET_ELF:
		return (read_elf(filename));

	case TARGET_ERROR:
		break;

	case TARGET_AOUT:
		return (process_aout_file(filename));

	case TARGET_UNKNOWN:
		warnx("%s: File format not recognized", filename);

		break;
	case TARGET_DEFAULT:
		/* NOTREACHED */
		break;
	default:
		warnx("%s: Invalid target", filename);
	};

	return (1);
}

static unsigned char *
relocate_sec(Elf_Data *org, Elf_Data *rela, int class)
{
	unsigned char *rtn;
	int i;
	Elf32_Sword add32;
	Elf64_Sword add64;
	GElf_Rela ra;

	if (org == NULL || rela == NULL || class == ELFCLASSNONE)
		return (NULL);

	if (class != ELFCLASS32 && class != ELFCLASS64)
		return (NULL);

	if ((rtn = malloc(sizeof(unsigned char) * org->d_size)) == NULL)
		return (NULL);

	memcpy(rtn, org->d_buf, org->d_size);
	
	i = 0;
	while (gelf_getrela(rela, i, &ra) != NULL) {
		if (class == ELFCLASS32) {
			memcpy(&add32, rtn + ra.r_offset, sizeof(add32));
			add32 += (Elf32_Sword)ra.r_addend;
			memcpy(rtn + ra.r_offset, &add32, sizeof(add32));
		} else {
			memcpy(&add64, rtn + ra.r_offset, sizeof(add64));
			add64 += (Elf64_Sword)ra.r_addend;
			memcpy(rtn + ra.r_offset, &add64, sizeof(add64));
		}

		++i;
	}

	return (rtn);
}

static int
search_addr(struct vector_line_info *v, GElf_Sym *g)
{
	int i, j, k;

	if (v == NULL || g == NULL)
		return (-1);

	i = 0;
	j = v->size;

	while (i < j) {
		k = (i + j) / 2;
		if (v->info[k].addr < g->st_value)
			i = k + 1;
		else
			j = k;
	}

	return (((size_t)i < v->size) &&
	    (v->info[i].addr == g->st_value) ? i : -1);
}

static void
set_g_value_print_fn(enum radix t)
{

	switch (t) {
	case RADIX_OCT :
		g_value_print_fn = &sym_value_oct_print;
		g_size_print_fn = &sym_size_oct_print;

		break;
	case RADIX_HEX :
		g_value_print_fn = &sym_value_hex_print;
		g_size_print_fn = &sym_size_hex_print;

		break;
	case RADIX_DEC :
		g_value_print_fn = &sym_value_dec_print;
		g_size_print_fn = &sym_size_dec_print;

		break;
	case RADIX_DEFAULT :
	default :
		if (g_elem_print_fn == &sym_elem_print_all_portable) {
			g_value_print_fn = &sym_value_hex_print;
			g_size_print_fn = &sym_size_hex_print;
		} else {
			g_value_print_fn = &sym_value_dec_print;
			g_size_print_fn = &sym_size_dec_print;
		}
	}

	assert(g_value_print_fn != NULL && "g_value_print_fn is null");
}

static void
sym_elem_print_all(char type, const char *sec, const GElf_Sym *sym,
    const char *name)
{
	enum demangle d;

	if (sec == NULL || sym == NULL || name == NULL ||
	    g_value_print_fn == NULL)
		return;

	if (IS_UNDEF_SYM_TYPE(type))
		printf("                ");
	else {
		switch ((g_sort_fn == & cmp_size ? 2 : 0) + g_print_size) {
		case 3:
			if (sym->st_size != 0) {
				g_value_print_fn(sym);

				printf(" ");

				g_size_print_fn(sym);
			}

			break;
		case 2:
			if (sym->st_size != 0)
				g_size_print_fn(sym);

			break;
		case 1:
			g_value_print_fn(sym);
			if (sym->st_size != 0) {
				printf(" ");

				g_size_print_fn(sym);
			}

			break;
		case 0:
		default:
			g_value_print_fn(sym);
		}
	}

	printf(" %c ", type);

	d = g_demangle_type == DEMANGLE_AUTO ?
	    get_demangle_type(name) : g_demangle_type;

	switch (d) {
	case DEMANGLE_GV3:
		{
			char *demangle = cpp_demangle_ia64(name);
		
			printf("%s", demangle == NULL ? name : demangle);

			free(demangle);
		}
		break;
	case DEMANGLE_AUTO:
		/* NOTREACHED */
		/* FALLTHROUGH */
	case DEMANGLE_NONE:
	default:
		printf("%s", name);
	}
}

static void
sym_elem_print_all_portable(char type, const char *sec, const GElf_Sym *sym,
    const char *name)
{
	enum demangle d;

	if (sec == NULL || sym == NULL || name == NULL ||
	    g_value_print_fn == NULL)
		return;

	d = g_demangle_type == DEMANGLE_AUTO ?
	    get_demangle_type(name) : g_demangle_type;

	switch (d) {
	case DEMANGLE_GV3:
		{
			char *demangle = cpp_demangle_ia64(name);

			printf("%s", demangle == NULL ? name : demangle);

			free(demangle);
		}

		break;
	case DEMANGLE_AUTO:
		/* NOTREACHED */
		/* FALLTHROUGH */
	case DEMANGLE_NONE:
	default:
		printf("%s", name);
	}

	printf(" %c ", type);

	if (!IS_UNDEF_SYM_TYPE(type)) {
		g_value_print_fn(sym);

		printf(" ");

		if (sym->st_size != 0)
			g_size_print_fn(sym);
	} else
		printf("        ");
}

static void
sym_elem_print_all_sysv(char type, const char *sec, const GElf_Sym *sym,
    const char *name)
{
	enum demangle d;

	if (sec == NULL || sym == NULL || name == NULL ||
	    g_value_print_fn == NULL)
		return;

	d = g_demangle_type == DEMANGLE_AUTO ?
	    get_demangle_type(name) : g_demangle_type;

	switch (d) {
	case DEMANGLE_GV3:
		{
			char *demangle = cpp_demangle_ia64(name);

			printf("%-20s|", demangle == NULL ? name : demangle);

			free(demangle);
		}

		break;
	case DEMANGLE_AUTO:
		/* NOTREACHED */
		/* FALLTHROUGH */
	case DEMANGLE_NONE:
	default:
		printf("%-20s|", name);
	}

	if (IS_UNDEF_SYM_TYPE(type))
		printf("                ");
	else
		g_value_print_fn(sym);

	printf("|   %c  |", type);

	switch (sym->st_info & 0xf) {
	case STT_OBJECT:
		printf("%18s|", "OBJECT");

		break;
	case STT_FUNC:
		printf("%18s|", "FUNC");

		break;
	case STT_SECTION:
		printf("%18s|", "SECTION");

		break;
	case STT_FILE:
		printf("%18s|", "FILE");

		break;
	case STT_LOPROC:
		printf("%18s|", "LOPROC");

		break;
	case STT_HIPROC:
		printf("%18s|", "HIPROC");

		break;
	case STT_NOTYPE:
	default:
		printf("%18s|", "NOTYPE");
	};

	if (sym->st_size != 0)
		g_size_print_fn(sym);
	else
		printf("                ");

	printf("|     |%s", sec);
}

static int
sym_elem_def(char type, const GElf_Sym *sym, const char *name)
{

	assert(IS_SYM_TYPE(type));

	UNUSED(sym);
	UNUSED(name);

	return (!IS_UNDEF_SYM_TYPE(type));
}

static int
sym_elem_global(char type, const GElf_Sym *sym, const char *name)
{

	assert(IS_SYM_TYPE(type));

	UNUSED(sym);
	UNUSED(name);

	return (isupper(type));
}

static int
sym_elem_nondebug(char type, const GElf_Sym *sym, const char *name)
{

	assert(sym != NULL);

	UNUSED(type);
	UNUSED(name);

	if (sym->st_value == 0 && (sym->st_info & 0xf) == STT_FILE)
		return (0);

	if (sym->st_name == 0)
		return (0);

	return (1);
}

static int
sym_elem_nonzero_size(char type, const GElf_Sym *sym, const char *name)
{

	assert(sym != NULL);

	UNUSED(type);
	UNUSED(name);

	return (sym->st_size > 0);
}

static int
sym_elem_undef(char type, const GElf_Sym *sym, const char *name)
{

	assert(IS_SYM_TYPE(type));

	UNUSED(sym);
	UNUSED(name);

	return (IS_UNDEF_SYM_TYPE(type));
}

static void
sym_list_dest(struct sym_head *headp)
{
	struct sym_entry *ep, *ep_n;

	if (headp == NULL)
		return;

	ep = TAILQ_FIRST(headp);
	while (ep != NULL) {
		ep_n = TAILQ_NEXT(ep, sym_entries);

		free(ep->sym);
		free(ep->name);
		free(ep);

		ep = ep_n;
	}
}

static int
sym_list_insert(struct sym_head *headp, const char *name, const GElf_Sym *sym)
{
	struct sym_entry *e;

	if (headp == NULL || name == NULL || sym == NULL)
		return (0);

	if ((e = malloc(sizeof(struct sym_entry))) == NULL)
		return (0);

	if ((e->name = strdup(name)) == NULL) {
		free(e);

		return (0);
	}

	if ((e->sym = malloc(sizeof(GElf_Sym))) == NULL) {
		free(e->name);
		free(e);

		return (0);
	}

	memcpy(e->sym, sym, sizeof(GElf_Sym));

	TAILQ_INSERT_TAIL(headp, e, sym_entries);

	return (1);
}

/* If file has not .debug_info, line_info will be NULL */
static void
sym_list_print(struct sym_print_data *p, struct vector_line_info *line_info)
{
	struct sym_entry *ep;

	if (p == NULL || CHECK_SYM_PRINT_DATA(p))
		return;

	if (g_elem_print_fn == &sym_elem_print_all_sysv) {
		printf("\n\n%s from %s",
		    g_undef_only == false ? "Symbols" : "Undefined symbols",
		    p->filename);

		if (p->objname != NULL)
			printf("[%s]", p->objname);

		printf(":\n\n");

		printf("\
Name                  Value           Class        Type         Size             Line  Section\n\n");
	} else {
		/* archive file without -A option */
		if (g_print_name != PRINT_NAME_FULL && p->objname != NULL)
			printf("%s[%s]:\n", p->filename, p->objname);
		/* multiple files(not archive) without -A option */
		else if (g_print_name == PRINT_NAME_MULTI) {
			if (g_elem_print_fn == sym_elem_print_all)
				printf("\n");

			printf("%s:\n", p->filename);
		}
	}

	if (g_sort_reverse == false)
		TAILQ_FOREACH(ep, p->headp, sym_entries)
		    sym_list_print_each(ep, p, line_info);
	else
		TAILQ_FOREACH_REVERSE(ep, p->headp, sym_head, sym_entries)
		    sym_list_print_each(ep, p, line_info);
}

/* If file has not .debug_info, line_info will be NULL */
static void
sym_list_print_each(struct sym_entry *ep, struct sym_print_data *p,
    struct vector_line_info *line_info)
{
	int i;
	struct filter_entry *fep;
	const char *sec;
	char type;

	if (ep == NULL || CHECK_SYM_PRINT_DATA(p))
		return;

	assert(ep->name != NULL);
	assert(ep->sym != NULL);

	type = get_sym_type(ep->sym, p->t_table);

	SLIST_FOREACH(fep, &g_filter, filter_entries)
	    if (fep->fn(type, ep->sym, ep->name) == 0)
		    return;

	if (g_print_name == PRINT_NAME_FULL) {
		printf("%s", p->filename);

		if (g_elem_print_fn == &sym_elem_print_all_sysv) {
			if (p->objname != NULL)
				printf(":%s", p->objname);

			printf(":");
		} else {
			if (p->objname != NULL)
				printf("[%s]", p->objname);

			printf(": ");
		}
	}

	switch (ep->sym->st_shndx) {
	case SHN_LOPROC:
		/* LOPROC or LORESERVE */
		sec = "*LOPROC*";

		break;
	case SHN_HIPROC:
		sec = "*HIPROC*";

		break;
	case SHN_LOOS:
		sec = "*LOOS*";

		break;
	case SHN_HIOS:
		sec = "*HIOS*";

		break;
	case SHN_ABS:
		sec = "*ABS*";

		break;
	case SHN_COMMON:
		sec = "*COM*";

		break;
	case SHN_HIRESERVE:
		/* HIRESERVE or XINDEX */
		sec = "*HIRESERVE*";

		break;
	default:
		if (ep->sym->st_shndx > p->sh_num)
			return;

		sec = p->s_table[ep->sym->st_shndx];
	};
	
	g_elem_print_fn(type, sec, ep->sym, ep->name);

	if (g_debug_line == true && line_info != NULL &&
	    !IS_UNDEF_SYM_TYPE(type)) {
		if ((i = search_addr(line_info, ep->sym)) != -1) {
			printf("\t%s:%" PRIu64, line_info->info[i].file,
			    line_info->info[i].line);
		}
	}

	printf("\n");
}

static void
sym_list_sort(struct sym_head *headp, const char *type_table, fn_sort fn)
{
	struct sym_head sorted;
	struct sym_entry *e_min;

	assert(headp != NULL && type_table != NULL);

	if (TAILQ_EMPTY(headp) != 0)
		return;

	if (TAILQ_NEXT(TAILQ_FIRST(headp), sym_entries) == NULL)
		return;

	/* Instead of TAILQ_HEAD_INITIALIZER to avoid warning */
	TAILQ_HINIT_AFTER(sorted);
	
	TAILQ_INIT(&sorted);

	while ((e_min = TAILQ_FIRST(headp)) != NULL) {
		struct sym_entry *ep;

		TAILQ_FOREACH(ep, headp, sym_entries) {
			if (fn(e_min, ep, type_table) > 0)
				e_min = ep;

			if (TAILQ_NEXT(ep, sym_entries) == NULL) {
				TAILQ_REMOVE(headp, e_min, sym_entries);

				TAILQ_INSERT_TAIL(&sorted, e_min, sym_entries);
			}
		}
	}

	*headp = sorted;
}

static void
sym_size_oct_print(const GElf_Sym *sym)
{

	assert(sym != NULL && "sym is null");

	printf("%016" PRIo64, sym->st_size);
}

static void
sym_size_hex_print(const GElf_Sym *sym)
{

	assert(sym != NULL && "sym is null");

	printf("%016" PRIx64, sym->st_size);

}

static void
sym_size_dec_print(const GElf_Sym *sym)
{

	assert(sym != NULL && "sym is null");

	printf("%016" PRId64, sym->st_size);
}

static void
sym_value_oct_print(const GElf_Sym *sym)
{

	assert(sym != NULL && "sym is null");

	printf("%016" PRIo64, sym->st_value);
}

static void
sym_value_hex_print(const GElf_Sym *sym)
{

	assert(sym != NULL && "sym is null");

	printf("%016" PRIx64, sym->st_value);
}

static void
sym_value_dec_print(const GElf_Sym *sym)
{

	assert(sym != NULL && "sym is null");

	printf("%016" PRId64, sym->st_value);
}

static void
usage(int exitcode)
{

	printf("Usage: %s [options] file ...\
\n  Display symbolic information in file.\
\n  The default option are bsd format, decimal radix, name sort, no-demangle.\
\n  Options : \
\n    -A, --print-file-name     Write the full pathname or library name of an\
\n                               object on each line\
\n    -a, --debug-syms          Display all symbols include debugger-only\
\n                               symbols", g_program_name);
	printf("\
\n    -B                        Same as --format=bsd\
\n    -C, --demangle[=style]    Decode low-level symbol names\
\n        --no-demangle         Do not demangle low-level symbol names\
\n    -D, --dynamic             Display only dynamic symbols\
\n    -e                        Display only global and static symbol. Same as\
\n                               -g");
	printf("\
\n    -f                        Produce full output. Same as default output\
\n    --format=format           Display output in specific format.\
\n    -g                        Display only global symbol information\
\n    -h, --help                Show help message\
\n    -l, --line-numbers        Display filename and linenumber using\
\n                               debugging information\
\n    -n, --numeric-sort        Sort symbols numerically by value");
	printf("\
\n    -o                        Write numeric values in octal. Same as -t o\
\n    -p, --no-sort             Do not sort symbols\
\n    -P                        Write information in a portable output format.\
\n                               Same as --format=posix\
\n    -r, --reverse-sort        Reverse the order of the sort\
\n    -S, --print-size          Print size instead value\
\n    -s, --print-armap         Include the index of archive members\
\n        --size-sort           Sort symbols by size");
	printf("\
\n    -t, --radix=format\
\n                              Write each numric value in the specified\
\n                               format\
\n                                 d   In decimal\
\n                                 o   In octal\
\n                                 x   In hexadecimal\
\n        --target=name         Specify an object code format");
	printf("\
\n    -u, --undefined-only      Display only undefined symbols\
\n        --defined-only        Display only defined symbols\
\n    -V, --version             Show the version number\
\n    -v                        Sort output by value\
\n    -x                        Write numeric values in hexadecimal.\
\n                               Same as -t x\n");
	
	exit(exitcode);
}

/*
 * Todo
 *
 * 1. test
 */

/*
 * Display symbolic information in file.
 * Return 0 at success, >0 at failed.
 *
 * NOTES.
 *  1. I do not have any test case, test file for a.out, it just come from on
 *    CVS attic only. So a.out may do not works correctly. If you have any
 *    sample a.out file, send me please.
 */
int
main(int argc, char *argv[])
{
	int ch, rtn;
	enum radix t;
	const char *target;

	global_init();

	t = RADIX_DEFAULT;
	target = NULL;

	while ((ch = getopt_long(argc, argv, "ABCDSVPaefghlnoprst:uvx",
		    nm_longopts, NULL)) != -1) {
		switch (ch) {
		case 'A':
			g_print_name = PRINT_NAME_FULL;
			aout_set_print_file(1);

			break;
		case 'B':
			g_elem_print_fn = &sym_elem_print_all;

			break;
		case 'C':
			g_demangle_type = get_demangle_option(optarg);
			if (optarg == NULL)
				g_demangle_type = DEMANGLE_AUTO;

			break;
		case 'F':
			/* sysv, bsd, posix */
			switch (optarg[0]) {
			case 'B':
			case 'b':
				g_elem_print_fn = &sym_elem_print_all;

				break;
			case 'P':
			case 'p':
				g_elem_print_fn = &sym_elem_print_all_portable;

				break;
			case 'S':
			case 's':
				g_elem_print_fn = &sym_elem_print_all_sysv;
				break;

			default:
				warnx("%s: Invalid format", optarg);

				usage(EX_USAGE);

				/* NOTREACHED */
			}

			break;
		case 'D':
			g_print_symbol = PRINT_SYM_DYN;

			break;
		case 'S':
			g_print_size = 1;

			break;
		case 'V':
			print_version();

			/* NOTREACHED */
			break;
		case 'P':
			g_elem_print_fn = &sym_elem_print_all_portable;

			break;
		case 'a':
			g_print_debug = true;
			aout_set_print_all(1);

			break;
		case 'f':
			break;
		case 'e':
			/* FALLTHROUGH */
		case 'g':
			filter_insert(sym_elem_global);
			aout_set_print_ext(1);

			break;
		case 'o':
			t = RADIX_OCT;

			break;
		case 'p':
			g_sort_fn = &cmp_none;

			break;
		case 'r':
			g_sort_reverse = true;

			break;
		case 's':
			g_print_armap = true;

			break;
		case 't':
			/* t require always argument to getopt_long */
			switch (optarg[0]) {
			case 'd':
				t = RADIX_DEC;

				break;
			case 'o':
				t = RADIX_OCT;

				break;
			case 'x':
				t = RADIX_HEX;

				break;
			default:
				warnx("%s: Invalid radix", optarg);

				usage(EX_USAGE);

				/* NOTREACHED */
			}

			break;
		case 'u':
			filter_insert(sym_elem_undef);
			g_undef_only = true;
			aout_set_print_und(1);

			break;
		case 'l':
			g_debug_line = true;

			break;
		case 'n':
			/* FALLTHROUGH */
		case 'v':
			g_sort_fn = &cmp_value;
			aout_set_sort_value();

			break;
		case 'x':
			t = RADIX_HEX;

			break;
		case 0:
			if (g_sort_size != 0) {
				g_sort_fn = &cmp_size;

				filter_insert(sym_elem_def);
				filter_insert(sym_elem_nonzero_size);
			}

			if (g_def_only != 0)
				filter_insert(sym_elem_def);

			if (g_no_demangle != 0)
				g_demangle_type = DEMANGLE_NONE;

			if (g_target != 0)
				target = optarg;

			break;
		case 'h':
		default :
			usage(EX_OK);

			/* NOTREACHED */
		}
	}

	argc -= optind;
	argv += optind;

	assert(g_program_name != NULL && "g_program_name is null");
	assert(g_default_filename != NULL && "g_default_filename is null");
	assert(g_sort_fn != NULL && "g_sort_fn is null");
	assert(g_elem_print_fn != NULL && "g_elem_print_fn is null");
	assert(g_value_print_fn != NULL && "g_value_print_fn is null");

	set_g_value_print_fn(t);

	if (g_undef_only == true) {
		if (g_sort_fn == &cmp_size)
			errx(EX_USAGE, "--size-sort with -u is meaningless");

		if (g_def_only != 0)
			errx(EX_USAGE,
			    "-u with --defined-only is meaningless");
	}

	if (g_print_debug == false)
		filter_insert(sym_elem_nondebug);

	if (g_sort_reverse == true)
		aout_set_sort_rname();

	rtn = 0;
	if (argc == 0)
		rtn |= readfile(g_default_filename, target);
	else {
		if (g_print_name == PRINT_NAME_NONE && argc > 1)
			g_print_name = PRINT_NAME_MULTI;

		while (argc > 0) {
			rtn |= readfile(*argv, target);

			--argc;
			++argv;
		}
	}

	filter_dest();

	return (rtn);
}
