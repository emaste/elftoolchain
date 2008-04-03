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
 *
 * $FreeBSD$
 */

#include <sys/queue.h>
#include <gelf.h>

/* List of user specified symbols. */
struct symlist {
	const char *name;

	STAILQ_ENTRY(symlist) syms;
};

/* Sections to copy/remove/rename/... */
struct sec_action {
	const char *name;
	const char *addopt;
	const char *newname;
	const char *string;

	int add;
	int append;
	int compress;
	int copy;
	int print;
	int remove;
	int rename;

	STAILQ_ENTRY(sec_action) sacs;
};

/* Sections to add from file. */
struct sec_add {
	char *name;
	char *content;
	size_t size;

	STAILQ_ENTRY(sec_add) sadds;
};

/* Section extent */
struct section {
	const char *name;
	size_t off;
	size_t size;

	TAILQ_ENTRY(section) sec_next;
};

/* Segment extent */
struct segment {
	size_t off;
	size_t fsize;
	size_t msize;

	char remove;

	TAILQ_HEAD(sec_head, section) v_sec;
};


/*
 * Structure encapsulates the "global" data for "elfcopy" program.
 */
struct elfcopy {
	const char *progname;	/* program name */

	/* Format convertion not supported yet. */
	int infmt;
	int outfmt;

	/* elfclass of intput object */
	int iec;
	/* elfclass of output object */
	int oec;
	/* ELF descriptor of input object */
	Elf *ein;
	/* ELF descriptor of output object */
	Elf *eout;
	/*
	 * keep track of the number of sections of output object.
	 */
	int os_cnt;
	/*
	 * number of program headers of input object;
	 */
	int iphnum;
	/*
	 * number of program headers of output object;
	 */
	int ophnum;
	/*
	 * flags indicating whether there exist sections
	 * to add/remove/(only)copy. FIXME use bit instead.
	 */
	int sections_to_add;
	int sections_to_append;
	int sections_to_compress;
	int sections_to_print;
	int sections_to_remove;
	int sections_to_copy;

	/* buffer for .shstrtab section */
	char *shstrtab;
	char *old_shstrtab;
	size_t shstrtab_cap;
	size_t shstrtab_size;

	enum {
		STRIP_NONE = 0,
		STRIP_ALL,
		STRIP_DEBUG,
		STRIP_NONDEBUG,
		STRIP_UNNEEDED
	} strip;

	Elf_Scn *symscn;
	union {
		Elf32_Sym *symtab32;
		Elf64_Sym *symtab64;
	} st;
	size_t symtab_cnt;
	size_t symtab_cap;
	size_t symtab_size;
	size_t symtab_orig_size;
	size_t symtab_align;

	Elf_Scn *strscn;
	char *strtab;
	size_t strtab_cap;
	size_t strtab_size;
	size_t strtab_orig_size;

	char *mcsbuf;
	size_t mcsbuf_cap;
	size_t mcsbuf_size;

#define	EXECUTABLE	0x0001
#define	DYNAMIC		0x0002
#define	RELOCATABLE	0x0004
#define	SYMTAB_EXIST	0x0010
#define	SYMTAB_INTACT	0x0020

	int flags;

	/* bit vector to mark symbols involving relocation */
	unsigned char *v_rel;

	struct segment *v_seg;

	STAILQ_HEAD(, sec_action) v_sac;
	STAILQ_HEAD(, sec_add) v_sadd;
	/* list of symbols to strip */
	STAILQ_HEAD(, symlist) v_sym_strip;
	/* list of symbols to keep */
	STAILQ_HEAD(, symlist) v_sym_keep;
};

size_t	add_sections(struct elfcopy *ecp, size_t off);
void	add_to_keep_list(struct elfcopy *ecp, const char *name);
void	add_to_strip_list(struct elfcopy *ecp, const char *name);
void	add_to_sec_list(struct segment *seg, struct section *sec);
void	copy_data(Elf_Scn *is, Elf_Scn *os);
void	copy_phdr(struct elfcopy *ecp);
void	create_shdr(struct elfcopy *ecp, Elf_Scn *is, Elf_Scn *os,
	    const char *name);
size_t	create_sections(struct elfcopy *ecp, size_t off);
size_t	create_shstrtab(struct elfcopy *ecp, size_t off);
size_t	create_symtab(struct elfcopy *ecp, size_t off);
int	find_duplicate(const char *tab, const char *s, int sz);
struct sec_action *lookup_sec_act(struct elfcopy *ecp,
	    const char *name, int add);
void	mcs_sections(struct elfcopy *ecp);
void	remove_section(struct elfcopy *ecp, GElf_Shdr *sh, const char *name);
void	resync_shname(struct elfcopy *ecp);
void	setup_phdr(struct elfcopy *ecp);
