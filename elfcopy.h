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

	STAILQ_ENTRY(symlist) sym_list;
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

	STAILQ_ENTRY(sec_action) sac_list;
};

/* Sections to add from file. */
struct sec_add {
	char *name;
	char *content;
	size_t size;

	STAILQ_ENTRY(sec_add) sadd_list;
};

/* Internal data structure for sections. */
struct section {
	const char *name;
	Elf_Scn *is;		/* input scn */
	Elf_Scn *os;		/* output scn */
	void *buf;		/* section content */
	uint64_t off;		/* section offset */
	uint64_t sz;		/* section size */
	uint64_t cap;		/* section capacity */
	uint64_t align;		/* section alignment */
	uint64_t type;		/* section type */
	int ndx;		/* original index */
	int loadable;		/* whether loadable */
	int pseudo;

	TAILQ_ENTRY(section) sec_list;	/* list of all sections */
	TAILQ_ENTRY(section) in_seg; /* list of sections in a segment */
};

/* Internal data structure for segments. */
struct segment {
	uint64_t off;
	uint64_t fsz;		/* file size */
	uint64_t msz;		/* memory size */
	uint64_t type;

	int remove;

	TAILQ_HEAD(sec_head, section) v_sec;
	STAILQ_ENTRY(segment) seg_list;
};

/*
 * Structure encapsulates the "global" data for "elfcopy" program.
 */
struct elfcopy {
	const char *progname;	/* program name */

	/* Format convertion not supported yet. */
	int infmt;
	int outfmt;
	
	int iec;	/* elfclass of intput object */
	int oec;	/* elfclass of output object */
	Elf *ein;	/* ELF descriptor of input object */
	Elf *eout;	/* ELF descriptor of output object */

	int iphnum;	/* number of program headers of input object */
	int ophnum;	/* number of program headers of output object */

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

	struct section *symtab;
	struct section *strtab;
	struct section *shstrtab;
	
	enum {
		STRIP_NONE = 0,
		STRIP_ALL,
		STRIP_DEBUG,
		STRIP_NONDEBUG,
		STRIP_UNNEEDED
	} strip;

#define	EXECUTABLE	0x0001
#define	DYNAMIC		0x0002
#define	RELOCATABLE	0x0004
#define	SYMTAB_EXIST	0x0010
#define	SYMTAB_INTACT	0x0020
#define SYMTAB_CREATED	0x0040

	int flags;

	/* bit vector to mark symbols involving relocation */
	unsigned char *v_rel;

	STAILQ_HEAD(, segment) v_seg;
	STAILQ_HEAD(, sec_action) v_sac;
	STAILQ_HEAD(, sec_add) v_sadd;
	/* list of symbols to strip */
	STAILQ_HEAD(, symlist) v_sym_strip;
	/* list of symbols to keep */
	STAILQ_HEAD(, symlist) v_sym_keep;
	/* list of internal section structure */
	TAILQ_HEAD(, section) v_sec;
	/* list of modified section data buffers */
	SLIST_HEAD(, section) v_mdat;
};

void	add_unloadables(struct elfcopy *ecp);
void	add_to_keep_list(struct elfcopy *ecp, const char *name);
void	add_to_strip_list(struct elfcopy *ecp, const char *name);
int	add_to_inseg_list(struct elfcopy *ecp, struct section *sec);
void	copy_content(struct elfcopy *ecp);
void	copy_data(Elf_Scn *is, Elf_Scn *os);
void	copy_phdr(struct elfcopy *ecp);
void	copy_shdr(struct elfcopy *ecp, Elf_Scn *is, Elf_Scn *os,
	    const char *name);
void	create_scn(struct elfcopy *ecp);
void	create_symtab(struct elfcopy *ecp);
int	find_duplicate(const char *tab, const char *s, int sz);
struct section *insert_shtab(struct elfcopy *ecp);
void	insert_to_strtab(struct section *t, const char *s);
struct sec_action *lookup_sec_act(struct elfcopy *ecp,
	    const char *name, int add);
int	lookup_string(struct section *t, const char *s);
void	resync_sections(struct elfcopy *ecp);
void	set_shstrtab(struct elfcopy *ecp);
void	setup_phdr(struct elfcopy *ecp);
