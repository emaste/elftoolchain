/*-
 * Copyright (c) 2003 David O'Brien.  All rights reserved.
 * Copyright (c) 2001 Jake Burkholder
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

#include <sys/cdefs.h>
__FBSDID("$FreeBSD: src/usr.bin/elfdump/elfdump.c,v 1.14 2006/01/28 17:58:22 marcel Exp $");

#include <sys/param.h>
#include <sys/stat.h>
#include <sys/endian.h>
#include <err.h>
#include <fcntl.h>
#include <gelf.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <sysexits.h>
#include <string.h>
#include <unistd.h>

#ifdef USE_LIBARCHIVE_AR
#include <archive.h>
#include <archive_entry.h>
#endif	/* USE_LIBARCHIVE_AR */

/*
 * elfdump(1) options.
 */
#define	ED_DYN		(1<<0)
#define	ED_EHDR		(1<<1)
#define	ED_GOT		(1<<2)
#define	ED_HASH		(1<<3)
#define	ED_INTERP	(1<<4)
#define	ED_NOTE		(1<<5)
#define	ED_PHDR		(1<<6)
#define	ED_REL		(1<<7)
#define	ED_SHDR		(1<<8)
#define	ED_SYMTAB	(1<<9)
#define	ED_ALL		((1<<10)-1)

/*
 * elfdump(1) run control flags.
 */
#define	DISPLAY_FILENAME	0x0001
#define	SECTIONS_LOADED		0x0002

/*
 * Internal data structure for sections.
 */
struct section {
	const char	*name;		/* section name */
	Elf_Scn		*scn;		/* section scn */
	uint64_t	 off;		/* section offset */
	uint64_t	 sz;		/* section size */
	uint64_t	 entsize;	/* section entsize */
	uint64_t	 align;		/* section alignment */
	uint64_t	 type;		/* section type */
	uint64_t	 flags;		/* section flags */
	uint64_t	 addr;		/* section virtual addr */
	uint32_t	 link;		/* section link ndx */
	uint32_t	 info;		/* section info ndx */
};

/*
 * Structure encapsulates the global data for readelf(1).
 */
struct elfdump {
	FILE		*out;		/* output redirection. */
	const char	*filename;	/* current processing file. */
	int		 options;	/* command line options. */
	int		 flags;		/* run control flags. */
	Elf		*elf;		/* underlying ELF descriptor. */
	GElf_Ehdr	 ehdr;		/* ELF header. */
	int		 ec;		/* ELF class. */
	size_t		 shnum;		/* #sections. */
	struct section	*sl;		/* list of sections. */
};

/* http://www.sco.com/developers/gabi/latest/ch5.dynamic.html#tag_encodings */
static const char *
d_tags(uint64_t tag)
{
	switch (tag) {
	case 0: return "DT_NULL";
	case 1: return "DT_NEEDED";
	case 2: return "DT_PLTRELSZ";
	case 3: return "DT_PLTGOT";
	case 4: return "DT_HASH";
	case 5: return "DT_STRTAB";
	case 6: return "DT_SYMTAB";
	case 7: return "DT_RELA";
	case 8: return "DT_RELASZ";
	case 9: return "DT_RELAENT";
	case 10: return "DT_STRSZ";
	case 11: return "DT_SYMENT";
	case 12: return "DT_INIT";
	case 13: return "DT_FINI";
	case 14: return "DT_SONAME";
	case 15: return "DT_RPATH";
	case 16: return "DT_SYMBOLIC";
	case 17: return "DT_REL";
	case 18: return "DT_RELSZ";
	case 19: return "DT_RELENT";
	case 20: return "DT_PLTREL";
	case 21: return "DT_DEBUG";
	case 22: return "DT_TEXTREL";
	case 23: return "DT_JMPREL";
	case 24: return "DT_BIND_NOW";
	case 25: return "DT_INIT_ARRAY";
	case 26: return "DT_FINI_ARRAY";
	case 27: return "DT_INIT_ARRAYSZ";
	case 28: return "DT_FINI_ARRAYSZ";
	case 29: return "DT_RUNPATH";
	case 30: return "DT_FLAGS";
	case 32: return "DT_PREINIT_ARRAY"; /* XXX: DT_ENCODING */
	case 33: return "DT_PREINIT_ARRAYSZ";
	/* 0x6000000D - 0x6ffff000 operating system-specific semantics */
	case 0x6ffffdf5: return "DT_GNU_PRELINKED";
	case 0x6ffffdf6: return "DT_GNU_CONFLICTSZ";
	case 0x6ffffdf7: return "DT_GNU_LIBLISTSZ";
	case 0x6ffffdf8: return "DT_SUNW_CHECKSUM";
	case 0x6ffffdf9: return "DT_PLTPADSZ";
	case 0x6ffffdfa: return "DT_MOVEENT";
	case 0x6ffffdfb: return "DT_MOVESZ";
	case 0x6ffffdfc: return "DT_FEATURE";
	case 0x6ffffdfd: return "DT_POSFLAG_1";
	case 0x6ffffdfe: return "DT_SYMINSZ";
	case 0x6ffffdff: return "DT_SYMINENT (DT_VALRNGHI)";
	case 0x6ffffe00: return "DT_ADDRRNGLO";
	case 0x6ffffef8: return "DT_GNU_CONFLICT";
	case 0x6ffffef9: return "DT_GNU_LIBLIST";
	case 0x6ffffefa: return "DT_SUNW_CONFIG";
	case 0x6ffffefb: return "DT_SUNW_DEPAUDIT";
	case 0x6ffffefc: return "DT_SUNW_AUDIT";
	case 0x6ffffefd: return "DT_SUNW_PLTPAD";
	case 0x6ffffefe: return "DT_SUNW_MOVETAB";
	case 0x6ffffeff: return "DT_SYMINFO (DT_ADDRRNGHI)";
	case 0x6ffffff9: return "DT_RELACOUNT";
	case 0x6ffffffa: return "DT_RELCOUNT";
	case 0x6ffffffb: return "DT_FLAGS_1";
	case 0x6ffffffc: return "DT_VERDEF";
	case 0x6ffffffd: return "DT_VERDEFNUM";
	case 0x6ffffffe: return "DT_VERNEED";
	case 0x6fffffff: return "DT_VERNEEDNUM";
	case 0x6ffffff0: return "DT_GNU_VERSYM";
	/* 0x70000000 - 0x7fffffff processor-specific semantics */
	case 0x70000000: return "DT_IA_64_PLT_RESERVE";
	case 0x7ffffffd: return "DT_SUNW_AUXILIARY";
	case 0x7ffffffe: return "DT_SUNW_USED";
	case 0x7fffffff: return "DT_SUNW_FILTER";
	default: return "ERROR: TAG NOT DEFINED";
	}
}

static const char *
e_machines(unsigned int mach)
{
	static char machdesc[64];

	switch (mach) {
	case EM_NONE:	return "EM_NONE";
	case EM_M32:	return "EM_M32";
	case EM_SPARC:	return "EM_SPARC";
	case EM_386:	return "EM_386";
	case EM_68K:	return "EM_68K";
	case EM_88K:	return "EM_88K";
	case EM_860:	return "EM_860";
	case EM_MIPS:	return "EM_MIPS";
	case EM_PPC:	return "EM_PPC";
	case EM_ARM:	return "EM_ARM";
	case EM_ALPHA:	return "EM_ALPHA (legacy)";
	case EM_SPARCV9:return "EM_SPARCV9";
	case EM_IA_64:	return "EM_IA_64";
	case EM_X86_64:	return "EM_X86_64";
	}
	snprintf(machdesc, sizeof(machdesc),
	    "(unknown machine) -- type 0x%x", mach);
	return (machdesc);
}

static const char *e_types[] = {
	"ET_NONE", "ET_REL", "ET_EXEC", "ET_DYN", "ET_CORE"
};

static const char *ei_versions[] = {
	"EV_NONE", "EV_CURRENT"
};

static const char *ei_classes[] = {
	"ELFCLASSNONE", "ELFCLASS32", "ELFCLASS64"
};

static const char *ei_data[] = {
	"ELFDATANONE", "ELFDATA2LSB", "ELFDATA2MSB"
};

static const char *ei_abis[] = {
	"ELFOSABI_SYSV", "ELFOSABI_HPUX", "ELFOSABI_NETBSD", "ELFOSABI_LINUX",
	"ELFOSABI_HURD", "ELFOSABI_86OPEN", "ELFOSABI_SOLARIS",
	"ELFOSABI_MONTEREY", "ELFOSABI_IRIX", "ELFOSABI_FREEBSD",
	"ELFOSABI_TRU64", "ELFOSABI_MODESTO", "ELFOSABI_OPENBSD"
};

static const char *p_types[] = {
	"PT_NULL", "PT_LOAD", "PT_DYNAMIC", "PT_INTERP", "PT_NOTE",
	"PT_SHLIB", "PT_PHDR", "PT_TLS"
};

static const char *p_flags[] = {
	"", "PF_X", "PF_W", "PF_X|PF_W", "PF_R", "PF_X|PF_R", "PF_W|PF_R",
	"PF_X|PF_W|PF_R"
};

/* http://www.sco.com/developers/gabi/latest/ch4.sheader.html#sh_type */
static const char *
sh_types(u_int64_t sht) {
	switch (sht) {
	case 0:	return "SHT_NULL";
	case 1: return "SHT_PROGBITS";
	case 2: return "SHT_SYMTAB";
	case 3: return "SHT_STRTAB";
	case 4: return "SHT_RELA";
	case 5: return "SHT_HASH";
	case 6: return "SHT_DYNAMIC";
	case 7: return "SHT_NOTE";
	case 8: return "SHT_NOBITS";
	case 9: return "SHT_REL";
	case 10: return "SHT_SHLIB";
	case 11: return "SHT_DYNSYM";
	case 14: return "SHT_INIT_ARRAY";
	case 15: return "SHT_FINI_ARRAY";
	case 16: return "SHT_PREINIT_ARRAY";
	case 17: return "SHT_GROUP";
	case 18: return "SHT_SYMTAB_SHNDX";
	/* 0x60000000 - 0x6fffffff operating system-specific semantics */
	case 0x6ffffff0: return "XXX:VERSYM";
	case 0x6ffffff7: return "SHT_GNU_LIBLIST";
	case 0x6ffffffc: return "XXX:VERDEF";
	case 0x6ffffffd: return "SHT_SUNW(GNU)_verdef";
	case 0x6ffffffe: return "SHT_SUNW(GNU)_verneed";
	case 0x6fffffff: return "SHT_SUNW(GNU)_versym";
	/* 0x70000000 - 0x7fffffff processor-specific semantics */
	case 0x70000000: return "SHT_IA_64_EXT";
	case 0x70000001: return "SHT_IA_64_UNWIND";
	case 0x7ffffffd: return "XXX:AUXILIARY";
	case 0x7fffffff: return "XXX:FILTER";
	/* 0x80000000 - 0xffffffff application programs */
	default: return "ERROR: SHT NOT DEFINED";
	}
}

static const char *sh_flags[] = {
	"", "SHF_WRITE", "SHF_ALLOC", "SHF_WRITE|SHF_ALLOC", "SHF_EXECINSTR",
	"SHF_WRITE|SHF_EXECINSTR", "SHF_ALLOC|SHF_EXECINSTR",
	"SHF_WRITE|SHF_ALLOC|SHF_EXECINSTR"
};

static const char *st_types[] = {
	"STT_NOTYPE", "STT_OBJECT", "STT_FUNC", "STT_SECTION", "STT_FILE"
};

static const char *st_bindings[] = {
	"STB_LOCAL", "STB_GLOBAL", "STB_WEAK"
};

static void	elf_print_object(struct elfdump *ed);
static void	elf_print_elf(struct elfdump *ed);
static void	elf_print_ehdr(struct elfdump *ed);
static void	elf_print_phdr(struct elfdump *ed);
static void	elf_print_shdr(struct elfdump *ed);
static void	elf_print_symtab(struct elfdump *ed, int i);
static void	elf_print_symtabs(struct elfdump *ed);
static void	elf_print_interp(struct elfdump *ed);
static void	elf_print_dynamic(struct elfdump *ed);
static void	elf_print_rela(struct elfdump *ed);
static void	elf_print_rel(struct elfdump *ed);
static void	elf_print_got(struct elfdump *ed);
static void	elf_print_note(struct elfdump *ed);
static void	elf_print_hash(struct elfdump *ed);
static void	load_sections(struct elfdump *ed);
static void	usage(void);
#ifdef USE_LIBARCHIVE_AR
static int	ac_detect_ar(int fd);
static void	ac_print_ar(struct elfdump *ed, int fd);
#endif	/* USE_LIBARCHIVE_AR */

int
main(int ac, char **av)
{
	struct elfdump	*ed, ed_storage;
	int		 ch, i;

	ed = &ed_storage;
	memset(ed, 0, sizeof(*ed));

	ed->out = stdout;
	while ((ch = getopt(ac, av, "acdeiGhnprsw:")) != -1)
		switch (ch) {
		case 'a':
			ed->options = ED_ALL;
			break;
		case 'c':
			ed->options |= ED_SHDR;
			break;
		case 'd':
			ed->options |= ED_DYN;
			break;
		case 'e':
			ed->options |= ED_EHDR;
			break;
		case 'i':
			ed->options |= ED_INTERP;
			break;
		case 'G':
			ed->options |= ED_GOT;
			break;
		case 'h':
			ed->options |= ED_HASH;
			break;
		case 'n':
			ed->options |= ED_NOTE;
			break;
		case 'p':
			ed->options |= ED_PHDR;
			break;
		case 'r':
			ed->options |= ED_REL;
			break;
		case 's':
			ed->options |= ED_SYMTAB;
			break;
		case 'w':
			if ((ed->out = fopen(optarg, "w")) == NULL)
				err(EX_NOINPUT, "%s", optarg);
			break;
		case '?':
		default:
			usage();
		}

	ac -= optind;
	av += optind;

	if (ac == 0 || ed->options == 0)
		usage();

	if (ac > 1)
		ed->flags |= DISPLAY_FILENAME;

	if (elf_version(EV_CURRENT) == EV_NONE)
		errx(EX_SOFTWARE, "ELF library initialization failed: %s",
		    elf_errmsg(-1));

	for (i = 0; i < ac; i++)
		if (av[i] != NULL) {
			ed->filename = av[i];
			elf_print_object(ed);
		}

	exit(EX_OK);
}

#ifdef USE_LIBARCHIVE_AR
/*
 * Convenient wrapper for general libarchive error handling.
 */
#define	AC(CALL) do {							\
	if ((CALL))							\
		errx(EX_SOFTWARE, "%s", archive_error_string(a));	\
} while (0)

static int
ac_detect_ar(int fd)
{
	struct archive		*a;
	struct archive_entry	*entry;
	int			 r;

	r = -1;
	if ((a = archive_read_new()) == NULL)
		return (0);
	archive_read_support_compression_all(a);
	archive_read_support_format_ar(a);
	if (archive_read_open_fd(a, fd, 10240) == ARCHIVE_OK)
		r = archive_read_next_header(a, &entry);
	archive_read_close(a);
	archive_read_finish(a);

	return (r == ARCHIVE_OK);
}

static void
ac_print_ar(struct elfdump *ed, int fd)
{
	struct archive		*a;
	struct archive_entry	*entry;
	const char		*name;
	void			*buff;
	size_t			 size;
	int			 r;

	if (lseek(fd, 0, SEEK_SET) == -1)
		err(EX_IOERR, "lseek failed");
	if ((a = archive_read_new()) == NULL)
		errx(EX_SOFTWARE, "%s", archive_error_string(a));
	archive_read_support_compression_all(a);
	archive_read_support_format_ar(a);
	AC(archive_read_open_fd(a, fd, 10240));
	for(;;) {
		r = archive_read_next_header(a, &entry);
		if (r == ARCHIVE_FATAL)
			errx(EX_DATAERR, "%s", archive_error_string(a));
		if (r == ARCHIVE_EOF)
			break;
		if (r == ARCHIVE_WARN || r == ARCHIVE_RETRY)
			warnx("%s", archive_error_string(a));
		if (r == ARCHIVE_RETRY)
			continue;

		name = archive_entry_pathname(entry);

		/* TODO: handle option '-c' here. */

		/* skip pseudo members. */
		if (strcmp(name, "/") == 0 || strcmp(name, "//") == 0)
			continue;

		size = archive_entry_size(entry);
		if (size > 0) {
			if ((buff = malloc(size)) == NULL)
				err(EX_SOFTWARE, "malloc failed");
			if (archive_read_data(a, buff, size) != (ssize_t)size) {
				warnx("%s", archive_error_string(a));
				free(buff);
				continue;
			}
			if ((ed->elf = elf_memory(buff, size)) == NULL) {
				warnx("elf_memroy() failed: %s",
				    elf_errmsg(-1));
				free(buff);
				continue;
			}
			elf_print_elf(ed);
			free(buff);
		}
	}
	AC(archive_read_close(a));
	AC(archive_read_finish(a));
}
#endif	/* USE_LIBARCHIVE_AR */

static void
elf_print_object(struct elfdump *ed)
{
	int fd;

	if ((fd = open(ed->filename, O_RDONLY)) == -1) {
		warn("open %s failed", ed->filename);
		return;
	}

#ifdef	USE_LIBARCHIVE_AR
	/*
	 * Detect and process ar(1) archive using libarchive.
	 */
	if (ac_detect_ar(fd)) {
		ac_print_ar(ed, fd);
		return;
	}
#endif	/* USE_LIBARCHIVE_AR */

	if ((ed->flags & DISPLAY_FILENAME) != 0)
		printf("\nFile: %s\n", ed->filename);

	if ((ed->elf = elf_begin(fd, ELF_C_READ, NULL)) == NULL) {
		warnx("elf_begin() failed: %s", elf_errmsg(-1));
		return;
	}

	switch (elf_kind(ed->elf)) {
	case ELF_K_NONE:
		warnx("Not an ELF file.");
		return;
	case ELF_K_ELF:
		elf_print_elf(ed);
		break;
	case ELF_K_AR:
		/* dump_ar(re); */
		break;
	default:
		warnx("Internal: libelf returned unknown elf kind.");
		return;
	}

	elf_end(ed->elf);
}

static void
elf_print_elf(struct elfdump *ed)
{

	/* Fetch ELF header. No need to continue if this fails. */
	if (gelf_getehdr(ed->elf, &ed->ehdr) == NULL) {
		warnx("gelf_getehdr failed: %s", elf_errmsg(-1));
		return;
	}
	if ((ed->ec = gelf_getclass(ed->elf)) == ELFCLASSNONE) {
		warnx("gelf_getclass failed: %s", elf_errmsg(-1));
		return;
	}

	load_sections(ed);

	if (ed->options & ED_EHDR)
		elf_print_ehdr(ed);
	if (ed->options & ED_PHDR)
		elf_print_phdr(ed);
	if (ed->options & ED_INTERP)
		elf_print_interp(ed);
	if (ed->options & ED_SHDR)
		elf_print_shdr(ed);
	if (ed->options & ED_DYN)
		elf_print_dynamic(ed);
	if (ed->options & ED_REL) {
		elf_print_rel(ed);
		elf_print_rela(ed);
	}
	if (ed->options & ED_GOT)
		elf_print_got(ed);
	if (ed->options & ED_SYMTAB)
		elf_print_symtabs(ed);
	if (ed->options & ED_NOTE)
		elf_print_note(ed);
	if (ed->options & ED_HASH)
		elf_print_hash(ed);
}

static void
load_sections(struct elfdump *ed)
{
	struct section	*s;
	const char	*name;
	Elf_Scn		*scn;
	GElf_Shdr	 sh;
	size_t		 shstrndx, ndx;
	int		 elferr;


	if (ed->flags & SECTIONS_LOADED)
		return;

	/* Allocate storage for internal section list. */
	if (!elf_getshnum(ed->elf, &ed->shnum)) {
		warnx("elf_getshnum failed: %s", elf_errmsg(-1));
		return;
	}
	if (ed->sl != NULL)
		free(ed->sl);
	if ((ed->sl = calloc(ed->shnum, sizeof(*ed->sl))) == NULL)
		err(EX_SOFTWARE, "calloc failed");

	/* Get the index of .shstrtab section. */
	if (!elf_getshstrndx(ed->elf, &shstrndx)) {
		warnx("elf_getshstrndx failed: %s", elf_errmsg(-1));
		return;
	}

	if ((scn = elf_getscn(ed->elf, 0)) == NULL) {
		warnx("elf_getscn failed: %s", elf_errmsg(-1));
		return;
	}

	(void) elf_errno();
	do {
		if (gelf_getshdr(scn, &sh) == NULL) {
			warnx("gelf_getshdr failed: %s", elf_errmsg(-1));
			(void) elf_errno();
			continue;
		}
		if ((name = elf_strptr(ed->elf, shstrndx, sh.sh_name)) == NULL) {
			(void) elf_errno();
			name = "ERROR";
		}
		if ((ndx = elf_ndxscn(scn)) == SHN_UNDEF) {
			if ((elferr = elf_errno()) != 0)
				warnx("elf_ndxscn failed: %s",
				    elf_errmsg(elferr));
			continue;
		}
		if (ndx >= ed->shnum) {
			warnx("section index of '%s' out of range", name);
			continue;
		}
		s = &ed->sl[ndx];
		s->name = name;
		s->scn = scn;
		s->off = sh.sh_offset;
		s->sz = sh.sh_size;
		s->entsize = sh.sh_entsize;
		s->align = sh.sh_addralign;
		s->type = sh.sh_type;
		s->flags = sh.sh_flags;
		s->addr = sh.sh_addr;
		s->link = sh.sh_link;
		s->info = sh.sh_info;
	} while ((scn = elf_nextscn(ed->elf, scn)) != NULL);
	elferr = elf_errno();
	if (elferr != 0)
		warnx("elf_nextscn failed: %s", elf_errmsg(elferr));

	ed->flags |= SECTIONS_LOADED;
}

static void
elf_print_ehdr(struct elfdump *ed)
{

	fprintf(ed->out, "\nelf header:\n");
	fprintf(ed->out, "\n");
	fprintf(ed->out, "\te_ident: %s %s %s\n",
	    ei_classes[ed->ehdr.e_ident[EI_CLASS]],
	    ei_data[ed->ehdr.e_ident[EI_DATA]],
	    ei_abis[ed->ehdr.e_ident[EI_OSABI]]);
	fprintf(ed->out, "\te_type: %s\n", e_types[ed->ehdr.e_type]);
	fprintf(ed->out, "\te_machine: %s\n", e_machines(ed->ehdr.e_machine));
	fprintf(ed->out, "\te_version: %s\n", ei_versions[ed->ehdr.e_version]);
	fprintf(ed->out, "\te_entry: %#jx\n", (uintmax_t)ed->ehdr.e_entry);
	fprintf(ed->out, "\te_phoff: %ju\n", (uintmax_t)ed->ehdr.e_phoff);
	fprintf(ed->out, "\te_shoff: %ju\n", (uintmax_t)ed->ehdr.e_shoff);
	fprintf(ed->out, "\te_flags: %ju\n", (uintmax_t)ed->ehdr.e_flags);
	fprintf(ed->out, "\te_ehsize: %ju\n", (uintmax_t)ed->ehdr.e_ehsize);
	fprintf(ed->out, "\te_phentsize: %ju\n",
	    (uintmax_t)ed->ehdr.e_phentsize);
	fprintf(ed->out, "\te_phnum: %ju\n", (uintmax_t)ed->ehdr.e_phnum);
	fprintf(ed->out, "\te_shentsize: %ju\n",
	    (uintmax_t)ed->ehdr.e_shentsize);
	fprintf(ed->out, "\te_shnum: %ju\n", (uintmax_t)ed->ehdr.e_shnum);
	fprintf(ed->out, "\te_shstrndx: %ju\n", (uintmax_t)ed->ehdr.e_shstrndx);
}

static void
elf_print_phdr(struct elfdump *ed)
{
	GElf_Phdr	 phdr;
	size_t		 phnum;
	int		 i;

	if (elf_getphnum(ed->elf, &phnum) == 0) {
		warnx("elf_getphnum failed: %s", elf_errmsg(-1));
		return;
	}
	fprintf(ed->out, "\nprogram header:\n");
	for (i = 0; (u_int64_t) i < phnum; i++) {
		if (gelf_getphdr(ed->elf, i, &phdr) != &phdr) {
			warnx("elf_getphdr failed: %s", elf_errmsg(-1));
			continue;
		}
		fprintf(ed->out, "\n");
		fprintf(ed->out, "entry: %d\n", i);
		fprintf(ed->out, "\tp_type: %s\n", p_types[phdr.p_type & 0x7]);
		fprintf(ed->out, "\tp_offset: %ju\n", (uintmax_t)phdr.p_offset);
		fprintf(ed->out, "\tp_vaddr: %#jx\n", (uintmax_t)phdr.p_vaddr);
		fprintf(ed->out, "\tp_paddr: %#jx\n", (uintmax_t)phdr.p_paddr);
		fprintf(ed->out, "\tp_filesz: %ju\n", (uintmax_t)phdr.p_filesz);
		fprintf(ed->out, "\tp_memsz: %ju\n", (uintmax_t)phdr.p_memsz);
		fprintf(ed->out, "\tp_flags: %s\n", p_flags[phdr.p_flags]);
		fprintf(ed->out, "\tp_align: %ju\n", (uintmax_t)phdr.p_align);
	}
}

static void
elf_print_shdr(struct elfdump *ed)
{
	struct section *s;
	int i;

	if ((ed->flags & SECTIONS_LOADED) == 0)
		return;
	fprintf(ed->out, "\nsection header:\n");

	for (i = 0; (size_t)i < ed->shnum; i++) {
		s = &ed->sl[i];
		fprintf(ed->out, "\n");
		fprintf(ed->out, "entry: %ju\n", (uintmax_t)i);
		fprintf(ed->out, "\tsh_name: %s\n", s->name);
		fprintf(ed->out, "\tsh_type: %s\n", sh_types(s->type));
		fprintf(ed->out, "\tsh_flags: %s\n", sh_flags[s->flags & 0x7]);
		fprintf(ed->out, "\tsh_addr: %#jx\n", s->addr);
		fprintf(ed->out, "\tsh_offset: %ju\n", (uintmax_t)s->off);
		fprintf(ed->out, "\tsh_size: %ju\n", (uintmax_t)s->sz);
		fprintf(ed->out, "\tsh_link: %ju\n", (uintmax_t)s->link);
		fprintf(ed->out, "\tsh_info: %ju\n", (uintmax_t)s->info);
		fprintf(ed->out, "\tsh_addralign: %ju\n", (uintmax_t)s->align);
		fprintf(ed->out, "\tsh_entsize: %ju\n", (uintmax_t)s->entsize);
	}
}

static void
elf_print_symtab(struct elfdump *ed, int i)
{
	struct section	*s;
	const char	*name;
	Elf_Data	*data;
	GElf_Sym	 sym;
	int		 len, j, strndx, elferr;

	s = &ed->sl[i];
	strndx = s->link;
	fprintf(ed->out, "\nsymbol table (%s):\n", s->name);
	(void) elf_errno();
	if ((data = elf_getdata(s->scn, NULL)) == NULL) {
		elferr = elf_errno();
		if (elferr != 0)
			warnx("elf_getdata failed: %s", elf_errmsg(elferr));
		return;
	}

	len = data->d_size / s->entsize;
	for (j = 0; j < len; j++) {
		if (gelf_getsym(data, j, &sym) != &sym) {
			warnx("gelf_getsym failed: %s", elf_errmsg(-1));
			continue;
		}
		if ((name = elf_strptr(ed->elf, strndx, sym.st_name)) ==
		    NULL)
			name = "";
		fprintf(ed->out, "\n");
		fprintf(ed->out, "entry: %d\n", j);
		fprintf(ed->out, "\tst_name: %s\n", name);
		fprintf(ed->out, "\tst_value: %#jx\n", sym.st_value);
		fprintf(ed->out, "\tst_size: %ju\n", (uintmax_t)sym.st_size);
		fprintf(ed->out, "\tst_info: %s %s\n",
		    st_types[GELF_ST_TYPE(sym.st_info)],
		    st_bindings[GELF_ST_BIND(sym.st_info)]);
		fprintf(ed->out, "\tst_shndx: %ju\n", (uintmax_t)sym.st_shndx);
	}
}

static void
elf_print_symtabs(struct elfdump *ed)
{
	int i;

	if ((ed->flags & SECTIONS_LOADED) == 0 || ed->shnum == 0)
		return;
	for (i = 0; (size_t)i < ed->shnum; i++) {
		if (ed->sl[i].type == SHT_SYMTAB ||
		    ed->sl[i].type == SHT_DYNSYM)
			elf_print_symtab(ed, i);
	}
}

static void
elf_print_dynamic(struct elfdump *ed)
{
	struct section	*s;
	const char	*name;
	Elf_Data	*data;
	GElf_Dyn	 dyn;
	int		 elferr;
	int		 i;
	int		 len;

	if ((ed->flags & SECTIONS_LOADED) == 0 || ed->shnum == 0)
		return;
	for (i = 0; (size_t)i < ed->shnum; i++) {
		s = &ed->sl[i];
		if (s->type == SHT_DYNAMIC)
			break;
	}
	if ((size_t)i >= ed->shnum)
		return;

	fprintf(ed->out, "\ndynamic:\n");
	(void) elf_errno();
	if ((data = elf_getdata(s->scn, NULL)) == NULL) {
		elferr = elf_errno();
		if (elferr != 0)
			warnx("elf_getdata failed: %s", elf_errmsg(elferr));
		return;
	}
	len = data->d_size / s->entsize;
	for (i = 0; i < len; i++) {
		if (gelf_getdyn(data, i, &dyn) != &dyn) {
			warnx("gelf_getdyn failed: %s", elf_errmsg(-1));
			continue;
		}
		fprintf(ed->out, "\n");
		fprintf(ed->out, "entry: %d\n", i);
		fprintf(ed->out, "\td_tag: %s\n", d_tags(dyn.d_tag));
		switch(dyn.d_tag) {
		case DT_NEEDED:
		case DT_SONAME:
		case DT_RPATH:
			if ((name = elf_strptr(ed->elf, s->link, dyn.d_un.d_val))
			    == NULL)
				name = "";
			fprintf(ed->out, "\td_val: %s\n", name);
			break;
		case DT_PLTRELSZ:
		case DT_RELA:
		case DT_RELASZ:
		case DT_RELAENT:
		case DT_STRSZ:
		case DT_SYMENT:
		case DT_RELSZ:
		case DT_RELENT:
		case DT_PLTREL:
			fprintf(ed->out, "\td_val: %ju\n",
			    (uintmax_t)dyn.d_un.d_val);
			break;
		case DT_PLTGOT:
		case DT_HASH:
		case DT_STRTAB:
		case DT_SYMTAB:
		case DT_INIT:
		case DT_FINI:
		case DT_REL:
		case DT_JMPREL:
			fprintf(ed->out, "\td_ptr: %#jx\n",
			    dyn.d_un.d_ptr);
			break;
		case DT_NULL:
		case DT_SYMBOLIC:
		case DT_DEBUG:
		case DT_TEXTREL:
			break;
		}
	}
}

static void
elf_print_rela(struct elfdump *ed)
{
	struct section	*s;
	Elf_Data	*data;
	GElf_Rela	 rela;
	int		 elferr;
	int		 i, j;
	int		 len;

	if ((ed->flags & SECTIONS_LOADED) == 0 || ed->shnum == 0)
		return;
	for (i = 0; (size_t)i < ed->shnum; i++) {
		s = &ed->sl[i];
		if (s->type != SHT_RELA)
			continue;
		fprintf(ed->out, "\nrelocation with addend (%s):\n", s->name);
		(void) elf_errno();
		if ((data = elf_getdata(s->scn, NULL)) == NULL) {
			elferr = elf_errno();
			if (elferr != 0)
				warnx("elf_getdata failed: %s",
				    elf_errmsg(elferr));
			return;
		}
		len = data->d_size / s->entsize;
		for (j = 0; j < len; j++) {
			if (gelf_getrela(data, j, &rela) != &rela) {
				warnx("gelf_getrela failed: %s",
				    elf_errmsg(-1));
				continue;
			}
			fprintf(ed->out, "\n");
			fprintf(ed->out, "entry: %d\n", j);
			fprintf(ed->out, "\tr_offset: %#jx\n", rela.r_offset);
			fprintf(ed->out, "\tr_info: %ju\n", rela.r_info);
			fprintf(ed->out, "\tr_addend: %jd\n", rela.r_addend);
		}
	}
}

static void
elf_print_rel(struct elfdump *ed)
{
	struct section	*s;
	Elf_Data	*data;
	GElf_Rel	 rel;
	int		 elferr;
	int		 i, j;
	int		 len;

	if ((ed->flags & SECTIONS_LOADED) == 0 || ed->shnum == 0)
		return;
	for (i = 0; (size_t)i < ed->shnum; i++) {
		s = &ed->sl[i];
		if (s->type != SHT_REL)
			continue;
		fprintf(ed->out, "\nrelocation (%s):\n", s->name);
		(void) elf_errno();
		if ((data = elf_getdata(s->scn, NULL)) == NULL) {
			elferr = elf_errno();
			if (elferr != 0)
				warnx("elf_getdata failed: %s",
				    elf_errmsg(elferr));
			return;
		}
		len = data->d_size / s->entsize;
		for (j = 0; j < len; j++) {
			if (gelf_getrel(data, j, &rel) != &rel) {
				warnx("gelf_getrel failed: %s", elf_errmsg(-1));
				continue;
			}
			fprintf(ed->out, "\n");
			fprintf(ed->out, "entry: %d\n", j);
			fprintf(ed->out, "\tr_offset: %#jx\n", rel.r_offset);
			fprintf(ed->out, "\tr_info: %ju\n", rel.r_info);
		}
	}
}

static void
elf_print_interp(struct elfdump *ed)
{
	const char *s;
	GElf_Phdr phdr;
	size_t phnum;
	int i;

	if ((s = elf_rawfile(ed->elf, NULL)) == NULL) {
		warnx("elf_rawfile failed: %s", elf_errmsg(-1));
		return;
	}
	if (!elf_getphnum(ed->elf, &phnum)) {
		warnx("elf_getphnum failed: %s", elf_errmsg(-1));
		return;
	}
	for (i = 0; (size_t)i < phnum; i++) {
		if (gelf_getphdr(ed->elf, i, &phdr) != &phdr) {
			warnx("elf_getphdr failed: %s", elf_errmsg(-1));
			continue;
		}
		if (phdr.p_type == PT_INTERP) {
			fprintf(ed->out, "\ninterp:\n");
			fprintf(ed->out, "\t%s\n", s + phdr.p_offset);
		}
	}
}

static void
elf_print_got(struct elfdump *ed)
{
	struct section	*s;
	Elf_Data	*data, dst;
	int		 elferr, i, len;

	if ((ed->flags & SECTIONS_LOADED) == 0 || ed->shnum == 0)
		return;
	for (i = 0; (size_t)i < ed->shnum; i++) {
		s = &ed->sl[i];
		if (!strcmp(s->name, ".got"))
			break;
	}
	if ((size_t)i >= ed->shnum)
		return;

	fprintf(ed->out, "\nglobal offset table:\n");
	(void) elf_errno();
	if ((data = elf_getdata(s->scn, NULL)) == NULL) {
		elferr = elf_errno();
		if (elferr != 0)
			warnx("elf_getdata failed: %s", elf_errmsg(elferr));
		return;
	}

	/*
	 * .got section has section type SHT_PROGBITS, thus libelf treats it as
	 * byte stream and will not perfrom any translation on it. As a result,
	 * an exlicit call to gelf_xlatetom is needed here. Depends on arch,
	 * .got section should be translated to either WORD or XWORD.
	 */
	if (ed->ec == ELFCLASS32)
		data->d_type = ELF_T_WORD;
	else
		data->d_type = ELF_T_XWORD;
	memcpy(&dst, data, sizeof(Elf_Data));
	if (gelf_xlatetom(ed->elf, &dst, data, ed->ehdr.e_ident[EI_DATA]) !=
	    &dst) {
		warnx("gelf_xlatetom failed: %s", elf_errmsg(-1));
		return;
	}
	len = dst.d_size / s->entsize;
	for(i = 0; i < len; i++) {
		fprintf(ed->out, "\nentry: %d\n", i);
		if (ed->ec == ELFCLASS32)
			fprintf(ed->out, "\t%#x\n",
			    *((uint32_t *)dst.d_buf + i));
		else
			fprintf(ed->out, "\t%#jx\n",
			    *((uint64_t *)dst.d_buf + i));
	}
}

static void
elf_print_note(struct elfdump *ed)
{
	struct section	*s;
	Elf_Data        *data;
	Elf_Note	*en;
	uint32_t	 namesz;
	uint32_t	 descsz;
	uint32_t	 desc;
	size_t		 count;
	int		 elferr, i;
	char		*src;

	for (i = 0; (size_t)i < ed->shnum; i++) {
		s = &ed->sl[i];
		if (s->type == SHT_NOTE && !strcmp(s->name, ".note.ABI-tag"))
			break;
	}
	if ((size_t)i >= ed->shnum)
		return;

	fprintf(ed->out, "\nnote (%s):\n", s->name);
	(void) elf_errno();
	if ((data = elf_getdata(s->scn, NULL)) == NULL) {
		elferr = elf_errno();
		if (elferr != 0)
			warnx("elf_getdata failed: %s", elf_errmsg(elferr));
		return;
	}
	src = data->d_buf;
	count = data->d_size;
	while (count > sizeof(Elf_Note)) {
		en = (Elf_Note *) (uintptr_t) src;
		namesz = en->n_namesz;
		descsz = en->n_descsz;
		src += sizeof(Elf_Note);
		count -= sizeof(Elf_Note);
		fprintf(ed->out, "\t%s ", src);
		src += roundup2(namesz, 4);
		count -= roundup2(namesz, 4);
		if (ed->ehdr.e_ident[EI_DATA] == ELFDATA2MSB)
			desc = be32dec(src);
		else
			desc = le32dec(src);
		fprintf(ed->out, "%d\n", desc);
		src += roundup2(descsz, 4);
		count -= roundup2(descsz, 4);
	}
}

static void
elf_print_hash(struct elfdump *ed)
{
	struct section	*s;
	Elf_Data	*data;
	Elf_Data	 dst;
	uint32_t	*s32;
	uint64_t	 i;
	uint64_t	 nbucket;
	uint64_t	 nchain;
	uint64_t	*s64;
	int		 elferr;

	/* Find .hash section. */
	for (i = 0; (size_t)i < ed->shnum; i++) {
		s = &ed->sl[i];
		if (s->type == SHT_HASH)
			break;
	}
	if ((size_t)i >= ed->shnum)
		return;
	fprintf(ed->out, "\nhash table (%s):\n", s->name);
	data = NULL;
	if (ed->ehdr.e_machine == EM_ALPHA) {
		/*
		 * Alpha uses 64-bit hash entries. Since libelf assumes that
		 * .hash section contains only 32-bit entry, an explicit
		 * gelf_xlatetom is needed here.
		 */
		if ((data = elf_rawdata(s->scn, data)) == NULL) {
			elferr = elf_errno();
			if (elferr != 0)
				warnx("elf_rawdata failed: %s",
				    elf_errmsg(elferr));
			return;
		}
		data->d_type = ELF_T_XWORD;
		memcpy(&dst, data, sizeof(Elf_Data));
		if (gelf_xlatetom(ed->elf, &dst, data,
		    ed->ehdr.e_ident[EI_DATA]) != &dst) {
			warnx("gelf_xlatetom failed: %s", elf_errmsg(-1));
			return;
		}
		s64 = dst.d_buf;
		nbucket = *s64++;
		nchain = *s64++;
		fprintf(ed->out, "\nnbucket:\n\t%ju\n", nbucket);
		fprintf(ed->out, "\nnchain:\n\t%ju\n\n", nchain);
		for(i = 0; i < nbucket; i++, s64++)
			fprintf(ed->out, "bucket[%jd]:\n\t%ju\n\n", i, *s64);
		for(i = 0; i < nchain; i++, s64++)
			fprintf(ed->out, "chain[%jd]:\n\t%ju\n\n", i, *s64);
	} else {
		if ((data = elf_getdata(s->scn, data)) == NULL) {
			elferr = elf_errno();
			if (elferr != 0)
				warnx("elf_getdata failed: %s",
				    elf_errmsg(elferr));
			return;
		}
		s32 = data->d_buf;
		nbucket = *s32++;
		nchain = *s32++;
		fprintf(ed->out, "\nnbucket:\n\t%ju\n", nbucket);
		fprintf(ed->out, "\nnchain:\n\t%ju\n\n", nchain);
		for(i = 0; i < nbucket; i++, s32++)
			fprintf(ed->out, "bucket[%jd]:\n\t%u\n\n", i, *s32);
		for(i = 0; i < nchain; i++, s32++)
			fprintf(ed->out, "chain[%jd]:\n\t%u\n\n", i, *s32);
	}
}

static void
usage(void)
{
	fprintf(stderr, "usage: elfdump -a | -cdeGhinprs [-w file] file\n");
	exit(1);
}
