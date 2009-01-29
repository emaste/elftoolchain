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
#include <err.h>
#include <fcntl.h>
#include <gelf.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <sysexits.h>
#include <string.h>
#include <unistd.h>

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

/* http://www.sco.com/developers/gabi/latest/ch5.dynamic.html#tag_encodings */
static const char *
d_tags(u_int64_t tag) {
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
e_machines(u_int mach)
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

const char *e_types[] = {
	"ET_NONE", "ET_REL", "ET_EXEC", "ET_DYN", "ET_CORE"
};

const char *ei_versions[] = {
	"EV_NONE", "EV_CURRENT"
};

const char *ei_classes[] = {
	"ELFCLASSNONE", "ELFCLASS32", "ELFCLASS64"
};

const char *ei_data[] = {
	"ELFDATANONE", "ELFDATA2LSB", "ELFDATA2MSB"
};

const char *ei_abis[] = {
	"ELFOSABI_SYSV", "ELFOSABI_HPUX", "ELFOSABI_NETBSD", "ELFOSABI_LINUX",
	"ELFOSABI_HURD", "ELFOSABI_86OPEN", "ELFOSABI_SOLARIS",
	"ELFOSABI_MONTEREY", "ELFOSABI_IRIX", "ELFOSABI_FREEBSD",
	"ELFOSABI_TRU64", "ELFOSABI_MODESTO", "ELFOSABI_OPENBSD"
};

const char *p_types[] = {
	"PT_NULL", "PT_LOAD", "PT_DYNAMIC", "PT_INTERP", "PT_NOTE",
	"PT_SHLIB", "PT_PHDR", "PT_TLS"
};

const char *p_flags[] = {
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

const char *sh_flags[] = {
	"", "SHF_WRITE", "SHF_ALLOC", "SHF_WRITE|SHF_ALLOC", "SHF_EXECINSTR",
	"SHF_WRITE|SHF_EXECINSTR", "SHF_ALLOC|SHF_EXECINSTR",
	"SHF_WRITE|SHF_ALLOC|SHF_EXECINSTR"
};

const char *st_types[] = {
	"STT_NOTYPE", "STT_OBJECT", "STT_FUNC", "STT_SECTION", "STT_FILE"
};

const char *st_bindings[] = {
	"STB_LOCAL", "STB_GLOBAL", "STB_WEAK"
};

size_t		 shstrndx;
size_t		 strtab;
size_t		 dynstr;
FILE		*out;

void		elf_print_ehdr(Elf * e);
void		elf_print_phdr(Elf * e);
void		elf_print_shdr(Elf * e);
void		elf_print_symtab(Elf * e, Elf_Scn * scn, size_t strndx);
void		elf_print_interp(Elf * e, Elf64_Off p_offset);
void		elf_print_dynamic(Elf * e, Elf_Scn * scn);
void		elf_print_rela(Elf * e, Elf_Scn * scn);
void		elf_print_rel(Elf * e, Elf_Scn * scn);
void		elf_print_got(Elf * e, Elf_Scn * scn);
void		elf_print_note(Elf * e, Elf_Scn * scn);
void		elf_print_hash(Elf * e, Elf_Scn * scn);

void		usage	  (void);

int
main(int ac, char **av)
{
	u_int		 flags;
	Elf		*e;
	Elf_Scn		*scn;
	GElf_Phdr	 phdr;
	GElf_Shdr	 shdr;
	struct stat	 sb;
	int		 ch;
	int		 elferr;
	int		 fd;
	int		 i;
	size_t		 phnum;
	char		*name;

	out = stdout;
	flags = 0;
	while ((ch = getopt(ac, av, "acdeiGhnprsw:")) != -1)
		switch (ch) {
		case 'a':
			flags = ED_ALL;
			break;
		case 'c':
			flags |= ED_SHDR;
			break;
		case 'd':
			flags |= ED_DYN;
			break;
		case 'e':
			flags |= ED_EHDR;
			break;
		case 'i':
			flags |= ED_INTERP;
			break;
		case 'G':
			flags |= ED_GOT;
			break;
		case 'h':
			flags |= ED_HASH;
			break;
		case 'n':
			flags |= ED_NOTE;
			break;
		case 'p':
			flags |= ED_PHDR;
			break;
		case 'r':
			flags |= ED_REL;
			break;
		case 's':
			flags |= ED_SYMTAB;
			break;
		case 'w':
			if ((out = fopen(optarg, "w")) == NULL)
				err(EX_NOINPUT, "%s", optarg);
			break;
		case '?':
		default:
			usage();
		}

	ac -= optind;
	av += optind;

	if (ac == 0 || flags == 0)
		usage();

	if (elf_version(EV_CURRENT) == EV_NONE)
		errx(EX_SOFTWARE, "ELF library initialization failed: %s",
		     elf_errmsg(-1));

	if ((fd = open(*av, O_RDONLY)) < 0 ||
	    fstat(fd, &sb) < 0)
		err(EX_NOINPUT, "%s", *av);

	if ((e = elf_begin(fd, ELF_C_READ, NULL)) == NULL)
		errx(EX_SOFTWARE, "elf_begin() failed: %s",
		    elf_errmsg(-1));

	if (elf_kind(e) != ELF_K_ELF)
		errx(EX_DATAERR, "not an elf file");

	if (elf_getshstrndx(e, &shstrndx) == 0)
		errx(EX_SOFTWARE, "elf_getshstrndx failed: %s",
		    elf_errmsg(-1));

	scn = NULL;
	while ((scn = elf_nextscn(e, scn)) != NULL) {
		if (gelf_getshdr(scn, &shdr) != &shdr)
			errx(EX_SOFTWARE, "elf_getshdr failed: %s",
			    elf_errmsg(-1));
		if ((name = elf_strptr(e, shstrndx, shdr.sh_name)) == NULL)
			errx(EX_SOFTWARE, "elf_strptr failed: %s",
			    elf_errmsg(-1));
		if (strcmp(name, ".strtab") == 0)
			strtab = elf_ndxscn(scn);
		if (strcmp(name, ".dynstr") == 0)
			dynstr = elf_ndxscn(scn);
	}
	elferr = elf_errno();
	if (elferr != 0)
		errx(EX_SOFTWARE, "elf_nextscn failed: %s",
		    elf_errmsg(elferr));

	if (flags & ED_EHDR)
		elf_print_ehdr(e);
	if (flags & ED_PHDR)
		elf_print_phdr(e);
	if (flags & ED_SHDR)
		elf_print_shdr(e);
	if (elf_getphnum(e, &phnum) == 0)
		errx(EX_DATAERR, "elf_getphnum failed: %s",
		    elf_errmsg(-1));
	for (i = 0; (u_int64_t)i < phnum; i++) {
		if (gelf_getphdr(e, i, &phdr) != &phdr)
			errx(EX_SOFTWARE, "elf_getphdr failed: %s",
			    elf_errmsg(-1));
		switch (phdr.p_type) {
		case PT_INTERP:
			if (flags & ED_INTERP)
				elf_print_interp(e, phdr.p_offset);
			break;
		case PT_NULL:
		case PT_LOAD:
		case PT_DYNAMIC:
		case PT_NOTE:
		case PT_SHLIB:
		case PT_PHDR:
			break;
		}
	}

	scn = NULL;
	while ((scn = elf_nextscn(e, scn)) != NULL) {
		if (gelf_getshdr(scn, &shdr) != &shdr)
			errx(EX_SOFTWARE, "elf_getshdr failed: %s",
			    elf_errmsg(-1));
		switch (shdr.sh_type) {
		case SHT_SYMTAB:
			if (flags & ED_SYMTAB)
				elf_print_symtab(e, scn, strtab);
			break;
		case SHT_DYNAMIC:
			if (flags & ED_DYN)
				elf_print_dynamic(e, scn);
			break;
		case SHT_RELA:
			if (flags & ED_REL)
				elf_print_rela(e, scn);
			break;
		case SHT_REL:
			if (flags & ED_REL)
				elf_print_rel(e, scn);
			break;
		case SHT_NOTE:
			if ((name = elf_strptr(e, shstrndx, shdr.sh_name)) == NULL)
				errx(EX_SOFTWARE, "elf_strptr failed: %s",
				    elf_errmsg(-1));
			if (flags & ED_NOTE &&
			    strcmp(name, ".note.ABI-tag") == 0)
				elf_print_note(e, scn);
			break;
		case SHT_DYNSYM:
			if (flags & ED_SYMTAB)
				elf_print_symtab(e, scn, dynstr);
			break;
		case SHT_PROGBITS:
			if ((name = elf_strptr(e, shstrndx, shdr.sh_name)) == NULL)
				errx(EX_SOFTWARE, "elf_strptr failed: %s",
				    elf_errmsg(-1));
			if (flags & ED_GOT &&
			    strcmp(name, ".got") == 0)
				elf_print_got(e, scn);
			break;
		case SHT_HASH:
			if (flags & ED_HASH)
				elf_print_hash(e, scn);
			break;
		case SHT_NULL:
		case SHT_STRTAB:
		case SHT_NOBITS:
		case SHT_SHLIB:
			break;
		}
	}
	elferr = elf_errno();
	if (elferr != 0)
		errx(EX_SOFTWARE, "elf_nextscn failed: %s",
		    elf_errmsg(elferr));
	return (0);
}

void
elf_print_ehdr(Elf * e)
{
	GElf_Ehdr	 ehdr;

	if (gelf_getehdr(e, &ehdr) == NULL)
		errx(EX_SOFTWARE, "gelf_getehdr failed: %s",
		     elf_errmsg(-1));
	fprintf(out, "\nelf header:\n");
	fprintf(out, "\n");
	fprintf(out, "\te_ident: %s %s %s\n",
	    ei_classes[ehdr.e_ident[EI_CLASS]],
	    ei_data[ehdr.e_ident[EI_DATA]],
	    ei_abis[ehdr.e_ident[EI_OSABI]]);
	fprintf(out, "\te_type: %s\n", e_types[ehdr.e_type]);
	fprintf(out, "\te_machine: %s\n", e_machines(ehdr.e_machine));
	fprintf(out, "\te_version: %s\n", ei_versions[ehdr.e_version]);
	fprintf(out, "\te_entry: %#jx\n", (uintmax_t)ehdr.e_entry);
	fprintf(out, "\te_phoff: %ju\n", (uintmax_t)ehdr.e_phoff);
	fprintf(out, "\te_shoff: %ju\n", (uintmax_t)ehdr.e_shoff);
	fprintf(out, "\te_flags: %ju\n", (uintmax_t)ehdr.e_flags);
	fprintf(out, "\te_ehsize: %ju\n", (uintmax_t)ehdr.e_ehsize);
	fprintf(out, "\te_phentsize: %ju\n", (uintmax_t)ehdr.e_phentsize);
	fprintf(out, "\te_phnum: %ju\n", (uintmax_t)ehdr.e_phnum);
	fprintf(out, "\te_shentsize: %ju\n", (uintmax_t)ehdr.e_shentsize);
	fprintf(out, "\te_shnum: %ju\n", (uintmax_t)ehdr.e_shnum);
	fprintf(out, "\te_shstrndx: %ju\n", (uintmax_t)ehdr.e_shstrndx);
}

void
elf_print_phdr(Elf * e)
{
	GElf_Phdr	 phdr;
	size_t		 phnum;
	int		 i;

	if (elf_getphnum(e, &phnum) == 0)
		errx(EX_DATAERR, "elf_getphnum failed: %s",
		    elf_errmsg(-1));
	fprintf(out, "\nprogram header:\n");
	for (i = 0; (u_int64_t) i < phnum; i++) {
		if (gelf_getphdr(e, i, &phdr) != &phdr)
			errx(EX_SOFTWARE, "elf_getphdr failed: %s",
			    elf_errmsg(-1));
		fprintf(out, "\n");
		fprintf(out, "entry: %d\n", i);
		fprintf(out, "\tp_type: %s\n", p_types[phdr.p_type & 0x7]);
		fprintf(out, "\tp_offset: %ju\n", (uintmax_t)phdr.p_offset);
		fprintf(out, "\tp_vaddr: %#jx\n", (uintmax_t)phdr.p_vaddr);
		fprintf(out, "\tp_paddr: %#jx\n", (uintmax_t)phdr.p_paddr);
		fprintf(out, "\tp_filesz: %ju\n", (uintmax_t)phdr.p_filesz);
		fprintf(out, "\tp_memsz: %ju\n", (uintmax_t)phdr.p_memsz);
		fprintf(out, "\tp_flags: %s\n", p_flags[phdr.p_flags]);
		fprintf(out, "\tp_align: %ju\n", (uintmax_t)phdr.p_align);
	}
}

void
elf_print_shdr(Elf * e)
{
	GElf_Shdr	 shdr;
	Elf_Scn		*scn;
	char		*name;
	int		 elferr;

	fprintf(out, "\nsection header:\n");
	scn = elf_getscn(e, SHN_UNDEF);
	do {
		if (gelf_getshdr(scn, &shdr) != &shdr)
			errx(EX_SOFTWARE, "elf_getshdr failed: %s",
			    elf_errmsg(-1));
		if ((name = elf_strptr(e, shstrndx, shdr.sh_name)) == NULL)
			errx(EX_SOFTWARE, "elf_strptr failed: %s",
			    elf_errmsg(-1));
		fprintf(out, "\n");
		fprintf(out, "entry: %ju\n", (uintmax_t)elf_ndxscn(scn));
		fprintf(out, "\tsh_name: %s\n", name);
		fprintf(out, "\tsh_type: %s\n", sh_types(shdr.sh_type));
		fprintf(out, "\tsh_flags: %s\n", sh_flags[shdr.sh_flags & 0x7]);
		fprintf(out, "\tsh_addr: %#jx\n", shdr.sh_addr);
		fprintf(out, "\tsh_offset: %ju\n", (uintmax_t)shdr.sh_offset);
		fprintf(out, "\tsh_size: %ju\n", (uintmax_t)shdr.sh_size);
		fprintf(out, "\tsh_link: %ju\n", (uintmax_t)shdr.sh_link);
		fprintf(out, "\tsh_info: %ju\n", (uintmax_t)shdr.sh_info);
		fprintf(out, "\tsh_addralign: %ju\n", (uintmax_t)shdr.sh_addralign);
		fprintf(out, "\tsh_entsize: %ju\n", (uintmax_t)shdr.sh_entsize);
	} while ((scn = elf_nextscn(e, scn)) != NULL);
	elferr = elf_errno();
	if (elferr != 0)
		errx(EX_SOFTWARE, "elf_nextscn failed: %s",
		    elf_errmsg(elferr));
}

void
elf_print_symtab(Elf * e, Elf_Scn * scn, size_t strndx)
{
	size_t		 n;
	char		*name;
	Elf_Data	*data;
	GElf_Sym	 sym;
	GElf_Shdr	 shdr;
	int		 elferr;
	int		 i;
	int		 len;

	if (gelf_getshdr(scn, &shdr) != &shdr)
		errx(EX_SOFTWARE, "elf_getshdr failed: %s",
		    elf_errmsg(-1));
	if ((name = elf_strptr(e, shstrndx, shdr.sh_name)) == NULL)
		errx(EX_SOFTWARE, "elf_strptr failed: %s",
		    elf_errmsg(-1));
	fprintf(out, "\nsymbol table (%s):\n", name);
	data = NULL;
	n = 0;
	while (n < shdr.sh_size && (data = elf_getdata(scn, data)) != NULL) {
		len = data->d_size / shdr.sh_entsize;
		for (i = 0; i < len; i++) {
			if (gelf_getsym(data, i, &sym) != &sym)
				errx(EX_SOFTWARE, "gelf_getsym failed: %s",
				    elf_errmsg(-1));
			if ((name = elf_strptr(e, strndx, sym.st_name)) ==
			    NULL)
				errx(EX_SOFTWARE, "elf_strptr failed: %s",
				    elf_errmsg(-1));
			fprintf(out, "\n");
			fprintf(out, "entry: %d\n", i);
			fprintf(out, "\tst_name: %s\n", name);
			fprintf(out, "\tst_value: %#jx\n", sym.st_value);
			fprintf(out, "\tst_size: %ju\n",
			    (uintmax_t)sym.st_size);
			fprintf(out, "\tst_info: %s %s\n",
			    st_types[GELF_ST_TYPE(sym.st_info)],
			    st_bindings[GELF_ST_BIND(sym.st_info)]);
			fprintf(out, "\tst_shndx: %ju\n",
			    (uintmax_t)sym.st_shndx);
		}
		n += data->d_size;
	}
	elferr = elf_errno();
	if (elferr != 0)
		errx(EX_SOFTWARE, "elf_getdata failed: %s",
		    elf_errmsg(elferr));
}

void
elf_print_dynamic(Elf * e, Elf_Scn * scn)
{
	size_t		 n;
	char		*name;
	Elf_Data	*data;
	GElf_Dyn	 dyn;
	GElf_Shdr	 shdr;
	int		 elferr;
	int		 i;
	int		 len;

	if (gelf_getshdr(scn, &shdr) != &shdr)
		errx(EX_SOFTWARE, "elf_getshdr failed: %s",
		    elf_errmsg(-1));
	fprintf(out, "\ndynamic:\n");
	data = NULL;
	n = 0;
	while (n < shdr.sh_size && (data = elf_getdata(scn, data)) != NULL) {
		len = data->d_size / shdr.sh_entsize;
		for (i = 0; i < len; i++) {
			if (gelf_getdyn(data, i, &dyn) != &dyn)
				errx(EX_SOFTWARE, "gelf_getdyn failed: %s",
				    elf_errmsg(-1));
			fprintf(out, "\n");
			fprintf(out, "entry: %d\n", i);
			fprintf(out, "\td_tag: %s\n", d_tags(dyn.d_tag));
			switch(dyn.d_tag) {
			case DT_NEEDED:
			case DT_SONAME:
			case DT_RPATH:
				name = elf_strptr(e, dynstr, dyn.d_un.d_val);
				if (name == NULL)
					errx(EX_SOFTWARE,
					    "elf_strptr failed: %s",
					    elf_errmsg(-1));
				fprintf(out, "\td_val: %s\n", name);
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
				fprintf(out, "\td_val: %ju\n",
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
				fprintf(out, "\td_ptr: %#jx\n",
				    dyn.d_un.d_ptr);
				break;
			case DT_NULL:
			case DT_SYMBOLIC:
			case DT_DEBUG:
			case DT_TEXTREL:
				break;
			}
		}
		n += data->d_size;
	}
	elferr = elf_errno();
	if (elferr != 0)
		errx(EX_SOFTWARE, "elf_getdata failed: %s",
		    elf_errmsg(elferr));
}

void
elf_print_rela(Elf * e, Elf_Scn * scn)
{
	size_t		 n;
	char		*name;
	Elf_Data	*data;
	GElf_Rela	 rela;
	GElf_Shdr	 shdr;
	int		 elferr;
	int		 i;
	int		 len;

	if (gelf_getshdr(scn, &shdr) != &shdr)
		errx(EX_SOFTWARE, "elf_getshdr failed: %s",
		    elf_errmsg(-1));
	if ((name = elf_strptr(e, shstrndx, shdr.sh_name)) == NULL)
		errx(EX_SOFTWARE, "elf_strptr failed: %s",
		    elf_errmsg(-1));
	fprintf(out, "\nrelocation with addend (%s):\n", name);
	data = NULL;
	n = 0;
	while (n < shdr.sh_size && (data = elf_getdata(scn, data)) != NULL) {
		len = data->d_size / shdr.sh_entsize;
		for (i = 0; i < len; i++) {
			if (gelf_getrela(data, i, &rela) != &rela)
				errx(EX_SOFTWARE, "gelf_getrela failed: %s",
				    elf_errmsg(-1));
			fprintf(out, "\n");
			fprintf(out, "entry: %d\n", i);
			fprintf(out, "\tr_offset: %#jx\n",
			    rela.r_offset);
			fprintf(out, "\tr_info: %ju\n",
			    (uintmax_t)rela.r_info);
			fprintf(out, "\tr_addend: %jd\n",
			    (intmax_t)rela.r_addend);
		}
		n += data->d_size;
	}
	elferr = elf_errno();
	if (elferr != 0)
		errx(EX_SOFTWARE, "elf_getdata failed: %s",
		    elf_errmsg(elferr));
}

void
elf_print_rel(Elf * e, Elf_Scn * scn)
{
	size_t		 n;
	char		*name;
	Elf_Data	*data;
	GElf_Rel	 rel;
	GElf_Shdr	 shdr;
	int		 elferr;
	int		 i;
	int		 len;

	if (gelf_getshdr(scn, &shdr) != &shdr)
		errx(EX_SOFTWARE, "elf_getshdr failed: %s",
		    elf_errmsg(-1));
	if ((name = elf_strptr(e, shstrndx, shdr.sh_name)) == NULL)
		errx(EX_SOFTWARE, "elf_strptr failed: %s",
		    elf_errmsg(-1));
	fprintf(out, "\nrelocation (%s):\n", name);
	data = NULL;
	n = 0;
	while (n < shdr.sh_size && (data = elf_getdata(scn, data)) != NULL) {
		len = data->d_size / shdr.sh_entsize;
		for (i = 0; i < len; i++) {
			if (gelf_getrel(data, i, &rel) != &rel)
				errx(EX_SOFTWARE, "gelf_getrel failed: %s",
				    elf_errmsg(-1));
			fprintf(out, "\n");
			fprintf(out, "entry: %d\n", i);
			fprintf(out, "\tr_offset: %#jx\n",
			    rel.r_offset);
			fprintf(out, "\tr_info: %ju\n",
			    (uintmax_t)rel.r_info);
		}
		n += data->d_size;
	}
	elferr = elf_errno();
	if (elferr != 0)
		errx(EX_SOFTWARE, "elf_getdata failed: %s",
		    elf_errmsg(elferr));
}

void
elf_print_interp(Elf * e, Elf64_Off p_offset)
{
	char	       *s;

	if ((s = elf_rawfile(e, NULL)) == NULL)
		errx(EX_SOFTWARE, "elf_rawfile failed: %s",
		    elf_errmsg(-1));
	fprintf(out, "\ninterp:\n");
	fprintf(out, "\t%s\n", s + (size_t)p_offset);
}

void
elf_print_got(Elf * e, Elf_Scn * scn)
{
	GElf_Ehdr	 ehdr;
	GElf_Shdr	 shdr;
	Elf_Data	*data;
	Elf_Data	*dst;
	size_t		 n;
	int		 ec;
	int		 elferr;
	int		 i;

	if (gelf_getehdr(e, &ehdr) == NULL)
		errx(EX_SOFTWARE, "gelf_getehdr failed: %s",
		    elf_errmsg(-1));
	if (gelf_getshdr(scn, &shdr) != &shdr)
		errx(EX_SOFTWARE, "elf_getshdr failed: %s",
		    elf_errmsg(-1));
	if ((ec = gelf_getclass(e)) == ELFCLASSNONE)
		errx(EX_DATAERR, "gelf_getclass failed: %s",
		    elf_errmsg(-1));
	fprintf(out, "\nglobal offset table:\n");
	data = NULL;
	n = 0;
	while (n < shdr.sh_size && (data = elf_getdata(scn, data)) != NULL) {
		if (ec == ELFCLASS32)
			data->d_type = ELF_T_WORD;
		else
			data->d_type = ELF_T_XWORD;
		if ((dst = malloc(sizeof(Elf_Data))) == NULL)
			err(1, "malloc failed: ");
		memcpy(dst, data, sizeof(Elf_Data));
		if (gelf_xlatetom(e, dst, data, ehdr.e_ident[EI_DATA]) != dst)
			errx(EX_SOFTWARE, "gelf_xlatetom failed: %s",
			    elf_errmsg(-1));
		for(i = 0; i * dst->d_align <  dst->d_size; i++) {
			fprintf(out, "\nentry: %d\n", i);
			if (ec == ELFCLASS32)
				fprintf(out, "\t%#x\n", *((u_int32_t *)dst->d_buf + i));
			else
				fprintf(out, "\t%#jx\n", *((u_int64_t *)dst->d_buf + i));
		}
		n += data->d_size;
		free(dst);
	}
	elferr = elf_errno();
	if (elferr != 0)
		errx(EX_SOFTWARE, "elf_getdata failed: %s",
		     elf_errmsg(elferr));
}

void
elf_print_note(Elf * e, Elf_Scn * scn)
{
	GElf_Shdr	 shdr;
	Elf_Data        *data;
	u_int32_t	 namesz;
	u_int32_t	 descsz;
	u_int32_t	*s;
	size_t		 n;
	char		*name;
	int		 elferr;

	if (gelf_getshdr(scn, &shdr) != &shdr)
		errx(EX_SOFTWARE, "elf_getshdr failed: %s",
		    elf_errmsg(-1));
	if ((name = elf_strptr(e, shstrndx, shdr.sh_name)) == NULL)
		errx(EX_SOFTWARE, "elf_strptr failed: %s",
		    elf_errmsg(-1));
	fprintf(out, "\nnote (%s):\n", name);
	data = NULL;
	n = 0;
	while (n < shdr.sh_size && (data = elf_getdata(scn, data)) != NULL) {
		s = data->d_buf;
		while ((char *)s < (char *)data->d_buf + data->d_size) {
			namesz = ((Elf_Note *)s)->n_namesz;
			descsz = ((Elf_Note *)s)->n_descsz;
			fprintf(out, "\t%s %d\n", (char *)s + sizeof(Elf_Note),
			    *(s + sizeof(Elf_Note)/sizeof(u_int32_t) +
			    roundup2(namesz, sizeof(u_int32_t)) /
			    sizeof(u_int32_t)));
			s = s + sizeof(Elf_Note)/sizeof(u_int32_t) +
			    roundup2(namesz,sizeof(u_int32_t)) /
			    sizeof(u_int32_t) +
			    roundup2(descsz,sizeof(u_int32_t)) /
			    sizeof(u_int32_t);
		}
		n += data->d_size;
	}
	elferr = elf_errno();
	if (elferr != 0)
		errx(EX_SOFTWARE, "elf_getdata failed: %s",
		    elf_errmsg(elferr));
}

void
elf_print_hash(Elf * e, Elf_Scn * scn)
{
	GElf_Ehdr	 ehdr;
	GElf_Shdr	 shdr;
	Elf_Data	*data;
	Elf_Data	*dst;
	u_int32_t	*s;
	u_int64_t	 i;
	u_int64_t	 nbucket;
	u_int64_t	 nchain;
	u_int64_t	*s64;
	char		*name;
	int		 elferr;

	if (gelf_getehdr(e, &ehdr) == NULL)
		errx(EX_SOFTWARE, "gelf_getehdr failed: %s",
		     elf_errmsg(-1));
	if (gelf_getshdr(scn, &shdr) != &shdr)
		errx(EX_SOFTWARE, "elf_getshdr failed: %s",
		     elf_errmsg(-1));
	if ((name = elf_strptr(e, shstrndx, shdr.sh_name)) == NULL)
		errx(EX_SOFTWARE, "elf_strptr failed: %s",
		     elf_errmsg(-1));
	fprintf(out, "\nhash table (%s):\n", name);
	data = NULL;
	if (ehdr.e_machine == EM_ALPHA) {
		/* Alpha uses 64-bit hash entries */
		if ((data = elf_rawdata(scn, data)) != NULL) {
			data->d_type = ELF_T_XWORD;
			if ((dst = malloc(sizeof(Elf_Data))) == NULL)
				err(1, "malloc failed: ");
			memcpy(dst, data, sizeof(Elf_Data));
			if (gelf_xlatetom(e, dst, data, ehdr.e_ident[EI_DATA])
			    != dst)
				errx(EX_SOFTWARE, "gelf_xlatetom failed: %s",
				    elf_errmsg(-1));
			s64 = dst->d_buf;
			nbucket = *s64++;
			nchain = *s64++;
			fprintf(out, "\nnbucket:\n\t%ju\n", nbucket);
			fprintf(out, "\nnchain:\n\t%ju\n\n", nchain);
			for(i = 0; i < nbucket; i++, s64++)
				fprintf(out, "bucket[%jd]:\n\t%ju\n\n",
				    i, *s64);
			for(i = 0; i < nchain; i++, s64++)
				fprintf(out, "chain[%jd]:\n\t%ju\n\n",
				    i, *s64);
			free(dst);
		}
	} else {
		if ((data = elf_getdata(scn, data)) != NULL) {
			s = data->d_buf;
			nbucket = *s++;
			nchain = *s++;
			fprintf(out, "\nnbucket:\n\t%ju\n", nbucket);
			fprintf(out, "\nnchain:\n\t%ju\n\n", nchain);
			for(i = 0; i < nbucket; i++, s++)
				fprintf(out, "bucket[%jd]:\n\t%u\n\n", i, *s);
			for(i = 0; i < nchain; i++, s++)
				fprintf(out, "chain[%jd]:\n\t%u\n\n", i, *s);
		}
	}
	elferr = elf_errno();
	if (elferr != 0)
		errx(EX_SOFTWARE, "elf_getdata failed: %s",
		    elf_errmsg(elferr));
}

void
usage(void)
{
	fprintf(stderr, "usage: elfdump -a | -cdeGhinprs [-w file] file\n");
	exit(1);
}
