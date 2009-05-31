/*-
 * Copyright (c) 2008,2009 Kai Wang
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
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <libelf.h>

#include "_libelftc.h"

struct _Elf_Target targets[] = {
	{"binary", ET_BINARY, ELFDATANONE, ELFCLASSNONE, EM_NONE},
	{"elf32-avr", ET_ELF, ELFDATA2LSB, ELFCLASS32, EM_AVR},
	{"elf32-big", ET_ELF, ELFDATA2MSB, ELFCLASS32, EM_NONE},
	{"elf32-bigarm", ET_ELF, ELFDATA2MSB, ELFCLASS32, EM_ARM},
	{"elf32-bigmips", ET_ELF, ELFDATA2MSB, ELFCLASS32, EM_MIPS},
	{"elf32-i386", ET_ELF, ELFDATA2LSB, ELFCLASS32, EM_386},
	{"elf32-i386-freebsd", ET_ELF, ELFDATA2LSB, ELFCLASS32, EM_386},
	{"elf32-ia64-big", ET_ELF, ELFDATA2MSB, ELFCLASS32, EM_IA_64},
	{"elf32-little", ET_ELF, ELFDATA2LSB, ELFCLASS32, EM_NONE},
	{"elf32-littlearm", ET_ELF, ELFDATA2LSB, ELFCLASS32, EM_ARM},
	{"elf32-littlemips", ET_ELF, ELFDATA2LSB, ELFCLASS32, EM_MIPS},
	{"elf32-powerpc", ET_ELF, ELFDATA2MSB, ELFCLASS32, EM_PPC},
	{"elf32-powerpcle", ET_ELF, ELFDATA2LSB, ELFCLASS32, EM_PPC},
	{"elf32-sparc", ET_ELF, ELFDATA2MSB, ELFCLASS32, EM_SPARC},
	{"elf64-alpha", ET_ELF, ELFDATA2LSB, ELFCLASS64, EM_ALPHA},
	{"elf64-alpha-freebsd", ET_ELF, ELFDATA2LSB, ELFCLASS64, EM_ALPHA},
	{"elf64-big", ET_ELF, ELFDATA2MSB, ELFCLASS64, EM_NONE},
	{"elf64-bigmips", ET_ELF, ELFDATA2MSB, ELFCLASS64, EM_MIPS},
	{"elf64-ia64-big", ET_ELF, ELFDATA2MSB, ELFCLASS64, EM_IA_64},
	{"elf64-ia64-little", ET_ELF, ELFDATA2LSB, ELFCLASS64, EM_IA_64},
	{"elf64-little", ET_ELF, ELFDATA2LSB, ELFCLASS64, EM_NONE},
	{"elf64-littlemips", ET_ELF, ELFDATA2LSB, ELFCLASS64, EM_NONE},
	{"elf64-powerpc", ET_ELF, ELFDATA2MSB, ELFCLASS64, EM_PPC64},
	{"elf64-powerpcle", ET_ELF, ELFDATA2LSB, ELFCLASS64, EM_PPC64},
	{"elf64-sparc", ET_ELF, ELFDATA2MSB, ELFCLASS64, EM_SPARCV9},
	{"elf64-sparc-freebsd", ET_ELF, ELFDATA2MSB, ELFCLASS64, EM_SPARCV9},
	{"elf64-x86-64", ET_ELF, ELFDATA2LSB, ELFCLASS64, EM_X86_64},
	{"elf64-x86-64-freebsd", ET_ELF, ELFDATA2LSB, ELFCLASS64, EM_X86_64},
	{"srec", ET_SREC, ELFDATANONE, ELFCLASSNONE, EM_NONE},
	{"symbolsrec", ET_SREC, ELFDATANONE, ELFCLASSNONE, EM_NONE},
	{NULL, 0, ELFDATANONE, ELFCLASSNONE, EM_NONE},
};
