#include <sys/cdefs.h>
#if defined(__RCSID)
__RCSID("$Id$");
#endif

#include <sys/param.h>
#include <sys/elf_common.h>
#include <string.h>

#include "target.h"

struct _elf_target {
	const char *name;
	unsigned char byteorder;
	unsigned char class;
};

struct _elf_target _elf_targets[] = {
	{"elf32-i386", ELFDATA2LSB, ELFCLASS32,},
	{"elf64-x86-64", ELFDATA2LSB, ELFCLASS64},
	{"binary", ELFDATANONE, ELFCLASSNONE},
	{NULL, ELFDATANONE, ELFCLASSNONE},
};

elf_target *
elf_find_target(const char *tgt_name)
{
	elf_target *tgt;

	for (tgt = _elf_targets; tgt->name; tgt++)
		if (!strcmp(tgt_name, tgt->name))
			return (tgt);

	return (NULL);		/* not found */
}

unsigned int
elf_target_byteorder(elf_target *tgt)
{
	return (tgt->byteorder);
}

unsigned int
elf_target_class(elf_target *tgt)
{
	return (tgt->class);
}
