typedef struct _elf_target elf_target;

elf_target	*elf_find_target(const char *tgt_name);
unsigned int	 elf_target_byteorder(elf_target *tgt);
unsigned int	 elf_target_class(elf_target *tgt);
