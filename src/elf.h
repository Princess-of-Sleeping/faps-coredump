
/*
 * faps-coredump elf.h
 * Copyright (C) 2021, Princess of Sleeping
 */

#ifndef _FAPS_COREDUMP_ELF_H_
#define _FAPS_COREDUMP_ELF_H_

#include <stdint.h>

typedef struct Elf32_Ehdr {
	unsigned char e_ident[0x10];	/* Magic number and other info */

	uint16_t e_type;			/* Object file type */
	uint16_t e_machine;		/* Architecture */
	uint32_t e_version;		/* Object file version */
	uint32_t e_entry;		/* Entry point virtual address */
	uint32_t e_phoff;		/* Program header table file offset */

	uint32_t e_shoff;		/* Section header table file offset */
	uint32_t e_flags;		/* Processor-specific flags */
	uint16_t e_ehsize;		/* ELF header size in bytes */
	uint16_t e_phentsize;		/* Program header table entry size */
	uint16_t e_phnum;		/* Program header table entry count */
	uint16_t e_shentsize;		/* Section header table entry size */

	uint16_t e_shnum;		/* Section header table entry count */
	uint16_t e_shstrndx;		/* Section header string table index */
} Elf32_Ehdr;

typedef struct ElfEntryInfo { // size is 0x20
	int type; // 1:loadable segment, 4:note
	uint32_t offset;
	uint32_t vaddr;
	uint32_t paddr;
	uint32_t filesz;
	uint32_t memsz;
	int flags;
	int align;
} ElfEntryInfo;

#endif /* _FAPS_COREDUMP_ELF_H_ */
