/*
 * faps-coredump process_memblock.c
 * Copyright (C) 2021, Princess of Sleeping
 */

#include <psp2kern/kernel/sysmem.h>
#include <psp2kern/kernel/sysclib.h>
#include <psp2kern/io/fcntl.h>
#include <psp2kern/io/stat.h>
#include "log.h"
#include "utility.h"
#include "sysmem_types.h"
#include "coredump_func.h"
#include "elf.h"

extern SceClass *(* _ksceKernelGetUIDMemBlockClass)(void);
extern int (* _kscePUIDGetUIDVectorByClass)(SceUID pid, SceClass *cls, int vis_level, SceUID *vector, SceSize num, SceSize *ret_num);

int replace_char(char *array, char target, char to_char){

	int array_len = strlen(array);

	for(int i=0;i<array_len;i++){
		if(array[i] == target)
			array[i] = to_char;
	}

	return 0;
}

int name_sanitization(char *name){

	replace_char(name, ':', '_');
	replace_char(name, '/', '_');
	replace_char(name, '\\', '_');
	replace_char(name, '?', '_');
	replace_char(name, '*', '_');
	replace_char(name, '"', '_');
	replace_char(name, '<', '_');
	replace_char(name, '>', '_');
	replace_char(name, '|', '_');

	return 0;
}

int fapsCoredumpCreateFile(const char *path, SceOff size){

	int res;
	SceUID fd;

	fd = ksceIoOpen(path, SCE_O_CREAT | SCE_O_WRONLY, 0666);
	if(fd < 0)
		return fd;

#define SCE_CST_SIZE        0x0004

	SceIoStat c_stat;
	memset(&c_stat, 0, sizeof(c_stat));

	c_stat.st_size = size;

	res = ksceIoChstatByFd(fd, &c_stat, SCE_CST_SIZE);
	ksceIoClose(fd);

	if(res < 0)
		return res;

	res = ksceIoSync(path, 0);
	if(res < 0)
		return res;

	return 0;
}

int fapsCreateMemBlockDump(FapsCoredumpContext *context){

	int res;
	SceUID fd, memid_kern;
	SceKernelMemBlockInfoEx mem_info;

	ElfEntryInfo *pElfEntryInfo;

	// size = sizeof(ElfEntryInfo) * 2048
	SceUID memid = ksceKernelAllocMemBlock("FapsMemBlockEntInfo", 0x1020D006, 0x10000, NULL);
	if(memid < 0)
		return memid;

	ksceKernelGetMemBlockBase(memid, (void **)(&pElfEntryInfo));

	memset(pElfEntryInfo, 0, 0x10000);


	uint32_t offset = sizeof(Elf32_Ehdr) + (context->memblock_number * sizeof(ElfEntryInfo));

	context->temp[FAPS_COREDUMP_TEMP_MAX_LENGTH] = 0;
	snprintf(context->temp, FAPS_COREDUMP_TEMP_MAX_LENGTH, "%s/%s", context->path, "memblock_dump.elf");


	res = fapsCoredumpCreateFile(context->temp, (SceOff)(offset + context->memblock_size_cache));
	if(res < 0){
		goto free_mem;
	}

	fd = ksceIoOpen(context->temp, SCE_O_WRONLY, 0666);
	ksceIoLseek(fd, sizeof(Elf32_Ehdr) + (context->memblock_number * sizeof(ElfEntryInfo)), SCE_SEEK_SET);

	for(int i=0;i<context->memblock_number;i++){

		if(context->uid_pool[i] < 0)
			continue;

		memid_kern = kscePUIDtoGUID(context->pid, context->uid_pool[i]);

		SceUIDMemBlockObject *pObj;
		res = ksceGUIDReferObjectWithClass(memid_kern, _ksceKernelGetUIDMemBlockClass(), (SceObjectBase **)&pObj);
		if(res < 0)
			continue;

		ksceGUIDReleaseObject(memid_kern);

		memset(&mem_info, 0, sizeof(mem_info));
		mem_info.size = 0xB8;

		res = ksceKernelMemBlockGetInfoEx(memid_kern, &mem_info);
		if(res < 0)
			continue;

		ksceDebugPrintf("0x%03X/0x%03X id:0x%X\n", (i + 1), context->memblock_number, context->uid_pool[i]);

		if((unsigned int)mem_info.paddr_list[0] < 0xE0000000){

			pElfEntryInfo[i].type   = 1;
			pElfEntryInfo[i].offset = offset;
			pElfEntryInfo[i].vaddr  = (uint32_t)pObj->vaddr;
			pElfEntryInfo[i].paddr  = (uint32_t)pObj->vaddr;
			pElfEntryInfo[i].filesz = pObj->size;
			pElfEntryInfo[i].memsz  = pObj->size;

			if((mem_info.details.type & 0xFF) >= 0x10){
				pElfEntryInfo[i].flags = (mem_info.details.type >> 4) & 0xF;
			}else{
				pElfEntryInfo[i].flags = (mem_info.details.type >> 0) & 0xF;
			}
			pElfEntryInfo[i].align = 4;

			offset += pObj->size;

			write_file_proc_by_fd(context->pid, fd, pObj->vaddr, pObj->size);
		}
	}

	ksceIoClose(fd);

	Elf32_Ehdr ehdr;
	memset(&ehdr, 0, sizeof(ehdr));

	ehdr.e_ident[0x0] = 0x7F;
	ehdr.e_ident[0x1] = 'E';
	ehdr.e_ident[0x2] = 'L';
	ehdr.e_ident[0x3] = 'F';
	ehdr.e_ident[0x4] = 1;
	ehdr.e_ident[0x5] = 1;
	ehdr.e_ident[0x6] = 1;

	ehdr.e_type = 4;
	ehdr.e_machine = 0x28;
	ehdr.e_version = 1;
	ehdr.e_entry = 0;
	ehdr.e_phoff = sizeof(ehdr);

	ehdr.e_shoff     = 0;
	ehdr.e_flags     = 0x05000000;
	ehdr.e_ehsize    = sizeof(ehdr);
	ehdr.e_phentsize = sizeof(ElfEntryInfo);
	ehdr.e_phnum     = context->memblock_number;
	ehdr.e_shentsize = 0;

	ehdr.e_shnum = 0;
	ehdr.e_shstrndx = 0;

	context->temp[FAPS_COREDUMP_TEMP_MAX_LENGTH] = 0;
	snprintf(context->temp, FAPS_COREDUMP_TEMP_MAX_LENGTH, "%s/%s", context->path, "memblock_dump.elf");
	fd = ksceIoOpen(context->temp, SCE_O_WRONLY, 0666);
	ksceIoLseek(fd, 0LL, SCE_SEEK_SET);
	ksceIoWrite(fd, &ehdr, sizeof(ehdr));
	ksceIoWrite(fd, pElfEntryInfo, context->memblock_number * sizeof(ElfEntryInfo));
	ksceIoClose(fd);

	res = 0;

free_mem:
	ksceKernelFreeMemBlock(memid);

	return res;
}

int fapsCreateMemBlockInfo(FapsCoredumpContext *context){

	int res;
	SceUID memid_kern;
	SceKernelMemBlockInfoEx mem_info;
	char name[0x20];

	context->temp[FAPS_COREDUMP_TEMP_MAX_LENGTH] = 0;
	snprintf(context->temp, FAPS_COREDUMP_TEMP_MAX_LENGTH, "%s/%s", context->path, "memblock_info.txt");
	if(LogOpen(context->temp) < 0)
		return -1;

	for(int i=0;i<context->memblock_number;i++){

		if(context->uid_pool[i] < 0)
			continue;

		memid_kern = kscePUIDtoGUID(context->pid, context->uid_pool[i]);

		SceUIDMemBlockObject *pObj;
		res = ksceGUIDReferObjectWithClass(memid_kern, _ksceKernelGetUIDMemBlockClass(), (SceObjectBase **)&pObj);
		if(res < 0){
			ksceDebugPrintf("[error] sceGUIDReferObjectWithClass failed : 0x%X, uid:0x%X\n", res, memid_kern);
			continue;
		}

		ksceGUIDReleaseObject(memid_kern);

		memset(&mem_info, 0, sizeof(mem_info));
		mem_info.size = 0xB8;

		ksceKernelMemBlockGetInfoEx(memid_kern, &mem_info);

		name[sizeof(name) - 1] = 0;
		strncpy(name, mem_info.details.name, sizeof(name) - 1);

		if(mem_info.details.name[0] == 0)
			strncpy(name, "noname_memblk", sizeof(name) - 1);

		LogWrite("[%-31s]\n", name);
		LogWrite("uid   : 0x%08X/0x%08X\n", context->uid_pool[i], memid_kern);
		LogWrite("flags : 0x%X\n", pObj->flags);
		LogWrite("type  : 0x%08X (", mem_info.details.type);

		SceUInt32 memtype = mem_info.details.type;

		if(context->pid != SCE_GUID_KERNEL_PROCESS_ID)
			memtype >>= 4;

		if((memtype & 0b111) == 0)
			LogWrite("none");

		if((memtype & 0b100) != 0)
			LogWrite("R");

		if((memtype & 0b010) != 0)
			LogWrite("W");

		if((memtype & 0b001) != 0)
			LogWrite("X");

		LogWrite(")\n");
		LogWrite("vaddr : 0x%X\n", pObj->vaddr);
		LogWrite("size  : 0x%X\n", pObj->size);

		SceKernelMemBlockAddressTree *address_tree = pObj->address_tree;
		while(address_tree != NULL){

			LogWrite(
				"vaddr 0x%08X paddr 0x%08X size 0x%-10X flags:0x%X\n",
				address_tree->vaddr, address_tree->paddr, address_tree->size, address_tree->flags
			);

			address_tree = address_tree->next;
		}

		LogWrite("\n");
	}

	LogClose();

	return 0;
}

int fapsUpdateMemBlockInfo(FapsCoredumpContext *context){

	int res;
	SceUIDMemBlockObject *pObj;
	SceSize memblock_number = 0;
	SceUID pid, memid_kern;
	SceClass *pUIDMemBlockClass;

	pid = context->pid;
	context->memblock_size_cache = 0;

	pUIDMemBlockClass = _ksceKernelGetUIDMemBlockClass();

	res = _kscePUIDGetUIDVectorByClass(pid, pUIDMemBlockClass, 5, context->uid_pool, 2048, &memblock_number);
	if(res < 0)
		return res;

	for(int i=0;i<memblock_number;i++){

		memid_kern = kscePUIDtoGUID(context->pid, context->uid_pool[i]);

		res = ksceGUIDReferObjectWithClass(memid_kern, _ksceKernelGetUIDMemBlockClass(), (SceObjectBase **)&pObj);
		if(res < 0){
			context->uid_pool[i] = -1;
		}else{
			ksceGUIDReleaseObject(memid_kern);
			context->memblock_size_cache += pObj->size;
		}
	}

	context->memblock_number = memblock_number;

	return 0;
}
