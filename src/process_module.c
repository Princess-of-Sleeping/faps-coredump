/*
 * faps-coredump process_module.c
 * Copyright (C) 2021, Princess of Sleeping
 */

#include <psp2kern/types.h>
#include <psp2kern/kernel/sysmem.h>
#include <psp2kern/kernel/sysclib.h>
#include <psp2kern/io/stat.h>
#include "log.h"
#include "utility.h"
#include "modulemgr_internal.h"
#include "coredump_func.h"
#include "sysmem_types.h"

extern SceClass *(* _ksceKernelGetUIDMemBlockClass)(void);
extern SceKernelProcessModuleInfo *(* sceKernelGetProcessModuleInfo)(SceUID pid);

int fapsCoredumpInitProcessModule(FapsCoredumpContext *context){

	int idx = 0;
	SceKernelProcessModuleInfo *process_module_info;
	SceModuleInfoInternal *module_info;

	process_module_info = sceKernelGetProcessModuleInfo(context->pid);

	context->process_module_info = process_module_info;
	if(process_module_info == NULL)
		return -1;

	module_info = process_module_info->module_info;

	while(module_info != NULL){
		context->module_list[idx++] = module_info;
		module_info = module_info->next;
	}

	return 0;
}

int write_membase_base_list(FapsCoredumpContext *context, SceUID memblk_id){

	int res;
	char name[0x20];
	SceKernelMemBlockInfoEx mem_info;

	if(memblk_id == 0)
		return 0;

	memset(&mem_info, 0, sizeof(mem_info));
	mem_info.size = 0xB8;

	res = ksceKernelMemBlockGetInfoEx(memblk_id, &mem_info);
	if(res < 0){
		ksceDebugPrintf("[error] sceKernelMemBlockGetInfoEx failed : 0x%X, uid:0x%X\n", res, memblk_id);
		return -1; // ?
	}

	name[sizeof(name) - 1] = 0;
	strncpy(name, mem_info.details.name, sizeof(name) - 1);

	if(strlen(mem_info.details.name) == 0)
		strncpy(name, "noname_memblk", sizeof(name) - 1);

	SceMemBlockObj *pObj;
	res = ksceKernelGetObjForUid(memblk_id, _ksceKernelGetUIDMemBlockClass(), (SceObjectBase **)&pObj);
	if(res < 0){
		ksceDebugPrintf("[error] sceGUIDReferObjectWithClass failed : 0x%X, uid:0x%X\n", res, memblk_id);
		return -1; // ?
	}

	ksceKernelUidRelease(memblk_id);

	LogWrite("\t[%-31s]\n", name);
	LogWrite("\tGUID : 0x%X\n", memblk_id);
	LogWrite("\ttype : 0x%08X (\n", mem_info.details.type);

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

	LogWrite("\tvaddr: 0x%X\n", pObj->vaddr);
	LogWrite("\tsize : 0x%X\n", pObj->size);
	LogWrite("\tflags: 0x%X\n", pObj->flags);

	SceKernelMemBlockAddressTree *address_tree = pObj->address_tree;
	while(address_tree != NULL){

		LogWrite(
			"\tvaddr 0x%08X paddr 0x%08X size 0x%-10X flags:0x%X\n",
			address_tree->vaddr, address_tree->paddr, address_tree->size, address_tree->flags
		);

		address_tree = address_tree->next;
	}

	LogWrite("\n");

	return 0;
}

int fapsCoredumpCreateModulesInfo(FapsCoredumpContext *context){

	SceSize modnum;
	SceModuleInfoInternal *module_info;

	if(context->process_module_info == NULL)
		return -1;

	if(LogIsOpened() != 0){
		ksceDebugPrintf("[error] Previously opened Log is not closed. in %s\n", __FUNCTION__);
		LogClose();
		return -1;
	}

	context->temp[FAPS_COREDUMP_TEMP_MAX_LENGTH] = 0;
	snprintf(context->temp, FAPS_COREDUMP_TEMP_MAX_LENGTH, "%s/%s", context->path, "modules_info.txt");
	if(LogOpen(context->temp) < 0)
		return -1;

	modnum = context->process_module_info->process_module_count;

	do {
		modnum--;
		module_info = context->module_list[modnum];

		if(module_info->segments[1].memsz != 0){
			LogWrite(
				"[%-27s]:text=%p(0x%08x), data=%p(0x%08x/0x%08x)\n",
				module_info->module_name,
				module_info->segments[0].vaddr,
				module_info->segments[0].memsz,
				module_info->segments[1].vaddr,
				module_info->segments[1].filesz,
				module_info->segments[1].memsz
			);
		}else{
			LogWrite(
				"[%-27s]:text=%p(0x%08x), (no data)\n",
				module_info->module_name,
				module_info->segments[0].vaddr,
				module_info->segments[0].memsz
			);
		}

		LogWrite("fingerprint: 0x%08X\n", module_info->module_nid);
		LogWrite("flags      : 0x%08X\n", module_info->flags);
		LogWrite("modid(user): 0x%08X\n", module_info->modid_user);
		LogWrite("modid(kern): 0x%08X\n", module_info->modid_kernel);
		LogWrite(
			"text params:0x%02X, 0x%02X, segment align:0x%X",
			module_info->segments[0].perms[0], module_info->segments[0].perms[3],
			(1 << module_info->segments[0].perms[2])
		);
		if(module_info->segments[0].perms[1] != 0){
			LogWrite(", extra memory size:0x%X", (module_info->segments[0].perms[1] << 0xC));
		}
		LogWrite("\n");

		LogWrite(
			"data params:0x%02X, 0x%02X, segment align:0x%X",
			module_info->segments[1].perms[0], module_info->segments[1].perms[3],
			(1 << module_info->segments[1].perms[2])
		);
		if(module_info->segments[1].perms[1] != 0){
			LogWrite(", extra memory size:0x%X", (module_info->segments[1].perms[1] << 0xC));
		}
		LogWrite("\n");

		LogWrite("path : %s\n", module_info->path);
		LogWrite("\n");

		if(fapsCoredumpIsFullDump() != 0){
			LogWrite("module membase list\n");
			write_membase_base_list(context, module_info->segments[0].memblk_id);
			write_membase_base_list(context, module_info->segments[1].memblk_id);
		}
	} while(modnum > 0);

	LogClose();

	return 0;
}

int fapsCoredumpCreateModuleSegmentDump(FapsCoredumpContext *context){

	int res;
	SceSize modnum;
	SceModuleInfoInternal *module_info;

	if(context->process_module_info == NULL)
		return -1;

	context->temp[FAPS_COREDUMP_TEMP_MAX_LENGTH] = 0;
	snprintf(context->temp, FAPS_COREDUMP_TEMP_MAX_LENGTH, "%s/%s", context->path, "module_segments");

	res = ksceIoMkdir(context->temp, 0666);
	if(res < 0)
		return res;

	modnum = context->process_module_info->process_module_count;

	do {
		modnum--;
		module_info = context->module_list[modnum];

		for(int i=0;i<module_info->segments_num;i++){

			if(module_info->segments[i].vaddr != NULL){

				context->temp[FAPS_COREDUMP_TEMP_MAX_LENGTH] = 0;
				snprintf(context->temp, FAPS_COREDUMP_TEMP_MAX_LENGTH, "%s/%s/%s_seg%X.bin", context->path, "module_segments", module_info->module_name, i);

				SceIoStat stat;
				if(ksceIoGetstat(context->temp, &stat) == 0){
					ksceDebugPrintf("[warning]:Skip because dump of the same module already exists -> (%s)\n", module_info->module_name);
				}else{
					write_file_user(context->pid, context->temp, module_info->segments[i].vaddr, module_info->segments[i].memsz);
				}
			}
		}
	} while(modnum > 0);

	return 0;
}

int fapsCoredumpCreateModuleNonlinkedInfo(FapsCoredumpContext *context){

	if(context->process_module_info == NULL)
		return -1;

	if(LogIsOpened() != 0){
		ksceDebugPrintf("[error] Previously opened Log is not closed. in %s\n", __FUNCTION__);
		LogClose();
		return -1;
	}

	SceModuleNonlinkedInfo *pNonlinkedInfo = context->process_module_info->nonlinked_info;

	if(pNonlinkedInfo == NULL){
		ksceDebugPrintf("[%-7s] not has nonlinked to this process.\n", "info");
		return 0;
	}

	context->temp[FAPS_COREDUMP_TEMP_MAX_LENGTH] = 0;
	snprintf(context->temp, FAPS_COREDUMP_TEMP_MAX_LENGTH, "%s/%s", context->path, "module_nonlinked_info.txt");
	if(LogOpen(context->temp) < 0){
		ksceDebugPrintf("[error] Log open failed. in %s\n", "fapsCreateModuleNonlinkedInfo");
		return -1;
	}

	LogWrite("# module nonlinked info\n");

	const char *old_name = "SceDummyModule_______________________________";

	while(pNonlinkedInfo != NULL){

		if(strcmp(pNonlinkedInfo->pModuleInfo->module_name, old_name) != 0){
			old_name = pNonlinkedInfo->pModuleInfo->module_name;
			LogWrite("\n[%-27s]\n", old_name);
		}

		LogWrite(
			"\tnid=0x%08X, flags=0x%04X, ver=%d, %s\n",
			pNonlinkedInfo->pImportInfo->type2.libnid,
			pNonlinkedInfo->pImportInfo->type2.flags,
			pNonlinkedInfo->pImportInfo->type2.version,
			pNonlinkedInfo->pImportInfo->type2.libname
		);

		pNonlinkedInfo = pNonlinkedInfo->next;
	}

	LogClose();

	return 0;
}
