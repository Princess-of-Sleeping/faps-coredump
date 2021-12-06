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
#include "process_mapping.h"
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
	LogWrite("\ttype : 0x%08X (", mem_info.details.type);

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

		SceUInt32 sdk = module_info->version;

		LogWrite("module id      : 0x%08X/0x%08X\n", module_info->modid_user, module_info->modid_kernel);
		LogWrite("path           : %s\n", module_info->path);
		LogWrite("version        : %X.%X\n", module_info->major, module_info->minor);
		LogWrite("SDK            : %X.%03X.%03X\n", (sdk >> 24) & 0xFF, (sdk >> 12) & 0xFFF, sdk & 0xFFF);
		LogWrite("attr           : 0x%04X\n", module_info->attr);
		LogWrite("fingerprint    : 0x%08X\n", module_info->fingerprint);
		LogWrite("library export : %d\n", module_info->lib_export_num);
		LogWrite("library import : %d\n", module_info->lib_import_num);

		LogWrite("flags          : 0x%04X\n", module_info->flags);
		LogWrite("text params    : 0x%02X, align:0x%X", module_info->segments[0].perms[0], (1 << module_info->segments[0].perms[2]));
		if(module_info->segments[0].perms[1] != 0)
			LogWrite(", extra memory size:0x%X", (module_info->segments[0].perms[1] << 0xC));
		LogWrite("\n");

		LogWrite("data params    : 0x%02X, align:0x%X", module_info->segments[1].perms[0], (1 << module_info->segments[1].perms[2]));
		if(module_info->segments[1].perms[1] != 0)
			LogWrite(", extra memory size:0x%X", (module_info->segments[1].perms[1] << 0xC));
		LogWrite("\n");

		// LogWrite("first import   : %s\n", module_info->data_0x60->type2.libname);
		LogWrite("\n");

		if(fapsCoredumpIsFullDump(context) != 0){
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
					write_file_proc(module_info->pid, context->temp, module_info->segments[i].vaddr, module_info->segments[i].memsz);
				}
			}
		}
	} while(modnum > 0);

	return 0;
}

int fapsCoredumpCreateModuleNonlinkedInfo(FapsCoredumpContext *context){

	if(context->process_module_info == NULL)
		return -1;

	SceModuleImportInfo *pNonlinkedInfo = context->process_module_info->nonlinked_info;

	if(pNonlinkedInfo == NULL){
		ksceDebugPrintf("[%-7s] not has nonlinked to this process.\n", "info");
		return 0;
	}

	context->temp[FAPS_COREDUMP_TEMP_MAX_LENGTH] = 0;
	snprintf(context->temp, FAPS_COREDUMP_TEMP_MAX_LENGTH, "%s/%s", context->path, "module_nonlinked_info.txt");
	if(LogOpen(context->temp) < 0)
		return -1;

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

int fapsCoredumpCreateModuleImportYml(FapsCoredumpContext *context){

	int res;
	SceModuleInfoInternal *pModuleInfo;

	if(context->process_module_info == NULL)
		return -1;

	context->temp[FAPS_COREDUMP_TEMP_MAX_LENGTH] = 0;
	snprintf(context->temp, FAPS_COREDUMP_TEMP_MAX_LENGTH, "%s/%s", context->path, "module_import_yml");

	res = ksceIoMkdir(context->temp, 0666);
	if(res < 0)
		return res;

	pModuleInfo = context->process_module_info->module_info;

	while(pModuleInfo != NULL){

		context->temp[FAPS_COREDUMP_TEMP_MAX_LENGTH] = 0;
		snprintf(context->temp, FAPS_COREDUMP_TEMP_MAX_LENGTH, "%s/%s/%s.yml", context->path, "module_import_yml", pModuleInfo->module_name);

		LogOpen(context->temp);

		LogWrite("version: %d\n", 2);

		SceUInt8 version_upper, version_lower;
		SceSize ent_num;
		SceNID *pNIDTable;
		SceModuleImport *pImportInfo;
		FapsProcessMappingContext mapping_context;

		version_upper = (pModuleInfo->version >> 24) & 0xFF;
		version_lower = (pModuleInfo->version >> 16) & 0xFF;

		LogWrite("firmware: %X.%02X\n", version_upper, version_lower);
		LogWrite("modules:\n");
		LogWrite("  %s:\n", pModuleInfo->module_name);
		LogWrite("    nid: 0x%08X\n", pModuleInfo->fingerprint);
		LogWrite("    libraries:\n");

		for(int i=0;i<pModuleInfo->lib_import_num;i++){

			pImportInfo = pModuleInfo->import_list[i].pImportInfo;

			LogWrite("      %s:\n", pImportInfo->type2.libname);
			LogWrite("        version: 0x%04X\n", pImportInfo->type2.version);
			LogWrite("        flags: 0x%04X\n", pImportInfo->type2.flags);
			LogWrite("        nid: 0x%08X\n", pImportInfo->type2.libnid);

			ent_num = pImportInfo->type2.entry_num_function;
			if(ent_num > 0){
				res = faps_process_mapping_map(&mapping_context, pModuleInfo->pid, (void **)&pNIDTable, pImportInfo->type2.table_func_nid, ent_num * sizeof(SceNID));
				if(res >= 0){
					LogWrite("        function:\n");
					for(int i=0;i<ent_num;i++){
						snprintf(context->temp, FAPS_COREDUMP_TEMP_MAX_LENGTH, "%s_%08X", pImportInfo->type2.libname, pNIDTable[i]);
						LogWrite("          %s: 0x%08X\n", context->temp, pNIDTable[i]);
					}
					faps_process_mapping_unmap(&mapping_context);
				}
			}

			ent_num = pImportInfo->type2.entry_num_variable;
			if(ent_num > 0){
				res = faps_process_mapping_map(&mapping_context, pModuleInfo->pid, (void **)&pNIDTable, pImportInfo->type2.table_vars_nid, ent_num * sizeof(SceNID));
				if(res >= 0){
					LogWrite("        variable:\n");
					for(int i=0;i<ent_num;i++){
						snprintf(context->temp, FAPS_COREDUMP_TEMP_MAX_LENGTH, "%s_%08X", pImportInfo->type2.libname, pNIDTable[i]);
						LogWrite("          %s: 0x%08X\n", context->temp, pNIDTable[i]);
					}
					faps_process_mapping_unmap(&mapping_context);
				}
			}
		}

		LogClose();

		pModuleInfo = pModuleInfo->next;
	}

	return 0;
}

int fapsCoredumpCreateModuleExportYml(FapsCoredumpContext *context){

	int res;
	SceModuleInfoInternal *pModuleInfo;

	if(context->process_module_info == NULL)
		return -1;

	context->temp[FAPS_COREDUMP_TEMP_MAX_LENGTH] = 0;
	snprintf(context->temp, FAPS_COREDUMP_TEMP_MAX_LENGTH, "%s/%s", context->path, "module_export_yml");

	res = ksceIoMkdir(context->temp, 0666);
	if(res < 0)
		return res;

	pModuleInfo = context->process_module_info->module_info;

	while(pModuleInfo != NULL){

		context->temp[FAPS_COREDUMP_TEMP_MAX_LENGTH] = 0;
		snprintf(context->temp, FAPS_COREDUMP_TEMP_MAX_LENGTH, "%s/%s/%s.yml", context->path, "module_export_yml", pModuleInfo->module_name);

		LogOpen(context->temp);

		LogWrite("version: %d\n", 2);

		SceUInt8 version_upper, version_lower;
		SceSize ent_num;
		SceNID *pNIDTable;
		FapsProcessMappingContext mapping_context;

		version_upper = (pModuleInfo->version >> 24) & 0xFF;
		version_lower = (pModuleInfo->version >> 16) & 0xFF;

		LogWrite("firmware: %X.%02X\n", version_upper, version_lower);
		LogWrite("modules:\n");
		LogWrite("  %s:\n", pModuleInfo->module_name);
		LogWrite("    nid: 0x%08X\n", pModuleInfo->fingerprint);
		LogWrite("    libraries:\n");

		char lib_name[0x100];

		for(int i=0;i<pModuleInfo->lib_export_num;i++){

			SceModuleExport *pExportInfo = &(pModuleInfo->pLibraryInfo->pExportInfo[i]);

			lib_name[sizeof(lib_name) - 1] = 0;

			strncpy(lib_name, (pExportInfo->libname == NULL) ? "noname" : pExportInfo->libname, sizeof(lib_name) - 1);

			LogWrite("      %s:\n", lib_name);
			LogWrite("        version: 0x%04X\n", pExportInfo->version);
			LogWrite("        flags: 0x%04X\n", pExportInfo->flags);
			LogWrite("        nid: 0x%08X\n", pExportInfo->libnid);

			ent_num = (pExportInfo->entry_num_function + pExportInfo->entry_num_variable) * sizeof(SceNID);

			res = faps_process_mapping_map(&mapping_context, pModuleInfo->pid, (void **)&pNIDTable, pExportInfo->table_nid, ent_num);
			if(res >= 0){
				ent_num = pExportInfo->entry_num_function;
				if(ent_num > 0){
					LogWrite("        function:\n");
					for(int i=0;i<ent_num;i++){
						snprintf(context->temp, FAPS_COREDUMP_TEMP_MAX_LENGTH, "%s_%08X", lib_name, pNIDTable[i]);
						LogWrite("          %s: 0x%08X\n", context->temp, pNIDTable[i]);
					}
				}

				ent_num = pExportInfo->entry_num_variable;
				if(ent_num > 0){
					LogWrite("        variable:\n");
					for(int i=0;i<ent_num;i++){
						snprintf(context->temp, FAPS_COREDUMP_TEMP_MAX_LENGTH, "%s_%08X", lib_name, pNIDTable[pExportInfo->entry_num_function + i]);
						LogWrite("          %s: 0x%08X\n", context->temp, pNIDTable[i]);
					}
				}

				faps_process_mapping_unmap(&mapping_context);
			}
		}

		LogClose();

		pModuleInfo = pModuleInfo->next;
	}

	return 0;
}
