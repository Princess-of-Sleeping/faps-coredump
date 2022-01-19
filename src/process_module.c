/*
 * faps-coredump process_module.c
 * Copyright (C) 2021, Princess of Sleeping
 */

#include <psp2kern/types.h>
#include <psp2kern/kernel/sysmem.h>
#include <psp2kern/kernel/sysclib.h>
#include <psp2kern/io/fcntl.h>
#include <psp2kern/io/stat.h>
#include "log.h"
#include "utility.h"
#include "modulemgr_internal.h"
#include "process_mapping.h"
#include "coredump_func.h"
#include "sysmem_types.h"
#include "elf.h"

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

typedef struct SceModuleEntryPoint { // size is 0x5C-bytes
	SceUInt16 attr;
	SceUInt8 minor;
	SceUInt8 major;
	char name[27];
	SceUInt8 type;
	void *gp_value;
	SceUInt32 libent_top;
	SceUInt32 libent_btm;
	SceUInt32 libstub_top;
	SceUInt32 libstub_btm;
	SceUInt32 fingerpint;
	int unk_0x38;
	int unk_0x3C;
	int unk_0x40;
	SceUInt32 module_start;
	SceUInt32 module_stop;
	SceUInt32 exidx_start;
	SceUInt32 exidx_end;
	SceUInt32 extab_start;
	SceUInt32 extab_end;
} SceModuleEntryPoint;

int search_module_entry_point(SceUID pid, SceModuleInfoInternal *module_info, SceUInt32 *entry){

	void *ent, *curr_ptr;
	char module_name[0x1C];
	SceModuleEntryPoint entryPoint;

	if(module_info->libent_top != NULL){ // get module entry point

		SceSize remain = module_info->libent_top - module_info->segments[0].vaddr;
		while(remain >= (0x24 + 4)){
			remain -= 4;

			curr_ptr = module_info->segments[0].vaddr + remain;

			ksceKernelProcMemcpyFromUser(pid, &ent, curr_ptr, sizeof(ent));

			if(ent == (void *)(module_info->libent_top - module_info->segments[0].vaddr)){

				ksceKernelProcMemcpyFromUser(pid, &entryPoint, curr_ptr - 0x24, sizeof(entryPoint));

				if(entryPoint.attr != module_info->attr)
					continue;

				if(entryPoint.minor != module_info->minor)
					continue;

				if(entryPoint.major != module_info->major)
					continue;

				strncpy(module_name, module_info->module_name, 0x1B);

				if(memcmp(module_name, entryPoint.name, 0x1B) != 0)
					continue;

				if(entryPoint.type != 6)
					continue;

				if(entry != NULL)
					*entry = remain - 0x24;

				return 0;
			}
		}
	}

	return -1;
}

int fapsCoredumpCreateModuleSegmentDump(FapsCoredumpContext *context){

	int res;
	SceUID memid;
	void *base;
	SceSize modnum;
	SceModuleInfoInternal *module_info;
	Elf32_Ehdr ehdr;
	ElfEntryInfo elf_ent[2];
	uint32_t offset;

	if(context->process_module_info == NULL)
		return -1;

	memid = ksceKernelAllocMemBlock("ZeroFill", 0x1020D006, 0x1000, NULL);
	if(memid < 0){
		return memid;
	}

	ksceKernelGetMemBlockBase(memid, &base);

	memset(base, 0, 0x1000);

	context->temp[FAPS_COREDUMP_TEMP_MAX_LENGTH] = 0;
	snprintf(context->temp, FAPS_COREDUMP_TEMP_MAX_LENGTH, "%s/%s", context->path, "module_segments");

	res = ksceIoMkdir(context->temp, 0666);
	if(res < 0){
		goto end;
	}

	modnum = context->process_module_info->process_module_count;

	do {
		modnum--;
		module_info = context->module_list[modnum];

		if(module_info->segments_num < 3){

			uint32_t entry = 0xDEADBEEF;

			res = search_module_entry_point(context->pid, module_info, &entry);
			if(res < 0 || entry == 0xDEADBEEF){
				ksceDebugPrintf("Not found entry point\n");
				entry = ~0;
			}

			offset = sizeof(Elf32_Ehdr) + module_info->segments_num * sizeof(ElfEntryInfo);

			for(int i=0;i<module_info->segments_num;i++){
				offset = ((offset + 0xF) & ~0xF);
				elf_ent[i].type   = 1;
				elf_ent[i].vaddr  = (uint32_t)module_info->segments[i].vaddr;
				elf_ent[i].paddr  = (uint32_t)module_info->segments[i].vaddr;
				elf_ent[i].filesz = module_info->segments[i].memsz;
				elf_ent[i].memsz  = module_info->segments[i].memsz;
				elf_ent[i].flags  = module_info->segments[i].perms[0];
				elf_ent[i].align  = 1 << module_info->segments[i].perms[2];

				elf_ent[i].offset = (offset + (elf_ent[i].align - 1)) & ~(elf_ent[i].align - 1);

				offset = elf_ent[i].offset + module_info->segments[i].memsz;
			}

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
			ehdr.e_entry = entry;
			ehdr.e_phoff = sizeof(ehdr);

			ehdr.e_shoff     = 0;
			ehdr.e_flags     = 0x05000000;
			ehdr.e_ehsize    = sizeof(ehdr);
			ehdr.e_phentsize = sizeof(ElfEntryInfo);
			ehdr.e_phnum     = module_info->segments_num;
			ehdr.e_shentsize = 0;

			ehdr.e_shnum = 0;
			ehdr.e_shstrndx = 0;

			context->temp[FAPS_COREDUMP_TEMP_MAX_LENGTH] = 0;
			snprintf(context->temp, FAPS_COREDUMP_TEMP_MAX_LENGTH, "%s/%s/%s.elf", context->path, "module_segments", module_info->module_name);

			SceUID fd = ksceIoOpen(context->temp, SCE_O_CREAT | SCE_O_TRUNC | SCE_O_WRONLY, 0666);
			if(fd >= 0){
				write_file_proc_by_fd(0x10005, fd, &ehdr, sizeof(ehdr));
				write_file_proc_by_fd(0x10005, fd, elf_ent, sizeof(ElfEntryInfo) * module_info->segments_num);

				offset = sizeof(Elf32_Ehdr) + module_info->segments_num * sizeof(ElfEntryInfo);

				for(int i=0;i<module_info->segments_num;i++){

					if((elf_ent[i].offset - offset) != 0){
						write_file_proc_by_fd(module_info->pid, fd, base, elf_ent[i].offset - offset);
					}

					offset = (offset + (elf_ent[i].align - 1)) & ~(elf_ent[i].align - 1);

					write_file_proc_by_fd(module_info->pid, fd, module_info->segments[i].vaddr, module_info->segments[i].memsz);

					offset += module_info->segments[i].memsz;
				}

				ksceIoClose(fd);
			}
		}
	} while(modnum > 0);

	res = 0;

end:
	ksceKernelFreeMemBlock(memid);

	return res;
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
