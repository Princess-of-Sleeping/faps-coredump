/*
 * faps-coredump process_info.c
 * Copyright (C) 2021, Princess of Sleeping
 */

#include <psp2kern/types.h>
#include <psp2kern/kernel/sysmem.h>
#include <psp2kern/kernel/sysclib.h>
#include "log.h"
#include "utility.h"
#include "modulemgr_internal.h"
#include "coredump_func.h"

extern SceClass *(* _ksceKernelGetUIDProcessClass)(void);
extern SceKernelProcessModuleInfo *(* sceKernelProcessModuleInfo)(SceUID pid);

int fapsCoredumpCreateProcessInfo(FapsCoredumpContext *context){

	int res;
	void *pObj;

	SceKernelProcessModuleInfo *process_module_info = context->process_module_info;

	if(process_module_info == NULL)
		return -1;

	res = ksceGUIDReferObjectWithClass(context->pid, _ksceKernelGetUIDProcessClass(), (SceObjectBase **)&pObj);
	if(res < 0){
		return res;
	}

	ksceGUIDReleaseObject(context->pid);

	context->temp[FAPS_COREDUMP_TEMP_MAX_LENGTH] = 0;
	snprintf(context->temp, FAPS_COREDUMP_TEMP_MAX_LENGTH, "%s/%s", context->path, "process_info.txt");
	if(LogOpen(context->temp) < 0)
		return -1;

	LogWrite("# Basic info\n");
	LogWrite("\tpid     : 0x%08X\n", *(SceUID *)(pObj + 0x64));
	LogWrite("\ttitleid : %s\n", (char *)(pObj + 0x4C0));
	LogWrite("\t__stack_chk_guard value : 0x%08X\n", *(uint32_t *)(pObj + 0x2C0));
	LogWrite("\n");

	LogWrite("# Module info\n");
	LogWrite("\tmodule count : %u\n", process_module_info->process_module_count);
	LogWrite("\tinhibit state\n");

	SceUInt16 inhibit_state = process_module_info->inhibit_state;

	if(inhibit_state == 0){
		LogWrite("\t- none\n");
	}else{
		if((inhibit_state & 0x1) != 0)
			LogWrite("\t- inhibit shared\n");

		if((inhibit_state & 0x2) != 0)
			LogWrite("\t- inhibit to disable ASLR\n");

		if((inhibit_state & 0xF0) != 0){
			if((inhibit_state & 0xF0) == 0x10){
				LogWrite("\t- inhibit load module level 1\n");
			}else if((inhibit_state & 0xF0) == 0x20){
				LogWrite("\t- inhibit load module level 2\n");
			}else if((inhibit_state & 0xF0) == 0x30){
				LogWrite("\t- inhibit load module level 3\n");
			}else{
				LogWrite("\t- inhibit load module (unknown)\n");
			}
		}

		if((inhibit_state & 0x8000) != 0)
			LogWrite("\t- inhibit to \"inhibit to disable ASLR\"\n");
	}

	LogClose();

	return 0;
}
