/*
 * faps-coredump summary.c
 * Copyright (C) 2021, Princess of Sleeping
 */

#include <psp2kern/types.h>
#include <psp2kern/kernel/sysmem.h>
#include <psp2kern/kernel/sysclib.h>
#include "types.h"
#include "log.h"
#include "utility.h"
#include "coredump_func.h"

int fapsCoredumpCreateSummary(FapsCoredumpContext *context){

	if(LogIsOpened() != 0){
		ksceDebugPrintf("[error] Previously opened Log is not closed. in %s\n", __FUNCTION__);
		LogClose();
		return -1;
	}

	context->temp[FAPS_COREDUMP_TEMP_MAX_LENGTH] = 0;
	snprintf(context->temp, FAPS_COREDUMP_TEMP_MAX_LENGTH, "%s/%s", context->path, "summary.txt");
	if(LogOpen(context->temp) < 0)
		return -1;

	LogWrite("Tick           : %010llu\n", context->tick);
	LogWrite("ProcessId      : 0x%X\n", context->pid);
	LogWrite("Crash ThreadId : 0x%X\n", context->thid);
	LogWrite("IsNonCpuCrash  : 0x%X\n", context->is_non_cpu_crash);
	LogWrite("Cause flag     : 0x%X\n", context->cause_flag);
	LogWrite("Title id       : %s\n", context->titleid);
	LogWrite("Path           : %s\n", context->path);
	LogWrite("Crash type     : ");

	if(fapsCoredumpIsSceShellUnknownCrash(context) != 0){ // SceShell Unknown Crash (GPU Crash?)
		LogWrite("SceShell Unknown Crash\n");
	}else if(fapsCoredumpIsGpuCrash(context) != 0){
		LogWrite("GPU Crash\n");
	}else if(fapsCoredumpIsNonCpuCrash(context) != 0){
		LogWrite("Non CPU Crash\n");
	}else{
		LogWrite("Normal Crash\n");
	}

	LogClose();

	return 0;
}
