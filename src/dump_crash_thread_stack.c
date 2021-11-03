/*
 * faps-coredump dump_crash_thread_stack.c
 * Copyright (C) 2021, Princess of Sleeping
 */

#include <psp2kern/types.h>
#include <psp2kern/kernel/threadmgr.h>
#include <psp2kern/kernel/sysclib.h>
#include "utility.h"
#include "coredump_func.h"
#include "threadmgr_types.h"

int fapsCoredumpCreateCrashThreadStackDump(FapsCoredumpContext *context){

	int res;
	SceKernelThreadInfo info;

	if(context->thid <= 0)
		return 0;

	memset(&info, 0, sizeof(info));
	info.size = sizeof(info);
	res = ksceKernelGetThreadInfo(context->thid, &info);
	if(res < 0)
		return res;

	void *stack    = (void *)(info.stack);
	int stackSize  = info.stackSize;

	context->temp[FAPS_COREDUMP_TEMP_MAX_LENGTH] = 0;
	snprintf(context->temp, FAPS_COREDUMP_TEMP_MAX_LENGTH, "%s/%s", context->path, "crash_thread_stack.bin");

	res = write_file_user(context->pid, context->temp, stack, stackSize);
	if(res < 0)
		return res;

	return 0;
}
