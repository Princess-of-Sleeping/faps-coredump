/*
 * faps-coredump coredump_func.c
 * Copyright (C) 2021, Princess of Sleeping
 */

#include <psp2kern/kernel/sysmem.h>
#include <psp2kern/kernel/sysclib.h>
#include <psp2kern/kernel/rtc.h>
#include <psp2kern/io/fcntl.h>
#include <psp2kern/sblaimgr.h>
#include "types.h"
#include "coredump_func.h"

int fapsCoredumpCreateDumpDirectory(FapsCoredumpContext *context){

	int res, path_len;

	path_len = strnlen(context->path, FAPS_COREDUMP_PATH_SIZE);

	if(path_len == 0 || path_len == FAPS_COREDUMP_PATH_SIZE)
		return -1;

	res = ksceIoMkdir(context->path, 0666);
	if(res < 0)
		return res;

	return 0;
}

int fapsCoredumpMakeDumpPathName(FapsCoredumpContext *context){

	int res;
	SceIoStat stat;

	context->name[FAPS_COREDUMP_NAME_MAX_LENGTH] = 0;
	context->path[FAPS_COREDUMP_PATH_MAX_LENGTH] = 0;

	res = ksceKernelGetProcessTitleId(context->pid, context->titleid, FAPS_COREDUMP_TITLEID_SIZE);
	if(res < 0){
		context->titleid[FAPS_COREDUMP_TITLEID_MAX_LENGTH] = 0;
		strncpy(context->titleid, "unknown", FAPS_COREDUMP_TITLEID_MAX_LENGTH);
	}

	snprintf(context->name, FAPS_COREDUMP_NAME_MAX_LENGTH, "fapscore-%s-%010llu-0x%010X", context->titleid, context->tick, context->pid);

	context->path[0] = 0;

	res = ksceIoGetstat("host0:", &stat);
	if(res == 0 && context->path[0] == 0 && ksceSblAimgrIsTool() != 0)
		snprintf(context->path, FAPS_COREDUMP_PATH_MAX_LENGTH, "%s/%s", "host0:", context->name);

	res = ksceIoGetstat("sd0:", &stat);
	if(res == 0 && context->path[0] == 0)
		snprintf(context->path, FAPS_COREDUMP_PATH_MAX_LENGTH, "%s/%s", "sd0:", context->name);

	res = ksceIoGetstat("ux0:/data", &stat);
	if(res == 0 && context->path[0] == 0)
		snprintf(context->path, FAPS_COREDUMP_PATH_MAX_LENGTH, "%s/%s", "ux0:/data", context->name);

	if(context->path[0] == 0)
		return -1;

	return 0;
}

int fapsCoredumpGetDumpTime(FapsCoredumpContext *context){

	int res;
	SceRtcTick tick;
	SceDateTime date_time;

	res = ksceRtcGetCurrentTick(&tick);
	if(res < 0)
		return res;

	res = ksceRtcConvertTickToDateTime(&date_time, &tick);
	if(res < 0)
		return res;

	res = ksceRtcConvertDateTimeToUnixTime(&date_time, &(context->tick));
	if(res < 0)
		return res;

	return 0;
}

int fapsCoredumpInitUIDPool(FapsCoredumpContext *context){

	int res;
	SceUID memid;

	context->memblock_id = -1;

	memid = ksceKernelAllocMemBlock("SceUIDPool", 0x1020D006, 0x2000, NULL);
	if(memid < 0)
		return memid;

	res = ksceKernelGetMemBlockBase(memid, (void **)&(context->uid_pool));
	if(res < 0)
		return res;

	context->memblock_id = memid;

	return 0;
}

int fapsCoredumpFineUIDPool(FapsCoredumpContext *context){

	if(context->memblock_id >= 0){
		ksceKernelFreeMemBlock(context->memblock_id);
		context->memblock_id = -1;
	}

	return 0;
}
