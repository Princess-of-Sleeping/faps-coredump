/*
 * faps-coredump coredump.c
 * Copyright (C) 2021, Princess of Sleeping
 */

#include <psp2kern/kernel/threadmgr.h>
#include <psp2kern/kernel/sysmem.h>
#include <psp2kern/kernel/sysclib.h>
#include <psp2kern/kernel/rtc.h>
#include <psp2kern/io/fcntl.h>
#include <psp2kern/ctrl.h>
#include <psp2kern/touch.h>
#include "types.h"
#include "utility.h"
#include "log.h"
#include "coredump_func.h"

extern SceUID mutex_uid;

typedef struct FapsCoredumpDumpFunc {
	int (* func)(FapsCoredumpContext *context);
} FapsCoredumpDumpFunc;

const FapsCoredumpDumpFunc dump_func_list[] = {
	{
		.func = fapsCoredumpInitProcessModule
	},
	{
		.func = fapsCoredumpCreateSummary
	},
	{
		.func = fapsCoredumpCreateHwInfo
	},
	{
		.func = fapsCoredumpCreateTtyInfo
	},
	{
		.func = fapsCoredumpCreateProcessInfo
	},
	{
		.func = fapsCoredumpCreateAsInfoDump
	},
	{
		.func = fapsCoredumpCreateCrashThreadInfo
	},
	{
		.func = fapsCoredumpCreateCrashThreadStackDump
	},
	{
		.func = fapsCoredumpCreateEventLogInfo
	},
	{
		.func = fapsCoredumpCreateModulesInfo
	},
	{
		.func = fapsCoredumpCreateModuleSegmentDump
	},
	{
		.func = fapsCoredumpCreateModuleNonlinkedInfo
	},
	{
		.func = fapsCoredumpMemblockAlloc
	},
	{
		.func = fapsUpdateMemBlockInfo
	},
	{
		.func = fapsCreateMemBlockInfo
	},
	{
		.func = fapsCreateMemBlockDump
	},
	{
		.func = fapsFreeMemBlockInfo
	},
	{
		.func = fapsCoredumpCreateProcessScreenShot
	},
	{
		.func = fapsCoredumpCreateProcessIofileInfo
	},
	{
		.func = fapsCreateProcessThreadInfo
	},
	{
		.func = fapsCreateProcessSemaphoreInfo
	},
	{
		.func = fapsCreateProcessEventflagInfo
	},
	{
		.func = fapsCreateProcessMutexInfo
	},
	{
		.func = fapsCreateProcessLwMutexInfo
	},
	{
		.func = fapsCreateProcessMsgpipeInfo
	},
	{
		.func = fapsCreateProcessLwCondInfo
	}
};

#define FAPS_COREDUMP_DUMP_FUNC_NUMBER (sizeof(dump_func_list) / sizeof(dump_func_list[0]))

int fapsCreateCoredump(FapsCoredumpContext *context){

	int res;
	SceUID memid;
	SceIoStat stat;
	SceRtcTick tick;
	SceDateTime date_time;

	if(context->pid == SCE_GUID_KERNEL_PROCESS_ID)
		return 0;

	fapsCoredumpIsFullDumpUpdate();

	memid = ksceKernelAllocMemBlock("SceUIDPool", 0x1020D006, 0x2000, NULL);
	if(memid < 0)
		return memid;

	res = ksceKernelGetMemBlockBase(memid, (void **)&(context->uid_pool));
	if(res < 0)
		goto end;

	res = ksceRtcGetCurrentTick(&tick);
	if(res < 0)
		goto end;

	res = ksceRtcConvertTickToDateTime(&date_time, &tick);
	if(res < 0)
		goto end;

	res = ksceRtcConvertDateTimeToUnixTime(&date_time, &(context->tick));
	if(res < 0)
		goto end;

	context->name[FAPS_COREDUMP_NAME_MAX_LENGTH] = 0;
	context->path[FAPS_COREDUMP_PATH_MAX_LENGTH] = 0;

	res = ksceKernelGetProcessTitleId(context->pid, context->titleid, FAPS_COREDUMP_TITLEID_SIZE);
	if(res < 0){
		context->titleid[FAPS_COREDUMP_TITLEID_MAX_LENGTH] = 0;
		strncpy(context->titleid, "unknown", FAPS_COREDUMP_TITLEID_MAX_LENGTH);
	}

	snprintf(context->name, FAPS_COREDUMP_NAME_MAX_LENGTH, "fapscore-%s-%010llu-0x%010X", context->titleid, context->tick, context->pid);

	if(ksceIoGetstat("host0:", &stat) == 0){
		snprintf(context->path, FAPS_COREDUMP_PATH_MAX_LENGTH, "%s/%s", "host0:", context->name);
	}else if(ksceIoGetstat("sd0:", &stat) == 0){
		snprintf(context->path, FAPS_COREDUMP_PATH_MAX_LENGTH, "%s/%s", "sd0:", context->name);
	}else{
		snprintf(context->path, FAPS_COREDUMP_PATH_MAX_LENGTH, "%s/%s", "ux0:/data", context->name);
	}

	res = ksceIoMkdir(context->path, 0666);
	if(res < 0)
		goto end;

	for(int i=0;i<FAPS_COREDUMP_DUMP_FUNC_NUMBER;i++){
		context->update_func(context->task_id, context->pid, (i * 100) / FAPS_COREDUMP_DUMP_FUNC_NUMBER);
		dump_func_list[i].func(context);
	}

	context->update_func(context->task_id, context->pid, (FAPS_COREDUMP_DUMP_FUNC_NUMBER * 100) / FAPS_COREDUMP_DUMP_FUNC_NUMBER);

	res = 0;

end:
	if(memid >= 0)
		ksceKernelFreeMemBlock(memid);

	return res;
}

int fapsCoredumpTrigger(FapsCoredumpContext *context){

	int res, cpu;
	SceUInt32 ctrl_mask;
	SceInt64 time_s, time_e;

	// TODO: Add ctrl/touch disables

	cpu = ksceKernelCpuGetCpuId();

	ksceKernelLockMutex(mutex_uid, 1, NULL);

	ksceTouchSetEnableFlag(0, 0);
	ksceTouchSetEnableFlag(1, 0);

	ksceCtrlGetMaskForAll(&ctrl_mask);
	ksceCtrlUpdateMaskForAll(~0, 0);

	ksceDebugPrintf("%d:[faps-coredump] start\n", cpu);

	time_s = ksceKernelGetSystemTimeWide();
	res = fapsCreateCoredump(context);
	time_e = ksceKernelGetSystemTimeWide();

	// Do not clean the context.
	// memset(context, 0, sizeof(*context));

	ksceDebugPrintf("%d:[faps-coredump] %s. in %lld usec.\n", cpu, (res >= 0) ? "done" : "error", (SceInt64)(time_e - time_s));

	if(res < 0){
		ksceDebugPrintf("%d:[faps-coredump] result=0x%X.\n", cpu, res);
	}

	ksceCtrlUpdateMaskForAll(0, ctrl_mask);

	ksceTouchSetEnableFlag(0, 1);
	ksceTouchSetEnableFlag(1, 1);

	ksceKernelUnlockMutex(mutex_uid, 1);

	return 0;
}
