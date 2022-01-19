/*
 * faps-coredump coredump.c
 * Copyright (C) 2021, Princess of Sleeping
 */

#include <psp2kern/kernel/debug.h>
#include <psp2kern/kernel/sysclib.h>
#include <psp2kern/kernel/threadmgr.h>
#include <psp2kern/ctrl.h>
#include <psp2kern/touch.h>
#include "types.h"
#include "utility.h"
#include "log.h"
#include "coredump_func.h"
#include "modulemgr_internal.h"

extern SceUID mutex_uid;

typedef struct FapsCoredumpDumpFunc {
	int (* func)(FapsCoredumpContext *context);
	const char *name;
	SceUInt32 flag;
} FapsCoredumpDumpFunc;

#define FAPS_COREDUMP_FUNC_FLAG_FORCED    (1 << 0)
#define FAPS_COREDUMP_FUNC_FLAG_SKIPPABLE (1 << 1)
#define FAPS_COREDUMP_FUNC_FLAG_LEVEL1    (1 << 2)
#define FAPS_COREDUMP_FUNC_FLAG_LEVEL2    (1 << 3)
#define FAPS_COREDUMP_FUNC_FLAG_LEVEL3    (1 << 4)
#define FAPS_COREDUMP_FUNC_FLAG_LEVEL4    (1 << 5)
#define FAPS_COREDUMP_FUNC_FLAG_LEVEL5    (1 << 6)

#define FAPS_COREDUMP_FUNC_FLAG_MINIMUM   FAPS_COREDUMP_FUNC_FLAG_LEVEL1
#define FAPS_COREDUMP_FUNC_FLAG_LITTLE    FAPS_COREDUMP_FUNC_FLAG_LEVEL2
#define FAPS_COREDUMP_FUNC_FLAG_NORMAL    FAPS_COREDUMP_FUNC_FLAG_LEVEL3
#define FAPS_COREDUMP_FUNC_FLAG_MANY      FAPS_COREDUMP_FUNC_FLAG_LEVEL4
#define FAPS_COREDUMP_FUNC_FLAG_FULL      FAPS_COREDUMP_FUNC_FLAG_LEVEL5

const FapsCoredumpDumpFunc dump_func_list[] = {
	{
		.func = fapsCoredumpGetDumpTime,
		.name = "GET_DUMP_TIME",
		.flag = FAPS_COREDUMP_FUNC_FLAG_FORCED
	},
	{
		.func = fapsCoredumpMakeDumpPathName,
		.name = "MAKE_DUMP_PATH_NAME",
		.flag = FAPS_COREDUMP_FUNC_FLAG_FORCED
	},
	{
		.func = fapsCoredumpCreateDumpDirectory,
		.name = "CREATE_DUMP_DIRECTORY",
		.flag = FAPS_COREDUMP_FUNC_FLAG_FORCED
	},
	{
		.func = fapsCoredumpInitProcessModule,
		.name = "INIT_PROCESS_MODULE",
		.flag = FAPS_COREDUMP_FUNC_FLAG_FORCED
	},
	{
		.func = fapsCoredumpInitUIDPool,
		.name = "UID_POOL_INIT",
		.flag = FAPS_COREDUMP_FUNC_FLAG_FORCED
	},
	{
		.func = fapsCoredumpCreateCrashThreadInfo,
		.name = "CRASH_THREAD_INFO",
		.flag = FAPS_COREDUMP_FUNC_FLAG_SKIPPABLE | FAPS_COREDUMP_FUNC_FLAG_MINIMUM
	},
	{
		.func = fapsCoredumpCreateCrashThreadStackDump,
		.name = "CRASH_THREAD_STACK_DUMP",
		.flag = FAPS_COREDUMP_FUNC_FLAG_SKIPPABLE | FAPS_COREDUMP_FUNC_FLAG_MINIMUM
	},
	{
		.func = fapsCoredumpCreateSummary,
		.name = "SUMMARY",
		.flag = FAPS_COREDUMP_FUNC_FLAG_SKIPPABLE | FAPS_COREDUMP_FUNC_FLAG_LITTLE
	},
	{
		.func = fapsCoredumpCreateHwInfo,
		.name = "HW_INFO",
		.flag = FAPS_COREDUMP_FUNC_FLAG_SKIPPABLE | FAPS_COREDUMP_FUNC_FLAG_LITTLE
	},
	{
		.func = fapsCoredumpCreateTtyInfo,
		.name = "TTY_INFO",
		.flag = FAPS_COREDUMP_FUNC_FLAG_SKIPPABLE | FAPS_COREDUMP_FUNC_FLAG_LITTLE
	},
	{
		.func = fapsCoredumpCreateProcessInfo,
		.name = "PROCESS_INFO",
		.flag = FAPS_COREDUMP_FUNC_FLAG_SKIPPABLE | FAPS_COREDUMP_FUNC_FLAG_NORMAL
	},
	{
		.func = fapsCoredumpCreateAsInfoDump,
		.name = "ADDRESS_SPACE_INFO",
		.flag = FAPS_COREDUMP_FUNC_FLAG_SKIPPABLE | FAPS_COREDUMP_FUNC_FLAG_NORMAL
	},
	{
		.func = fapsCoredumpCreateEventLogInfo,
		.name = "EVENT_LOG_INFO",
		.flag = FAPS_COREDUMP_FUNC_FLAG_SKIPPABLE | FAPS_COREDUMP_FUNC_FLAG_MANY
	},
	{
		.func = fapsCoredumpCreateModulesInfo,
		.name = "MODULE_INFO",
		.flag = FAPS_COREDUMP_FUNC_FLAG_SKIPPABLE | FAPS_COREDUMP_FUNC_FLAG_NORMAL
	},
	{
		.func = fapsCoredumpCreateModuleSegmentDump,
		.name = "MODULE_SEGMENT_DUMP",
		.flag = FAPS_COREDUMP_FUNC_FLAG_SKIPPABLE | FAPS_COREDUMP_FUNC_FLAG_MANY
	},
	{
		.func = fapsCoredumpCreateModuleNonlinkedInfo,
		.name = "MODULE_NONLINKED_INFO",
		.flag = FAPS_COREDUMP_FUNC_FLAG_SKIPPABLE | FAPS_COREDUMP_FUNC_FLAG_MANY
	},
	{
		.func = fapsCoredumpCreateModuleImportYml,
		.name = "MODULE_IMPORT_INFO",
		.flag = FAPS_COREDUMP_FUNC_FLAG_SKIPPABLE | FAPS_COREDUMP_FUNC_FLAG_MANY
	},
	{
		.func = fapsCoredumpCreateModuleExportYml,
		.name = "MODULE_EXPORT_INFO",
		.flag = FAPS_COREDUMP_FUNC_FLAG_SKIPPABLE | FAPS_COREDUMP_FUNC_FLAG_MANY
	},
	{
		.func = fapsUpdateMemBlockInfo,
		.name = "MEMBLOCK_UPDATE",
		.flag = FAPS_COREDUMP_FUNC_FLAG_SKIPPABLE | FAPS_COREDUMP_FUNC_FLAG_NORMAL
	},
	{
		.func = fapsCreateMemBlockInfo,
		.name = "MEMBLOCK_INFO",
		.flag = FAPS_COREDUMP_FUNC_FLAG_SKIPPABLE | FAPS_COREDUMP_FUNC_FLAG_NORMAL
	},
	{
		.func = fapsCreateMemBlockDump,
		.name = "MEMBLOCK_DUMP",
		.flag = FAPS_COREDUMP_FUNC_FLAG_SKIPPABLE | FAPS_COREDUMP_FUNC_FLAG_FULL
	},
	{
		.func = fapsCoredumpCreateProcessScreenShot,
		.name = "PROCESS_SCREEN_SHOT",
		.flag = FAPS_COREDUMP_FUNC_FLAG_SKIPPABLE | FAPS_COREDUMP_FUNC_FLAG_MANY
	},
	{
		.func = fapsCoredumpCreateProcessIofileInfo,
		.name = "PROCESS_FILE_INFO",
		.flag = FAPS_COREDUMP_FUNC_FLAG_SKIPPABLE | FAPS_COREDUMP_FUNC_FLAG_NORMAL
	},
	{
		.func = fapsCreateProcessThreadInfo,
		.name = "PROCESS_THREAD_INFO",
		.flag = FAPS_COREDUMP_FUNC_FLAG_SKIPPABLE | FAPS_COREDUMP_FUNC_FLAG_MANY
	},
	{
		.func = fapsCreateProcessSemaphoreInfo,
		.name = "PROCESS_SEMA_INFO",
		.flag = FAPS_COREDUMP_FUNC_FLAG_SKIPPABLE | FAPS_COREDUMP_FUNC_FLAG_MANY
	},
	{
		.func = fapsCreateProcessEventflagInfo,
		.name = "PROCESS_EVENT_FLAG_INFO",
		.flag = FAPS_COREDUMP_FUNC_FLAG_SKIPPABLE | FAPS_COREDUMP_FUNC_FLAG_MANY
	},
	{
		.func = fapsCreateProcessMutexInfo,
		.name = "PROCESS_MUTEX_INFO",
		.flag = FAPS_COREDUMP_FUNC_FLAG_SKIPPABLE | FAPS_COREDUMP_FUNC_FLAG_MANY
	},
	{
		.func = fapsCreateProcessLwMutexInfo,
		.name = "PROCESS_LW_MUTEX_INFO",
		.flag = FAPS_COREDUMP_FUNC_FLAG_SKIPPABLE | FAPS_COREDUMP_FUNC_FLAG_MANY
	},
	{
		.func = fapsCreateProcessMsgpipeInfo,
		.name = "PROCESS_MSG_PIPE_INFO",
		.flag = FAPS_COREDUMP_FUNC_FLAG_SKIPPABLE | FAPS_COREDUMP_FUNC_FLAG_MANY
	},
	{
		.func = fapsCreateProcessLwCondInfo,
		.name = "PROCESS_LW_COND_INFO",
		.flag = FAPS_COREDUMP_FUNC_FLAG_SKIPPABLE | FAPS_COREDUMP_FUNC_FLAG_MANY
	},
	{
		.func = fapsCoredumpFineUIDPool,
		.name = "UID_POOL_FINE",
		.flag = FAPS_COREDUMP_FUNC_FLAG_FORCED
	}
};

#define FAPS_COREDUMP_DUMP_FUNC_NUMBER (sizeof(dump_func_list) / sizeof(dump_func_list[0]))

int fapsCoredumpTrigger(FapsCoredumpContext *context){

	int res, cpu, is_skip, is_fulldump, flag;
	SceUInt32 ctrl_mask;
	SceInt64 time_s, time_e;

	if(context->pid == SCE_GUID_KERNEL_PROCESS_ID)
		return 0;

	cpu = ksceKernelCpuGetCpuId();

	ksceKernelLockMutex(mutex_uid, 1, NULL);

	ksceTouchSetEnableFlag(0, 0);
	ksceTouchSetEnableFlag(1, 0);

	ksceCtrlGetMaskForAll(&ctrl_mask);
	ksceCtrlUpdateMaskForAll(~0, 0);

	ksceDebugPrintf("%d:[faps-coredump] start\n", cpu);

	time_s = ksceKernelGetSystemTimeWide();

	is_skip = 0; // TODO
	is_fulldump = _fapsCoredumpIsFullDump();

	context->dump_level = 3 + is_fulldump;

	for(int i=0;i<FAPS_COREDUMP_DUMP_FUNC_NUMBER;i++){
		if(context->update_func != NULL){
			context->update_func(context->task_id, context->pid, (i * 100) / FAPS_COREDUMP_DUMP_FUNC_NUMBER);
		}

		flag = dump_func_list[i].flag;

		if((flag & FAPS_COREDUMP_FUNC_FLAG_FORCED) == 0){
			if((flag & FAPS_COREDUMP_FUNC_FLAG_FULL) != 0 && is_fulldump == 0)
				continue;

			if((flag & FAPS_COREDUMP_FUNC_FLAG_SKIPPABLE) != 0 && is_skip != 0)
				continue;
		}



		SceInt64 ftime_s, ftime_e;

		ftime_s = ksceKernelGetSystemTimeWide();

		if(dump_func_list[i].func == NULL){
			res = 0;
		}else{
			res = dump_func_list[i].func(context);
		}

		ftime_e = ksceKernelGetSystemTimeWide();

		ksceDebugPrintf("%d:[faps-coredump] %-32s %10lld [usec]\n", cpu, dump_func_list[i].name, (SceUInt64)(ftime_e - ftime_s));

		if(res < 0){
			ksceDebugPrintf("%d:[faps-coredump] failed function (%s result=0x%X)\n", cpu, dump_func_list[i].name, res);

			if((flag & FAPS_COREDUMP_FUNC_FLAG_FORCED) != 0)
				is_skip = 1;
		}

		if(LogIsOpened() != 0){
			LogClose();
			ksceDebugPrintf("%d:[faps-coredump] Previously opened Log is not closed. in %s\n", cpu, dump_func_list[i].name);
		}
	}

	if(context->update_func != NULL){
		context->update_func(context->task_id, context->pid, (FAPS_COREDUMP_DUMP_FUNC_NUMBER * 100) / FAPS_COREDUMP_DUMP_FUNC_NUMBER);
	}

	time_e = ksceKernelGetSystemTimeWide();

	// Do not clean the context.
	// memset(context, 0, sizeof(*context));

	ksceDebugPrintf("%d:[faps-coredump] done. in %lld usec.\n", cpu, (SceInt64)(time_e - time_s));

	ksceCtrlUpdateMaskForAll(0, ctrl_mask);

	ksceTouchSetEnableFlag(0, 1);
	ksceTouchSetEnableFlag(1, 1);

	ksceKernelUnlockMutex(mutex_uid, 1);

	return 0;
}
