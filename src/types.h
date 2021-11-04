/*
 * faps-coredump types.h
 * Copyright (C) 2021, Princess of Sleeping
 */

#ifndef _FAPS_COREDUMP_TYPES_H_
#define _FAPS_COREDUMP_TYPES_H_

#include <psp2kern/kernel/processmgr.h>
#include <psp2kern/kernel/sysroot.h>

#define FAPS_COREDUMP_TITLEID_SIZE       (0x20)
#define FAPS_COREDUMP_TITLEID_MAX_LENGTH (FAPS_COREDUMP_TITLEID_SIZE - 1)
#define FAPS_COREDUMP_NAME_SIZE          (0x80)
#define FAPS_COREDUMP_NAME_MAX_LENGTH    (FAPS_COREDUMP_NAME_SIZE - 1)
#define FAPS_COREDUMP_PATH_SIZE          (0x100)
#define FAPS_COREDUMP_PATH_MAX_LENGTH    (FAPS_COREDUMP_PATH_SIZE - 1)
#define FAPS_COREDUMP_TEMP_SIZE          (0x180)
#define FAPS_COREDUMP_TEMP_MAX_LENGTH    (FAPS_COREDUMP_TEMP_SIZE - 1)

typedef struct FapsCoredumpContext {
	SceUInt64 tick;
	SceUID pid;
	SceUID thid;

	SceKernelCoredumpStateUpdateCallback update_func;
	int pad_0x14;
	int pad_0x18;
	int pad_0x1C;

	SceUID  memblock_id;
	SceUID *uid_pool;
	SceSize memblock_number;
	SceSize memblock_size_cache;

	int task_id;
	int cause_flag;
	int is_non_cpu_crash;
	SceKernelProcessModuleInfo *process_module_info;

	SceModuleInfoInternal *module_list[0xC0];
	char titleid[FAPS_COREDUMP_TITLEID_SIZE];
	char name[FAPS_COREDUMP_NAME_SIZE];
	char path[FAPS_COREDUMP_PATH_SIZE];
	char temp[FAPS_COREDUMP_TEMP_SIZE];
} FapsCoredumpContext;

#endif /* _FAPS_COREDUMP_TYPES_H_ */
