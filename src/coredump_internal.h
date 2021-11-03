
#ifndef _PSP2_COREDUMP_INTERNAL_H_
#define _PSP2_COREDUMP_INTERNAL_H_

#include <psp2kern/kernel/sysroot.h>

typedef struct SceCoredumpCrashCauseParam { // size is 8-bytes
	SceUID thid;
	int cause_flags;
} SceCoredumpCrashCauseParam;

typedef struct SceCoredumpCrashCauseResult { // size is 0x14-bytes
	SceUInt32 data_0x00;
	SceUInt32 cause;
	SceUInt32 data_0x08;
	SceUInt32 data_0x0C;
	SceUInt32 data_0x10;
} SceCoredumpCrashCauseResult;

typedef struct SceCoredumpTaskInfo { // size is 0x68
	int unk_0x00;
	SceUID pid;
	int task_id;
	int unk_0x0C;

	SceUInt32 dump_level; // 0xF (minimal coredump), 0xEF0 (full coredump)
	int unk_0x14;
	int unk_0x18;
	int unk_0x1C;

	int unk_0x20; // ex:0xA
	void *ptr_0x24;
	int unk_0x28; // ex:0xC
	void *ptr_0x2C;

	int unk_0x30; // ex:0x64
	int cause_flag;
	SceUID thid;
	int IsNonCpuCrash;

	SceKernelCoredumpStateUpdateCallback update_func;
	const void *cb_0x44; // in SceCoredump
	SceUID uid_0x48;
	int unk_0x4C;

	SceKernelCoredumpStateFinishCallback finish_func;
	int unk_0x54;
	int unk_0x58;
	int unk_0x5C;

	int unk_0x60;
	int unk_0x64;
} SceCoredumpTaskInfo;

typedef struct SceCoredumpQueueInfo {
	SceSize task_count;
	SceUID mutex_id;
	SceUID cond_id;
	SceCoredumpTaskInfo task_list[0xA];
} SceCoredumpQueueInfo;

#endif /* _PSP2_COREDUMP_INTERNAL_H_ */
