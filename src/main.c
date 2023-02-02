/*
 * faps-coredump main.c
 * Copyright (C) 2021, Princess of Sleeping
 */

#include <psp2kern/kernel/modulemgr.h>
#include <psp2kern/kernel/threadmgr.h>
#include <psp2kern/kernel/sysmem.h>
#include <psp2kern/kernel/sysclib.h>
#include <psp2kern/kernel/sysroot.h>
#include <psp2kern/io/fcntl.h>
#include <psp2kern/sblaimgr.h>
#include <taihen.h>
#include "types.h"
#include "utility.h"
#include "coredump.h"
#include "coredump_internal.h"
#include "sce_as.h"
#include "modulemgr_3.10_3.74.h"

#define HookExport(module_name, library_nid, func_nid, func_name) taiHookFunctionExportForKernel(SCE_GUID_KERNEL_PROCESS_ID, &func_name ## _ref, module_name, library_nid, func_nid, func_name ## _patch)
#define HookImport(module_name, library_nid, func_nid, func_name) taiHookFunctionImportForKernel(SCE_GUID_KERNEL_PROCESS_ID, &func_name ## _ref, module_name, library_nid, func_nid, func_name ## _patch)
#define HookOffset(modid, offset, thumb, func_name) taiHookFunctionOffsetForKernel(SCE_GUID_KERNEL_PROCESS_ID, &func_name ## _ref, modid, 0, offset, thumb, func_name ## _patch)

#define HookRelease(hook_uid, hook_func_name)({ \
	(hook_uid > 0) ? taiHookReleaseForKernel(hook_uid, hook_func_name ## _ref) : -1; \
})

#define GetExport(modname, lib_nid, func_nid, func) module_get_export_func(SCE_GUID_KERNEL_PROCESS_ID, modname, lib_nid, func_nid, (uintptr_t *)func)

int module_get_offset(SceUID pid, SceUID modid, int segidx, size_t offset, uintptr_t *addr);
int module_get_export_func(SceUID pid, const char *modname, SceNID libnid, SceNID funcnid, uintptr_t *func);

/* ================================ data section ================================ */

FapsCoredumpContext coredump_context;

int (* sceKernelCoredumpStateFinish)(int task_id, SceUID pid, int error_code, const char *path, SceSize path_len, int a6);

SceKernelLibraryDB *(* sceKernelGetProcessModuleInfo)(SceUID pid);
SceUID (* sceKernelGetProcessAddressSpace)(SceUID pid);

int (* SceSysmemForKernel_C3EF4055)(SceUID asid, void *pInfo);
SceClass *(* _ksceKernelGetUIDMemBlockClass)(void);
SceClass *(* _ksceKernelGetUIDProcessClass)(void);
SceClass *(* _ksceKernelGetUIDThreadClass)(void);

int (* _ksceKernelFindClassByName)(const char *name, SceClass **cls);
int (* _kscePUIDGetUIDVectorByClass)(SceUID pid, SceClass *cls, int vis_level, SceUID *vector, SceSize num, SceSize *ret_num);
int (* _ksceKernelGetModuleInfo)(SceUID pid, SceUID modid, SceKernelModuleInfo *info);
int (* _ksceKernelGetModuleIdByAddr)(SceUID pid, const void *a2);

int (* sceKernelGetPhyMemPartInfoCore)(SceUIDPhyMemPartObject *a1, SceSysmemAddressSpaceInfo *pInfo);

int (* sceCoredumpGetCrashThreadCause)(SceUID thid, const SceCoredumpCrashCauseParam *param, SceCoredumpCrashCauseResult *result);

SceUID mutex_uid;
SceUID hook_id[4];

/* ================================ data section ================================ */

int fapsKernelGetModuleInfo(SceUID pid, SceUID modid, SceKernelModuleInfo *info){
	return _ksceKernelGetModuleInfo(pid, modid, info);
}

int fapsKernelGetModuleIdByAddr(SceUID pid, const void *a2){
	return _ksceKernelGetModuleIdByAddr(pid, a2);
}

const char *strchr_back(const char *s, int ch){

	int n = strlen(s);

	while(n-- != 0){
		if(s[n] == ch)
			return &s[n];
	}

	return NULL;
}

int fapsCoredumpMoveOriginalSceCoredump(FapsCoredumpContext *context, const char *sce_coredump_path){

	int res = 0;

	int path_len = strnlen(context->path, FAPS_COREDUMP_PATH_SIZE);

	if(path_len == 0 || path_len == FAPS_COREDUMP_PATH_SIZE)
		return -1;

	const char *s = strchr(sce_coredump_path, ':');
	if(s == NULL){
		return -1;
	}

	if(strncmp(sce_coredump_path, context->path, s - sce_coredump_path) == 0){

		const char *file = strchr_back(sce_coredump_path, '/');
		if(file == NULL){
			file = s;
		}

		if(file != NULL){
			context->temp[FAPS_COREDUMP_TEMP_MAX_LENGTH] = 0;
			snprintf(context->temp, FAPS_COREDUMP_TEMP_MAX_LENGTH, "%s/%s", context->path, &file[1]);

			res = ksceIoRename(sce_coredump_path, context->temp);
		}
	}

	return res;
}

int sceFapsCoredumpStateFinish(int task_id, SceUID pid, int result, const char *path, SceSize path_len, int a6){

	// Already coredump file is closed
	int res = fapsCoredumpMoveOriginalSceCoredump(&coredump_context, path);
	if(res >= 0){
		path     = coredump_context.path;
		path_len = strnlen(coredump_context.path, FAPS_COREDUMP_PATH_MAX_LENGTH) + 1;
	}

	return sceKernelCoredumpStateFinish(task_id, pid, result, path, path_len, a6);
}

tai_hook_ref_t sceCoredumpWaitRequest_ref;
int sceCoredumpWaitRequest_patch(void *a1, void *a2){

	int ret;

	sceKernelCoredumpStateFinish = NULL;

	ret = TAI_CONTINUE(int, sceCoredumpWaitRequest_ref, a1, a2);
	if(ret == 0){
		SceCoredumpTaskInfo *info = a2;

		memset(&coredump_context, 0, sizeof(coredump_context));

		coredump_context.pid              = info->pid;
		coredump_context.thid             = info->thid;
		coredump_context.update_func      = info->update_func;
		coredump_context.task_id          = info->task_id;
		coredump_context.cause_flag       = info->cause_flag;
		coredump_context.is_non_cpu_crash = info->IsNonCpuCrash;

		fapsCoredumpTrigger(&coredump_context);
	}

	return ret;
}

tai_hook_ref_t sceKernelCoredumpTrigger_ref;
int sceKernelCoredumpTrigger_patch(
	SceUID pid,
	SceKernelCoredumpStateUpdateCallback update_func,
	SceKernelCoredumpStateFinishCallback finish_func,
	SceCoredumpTriggerParam *param
){
	sceKernelCoredumpStateFinish = finish_func;
	finish_func = sceFapsCoredumpStateFinish;

	return TAI_CONTINUE(int, sceKernelCoredumpTrigger_ref, pid, update_func, finish_func, param);
}

tai_hook_ref_t ksceCoredumpCreateDump_ref;
int ksceCoredumpCreateDump_patch(SceUID pid, const char *titleid, SceSize titleid_len, const char *app_title, SceSize app_title_len, int flags, char *coredump_path, SceSize coredump_path_max){

	int res = TAI_CONTINUE(int, ksceCoredumpCreateDump_ref, pid, titleid, titleid_len, app_title, app_title_len, flags, coredump_path, coredump_path_max);
	if(res == 0){ // Already coredump file is closed
		int res2 = fapsCoredumpMoveOriginalSceCoredump(&coredump_context, coredump_path);
		if(res2 >= 0){
			coredump_path[coredump_path_max - 1] = 0;
			strncpy(coredump_path, coredump_context.path, coredump_path_max - 1);
		}
	}

	return res;
}

tai_hook_ref_t sceSblACMgrIsAllowProcessDebug_ref;
int sceSblACMgrIsAllowProcessDebug_patch(SceUID pid){

	TAI_CONTINUE(int, sceSblACMgrIsAllowProcessDebug_ref, pid);

	return 1;
}

int fapsCoredumpGetFunction(void){

	if(GetExport("SceSysmem", 0x63A519E5, 0x62989905, &_ksceKernelFindClassByName) < 0)
	if(GetExport("SceSysmem", 0x02451F0F, 0x7D87F706, &_ksceKernelFindClassByName) < 0)
		return -1;

	if(GetExport("SceSysmem", 0x63A519E5, 0xB16D5136, &_kscePUIDGetUIDVectorByClass) < 0)
	if(GetExport("SceSysmem", 0x02451F0F, 0x08C05493, &_kscePUIDGetUIDVectorByClass) < 0)
		return -1;

	if(GetExport("SceSysmem", 0x63A519E5, 0x3650963F, &sceKernelGetPhyMemPartInfoCore) < 0)
	if(GetExport("SceSysmem", 0x02451F0F, 0xB9B69700, &sceKernelGetPhyMemPartInfoCore) < 0)
		return -1;

	if(GetExport("SceSysmem", 0x63A519E5, 0x4492421F, &SceSysmemForKernel_C3EF4055) < 0)
	if(GetExport("SceSysmem", 0x02451F0F, 0xC3EF4055, &SceSysmemForKernel_C3EF4055) < 0)
		return -1;

	if(GetExport("SceKernelModulemgr", 0xC445FA63, 0xD269F915, &_ksceKernelGetModuleInfo) < 0)
	if(GetExport("SceKernelModulemgr", 0x92C9FFC2, 0xDAA90093, &_ksceKernelGetModuleInfo) < 0)
		return -1;

	if(GetExport("SceKernelModulemgr", 0xC445FA63, 0x0053BA4A, &_ksceKernelGetModuleIdByAddr) < 0)
	if(GetExport("SceKernelModulemgr", 0x92C9FFC2, 0x0C668636, &_ksceKernelGetModuleIdByAddr) < 0)
		return -1;

	if(GetExport("SceProcessmgr", 0x7A69DE86, 0xC1C91BB2, &sceKernelGetProcessModuleInfo) < 0)
	if(GetExport("SceProcessmgr", 0xEB1F8EF7, 0x3AF6B088, &sceKernelGetProcessModuleInfo) < 0)
		return -1;

	if(GetExport("SceSysmem", 0x63A519E5, 0xAF729575, &_ksceKernelGetUIDMemBlockClass) < 0)
	if(GetExport("SceSysmem", 0x02451F0F, 0x86681B64, &_ksceKernelGetUIDMemBlockClass) < 0)
		return -1;

	if(GetExport("SceProcessmgr", 0x7A69DE86, 0xC6820972, &_ksceKernelGetUIDProcessClass) < 0)
	if(GetExport("SceProcessmgr", 0xEB1F8EF7, 0x98AE4BC8, &_ksceKernelGetUIDProcessClass) < 0)
		return -1;

	if(GetExport("SceProcessmgr", 0x7A69DE86, 0xC77C2085, &sceKernelGetProcessAddressSpace) < 0)
	if(GetExport("SceProcessmgr", 0xEB1F8EF7, 0x9BC44974, &sceKernelGetProcessAddressSpace) < 0)
		return -1;

	if(GetExport("SceKernelThreadMgr", 0xA8CA0EFD, 0x88D5BC33, &_ksceKernelGetUIDThreadClass) < 0)
	if(GetExport("SceKernelThreadMgr", 0x7F8593BA, 0x565BD2DA, &_ksceKernelGetUIDThreadClass) < 0)
		return -1;

	return 0;
}

void _start() __attribute__ ((weak, alias ("module_start")));
int module_start(SceSize argc, const void *args){

	int res;
	SceUInt32 oalEventQueueReceive_offset, queue_offset;

	tai_module_info_t tai_coredump_info;
	tai_coredump_info.size = sizeof(tai_module_info_t);

	res = taiGetModuleInfoForKernel(SCE_GUID_KERNEL_PROCESS_ID, "SceCoredump", &tai_coredump_info);
	if(res < 0){
		return SCE_KERNEL_START_NO_RESIDENT;
	}

	res = fapsCoredumpGetFunction();
	if(res < 0){
		return SCE_KERNEL_START_NO_RESIDENT;
	}

	res = ksceKernelCreateMutex("FapsCoredumpMutex", 0, 1, 0);
	if(res < 0){
		return SCE_KERNEL_START_NO_RESIDENT;
	}

	mutex_uid = res;

	/*
	 * Patch to Create faps-coredump from the first crash dump
	 */
	SceUID temp_patch_uid;

	switch(tai_coredump_info.module_nid){
	case 0x0BB484AF: // special 3.50
		temp_patch_uid = taiInjectDataForKernel(SCE_GUID_KERNEL_PROCESS_ID, tai_coredump_info.modid, 0, 0xC4B0 + 1, (SceUInt8[]){0xE7}, 1);
		oalEventQueueReceive_offset = 0x1588;
		queue_offset = 0x1CA10;
		break;
	case 0x3E0F5EBD: // 3.60
		temp_patch_uid = taiInjectDataForKernel(SCE_GUID_KERNEL_PROCESS_ID, tai_coredump_info.modid, 0, 0xB3FA + 1, (SceUInt8[]){0xE7}, 1);
		oalEventQueueReceive_offset = 0x13F4;
		queue_offset = 0x1CBC8;
		break;
	case 0xDAD20481: // 3.65
	case 0x3CD1BC7E: // 3.67
	case 0x442FC8DA: // 3.68
		temp_patch_uid = taiInjectDataForKernel(SCE_GUID_KERNEL_PROCESS_ID, tai_coredump_info.modid, 0, 0xB3FE + 1, (SceUInt8[]){0xE7}, 1);
		oalEventQueueReceive_offset = 0x13F4;
		queue_offset = 0x1CBC8;
		break;
	default:
		return SCE_KERNEL_START_NO_RESIDENT;
	}

	module_get_offset(SCE_GUID_KERNEL_PROCESS_ID, tai_coredump_info.modid, 0, 0x178 | 1, (uintptr_t *)&sceCoredumpGetCrashThreadCause);

	// for main hooks
	hook_id[0] = HookOffset(tai_coredump_info.modid, oalEventQueueReceive_offset, 1, sceCoredumpWaitRequest);

	// for normal process crash
	hook_id[1] = HookImport("SceAppMgr", 0xA351714A, 0xA7D214A7, sceKernelCoredumpTrigger);

	// for ★Generate Core File
	hook_id[2] = HookImport("SceVshBridge", 0xA351714A, 0x0C10313F, ksceCoredumpCreateDump);

	// for Create debuggable sce coredump
	hook_id[3] = HookImport("SceCoredump", 0x9AD8E213, 0x4CBD6156, sceSblACMgrIsAllowProcessDebug);

	if(ksceSblAimgrIsTest() != SCE_FALSE || ksceSblAimgrIsTool() != SCE_FALSE){
		/*
		 * for Development Kit remote process dump (psp2ctrl pdump)
		 *
		 * The original registration is SceCoredump::sceKernelCoredumpTrigger,
		 * but since it calls SceAppMgr::sceKernelCoredumpTrigger (import) inside sceKernelCoredumpTrigger_patch, it doesn't matter if overwrite it.
		 */
		ksceKernelSysrootRegisterCoredumpTrigger(sceKernelCoredumpTrigger_patch);
	}

	SceCoredumpQueueInfo *pQueueInfo;

	module_get_offset(SCE_GUID_KERNEL_PROCESS_ID, tai_coredump_info.modid, 1, queue_offset, (uintptr_t *)&pQueueInfo);

	pQueueInfo->task_count = 1;
	ksceKernelSignalCond(pQueueInfo->cond_id);
	ksceKernelDelayThread(1000);

	taiInjectReleaseForKernel(temp_patch_uid);

	return SCE_KERNEL_START_SUCCESS;
}
