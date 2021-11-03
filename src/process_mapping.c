/*
 * faps-coredump process_mapping.c
 * Copyright (C) 2021, Princess of Sleeping
 */

#include <psp2kern/types.h>
#include <psp2kern/kernel/sysmem.h>
#include <psp2kern/kernel/sysclib.h>
#include "process_mapping.h"

int faps_process_mapping_map(FapsProcessMappingContext *context, SceUID pid, void **dst, const void *src, SceSize length){

	SceUID mapid;
	SceKernelProcessContext *ctx;

	void *kernel_page = NULL;
	SceSize kernel_size = 0;
	SceUInt32 kernel_offset = 0;

	if(context == NULL || pid < 0 || dst == NULL || src == NULL || length == 0)
		return -1;

	if(pid != SCE_GUID_KERNEL_PROCESS_ID){
		ksceKernelCpuSaveContext(&(context->current));
		ksceKernelGetPidContext(pid, &ctx);
		ksceKernelCpuRestoreContext(ctx);

		mapid = ksceKernelProcUserMap(
			pid, "FapsUserMemoryRefer", SCE_KERNEL_MEMORY_REF_PERM_USER_R,
			src, length, &kernel_page, &kernel_size, &kernel_offset
		);
		if(mapid < 0){
			ksceKernelCpuRestoreContext(&(context->current));
			return mapid;
		}
	}else{
		kernel_page   = (void *)src;
		kernel_offset = 0;
		mapid = -1;
	}

	context->pid   = pid;
	context->mapid = mapid;
	*dst = (void *)(((uintptr_t)kernel_page) + kernel_offset);

	return 0;
}

int faps_process_mapping_unmap(FapsProcessMappingContext *context){

	int res;

	if(context == NULL)
		return -1;

	if(context->pid != SCE_GUID_KERNEL_PROCESS_ID){
		res = ksceKernelMemBlockRelease(context->mapid);
		if(res < 0){
			return res;
		}

		context->mapid = -1;

		ksceKernelCpuRestoreContext(&(context->current));
	}

	return 0;
}
