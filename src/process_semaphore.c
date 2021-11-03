/*
 * faps-coredump process_semaphore.c
 * Copyright (C) 2021, Princess of Sleeping
 */

#include <psp2kern/types.h>
#include <psp2kern/kernel/sysmem.h>
#include <psp2kern/kernel/sysclib.h>
#include <psp2kern/kernel/threadmgr.h>
#include "log.h"
#include "utility.h"
#include "coredump_func.h"
#include "threadmgr_types.h"

extern int (* _ksceKernelFindClassByName)(const char *name, SceClass **cls);
extern int (* _kscePUIDGetUIDVectorByClass)(SceUID pid, SceClass *cls, int vis_level, SceUID *vector, SceSize num, SceSize *ret_num);

int fapsCreateProcessSemaphoreInfo(FapsCoredumpContext *context){

	SceClass *pSceUIDSemaphoreClass;
	SceUID *semaids;
	SceSize number;

	if(LogIsOpened() != 0){
		ksceDebugPrintf("[error] Previously opened Log is not closed. in %s\n", __FUNCTION__);
		LogClose();
		return -1;
	}

	pSceUIDSemaphoreClass = NULL;
	semaids = context->uid_pool;
	number = 0;

	int res = _ksceKernelFindClassByName("SceUIDSemaphoreClass", &pSceUIDSemaphoreClass);
	if(res < 0)
		return res;

	res = _kscePUIDGetUIDVectorByClass(context->pid, pSceUIDSemaphoreClass, 5, semaids, 2048, &number);
	if(res < 0)
		return res;

	context->temp[FAPS_COREDUMP_TEMP_MAX_LENGTH] = 0;
	snprintf(context->temp, FAPS_COREDUMP_TEMP_MAX_LENGTH, "%s/%s", context->path, "process_semaphore.txt");
	if(LogOpen(context->temp) < 0)
		return -1;

	if(number == 0){
		LogWrite("Not has semaphore to this process.\n");
	}

	while(number > 0){
		number--;

		SceKernelSemaInfo info;
		memset(&info, 0, sizeof(info));
		info.size = sizeof(info);

		SceUID sema_guid, sema_puid;

		sema_puid = semaids[number];
		sema_guid = kscePUIDtoGUID(context->pid, sema_puid);

		res = ksceKernelGetSemaInfo(sema_guid, &info);
		if(res < 0){
			LogWrite("sceKernelGetSemaInfo failed : 0x%X\n", res);
			LogWrite("Semaphore id : 0x%X/0x%X\n", sema_puid, sema_guid);
			continue;
		}

		LogWrite("[%-31s]\n", info.name);
		LogWrite("Semaphore id  :0x%X/0x%X\n", sema_puid, sema_guid);
		LogWrite("attr          :0x%X\n", info.attr);
		LogWrite("initCount     :0x%X\n", info.initCount);
		LogWrite("currentCount  :0x%X\n", info.currentCount);
		LogWrite("maxCount      :0x%X\n", info.maxCount);
		LogWrite("numWaitThreads:0x%X\n", info.numWaitThreads);
		LogWrite("\n");
	}

	LogClose();

	return 0;
}
