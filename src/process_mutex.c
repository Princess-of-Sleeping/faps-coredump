/*
 * faps-coredump process_mutex.c
 * Copyright (C) 2021, Princess of Sleeping
 */

#include <psp2kern/types.h>
#include <psp2kern/kernel/sysmem.h>
#include <psp2kern/kernel/sysclib.h>
#include <psp2kern/kernel/threadmgr.h>
#include "log.h"
#include "utility.h"
#include "coredump_func.h"

extern int (* _ksceKernelFindClassByName)(const char *name, SceClass **cls);
extern int (* _kscePUIDGetUIDVectorByClass)(SceUID pid, SceClass *cls, int vis_level, SceUID *vector, SceSize num, SceSize *ret_num);

int fapsCoredumpCreateProcessMutexInfo(FapsCoredumpContext *context){

	SceClass *pSceUIDMutexClass;
	SceUID *mtxids;
	SceSize number;

	pSceUIDMutexClass = NULL;
	mtxids = context->uid_pool;
	number = 0;

	int res = _ksceKernelFindClassByName("SceUIDMutexClass", &pSceUIDMutexClass);
	if(res < 0)
		return res;

	res = _kscePUIDGetUIDVectorByClass(context->pid, pSceUIDMutexClass, 5, mtxids, 2048, &number);
	if(res < 0)
		return res;

	context->temp[FAPS_COREDUMP_TEMP_MAX_LENGTH] = 0;
	snprintf(context->temp, FAPS_COREDUMP_TEMP_MAX_LENGTH, "%s/%s", context->path, "process_mutex.txt");
	if(LogOpen(context->temp) < 0)
		return -1;

	if(number == 0){
		LogWrite("Not has mutex to this process.\n");
	}

	while(number > 0){
		number--;

		SceKernelMutexInfo info;
		memset(&info, 0, sizeof(info));
		info.size = sizeof(info);

		SceUID mtx_guid, mtx_puid;

		mtx_puid = mtxids[number];
		mtx_guid = kscePUIDtoGUID(context->pid, mtx_puid);

		res = ksceKernelGetMutexInfo(mtx_guid, &info);
		if(res < 0){
			LogWrite("sceKernelGetMutexInfo failed : 0x%X\n", res);
			LogWrite("Mutex id : 0x%X/0x%X\n", mtx_puid, mtx_guid);
			continue;
		}

		LogWrite("[%-31s]\n", info.name);
		LogWrite("Mutex id      : 0x%X/0x%X\n", mtx_puid, mtx_guid);
		LogWrite("attr          :0x%X\n", info.attr);
		LogWrite("initCount     :0x%X\n", info.initCount);
		LogWrite("currentCount  :0x%X\n", info.currentCount);
		LogWrite("currentOwnerId:0x%X\n", info.currentOwnerId);
		LogWrite("numWaitThreads:0x%X\n", info.numWaitThreads);
		LogWrite("\n");
	}

	LogClose();

	return 0;
}
