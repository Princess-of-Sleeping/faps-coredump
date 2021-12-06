/*
 * faps-coredump process_lwmutex.c
 * Copyright (C) 2021, Princess of Sleeping
 */

#include <psp2kern/types.h>
#include <psp2kern/kernel/sysmem.h>
#include <psp2kern/kernel/sysclib.h>
#include <psp2kern/kernel/threadmgr.h>
#include "log.h"
#include "utility.h"
#include "threadmgr_types.h"
#include "coredump_func.h"

extern int (* _ksceKernelFindClassByName)(const char *name, SceClass **cls);
extern int (* _kscePUIDGetUIDVectorByClass)(SceUID pid, SceClass *cls, int vis_level, SceUID *vector, SceSize num, SceSize *ret_num);

int fapsCreateProcessLwMutexInfo(FapsCoredumpContext *context){

	SceClass *pSceUIDLwMutexClass;
	SceUID *mtxids;
	SceSize number;

	pSceUIDLwMutexClass = NULL;
	mtxids = context->uid_pool;
	number = 0;

	int res = _ksceKernelFindClassByName("SceUIDLwMutexClass", &pSceUIDLwMutexClass);
	if(res < 0)
		return res;

	res = _kscePUIDGetUIDVectorByClass(context->pid, pSceUIDLwMutexClass, 5, mtxids, 2048, &number);
	if(res < 0)
		return res;

	context->temp[FAPS_COREDUMP_TEMP_MAX_LENGTH] = 0;
	snprintf(context->temp, FAPS_COREDUMP_TEMP_MAX_LENGTH, "%s/%s", context->path, "process_lwmutex.txt");
	if(LogOpen(context->temp) < 0)
		return -1;

	if(number == 0){
		LogWrite("Not has lwmutex to this process.\n");
	}

	while(number > 0){
		number--;

		SceKernelLwMutexInfo info;
		memset(&info, 0, sizeof(info));
		info.size = sizeof(info);

		SceUID lwmtx_guid, lwmtx_puid;

		lwmtx_puid = mtxids[number];
		lwmtx_guid = kscePUIDtoGUID(context->pid, lwmtx_puid);

		res = ksceKernelGetLwMutexInfo(lwmtx_guid, &info);
		if(res < 0){
			LogWrite("sceKernelGetLwMutexInfo failed : 0x%X\n", res);
			LogWrite("Mutex id : 0x%X/0x%X\n", lwmtx_puid, lwmtx_guid);
			continue;
		}

		LogWrite("[%-31s]\n", info.name);
		LogWrite("Mutex id      : 0x%X/0x%X\n", lwmtx_puid, lwmtx_guid);
		LogWrite("attr          :0x%X\n", info.attr);
		LogWrite("pWork         :%p\n", info.work);
		LogWrite("initCount     :0x%X\n", info.init_count);
		LogWrite("currentCount  :0x%X\n", info.current_count);
		LogWrite("currentOwnerId:0x%X\n", info.current_owner_id);
		LogWrite("numWaitThreads:0x%X\n", info.num_wait_threads);
		LogWrite("\n");
	}

	LogClose();

	return 0;
}
