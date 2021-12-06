/*
 * faps-coredump process_lwcond.c
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

int fapsCreateProcessLwCondInfo(FapsCoredumpContext *context){

	SceClass *pSceUIDLwCondClass;
	SceUID *condids;
	SceSize number;

	pSceUIDLwCondClass = NULL;
	condids = context->uid_pool;
	number = 0;

	int res = _ksceKernelFindClassByName("SceUIDLwCondClass", &pSceUIDLwCondClass);
	if(res < 0)
		return res;

	res = _kscePUIDGetUIDVectorByClass(context->pid, pSceUIDLwCondClass, 5, condids, 2048, &number);
	if(res < 0)
		return res;

	context->temp[FAPS_COREDUMP_TEMP_MAX_LENGTH] = 0;
	snprintf(context->temp, FAPS_COREDUMP_TEMP_MAX_LENGTH, "%s/%s", context->path, "process_lwcond.txt");
	if(LogOpen(context->temp) < 0){
		return -1;
	}

	if(number == 0){
		LogWrite("Not has lwcond to this process.\n");
	}

	while(number > 0){
		number--;

		SceKernelLwCondInfo info;
		memset(&info, 0, sizeof(info));
		info.size = sizeof(info);

		SceUID cond_puid, cond_guid;

		cond_puid = condids[number];
		cond_guid = kscePUIDtoGUID(context->pid, cond_puid);

		res = ksceKernelGetLwCondInfo(cond_guid, &info);
		if(res < 0){
			LogWrite("sceKernelGetLwCondInfo failed : 0x%X\n", res);
			LogWrite("LwCond id : 0x%X/0x%X\n", cond_puid, cond_guid);
			continue;
		}

		LogWrite("[%-31s]\n", info.name);
		LogWrite("LwCond id     : 0x%X/0x%X\n", cond_puid, cond_guid);
		LogWrite("attr          :0x%X\n", info.attr);
		LogWrite("pWork         :%p\n", info.work);
		LogWrite("pLwMutex      :%p\n", info.lwmutex);
		LogWrite("numWaitThreads:0x%X\n", info.num_wait_threads);
		LogWrite("\n");
	}

	LogClose();

	return 0;
}
