/*
 * faps-coredump process_eventflag.c
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

int fapsCreateProcessEventflagInfo(FapsCoredumpContext *context){

	SceClass *pSceUIDEventFlagClass;
	SceSize number;
	SceUID *evfids;

	pSceUIDEventFlagClass = NULL;
	number = 0;
	evfids = context->uid_pool;

	int res = _ksceKernelFindClassByName("SceUIDEventFlagClass", &pSceUIDEventFlagClass);
	if(res < 0)
		return res;

	res = _kscePUIDGetUIDVectorByClass(context->pid, pSceUIDEventFlagClass, 5, evfids, 2048, &number);
	if(res < 0)
		return res;

	context->temp[FAPS_COREDUMP_TEMP_MAX_LENGTH] = 0;
	snprintf(context->temp, FAPS_COREDUMP_TEMP_MAX_LENGTH, "%s/%s", context->path, "process_eventflag.txt");
	if(LogOpen(context->temp) < 0)
		return -1;

	if(number == 0){
		LogWrite("Not has eventflag to this process.\n");
	}

	while(number > 0){
		number--;

		SceKernelEventFlagInfo info;
		memset(&info, 0, sizeof(info));
		info.size = sizeof(info);

		SceUID evf_puid, evf_guid;

		evf_puid = evfids[number];
		evf_guid = kscePUIDtoGUID(context->pid, evf_puid);

		res = ksceKernelGetEventFlagInfo(evf_guid, &info);
		if(res < 0){
			LogWrite("sceKernelGetEventflagInfo failed : 0x%X\n", res);
			LogWrite("Eventflag id : 0x%X/0x%X\n", evf_puid, evf_guid);
			continue;
		}

		LogWrite("[%-31s]\n", info.name);
		LogWrite("Eventflag id  :0x%X/0x%X\n", evf_puid, evf_guid);
		LogWrite("attr          :0x%X\n", info.attr);
		LogWrite("initPattern   :0x%X\n", info.initPattern);
		LogWrite("currentPattern:0x%X\n", info.currentPattern);
		LogWrite("numWaitThreads:0x%X\n", info.numWaitThreads);
		LogWrite("\n");
	}

	LogClose();

	return 0;
}
