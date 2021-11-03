/*
 * faps-coredump process_msgpipe.c
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

int fapsCreateProcessMsgpipeInfo(FapsCoredumpContext *context){

	SceClass *pSceUIDMsgPipeClass;
	SceUID *msgpipeids;
	SceSize number;

	if(LogIsOpened() != 0){
		ksceDebugPrintf("[error] Previously opened Log is not closed. in %s\n", __FUNCTION__);
		LogClose();
		return -1;
	}

	pSceUIDMsgPipeClass = NULL;
	msgpipeids = context->uid_pool;
	number = 0;

	int res = _ksceKernelFindClassByName("SceUIDMsgPipeClass", &pSceUIDMsgPipeClass);
	if(res < 0)
		return res;

	res = _kscePUIDGetUIDVectorByClass(context->pid, pSceUIDMsgPipeClass, 5, msgpipeids, 2048, &number);
	if(res < 0)
		return res;

	context->temp[FAPS_COREDUMP_TEMP_MAX_LENGTH] = 0;
	snprintf(context->temp, FAPS_COREDUMP_TEMP_MAX_LENGTH, "%s/%s", context->path, "process_msgpipe.txt");
	if(LogOpen(context->temp) < 0)
		return -1;

	if(number == 0){
		LogWrite("Not has msgpipe to this process.\n");
	}

	while(number > 0){
		number--;

		SceKernelMsgPipeInfo info;
		memset(&info, 0, sizeof(info));
		info.size = sizeof(info);

		SceUID msgpipe_guid, msgpipe_puid;

		msgpipe_puid = msgpipeids[number];
		msgpipe_guid = kscePUIDtoGUID(context->pid, msgpipe_puid);

		res = ksceKernelGetMsgPipeInfo(msgpipe_guid, &info);
		if(res < 0){
			LogWrite("sceKernelGetMsgPipeInfo failed : 0x%X\n", res);
			LogWrite("Msgpipe id : 0x%X/0x%X\n", msgpipe_puid, msgpipe_guid);
			continue;
		}

		LogWrite("[%-31s]\n", info.name);
		LogWrite("Msgpipe id           : 0x%X/0x%X\n", msgpipe_puid, msgpipe_guid);
		LogWrite("attr                 :0x%X\n", info.attr);
		LogWrite("bufferSize           :0x%X\n", info.buffer_size);
		LogWrite("freeSize             :0x%X\n", info.free_size);
		LogWrite("numSendWaitThreads   :0x%X\n", info.num_send_wait_threads);
		LogWrite("numReceiveWaitThreads:0x%X\n", info.num_receive_wait_threads);
		LogWrite("\n");
	}

	LogClose();

	return 0;
}
