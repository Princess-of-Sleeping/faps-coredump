/*
 * faps-coredump event_log.c
 * Copyright (C) 2021, Princess of Sleeping
 */

#include <psp2kern/types.h>
#include <psp2kern/kernel/sysmem.h>
#include <psp2kern/kernel/sysclib.h>
#include "log.h"
#include "utility.h"
#include "coredump_func.h"

int fapsCoredumpCreateEventLogInfo(FapsCoredumpContext *context){

	if(LogIsOpened() != 0){
		ksceDebugPrintf("[%-7s] Previously opened Log is not closed. in %s\n", "error", __FUNCTION__);
		LogClose();
		return -1;
	}

	context->temp[FAPS_COREDUMP_TEMP_MAX_LENGTH] = 0;
	snprintf(context->temp, FAPS_COREDUMP_TEMP_MAX_LENGTH, "%s/%s", context->path, "event_log.txt");
	if(LogOpen(context->temp) < 0)
		return -1;

	char buf[0x800];

	memset(buf, 0, sizeof(buf));
	SceSize num = 0;

	ksceEventLogGetInfo(buf, sizeof(buf), &num);

	// LogWrite("sceKernelGetDebugEventLog:0x%X\n", res);
	LogWrite("has %d items\n\n", num);

	SceKernelDebugEventLog *pData = (SceKernelDebugEventLog *)(buf);

	while(num > 0){
		LogWrite("titleid  :%s\n", pData->titleid);
		LogWrite("flags    :0x%X\n", pData->flags);
		LogWrite("ppid     :0x%X\n", pData->ppid);
		LogWrite("data_0x1C:0x%X\n", pData->data_0x1C);
		LogWrite("time     :%lld\n", pData->time);
		LogWrite("data_0x38:0x%X\n", pData->data_0x38);

		if(pData->item_size == sizeof(SceKernelDebugEventLog1)){

			if((pData->flags & 0xF0000) == 0x10000){
				LogWrite("Process create\n");
			}else if((pData->flags & 0xF0000) == 0x20000){
				LogWrite("Process exit\n");
			}else if((pData->flags & 0xF0000) == 0x30000){
				LogWrite("Process kill\n");
			}else if((pData->flags & 0xF0000) == 0x40000){
				LogWrite("Process coredump\n"); // stop all thread?
			}else{
				LogWrite("Process unknown event\n");
			}

			LogWrite("data_0x40  :0x%X\n", pData->type1.data_0x40);
			LogWrite("pid        :0x%X\n", pData->type1.pid);
			LogWrite("budget_type:0x%X\n", pData->type1.budget_type);
			LogWrite("titleid    :%s\n", pData->type1.titleid);

		}else if(pData->item_size == sizeof(SceKernelDebugEventLog2)){

			LogWrite("Resume/Suspend\n");
			LogWrite("data_0x40:0x%X\n", pData->type2.data_0x40);

		}else if(pData->item_size == sizeof(SceKernelDebugEventLog3)){

			LogWrite("data_0x40:0x%X\n", pData->type3.data_0x40);
			LogWrite("ip1      :%s\n", pData->type3.ip1);
			LogWrite("ip2      :%s\n", pData->type3.ip2);
			LogWrite("ip3      :%s\n", pData->type3.ip3);
			LogWrite("ip4      :%s\n", pData->type3.ip4);
			LogWrite("ip5      :%s\n", pData->type3.ip5);
		}else{
			LogWrite("unknown event.\n");

			context->temp[FAPS_COREDUMP_TEMP_MAX_LENGTH] = 0;
			snprintf(context->temp, FAPS_COREDUMP_TEMP_MAX_LENGTH, "%s/event_log_0x%X.bin", context->path, num);

			LogWrite("dumped to %s\n", context->temp);
		}

		LogWrite("\n");

		pData = (SceKernelDebugEventLog *)((uintptr_t)(pData) + pData->size);
		num--;
	}

	LogClose();

	return 0;
}
