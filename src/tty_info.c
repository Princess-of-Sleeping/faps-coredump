/*
 * faps-coredump tty_info.c
 * Copyright (C) 2021, Princess of Sleeping
 */

#include <psp2kern/types.h>
#include <psp2kern/kernel/sysmem.h>
#include <psp2kern/kernel/sysclib.h>
#include "log.h"
#include "utility.h"
#include "coredump_func.h"

int fapsCoredumpCreateTtyInfo(FapsCoredumpContext *context){

	SceUID memid;
	char *pTtyBuffer;

	memid = ksceKernelAllocMemBlock("SceTtyBuffer", 0x1020D006, 0x1000, NULL);
	if(memid < 0)
		return memid;

	ksceKernelGetMemBlockBase(memid, (void *)&pTtyBuffer);

	memset(pTtyBuffer, 0, 0x1000);

	int log_length = ksceKernelGetTtyInfo(pTtyBuffer, 0x1000);
	if(log_length >= 0){
		for(int i=0;i<0x1000;i++){
			if(pTtyBuffer[i] != 0){
				context->temp[FAPS_COREDUMP_TEMP_MAX_LENGTH] = 0;
				snprintf(context->temp, FAPS_COREDUMP_TEMP_MAX_LENGTH, "%s/%s", context->path, "tty_info.txt");

				write_file(context->temp, &pTtyBuffer[i], strnlen(&pTtyBuffer[i], 0x1000 - i));
				break;
			}
		}
	}

	ksceKernelFreeMemBlock(memid);

	if(log_length < 0)
		return log_length;

	return 0;
}
