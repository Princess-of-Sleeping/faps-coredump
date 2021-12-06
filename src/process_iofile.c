/*
 * faps-coredump process_iofile.c
 * Copyright (C) 2021, Princess of Sleeping
 */

#include <psp2kern/types.h>
#include <psp2kern/kernel/sysmem.h>
#include <psp2kern/kernel/sysclib.h>
#include <psp2kern/kernel/iofilemgr.h>
#include "log.h"
#include "utility.h"
#include "coredump_func.h"

int fapsCoredumpCreateProcessIofileInfo(FapsCoredumpContext *context){

	SceIoFdInfo fd_list[0x80];

	context->temp[FAPS_COREDUMP_TEMP_MAX_LENGTH] = 0;
	snprintf(context->temp, FAPS_COREDUMP_TEMP_MAX_LENGTH, "%s/%s", context->path, "process_iofile.txt");
	if(LogOpen(context->temp) < 0)
		return -1;

	SceSize num = 0x80;

	ksceIoGetPUIDFdListForDebugger(5, fd_list, num, &num);

	LogWrite("# process iofile info\n\n");

	while(num > 0){
		num--;

		if(fd_list[num].pid != context->pid)
			continue;

		LogWrite("fd : 0x%X\n", fd_list[num].fd);

		SceIofileInfo info;
		memset(&info, 0, sizeof(info));

		int res = ksceIoGetFileInfo(fd_list[num].fd, fd_list[num].pid, &info);
		if(res >= 0){
			LogWrite("Path\n");
			LogWrite("\t%s\n", info.path);
			LogWrite("\t%s\n", info.path2);
			LogWrite("flags      : 0x%X\n", info.data_0x804);
			if((info.data_0x804 & 2) != 0){
				LogWrite("size       : 0x%X\n", info.data_0x808);
			}else{
				LogWrite("data_0x808 : 0x%X\n", info.data_0x808);
			}

			LogWrite("data_0x80C : 0x%X\n", info.data_0x80C);
			LogWrite("data_0x810 : 0x%X\n", info.data_0x810);
			LogWrite("mode       : 0x%X\n", info.data_0x814);
			LogWrite("size2      : 0x%X\n", info.data_0x818);
			LogWrite("data_0x81C : 0x%X\n", info.data_0x81C);
			LogWrite("data_0x820 : 0x%X\n", info.data_0x820);
			LogWrite("data_0x824 : 0x%X\n", info.data_0x824);
			LogWrite("\n");
		}
	}

	LogClose();

	return 0;
}
