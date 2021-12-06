/*
 * faps-coredump utility.c
 * Copyright (C) 2021, Princess of Sleeping
 */

#include <psp2kern/types.h>
#include <psp2kern/kernel/sysmem.h>
#include <psp2kern/io/fcntl.h>
#include <psp2kern/io/stat.h>
#include <psp2kern/registrymgr.h>
#include "types.h"
#include "utility.h"
#include "process_mapping.h"

int write_file_proc_by_fd(SceUID pid, SceUID fd, const void *data, SceSize len){

	if(fd <= 0 || data == NULL || len == 0)
		return -1;

	int res;
	FapsProcessMappingContext map_context;

	if(pid != SCE_GUID_KERNEL_PROCESS_ID){
		void *data_ptr;

		res = faps_process_mapping_map(&map_context, pid, &data_ptr, data, len);
		if(res < 0){
			return res;
		}

		data = data_ptr;
	}

	// sdif internal buffer size is 0x20000-bytes.
	while(len >= 0x20000){
		ksceIoWrite(fd, data, 0x20000);
		len  -= 0x20000;
		data += 0x20000;
	}

	if(len > 0){
		ksceIoWrite(fd, data, len);
	}

	if(pid != SCE_GUID_KERNEL_PROCESS_ID){
		faps_process_mapping_unmap(&map_context);
	}

	return 0;
}

int write_file_proc(SceUID pid, const char *path, const void *data, SceSize len){

	int res;
	SceUID fd;

	if((path == NULL) || (data == NULL) || (len == 0))
		return -1;

	fd = ksceIoOpen(path, SCE_O_WRONLY | SCE_O_CREAT | SCE_O_APPEND, 0666);
	if(fd < 0)
		return fd;

	res = write_file_proc_by_fd(pid, fd, data, len);

	ksceIoClose(fd);

	return res;
}

int write_file(const char *path, const void *data, SceSize len){
	return write_file_proc(SCE_GUID_KERNEL_PROCESS_ID, path, data, len);
}

int fapsCoredumpIsNonCpuCrash(const FapsCoredumpContext *context){
	return context->is_non_cpu_crash != 0;
}

int fapsCoredumpIsSceShellUnknownCrash(const FapsCoredumpContext *context){

	if(strcmp(context->titleid, "main") == 0 && context->thid == 0xFFFFFFFF){
		return 1;
	}

	return 0;
}

int fapsCoredumpIsGpuCrash(const FapsCoredumpContext *context){

	if(fapsCoredumpIsNonCpuCrash(context) != 0 && context->cause_flag == 1 && context->thid == 0){
		return 1;
	}

	return 0;
}

int _fapsCoredumpIsFullDump(void){

	SceIoStat stat;
	int res, val;

	if(ksceIoGetstat("sd0:faps-coredump-fulldump-flag", &stat) == 0)
		return 1;

	if(ksceIoGetstat("host0:data/faps-coredump-fulldump-flag", &stat) == 0)
		return 1;

	res = ksceRegMgrGetKeyInt("/CONFIG/COREDUMP/", "dump_level", &val);
	if(res >= 0){
		return (val == 0) ? 0 : 1;
	}

	res = (ksceIoGetstat("ux0:data/faps-coredump-fulldump-flag", &stat) == 0) ? 1 : 0;

	return res;
}

int fapsCoredumpIsTargetDump(const FapsCoredumpContext *context, int target_level){

	if(context->dump_level >= target_level)
		return 1;

	return 0;
}

int fapsCoredumpIsMiniDump(const FapsCoredumpContext *context){
	return fapsCoredumpIsTargetDump(context, 0);
}

int fapsCoredumpIsLittleDump(const FapsCoredumpContext *context){
	return fapsCoredumpIsTargetDump(context, 1);
}

int fapsCoredumpIsNormalDump(const FapsCoredumpContext *context){
	return fapsCoredumpIsTargetDump(context, 2);
}

int fapsCoredumpIsManyDump(const FapsCoredumpContext *context){
	return fapsCoredumpIsTargetDump(context, 3);
}

int fapsCoredumpIsFullDump(const FapsCoredumpContext *context){
	return fapsCoredumpIsTargetDump(context, 4);
}
