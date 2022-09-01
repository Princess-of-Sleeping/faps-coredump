/*
 * faps-coredump hw_info.c
 * Copyright (C) 2021, Princess of Sleeping
 */

#include <psp2kern/types.h>
#include <psp2kern/kernel/sysmem.h>
#include <psp2kern/kernel/sysclib.h>
#include <psp2kern/lowio/pervasive.h>
#include <psp2kern/sblaimgr.h>
#include <psp2kern/syscon.h>
#include "log.h"
#include "utility.h"
#include "coredump_func.h"

int fapsCoredumpCreateHwInfo(FapsCoredumpContext *context){

	int res;

	context->temp[FAPS_COREDUMP_TEMP_MAX_LENGTH] = 0;
	snprintf(context->temp, FAPS_COREDUMP_TEMP_MAX_LENGTH, "%s/%s", context->path, "hw_info.txt");
	if(LogOpen(context->temp) < 0){
		return -1;
	}

	SceUInt32 hwinfo = ksceSysconGetHardwareInfo();

	LogWrite("hw info: 0x%X\n", hwinfo);

	SceUInt32 hwinfo2[4];

	res = ksceSysconGetHardwareInfo2(hwinfo2, NULL, NULL);
	if(res == 0){
		LogWrite("hw info 2: 0x%08X 0x%08X 0x%08X 0x%08X\n", hwinfo2[0], hwinfo2[1], hwinfo2[2], hwinfo2[3]);
	}

	LogWrite("ProductCode:0x%X ProductSubCode:0x%X\n", ksceSblAimgrGetProductCode(), ksceSblAimgrGetProductSubCode());

	SceUInt32 rev = kscePervasiveGetSoCRevision();

	LogWrite("SoC Revision : 0x%X\n", rev);
	LogWrite("Kermit Revision : 0x%X\n", rev & 0x1FFFF);

	uint32_t paddr;

	if((0x1FF00 & rev) == 0){
		paddr = ((rev & 0x80000000) != 0) ? 0x58000000 : 0x60000000;
	}else{
		paddr = ((rev & 0x30000000) == 0) ? 0x58000000 : 0x60000000;
	}

	if(paddr == 0x60000000){
		LogWrite("Has additional 512MiB RAM to this device\n");
	}

	LogClose();

	return 0;
}
