/*
 * faps-coredump process_address_space.c
 * Copyright (C) 2021, Princess of Sleeping
 */

#include <psp2kern/types.h>
#include <psp2kern/kernel/sysmem.h>
#include <psp2kern/kernel/sysclib.h>
#include "types.h"
#include "log.h"
#include "sce_as.h"
#include "coredump_func.h"

extern int (* sceKernelGetPhyMemPartInfoCore)(SceKernelPhyMemPart *a1, SceSysmemAddressSpaceInfo *pInfo);
extern int (* sceKernelSysrootPIDtoAddressSpaceCB)(SceUID pid, SceKernelAddressSpaceInfo **ppInfo);

int write_as_phymem_part(SceKernelPhyMemPart *a1){

	int res;

	if(a1 == NULL)
		return 0;

	SceSysmemAddressSpaceInfo as_info;
	memset(&as_info, 0, sizeof(as_info));

	LogWrite("\t[%-31s]\n", a1->name);

	res = sceKernelGetPhyMemPartInfoCore(a1, &as_info);
	if(res < 0){
		LogWrite("\tFailed getPhyMemPartInfoCore : 0x%X\n", res);
		return res;
	}

	LogWrite("\tbase:0x%08X, total:0x%08X, free:0x%08X\n\n", as_info.base, as_info.total, as_info.free);

	return 0;
}

int fapsCoredumpCreateAsInfoDump(FapsCoredumpContext *context){

	SceKernelAddressSpaceInfo *pAsInfoProc;
	sceKernelSysrootPIDtoAddressSpaceCB(context->pid, &pAsInfoProc);

	context->temp[FAPS_COREDUMP_TEMP_MAX_LENGTH] = 0;
	snprintf(context->temp, FAPS_COREDUMP_TEMP_MAX_LENGTH, "%s/%s", context->path, "address_space_info.txt");
	if(LogOpen(context->temp) < 0)
		return -1;

	LogWrite("=== Physics memory partition info ===\n\n");

	write_as_phymem_part(pAsInfoProc->unk_0x130);
	write_as_phymem_part(pAsInfoProc->unk_0x134);
	write_as_phymem_part(pAsInfoProc->unk_0x138);
	write_as_phymem_part(pAsInfoProc->unk_0x13C);
	write_as_phymem_part(pAsInfoProc->unk_0x140);
	write_as_phymem_part(pAsInfoProc->unk_0x144);
	write_as_phymem_part(pAsInfoProc->unk_0x148);
	write_as_phymem_part(pAsInfoProc->unk_0x14C);
	write_as_phymem_part(pAsInfoProc->unk_0x150);
	write_as_phymem_part(pAsInfoProc->unk_0x154);
	write_as_phymem_part(pAsInfoProc->unk_0x158);

	LogWrite("=== Virtual memory partition info ===\n\n");

	for(int i=0;i<0x20;i++){
		if(pAsInfoProc->pProcAS[i] != NULL){
			LogWrite("\t[%-27s]\n", pAsInfoProc->pProcAS[i]->name);
			LogWrite("\tbase:0x%08X, size:0x%08X\n\n", pAsInfoProc->pProcAS[i]->base_vaddr, pAsInfoProc->pProcAS[i]->base_size);

			SceObjectBase *pObj;
			int res = ksceGUIDReferObjectWithClass(pAsInfoProc->unk_uid[i], pAsInfoProc->pProcAS[i]->unk_0x04, &pObj);
			if(res >= 0){
				ksceGUIDReleaseObject(pAsInfoProc->unk_uid[i]);
			}
		}
	}

	LogClose();

	return 0;
}
