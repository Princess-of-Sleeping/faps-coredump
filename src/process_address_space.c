/*
 * faps-coredump process_address_space.c
 * Copyright (C) 2021, Princess of Sleeping
 */

#include <psp2kern/types.h>
#include <psp2kern/kernel/sysmem.h>
#include <psp2kern/kernel/sysclib.h>
#include "types.h"
#include "log.h"
#include "utility.h"
#include "sce_as.h"
#include "coredump_func.h"

extern int (* sceKernelGetPhyMemPartInfoCore)(SceUIDPhyMemPartObject *a1, SceSysmemAddressSpaceInfo *pInfo);
extern int (* sceKernelSysrootPIDtoAddressSpaceCB)(SceUID pid, SceUIDAddressSpaceObject **ppInfo);

/*
 *    AP | Privilege | User | Description
 * 0 0 0 |        -- |   -- | Access prohibited
 * 0 0 1 |        RW |   -- | Access prohibited on Non Privilege
 * 0 1 0 |        RW |   RO | Read-Only on Non Privilege
 * 0 1 1 |        RW |   RW | Full access
 * 1 0 0 |        -- |   -- | Reserved
 * 1 0 1 |        RO |   -- | Read-Only on Privilege
 * 1 1 0 |        RO |   RO | Read-Only
 * 1 1 1 |        RO |   RO | Read-Only
 */

int write_ttbr_page_large(SceUInt32 i, SceUIntPtr v, SceUInt32 n, SceUIntPtr v2){

	SceUInt32 domain, ns, xn, tex, nG, s, ap, c, b;
	SceUIntPtr memory_pa;

	domain = (v & 0x1E0) >> 5;
	ns = (v & 8) >> 3;

	xn  = (v2 & 0x8000) >> 15;
	tex = (v2 & 0x7000) >> 12;
	nG  = (v2 & 0x800) >> 11;
	s   = (v2 & 0x400) >> 10;
	ap  = ((v2 & 0x200) >> 7) | ((v2 & 0x30) >> 4);
	c   = (v2 & 0x8) >> 3;
	b   = (v2 & 0x4) >> 2;
	memory_pa = v2 & 0xFFFF0000;

	LogWrite("%p %p VA:%p PA:%p DOMAIN:%02d NS:%d XN:%d TEX:%d nG:%d S:%d AP:%d C:%d B:%d (%s)\n", v, v2, (i << 20) | (n << 12), memory_pa, domain, ns, xn, tex, nG, s, ap, c, b, "large");

	return 0;
}

int write_ttbr_page_small(SceUInt32 i, SceUIntPtr v, SceUInt32 n, SceUIntPtr v2){

	SceUInt32 domain, ns, xn, tex, nG, s, ap, c, b;
	SceUIntPtr memory_pa;

	domain = (v & 0x1E0) >> 5;
	ns = (v & 8) >> 3;

	xn  = v2 & 1;
	tex = (v2 & 0x1C0) >> 6;
	nG  = (v2 & 0x800) >> 11;
	s   = (v2 & 0x400) >> 10;
	ap  = ((v2 & 0x200) >> 7) | ((v2 & 0x30) >> 4);
	c   = (v2 & 0x8) >> 3;
	b   = (v2 & 0x4) >> 2;
	memory_pa = v2 & 0xFFFFF000;

	LogWrite("%p %p VA:%p PA:%p DOMAIN:%02d NS:%d XN:%d TEX:%d nG:%d S:%d AP:%d C:%d B:%d (%s)\n", v, v2, (i << 20) | (n << 12), memory_pa, domain, ns, xn, tex, nG, s, ap, c, b, "small");

	return 0;
}

int write_ttbr_page2(SceUInt32 i, SceUIntPtr v, SceUInt32 n, SceUIntPtr v2){

	switch(3 & v2){
	case 0: // Fault
		break;
	case 1: // Large page
		write_ttbr_page_large(i, v, n, v2);
		break;
	case 2: // Small page
	case 3:
		write_ttbr_page_small(i, v, n, v2);
		break;
	}

	return 0;
}

int write_ttbr_page(SceKernelPTVVector *p, SceUInt32 i, SceUIntPtr v){

	SceKernelPTV *ptr = (SceKernelPTV *)(p->vector[i] & ~0x3F);
	if(NULL == ptr){
		return 0;
	}

	for(int n=0;n<0x100;n++){
		write_ttbr_page2(i, v, n, ptr->pSecondLevelDescription[n]);
	}

	return 0;
}

int write_ttbr_section(SceKernelPTVVector *p, SceUInt32 i, SceUIntPtr v){

	SceUInt32 domain, ns, xn, tex, nG, s, ap, c, b;
	SceUIntPtr memory_pa;

	domain = (v & 0x1E0) >> 5;
	ns     = (v & 0x80000) >> 19;
	xn     = (v & 0x10) >> 4;
	tex    = (v & 0x7000) >> 12;
	nG     = (v & 0x20000) >> 17;
	s      = (v & 0x10000) >> 16;
	ap     = ((v & 0x8000) >> 13) | ((v & 0xC00) >> 10);
	c      = (v & 0x8) >> 3;
	b      = (v & 0x4) >> 2;
	memory_pa = v & 0xFFF00000;

	LogWrite("%p VA:%p PA:%p DOMAIN:%02d NS:%d XN:%d TEX:%d nG:%d S:%d AP:%d C:%d B:%d (%s)\n", v, (i << 20), memory_pa, domain, ns, xn, tex, nG, s, ap, c, b, "section");

	return 0;
}

int write_ttbr(SceKernelPTVVector *p, SceUInt32 i, SceUIntPtr v){

	switch(3 & v){
	case 0: // Fault
		break;
	case 1: // Page table
		write_ttbr_page(p, i, v);
		break;
	case 2: // Section
		write_ttbr_section(p, i, v);
		break;
	case 3: // Super section
		break;
	}

	return 0;
}

int _fapsCoredumpCreateTTBR1Dump(FapsCoredumpContext *context, SceUIDAddressSpaceObject *pAsInfoProc){

	context->temp[FAPS_COREDUMP_TEMP_MAX_LENGTH] = 0;
	snprintf(context->temp, FAPS_COREDUMP_TEMP_MAX_LENGTH, "%s/%s", context->path, "ttbr_info.txt");
	if(LogOpen(context->temp) < 0)
		return -1;

	LogWrite("TTBR1     : %p\n", pAsInfoProc->unk_0x18->cpu_ctx.TTBR1);
	LogWrite("DACR      : 0x%08X\n", pAsInfoProc->unk_0x18->cpu_ctx.DACR);
	LogWrite("CONTEXTIDR: 0x%X\n", pAsInfoProc->unk_0x18->cpu_ctx.CONTEXTIDR);

	LogClose();

	context->temp[FAPS_COREDUMP_TEMP_MAX_LENGTH] = 0;
	snprintf(context->temp, FAPS_COREDUMP_TEMP_MAX_LENGTH, "%s/%s", context->path, "ttbr1.txt");
	if(LogOpen(context->temp) < 0)
		return -1;

	for(int i=0;i<0x1000;i++){
		write_ttbr(pAsInfoProc->unk_0x18->unk_0x10, i, pAsInfoProc->unk_0x18->pProcessTTBR->pTTBR1[i]);
	}

	LogClose();

	return 0;
}

int write_as_phymem_part(SceUIDPhyMemPartObject *a1){

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

	int res;
	SceUIDAddressSpaceObject *pAsInfoProc;

	res = sceKernelSysrootPIDtoAddressSpaceCB(context->pid, &pAsInfoProc);
	if(res < 0){
		return res;
	}

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
			LogWrite("\t[%-27s]\n", pAsInfoProc->pProcAS[i]->tiny.name);
			LogWrite("\tbase:0x%08X, size:0x%08X\n\n", pAsInfoProc->pProcAS[i]->tiny.base_vaddr, pAsInfoProc->pProcAS[i]->tiny.base_size);

			SceObjectBase *pObj;
			int res = ksceGUIDReferObjectWithClass(pAsInfoProc->unk_uid[i], pAsInfoProc->pProcAS[i]->tiny.pClass, &pObj);
			if(res >= 0){
				ksceGUIDReleaseObject(pAsInfoProc->unk_uid[i]);
			}
		}
	}

	LogClose();

	if(fapsCoredumpIsFullDump(context) != 0){
		_fapsCoredumpCreateTTBR1Dump(context, pAsInfoProc);
	}

	return 0;
}
