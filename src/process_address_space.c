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
extern SceUID (* sceKernelGetProcessAddressSpace)(SceUID pid);
extern int (* SceSysmemForKernel_C3EF4055)(SceUID asid, void *pInfo);

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

/*
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
*/

typedef struct SceKernelAddressSpaceInfo { // size is 0x654-bytes
    SceSize size;
	SceUID asid;
	SceUInt8 CONTEXTID;
	SceUInt8 paddinf[3];
	SceUInt32 nList;
	struct {
		SceSize size;
		SceUIDPartitionObject *pPart;
		SceUIntPtr vbase;
		SceSize vsize;
		SceUInt32 unk_0x10; // nBlock?
		SceSize vsizeRemain;
		const char *name;
		SceUInt32 unk_0x1C;
		SceUInt32 unk_0x20;
		SceUInt32 unk_0x24;
		SceUInt32 unk_0x28;
		SceUInt32 unk_0x2C;
	} list[0x20];
	SceUInt32 nPhyMemPart;
	SceUIDPhyMemPartObject *pPhyMemPart[0x10];
} SceKernelAddressSpaceInfo;

int fapsCoredumpCreateAsInfoDump(FapsCoredumpContext *context){

	int res;
	SceKernelAddressSpaceInfo *as_info;

	as_info = ksceKernelAllocHeapMemory(0x1000B, sizeof(*as_info));
	if(as_info == NULL){
		ksceDebugPrintf("%s sceKernelAllocHeapMemory result is SCE_NULL\n", __FUNCTION__);
		return 0;
	}

	do {
		SceUID asid = sceKernelGetProcessAddressSpace(context->pid);
		if(asid < 0){
			ksceDebugPrintf("sceKernelGetProcessAddressSpace 0x%08X\n", asid);
			break;
		}

		memset(as_info, 0, sizeof(*as_info));
		as_info->size = sizeof(*as_info);

		res = SceSysmemForKernel_C3EF4055(asid, as_info);
		if(res < 0){
			ksceDebugPrintf("%s: SceSysmemForKernel_C3EF4055 0x%X\n", __FUNCTION__, res);
			break;
		}

		context->temp[FAPS_COREDUMP_TEMP_MAX_LENGTH] = 0;
		snprintf(context->temp, FAPS_COREDUMP_TEMP_MAX_LENGTH, "%s/%s", context->path, "address_space_info.txt");
		if(LogOpen(context->temp) < 0){
			ksceDebugPrintf("%s: failed LogOpen\n", __FUNCTION__);
			break;
		}

		LogWrite("# Virtual Address Info\n");

		for(int i=0;i<as_info->nList;i++){
			LogWrite(
				"[%-31s]: vbase=%p vsize=0x%08X/0x%08X\n",
				as_info->list[i].name, as_info->list[i].vbase, as_info->list[i].vsize, as_info->list[i].vsizeRemain
			);
		}

		LogWrite("\n# Physical Address Info\n");

		for(int i=0;i<0x10;i++){
			if(as_info->pPhyMemPart[i] != NULL){

				SceSysmemAddressSpaceInfo pmp_info;
				memset(&pmp_info, 0, sizeof(pmp_info));

				res = sceKernelGetPhyMemPartInfoCore(as_info->pPhyMemPart[i], &pmp_info);
				if(res < 0){
					ksceDebugPrintf("sceKernelGetPhyMemPartInfoCore 0x%X\n", res);
					continue;
				}

				LogWrite(
					"[%-31s]: pbase=%p psize=0x%08X/0x%08X\n",
					as_info->pPhyMemPart[i]->name, pmp_info.base, pmp_info.total, pmp_info.free
				);
			}
		}

		LogClose();
	} while(0);

	ksceKernelFreeHeapMemory(0x1000B, as_info);

	return 0;
}
