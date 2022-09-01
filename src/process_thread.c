/*
 * faps-coredump process_thread.c
 * Copyright (C) 2021, Princess of Sleeping
 */

#include <psp2kern/types.h>
#include <psp2kern/kernel/sysmem.h>
#include <psp2kern/kernel/sysclib.h>
#include <psp2kern/kernel/threadmgr.h>
#include <psp2kern/kernel/modulemgr.h>
#include "log.h"
#include "utility.h"
#include "threadmgr_types.h"
#include "coredump_func.h"
#include "dump_crash_thread_info.h"

extern SceClass *(* _ksceKernelGetUIDThreadClass)(void);
extern int (* _kscePUIDGetUIDVectorByClass)(SceUID pid, SceClass *cls, int vis_level, SceUID *vector, SceSize num, SceSize *ret_num);

int fapsCoredumpCreateProcessThreadInfo(FapsCoredumpContext *context){

	SceClass *pSceUIDThreadClass;
	SceUID *thread_ids;
	SceSize number;

	pSceUIDThreadClass = _ksceKernelGetUIDThreadClass();
	thread_ids = context->uid_pool;
	number = 0;

	int res = _kscePUIDGetUIDVectorByClass(context->pid, pSceUIDThreadClass, 5, thread_ids, 2048, &number);
	if(res < 0)
		return res;

	context->temp[FAPS_COREDUMP_TEMP_MAX_LENGTH] = 0;
	snprintf(context->temp, FAPS_COREDUMP_TEMP_MAX_LENGTH, "%s/%s", context->path, "process_thread.txt");
	if(LogOpen(context->temp) < 0)
		return -1;

	while(number > 0){
		number--;

		SceKernelThreadInfoInternal info;
		memset(&info, 0, sizeof(info));
		info.size = sizeof(info);

		SceUID thread_guid, thread_puid;

		thread_puid = thread_ids[number];
		thread_guid = kscePUIDtoGUID(context->pid, thread_puid);

		res = sceKernelGetThreadInfoInternal(thread_guid, 0, &info);
		if(res < 0){
			LogWrite("sceKernelGetThreadInfoInternal failed : 0x%X\n", res);
			LogWrite("Thread id : 0x%X/0x%X\n", thread_puid, thread_guid);
			continue;
		}

		SceUID modid = fapsKernelGetModuleIdByAddr(context->pid, info.entry);
		if(context->pid != SCE_GUID_KERNEL_PROCESS_ID)
			modid = kscePUIDtoGUID(context->pid, modid);

		SceKernelModuleInfo sce_info;
		memset(&sce_info, 0, sizeof(sce_info));
		fapsKernelGetModuleInfo(context->pid, modid, &sce_info);

		LogWrite("[%-31s]\n", info.name);
		LogWrite("thread id              : 0x%X/0x%X\n", thread_puid, thread_guid);
		LogWrite("attr                   : 0x%X\n", info.attr);
		LogWrite("status                 : %s\n", getThreadStatusStrings(info.status));
		LogWrite("entry                  : %s + 0x%X\n", sce_info.module_name, (info.entry - (uint32_t)sce_info.segments[0].vaddr));
		LogWrite("stack (bottom)         : 0x%X\n", info.stack);
		LogWrite("stackSize              : 0x%X\n", info.stackSize);
		LogWrite("initPriority           : 0x%X\n", info.initPriority);
		LogWrite("currentPriority        : 0x%X\n", info.currentPriority);
		LogWrite("initCpuAffinityMask    : 0x%X\n", info.initCpuAffinityMask);
		LogWrite("currentCpuAffinityMask : 0x%X\n", info.currentCpuAffinityMask);
		LogWrite("currentCpuId           : 0x%X\n", info.currentCpuId);
		LogWrite("lastExecutedCpuId      : 0x%X\n", info.lastExecutedCpuId);
		LogWrite("waitType               : 0x%X\n", info.waitType);
		// LogWrite("waitId                 : 0x%X\n", info.waitId);
		LogWrite("exitStatus             : 0x%X\n", info.exitStatus);
		LogWrite("runClocks              : %lld\n", info.runClocks);
		LogWrite("intrPreemptCount       : 0x%X\n", info.intrPreemptCount);
		LogWrite("threadPreemptCount     : 0x%X\n", info.threadPreemptCount);
		LogWrite("threadReleaseCount     : 0x%X\n", info.threadReleaseCount);
		LogWrite("fNotifyCallback        : 0x%X\n", info.fNotifyCallback);
		LogWrite("\n");

		SceThreadCpuRegisters cpu_registers;
		memset(&cpu_registers, 0, sizeof(cpu_registers));

		res = ksceKernelGetThreadCpuRegisters(thread_guid, &cpu_registers);
		if(res == 0){
			if((cpu_registers.entry[0].cpsr & 0x1F) == 0x1F){
				memcpy(&cpu_registers.entry[0], &cpu_registers.entry[1], sizeof(SceArmCpuRegisters));
			}

			LogWriteThreadCpuRegs(context->pid, &cpu_registers);
		}else{
			LogWrite("sceKernelGetThreadCpuRegisters failed : 0x%X\n", res);

			LogWrite("a1 0x%08X a2 0x%08X a3 0x%08X a4 0x%08X\n", info.pRegisters->reg[0x0], info.pRegisters->reg[0x1], info.pRegisters->reg[0x2], info.pRegisters->reg[0x3]);
			LogWrite("v1 0x%08X v2 0x%08X v3 0x%08X v4 0x%08X\n", info.pRegisters->reg[0x4], info.pRegisters->reg[0x5], info.pRegisters->reg[0x6], info.pRegisters->reg[0x7]);
			LogWrite("v5 0x%08X sb 0x%08X sl 0x%08X fp 0x%08X\n", info.pRegisters->reg[0x8], info.pRegisters->reg[0x9], info.pRegisters->reg[0xA], info.pRegisters->reg[0xB]);
			LogWrite("ip 0x%08X sp 0x%08X lr 0x%08X pc 0x%08X\n", info.pRegisters->reg[0xC], info.pRegisters->reg[0xD], info.pRegisters->reg[0xE], info.pRegisters->pc);
			LogWrite("\n");
		}

		LogWrite("Vfp register\n");
		for(int i=0;i<0x20;i+=2){
			LogWrite(
				"d%-02d 0x%016llX d%-02d 0x%016llX\n",
				(i + 0), info.pVfpInfo->vfp_register.d.value_as_int[i + 0],
				(i + 1), info.pVfpInfo->vfp_register.d.value_as_int[i + 1]
			);
		}

		LogWrite("\n");
	}

	LogClose();

	return 0;
}
