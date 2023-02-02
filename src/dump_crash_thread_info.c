/*
 * faps-coredump dump_crash_thread_info.c
 * Copyright (C) 2021, Princess of Sleeping
 */

#include <psp2kern/types.h>
#include <psp2kern/kernel/sysmem.h>
#include <psp2kern/kernel/sysclib.h>
#include <psp2kern/kernel/threadmgr.h>
#include <psp2kern/kernel/modulemgr.h>
#include "types.h"
#include "log.h"
#include "utility.h"
#include "dump_crash_thread_info.h"
#include "coredump_func.h"
#include "coredump_internal.h"
#include "threadmgr_types.h"

extern int (* sceCoredumpGetCrashThreadCause)(SceUID thid, const SceCoredumpCrashCauseParam *param, SceCoredumpCrashCauseResult *result);


static const char * const it_block_list[0x10] = {
	"     ",
	"ITEEE",
	"ITEE ",
	"ITEET",
	"ITE  ",
	"ITETE",
	"ITET ",
	"ITETT",
	"IT   ",
	"ITTEE",
	"ITTE ",
	"ITTET",
	"ITT  ",
	"ITTTE",
	"ITTT ",
	"ITTTT"
};

static const char * const it_block_list_inv[0x10] = {
	"     ",
	"ITTTT",
	"ITTT ",
	"ITTTE",
	"ITT  ",
	"ITTET",
	"ITTE ",
	"ITTEE",
	"IT   ",
	"ITETT",
	"ITET ",
	"ITETE",
	"ITE  ",
	"ITEET",
	"ITEE ",
	"ITEEE"
};

static const char * const arm_cond_list[0x10] = {
	"EQ",
	"NE",
	"CS",
	"CC",
	"MI",
	"PL",
	"VS",
	"VC",
	"HI",
	"LS",
	"GE",
	"LT",
	"GT",
	"LE",
	"AL",
	"  "
};

void sceKernelGetCPSRStrings(char *dst, SceUInt32 cpsr){

	char *current;
	SceUInt32 it_blk;

	current = dst;

	current[0] = ((cpsr & 0x80000000) != 0) ? 'N' : 'n';
	current[1] = ((cpsr & 0x40000000) != 0) ? 'Z' : 'z';
	current[2] = ((cpsr & 0x20000000) != 0) ? 'C' : 'c';
	current[3] = ((cpsr & 0x10000000) != 0) ? 'V' : 'v';
	current[4] = ((cpsr & 0x8000000) != 0) ? 'Q' : 'q';
	current[5] = ' ';
	current += 6;

	current[0] = 'G';
	current[1] = 'E';
	current[2] = ((cpsr & 0x80000) == 0) ? '_' : '3';
	current[3] = ((cpsr & 0x40000) == 0) ? '_' : '2';
	current[4] = ((cpsr & 0x20000) == 0) ? '_' : '1';
	current[5] = ((cpsr & 0x10000) == 0) ? '_' : '0';
	current[6] = ' ';
	current += 7;

	it_blk = ((cpsr << 5) >> 0x1E) | (((cpsr << 0x14) >> 0x1E) << 2);
	if(it_blk != 0){
		if(((cpsr >> 0xC) & 1) != 0){
			current[0] = it_block_list[it_blk][0];
			current[1] = it_block_list[it_blk][1];
			current[2] = it_block_list[it_blk][2];
			current[3] = it_block_list[it_blk][3];
			current[4] = it_block_list[it_blk][4];
		}else{
			current[0] = it_block_list_inv[it_blk][0];
			current[1] = it_block_list_inv[it_blk][1];
			current[2] = it_block_list_inv[it_blk][2];
			current[3] = it_block_list_inv[it_blk][3];
			current[4] = it_block_list_inv[it_blk][4];
		}

		current[5] = ' ';
		current[6] = arm_cond_list[(cpsr >> 0xC) & 0xF][0];
		current[7] = arm_cond_list[(cpsr >> 0xC) & 0xF][1];
		current += 8;
	}

	current[0] = ((cpsr & 0x200) != 0) ? 'E' : 'e';
	current[1] = ((cpsr & 0x100) != 0) ? 'A' : 'a';
	current[2] = ((cpsr & 0x80) != 0) ? 'I' : 'i';
	current[3] = ((cpsr & 0x40) != 0) ? 'F' : 'f';
	current[4] = ' ';
	current += 5;

	switch(cpsr & 0x1000020){
	case 0:
		current[0] = 'A';
		current[1] = 'R';
		current[2] = 'M';
		current += 3;
		break;
	case 0x20:
		current[0] = 'T';
		current[1] = 'h';
		current[2] = 'u';
		current[3] = 'm';
		current[4] = 'b';
		current += 5;
		break;
	case 0x1000000:
		current[0] = 'J';
		current[1] = 'a';
		current[2] = 'z';
		current[3] = 'e';
		current[4] = 'l';
		current[5] = 'l';
		current[6] = 'e';
		current += 7;
		break;
	case 0x1000020:
		current[0] = 'T';
		current[1] = 'h';
		current[2] = 'u';
		current[3] = 'm';
		current[4] = 'b';
		current[5] = 'E';
		current[6] = 'E';
		current += 7;
		break;
	default:
		break;
	}

	current[0] = ' ';

	switch(cpsr & 0x1F){
	case 0x10:
		current[1] = 'U';
		current[2] = 's';
		current[3] = 'r';
		break;
	case 0x11:
		current[1] = 'F';
		current[2] = 'i';
		current[3] = 'q';
		break;
	case 0x12:
		current[1] = 'I';
		current[2] = 'r';
		current[3] = 'q';
		break;
	case 0x13:
		current[1] = 'S';
		current[2] = 'v';
		current[3] = 'c';
		break;
	case 0x16:
		current[1] = 'M';
		current[2] = 'o';
		current[3] = 'n';
		break;
	case 0x17:
		current[1] = 'A';
		current[2] = 'b';
		current[3] = 't';
		break;
	case 0x1B:
		current[1] = 'U';
		current[2] = 'n';
		current[3] = 'd';
		break;
	case 0x1F:
		current[1] = 'S';
		current[2] = 'y';
		current[3] = 's';
		break;
	default:
		current[1] = '?';
		current[2] = '?';
		current[3] = '?';
		break;
	}

	current[4] = 0;
}




int getAddressLocation(char *dst, int max_len, SceUID pid, unsigned int val){

	if(val == 0 || val == 0xDEADBEEF)
		return -1;

	SceKernelModuleInfo sce_info;

	SceUID modid = fapsKernelGetModuleIdByAddr(pid, (const void *)val);
	if(modid < 0)
		return -1;


	if(pid != 0x10005)
		modid = kscePUIDtoGUID(pid, modid);

	memset(&sce_info, 0, sizeof(sce_info));
	fapsKernelGetModuleInfo(pid, modid, &sce_info);

	if((SceSize)(val - (uintptr_t)sce_info.segments[0].vaddr) < (SceSize)sce_info.segments[0].memsz){

		snprintf(dst, max_len, "%-31s text + 0x%X", sce_info.module_name, val - (SceSize)sce_info.segments[0].vaddr);

		return 0;
	}

	if((SceSize)(val - (uintptr_t)sce_info.segments[1].vaddr) < (SceSize)sce_info.segments[1].memsz){

		snprintf(dst, max_len, "%-31s data + 0x%X", sce_info.module_name, val - (SceSize)sce_info.segments[1].vaddr);

		return 0;
	}

	return -1;
}

const char *getThreadStatusStrings(int status){

	status = status & (~(status - 1));

	if((status & SCE_THREAD_RUNNING) != 0)
		return "Runnig";

	if((status & SCE_THREAD_READY) != 0)
		return "Ready";

	if((status & SCE_THREAD_STANDBY) != 0)
		return "Standby";

	if((status & SCE_THREAD_WAITING) != 0)
		return "Waiting";

	if((status & SCE_THREAD_DORMANT) != 0)
		return "Dormant";

	if((status & SCE_THREAD_DELETED) != 0)
		return "Deleted";

	if((status & SCE_THREAD_DEAD) != 0)
		return "Dead";

	if((status & SCE_THREAD_STAGNANT) != 0)
		return "Stagnant";

	if((status & SCE_THREAD_SUSPENDED) != 0)
		return "Suspended";

	return "Unknown";
}

const char *const reg_strings[] = {
	"a1", "a2", "a3", "a4",
	"v1", "v2", "v3", "v4",
	"v5", "sb", "sl", "fp",
	"ip", "sp", "lr", "pc"
};

void _LogWriteArmRegs(ArmCpuRegisters *arm_regs){
	LogWrite("a1 0x%08X a2 0x%08X a3 0x%08X a4 0x%08X\n", arm_regs->r0, arm_regs->r1, arm_regs->r2, arm_regs->r3);
	LogWrite("v1 0x%08X v2 0x%08X v3 0x%08X v4 0x%08X\n", arm_regs->r4, arm_regs->r5, arm_regs->r6, arm_regs->r7);
	LogWrite("v5 0x%08X sb 0x%08X sl 0x%08X fp 0x%08X\n", arm_regs->r8, arm_regs->r9, arm_regs->r10, arm_regs->r11);
	LogWrite("ip 0x%08X sp 0x%08X lr 0x%08X pc 0x%08X\n", arm_regs->r12, arm_regs->sp, arm_regs->lr, arm_regs->pc);
}

void LogWriteArmRegs(SceUID pid, ArmCpuRegisters *arm_regs){

	int res;
	char addr_loca[0x40];
	char cpsr_str[0x40];

	addr_loca[sizeof(addr_loca) - 1] = 0;

	_LogWriteArmRegs(arm_regs);

	sceKernelGetCPSRStrings(cpsr_str, arm_regs->cpsr);

	LogWrite("cpsr  0x%08X [%s]\n", arm_regs->cpsr, cpsr_str);
	LogWrite("fpscr 0x%08X\n", arm_regs->fpscr);
	LogWrite("\n");

	uint32_t *pCpuRegiser = &arm_regs->r0;

	for(int i=0;i<0x10;i++){
		res = getAddressLocation(addr_loca, sizeof(addr_loca) - 1, pid, pCpuRegiser[i]);
		if(res == 0)
			LogWrite("%s %s\n", reg_strings[i], addr_loca);
	}

	LogWrite("\n");
}

int LogWriteThreadCpuRegs(SceUID pid, SceThreadCpuRegisters *cpu_registers){

	if(cpu_registers->entry[0].cpsr == 0 || (cpu_registers->entry[0].cpsr & 0x1F) == 0x10){
		LogWrite("user registers\n");
		LogWriteArmRegs(pid, &cpu_registers->entry[0]);
	}else{
		LogWrite("kernel registers\n");
		LogWriteArmRegs(SCE_GUID_KERNEL_PROCESS_ID, &cpu_registers->entry[0]);

		LogWrite("user registers\n");
		LogWriteArmRegs(pid, &cpu_registers->entry[1]);
	}

	return 0;
}

int getCauseString(char *dst, int max_len, int cause){

	if(cause == 0x10002 || cause == 0x10003){
		strncpy(dst, "Nothing", max_len);
	}else if(cause == 0x10004){
		strncpy(dst, "AppMgr detected hungup", max_len);
	}else if(cause == 0x10005){
		strncpy(dst, "Spontaneous exit", max_len);
	}else if(cause == 0x10006){
		strncpy(dst, "Stack overflow", max_len);
	}else if(cause == 0x10007){
		strncpy(dst, "Syscall illegal context", max_len);
	}else if(cause == 0x10008){
		strncpy(dst, "Syscall critical usage", max_len);
	}else if(cause == 0x10009){
		strncpy(dst, "Syscall illegal number", max_len);

	}else if(cause == 0x20001){
		strncpy(dst, "Hardware watchpoint", max_len);
	}else if(cause == 0x20002){
		strncpy(dst, "Software watchpoint", max_len);
	}else if(cause == 0x20003){
		strncpy(dst, "Hardware bkpt", max_len);
	}else if(cause == 0x20004){
		strncpy(dst, "Software bkpt", max_len);
	}else if(cause == 0x20005){
		strncpy(dst, "Startup failed", max_len);
	}else if(cause == 0x20006){
		strncpy(dst, "Prx stop init", max_len);
	}else if(cause == 0x20007){
		strncpy(dst, "Dtrace bkpt", max_len);

	}else if(cause == 0x30002){
		strncpy(dst, "Undefined instruction exception", max_len);
	}else if(cause == 0x30003){
		strncpy(dst, "Prefetch abort exception", max_len);
	}else if(cause == 0x30004){
		strncpy(dst, "Data abort exception", max_len);

	}else if(cause == 0x40001){
		strncpy(dst, "Fpu vfp", max_len);
	}else if(cause == 0x40002){
		strncpy(dst, "Fpu neon", max_len);

	}else if(cause == 0x50001){
		strncpy(dst, "Gpu exception", max_len);

	}else if(cause == 0x60080){
		strncpy(dst, "Int div0", max_len);

	}else if((cause & 0xF0000) == 0x80000){
		snprintf(dst, max_len, "Unrecoverable(0x%X)", cause);

	}else{
		snprintf(dst, max_len, "Unknown cause(0x%X)", cause);
	}

	return 0;
}

const char *const dbg_event_string_list[] = {
	"Halt Request debug event",
	"Breakpoint debug event",
	"Asynchronous Watchpoint debug event",
	"BKPT Instruction debug event",

	"External Debug Request debug event",
	"Vector Catch debug event",
	"0x6",
	"0x7",

	"OS Unlock Catch debug event",
	"0x9",
	"Synchronous Watchpoint debug event",
	"0xB",

	"0xC",
	"0xD",
	"0xE",
	"0xF"
};

const char *const DFSR_string_list[] = {
	"0x00",
	"Alignment fault",
	"Debug event",
	"Section Access Flag fault",

	"Instruction cache maintenance fault",
	"Section Translation fault",
	"Page Access Flag fault",
	"Page Translation fault",

	"Synchronous external abort",
	"Section Domain fault",
	"0x0A",
	"Page Domain fault",

	"1st level Translation table walk synchronous external abort",
	"Section Permission fault",
	"2nd level Translation table walk synchronous external abort",
	"Page Permission fault",

	"0x10",
	"0x11",
	"0x12",
	"0x13",

	"Lockdown",
	"0x15",
	"Asynchronous external abort",
	"0x17",

	"0x18",
	"Memory access synchronous parity error",
	"Coprocessor abort",
	"0x1B",

	"1st level Translation table walk synchronous parity error",
	"0x1D",
	"2nd level Translation table walk synchronous parity error",
	"0x1F"
};

int dump_crash_thread_info(FapsCoredumpContext *context, SceKernelThreadInfoInternal *thread_info){

	SceUID modid;
	char cause_string[0x40];
	SceKernelModuleInfo sce_info;
	ThreadCpuRegisters cpu_registers;

	SceCoredumpCrashCauseParam cause_param;
	cause_param.thid        = context->thid;
	cause_param.cause_flags = context->cause_flag;

	SceCoredumpCrashCauseResult cause_result;

	sceCoredumpGetCrashThreadCause(context->thid, &cause_param, &cause_result);

	cause_string[sizeof(cause_string) - 1] = 0;
	getCauseString(cause_string, sizeof(cause_string) - 1, cause_result.cause);

	/*
	 * write crash thread info
	 */
	SceUID thid_user = ksceKernelGetUserThreadId(context->thid);
	if(thid_user >= 0){
		LogWrite("Thread id: 0x%X/0x%X\n", thid_user, context->thid);
	}else{
		LogWrite("GetUserThreadId failed=0x%X(thid_kernel=0x%08X)\n", thid_user, context->thid);
	}
	LogWrite("thread name    : %s\n", thread_info->name);
	LogWrite("cause          : %s (0x%X)\n", cause_string, cause_result.cause);

	if(thread_info->pRegisters->IFSR != 0){ // Provisional, need more RE

		uint32_t IFSR = thread_info->pRegisters->IFSR;
		LogWrite("IFSR           : 0x%08X [ %s ]\n", IFSR, DFSR_string_list[(IFSR & 0xF) | ((IFSR & 0x400) >> 0x6)]);

		if((IFSR & 0x40F) == 2){
			LogWrite(
				"DBGDSCR        : 0x%08X [ %s ]\n",
				thread_info->pRegisters->DBGDSCR,
				dbg_event_string_list[(thread_info->pRegisters->DBGDSCR >> 2) & 0xF]
			);
		}
	}else if(thread_info->pRegisters->DFSR != 0){
		uint32_t DFSR = thread_info->pRegisters->DFSR;
		LogWrite("DFSR           : 0x%08X [ %s ]\n", DFSR, DFSR_string_list[(DFSR & 0xF) | ((DFSR & 0x400) >> 0x6)]);
	}

	if(thread_info->pRegisters->pc == 0){
no_module_pc:
		LogWrite("pc             : 0x%X\n", thread_info->pRegisters->pc);
	}else{
		modid = fapsKernelGetModuleIdByAddr(context->pid, thread_info->pRegisters->pc);

		if(modid < 0 && (cause_result.cause & ~0xF) == 0x10000){
			modid = fapsKernelGetModuleIdByAddr(SCE_GUID_KERNEL_PROCESS_ID, thread_info->pRegisters->pc);
			if(modid < 0)
				goto no_module_pc;

			memset(&sce_info, 0, sizeof(sce_info));
			fapsKernelGetModuleInfo(SCE_GUID_KERNEL_PROCESS_ID, modid, &sce_info);
		}else{
			if(modid < 0)
				goto no_module_pc;

			if(context->pid != SCE_GUID_KERNEL_PROCESS_ID)
				modid = kscePUIDtoGUID(context->pid, modid);

			memset(&sce_info, 0, sizeof(sce_info));
			fapsKernelGetModuleInfo(context->pid, modid, &sce_info);
		}

		if((SceSize)(thread_info->pRegisters->pc - (SceUInt32)sce_info.segments[0].vaddr) >= (SceSize)sce_info.segments[0].memsz)
			goto no_module_pc;

		LogWrite(
			"pc             : %s + 0x%X(0x%X)\n",
			sce_info.module_name,
			(thread_info->pRegisters->pc - (SceUInt32)sce_info.segments[0].vaddr),
			thread_info->pRegisters->pc
		);
	}

	LogWrite("Bad Vaddr      : 0x%X", thread_info->pRegisters->DFAR);

	if(cause_result.cause == 0x30004){
		LogWrite("(");
		if((thread_info->pRegisters->DFSR & 0x800) == 0){
			LogWrite("Read");
		}else{
			LogWrite("Write");
		}

		LogWrite(")");
	}

	LogWrite("\n\n");

	/*
	 * write crash thread register
	 */
	memset(&cpu_registers, 0, sizeof(cpu_registers));
	ksceKernelGetThreadCpuRegisters(context->thid, &cpu_registers);

	LogWriteThreadCpuRegs(context->pid, &cpu_registers);

	LogWrite("float register(user)\n");
	for(int i=0;i<0x20;i+=2){
		LogWrite(
			"d%-02d 0x%016llX d%-02d 0x%016llX\n",
			(i + 0), thread_info->pVfpInfo->vfp_register.d.value_as_int[i + 0],
			(i + 1), thread_info->pVfpInfo->vfp_register.d.value_as_int[i + 1]
		);
	}

	LogWrite("\n");

	modid = fapsKernelGetModuleIdByAddr(context->pid, thread_info->entry);
	if(context->pid != SCE_GUID_KERNEL_PROCESS_ID)
		modid = kscePUIDtoGUID(context->pid, modid);

	memset(&sce_info, 0, sizeof(sce_info));
	fapsKernelGetModuleInfo(context->pid, modid, &sce_info);

	LogWrite("thread info\n");
	LogWrite("thread id              : 0x%X\n", context->thid);
	// LogWrite("processId              : 0x%X\n", thread_info->processId);
	LogWrite("thread name            : %s\n", thread_info->name);
	LogWrite("attr                   : 0x%X\n", thread_info->attr);
	LogWrite("status                 : %s\n", getThreadStatusStrings(thread_info->status));
	LogWrite("entry                  : %s + 0x%X\n", sce_info.module_name, (thread_info->entry - (uint32_t)sce_info.segments[0].vaddr));
	LogWrite("stack (bottom)         : 0x%X\n", thread_info->stack);
	LogWrite("stackSize              : 0x%X\n", thread_info->stackSize);
	LogWrite("initPriority           : 0x%X\n", thread_info->initPriority);
	LogWrite("currentPriority        : 0x%X\n", thread_info->currentPriority);
	LogWrite("initCpuAffinityMask    : 0x%X\n", thread_info->initCpuAffinityMask);
	LogWrite("currentCpuAffinityMask : 0x%X\n", thread_info->currentCpuAffinityMask);
	// LogWrite("currentCpuId           : 0x%X\n", thread_info->currentCpuId);
	LogWrite("lastExecutedCpuId      : 0x%X\n", thread_info->lastExecutedCpuId);
	LogWrite("waitType               : 0x%X\n", thread_info->waitType);
	// LogWrite("waitId                 : 0x%X\n", thread_info->waitId);
	LogWrite("exitStatus             : 0x%X\n", thread_info->exitStatus);
	LogWrite("runClocks              : %lld\n", thread_info->runClocks);
	LogWrite("intrPreemptCount       : 0x%X\n", thread_info->intrPreemptCount);
	LogWrite("threadPreemptCount     : 0x%X\n", thread_info->threadPreemptCount);
	LogWrite("threadReleaseCount     : 0x%X\n", thread_info->threadReleaseCount);
	LogWrite("fNotifyCallback        : 0x%X\n", thread_info->fNotifyCallback);

	return 0;
}

int fapsCoredumpCreateCrashThreadInfo(FapsCoredumpContext *context){

	int res;
	SceKernelThreadInfoInternal thread_info;

	if(context->thid <= 0)
		return 0;

	memset(&thread_info, 0, sizeof(thread_info));
	thread_info.size = sizeof(thread_info);
	res = sceKernelGetThreadInfoInternal(context->thid, 0, &thread_info);
	if(res < 0)
		return res;

	context->temp[FAPS_COREDUMP_TEMP_MAX_LENGTH] = 0;
	snprintf(context->temp, FAPS_COREDUMP_TEMP_MAX_LENGTH, "%s/%s", context->path, "crash_thread_info.txt");
	if(LogOpen(context->temp) < 0){
		return -1;
	}

	res = dump_crash_thread_info(context, &thread_info);

	LogClose();

	if(res < 0)
		return res;

	return 0;
}
