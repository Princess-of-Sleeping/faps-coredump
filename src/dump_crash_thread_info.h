/*
 * faps-coredump dump_crash_thread_info.h
 * Copyright (C) 2021, Princess of Sleeping
 */

#ifndef _FAPS_COREDUMP_DUMP_CRASH_THREAD_INFO_H_
#define _FAPS_COREDUMP_DUMP_CRASH_THREAD_INFO_H_

const char *getThreadStatusStrings(int status);
int LogWriteThreadCpuRegs(SceUID pid, SceThreadCpuRegisters *cpu_registers);

#endif /* _FAPS_COREDUMP_DUMP_CRASH_THREAD_INFO_H_ */
