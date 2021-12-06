/*
 * faps-coredump utility.h
 * Copyright (C) 2021, Princess of Sleeping
 */

#ifndef _FAPS_COREDUMP_UTILITY_H_
#define _FAPS_COREDUMP_UTILITY_H_

#include <psp2kern/types.h>
#include <psp2kern/kernel/modulemgr.h>
#include "types.h"

int fapsKernelGetModuleInfo(SceUID pid, SceUID modid, SceKernelModuleInfo *info);
int fapsKernelGetModuleIdByAddr(SceUID pid, const void *a2);

int write_file(const char *path, const void *data, SceSize len);
int write_file_proc(SceUID pid, const char *path, const void *data, SceSize len);
int write_file_proc_by_fd(SceUID pid, SceUID fd, const void *data, SceSize len);

int fapsCoredumpIsNonCpuCrash(const FapsCoredumpContext *context);
int fapsCoredumpIsSceShellUnknownCrash(const FapsCoredumpContext *context);
int fapsCoredumpIsGpuCrash(const FapsCoredumpContext *context);

int _fapsCoredumpIsFullDump(void);

int fapsCoredumpIsMiniDump(const FapsCoredumpContext *context);
int fapsCoredumpIsLittleDump(const FapsCoredumpContext *context);
int fapsCoredumpIsNormalDump(const FapsCoredumpContext *context);
int fapsCoredumpIsManyDump(const FapsCoredumpContext *context);
int fapsCoredumpIsFullDump(const FapsCoredumpContext *context);

#endif /* _FAPS_COREDUMP_UTILITY_H_ */
