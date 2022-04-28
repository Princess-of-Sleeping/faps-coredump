/*
 * faps-coredump coredump_func.h
 * Copyright (C) 2021, Princess of Sleeping
 */

#ifndef _FAPS_COREDUMP_FUNC_H_
#define _FAPS_COREDUMP_FUNC_H_

int fapsCoredumpGetDumpTime(FapsCoredumpContext *context);
int fapsCoredumpMakeDumpPathName(FapsCoredumpContext *context);
int fapsCoredumpCreateDumpDirectory(FapsCoredumpContext *context);
int fapsCoredumpInitUIDPool(FapsCoredumpContext *context);
int fapsCoredumpFiniUIDPool(FapsCoredumpContext *context);

int fapsCoredumpCreateSummary(FapsCoredumpContext *context);
int fapsCoredumpCreateTtyInfo(FapsCoredumpContext *context);
int fapsCoredumpCreateHwInfo(FapsCoredumpContext *context);
int fapsCoredumpCreateEventLogInfo(FapsCoredumpContext *context);
int fapsCoredumpCreateAsInfoDump(FapsCoredumpContext *context);
int fapsCoredumpCreateProcessInfo(FapsCoredumpContext *context);
int fapsCoredumpCreateProcessIofileInfo(FapsCoredumpContext *context);
int fapsCoredumpCreateCrashThreadInfo(FapsCoredumpContext *context);
int fapsCoredumpCreateCrashThreadStackDump(FapsCoredumpContext *context);

/* sysmem */
int fapsCoredumpUpdateMemBlockInfo(FapsCoredumpContext *context);
int fapsCoredumpCreateMemBlockInfo(FapsCoredumpContext *context);
int fapsCoredumpCreateMemBlockDump(FapsCoredumpContext *context);

/* modulemgr */
int fapsCoredumpInitProcessModule(FapsCoredumpContext *context);
int fapsCoredumpCreateModulesInfo(FapsCoredumpContext *context);
int fapsCoredumpCreateModuleSegmentDump(FapsCoredumpContext *context);
int fapsCoredumpCreateModuleNonlinkedInfo(FapsCoredumpContext *context);
int fapsCoredumpCreateModuleImportYml(FapsCoredumpContext *context);
int fapsCoredumpCreateModuleExportYml(FapsCoredumpContext *context);

/* display */
int fapsCoredumpCreateProcessDisplayInfo(FapsCoredumpContext *context);

/* threadmgr */
int fapsCoredumpCreateProcessThreadInfo(FapsCoredumpContext *context);
int fapsCoredumpCreateProcessEventflagInfo(FapsCoredumpContext *context);
int fapsCoredumpCreateProcessLwCondInfo(FapsCoredumpContext *context);
int fapsCoredumpCreateProcessLwMutexInfo(FapsCoredumpContext *context);
int fapsCoredumpCreateProcessMsgpipeInfo(FapsCoredumpContext *context);
int fapsCoredumpCreateProcessMutexInfo(FapsCoredumpContext *context);
int fapsCoredumpCreateProcessSemaphoreInfo(FapsCoredumpContext *context);

#endif /* _FAPS_COREDUMP_FUNC_H_ */
