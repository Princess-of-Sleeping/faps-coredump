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
int fapsCoredumpFineUIDPool(FapsCoredumpContext *context);

int fapsCoredumpCreateSummary(FapsCoredumpContext *context);
int fapsCoredumpCreateTtyInfo(FapsCoredumpContext *context);
int fapsCoredumpCreateHwInfo(FapsCoredumpContext *context);
int fapsCoredumpCreateEventLogInfo(FapsCoredumpContext *context);
int fapsCoredumpCreateAsInfoDump(FapsCoredumpContext *context);
int fapsCoredumpCreateProcessInfo(FapsCoredumpContext *context);
int fapsCoredumpCreateProcessIofileInfo(FapsCoredumpContext *context);
int fapsCoredumpCreateCrashThreadInfo(FapsCoredumpContext *context);
int fapsCoredumpCreateCrashThreadStackDump(FapsCoredumpContext *context);

int fapsUpdateMemBlockInfo(FapsCoredumpContext *context);
int fapsCreateMemBlockInfo(FapsCoredumpContext *context);
int fapsCreateMemBlockDump(FapsCoredumpContext *context);

int fapsCoredumpInitProcessModule(FapsCoredumpContext *context);
int fapsCoredumpCreateModulesInfo(FapsCoredumpContext *context);
int fapsCoredumpCreateModuleSegmentDump(FapsCoredumpContext *context);
int fapsCoredumpCreateModuleNonlinkedInfo(FapsCoredumpContext *context);
int fapsCoredumpCreateModuleImportYml(FapsCoredumpContext *context);
int fapsCoredumpCreateModuleExportYml(FapsCoredumpContext *context);

int fapsCoredumpCreateProcessScreenShot(FapsCoredumpContext *context);
int fapsCreateProcessThreadInfo(FapsCoredumpContext *context);
int fapsCreateProcessEventflagInfo(FapsCoredumpContext *context);
int fapsCreateProcessLwCondInfo(FapsCoredumpContext *context);
int fapsCreateProcessLwMutexInfo(FapsCoredumpContext *context);
int fapsCreateProcessMsgpipeInfo(FapsCoredumpContext *context);
int fapsCreateProcessMutexInfo(FapsCoredumpContext *context);
int fapsCreateProcessSemaphoreInfo(FapsCoredumpContext *context);

#endif /* _FAPS_COREDUMP_FUNC_H_ */
