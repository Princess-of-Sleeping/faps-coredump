/*
 * faps-coredump process_mapping.h
 * Copyright (C) 2021, Princess of Sleeping
 */

#ifndef _FAPS_COREDUMP_PROCESS_MAPPING_H_
#define _FAPS_COREDUMP_PROCESS_MAPPING_H_

typedef struct FapsProcessMappingContext {
	SceUID pid;
	SceUID mapid;
	SceKernelProcessContext current;
} FapsProcessMappingContext;

int faps_process_mapping_map(FapsProcessMappingContext *context, SceUID pid, void **dst, const void *src, SceSize length);
int faps_process_mapping_unmap(FapsProcessMappingContext *context);

#endif /* _FAPS_COREDUMP_PROCESS_MAPPING_H_ */
