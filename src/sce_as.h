/*
 * PS Vita Address Space Header
 * Copyright (C) 2021, Princess of Sleeping
 */

#ifndef _PSP2_KERNEL_AS_H_
#define _PSP2_KERNEL_AS_H_

#include <psp2kern/types.h>
#include <psp2kern/kernel/sysmem.h>

typedef struct SceKernelProcASInfo { // size is 0x80
	int unk_0x00;
	void *unk_0x04; // SceClass?
	const char *name;
	int cpu_intr;
	int unk_0x10; // (void *)?
	void *base_vaddr;
	SceSize base_size;
	void *unk_0x1C; // proc cpu ctx
	int unk_0x20; // some flag?
	int unk_0x24; // size?
	int unk_0x28; // -1
	int unk_0x2C;
	int unk_0x30; // -1
	uint32_t magic; // 0xD946F262
	int unk_0x38;
	int unk_0x3C;
	int unk_0x40;
	int unk_0x44;
	int unk_0x48;
	int unk_0x4C; // ex:8
	int unk_0x50;
	void *unk_0x54; // SceKernelAddressSpaceInfo ptr
	int unk_0x58;
	int unk_0x5C;
	int unk_0x60; // -1
	SceUID pid;
	SceUID unk_0x68;
	int unk_0x6C;
	int unk_0x70;
	int unk_0x74;
	int unk_0x78;
	int unk_0x7C;
} SceKernelProcASInfo;

typedef struct SceKernelPhyMemPart { // size is 0xAC
	int data_0x00;
	void *data_0x04;
	int data_0x08; // for cpu function
	int data_0x0C;

	SceUID data_0x10;
	int data_0x14;
	int data_0x18;
	void *data_0x1C;

	void *data_0x20;
	int data_0x24;
	int data_0x28;
	void *data_0x2C;

	void *data_0x30;
	int data_0x34;
	void *data_0x38;
	int data_0x3C;

	void *data_0x40;
	int data_0x44;
	void *data_0x48;
	int data_0x4C;

	void *data_0x50;
	int data_0x54;
	void *data_0x58;
	int data_0x5C;

	void *data_0x60;
	int data_0x64;
	void *data_0x68;
	int data_0x6C;

	void *data_0x70;
	int data_0x74;
	void *data_0x78;
	void *data_0x7C;

	int data_0x80;
	int data_0x84;
	int data_0x88;
	char name[0x20];
} SceKernelPhyMemPart;

typedef struct SceKernelAddressSpaceInfo { // size is 0x170
	int unk_0x00;
	SceClass *pASClass;
	int unk_0x08;		// for cpu function
	int unk_0x0C;
	int flag;		// kernel:0x30000002, user:0x10000001
	SceUID pid;
	SceKernelProcessContext *unk_0x18;
	SceKernelProcASInfo *pProcAS[0x20];
	SceUID unk_uid[0x20];	// AS Info uid?
	int unk_0x11C;
	int unk_0x120[4];
	SceKernelPhyMemPart *unk_0x130;
	SceKernelPhyMemPart *unk_0x134;
	SceKernelPhyMemPart *unk_0x138;
	SceKernelPhyMemPart *unk_0x13C;
	SceKernelPhyMemPart *unk_0x140;
	SceKernelPhyMemPart *unk_0x144;
	SceKernelPhyMemPart *unk_0x148;
	SceKernelPhyMemPart *unk_0x14C;
	SceKernelPhyMemPart *unk_0x150;
	SceKernelPhyMemPart *unk_0x154;
	SceKernelPhyMemPart *unk_0x158;
	SceUID unk_0x15C; // for user process? it guid
	SceUID unk_0x160; // for user process? it guid
	int unk_0x164;
	uint32_t unk_0x168;	// kernel:0x511389B0
	uint32_t magic;		// 0x4D95AEEC
} SceKernelAddressSpaceInfo;

typedef struct SceSysmemAddressSpaceInfo {
	uintptr_t base;
	SceSize total;
	SceSize free;
	SceSize unkC;
} SceSysmemAddressSpaceInfo;

#endif /* _PSP2_KERNEL_AS_H_ */
