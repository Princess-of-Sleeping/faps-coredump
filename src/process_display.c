/*
 * faps-coredump process_display.c
 * Copyright (C) 2021, Princess of Sleeping
 */

#include <psp2kern/types.h>
#include <psp2kern/kernel/threadmgr.h>
#include <psp2kern/kernel/sysmem.h>
#include <psp2kern/kernel/sysclib.h>
#include <psp2kern/io/fcntl.h>
#include <psp2kern/display.h>
#include "utility.h"
#include "log.h"
#include "process_mapping.h"
#include "coredump_func.h"

typedef struct {
	char magic[2];                 // "BM"
	uint32_t full_file_size;       // 0x1FE08A : header size(0x8A) + image_size (960 * 544 * 4 : 0x1FE000)
	uint16_t rev[2];               // 0, 0
	uint32_t image_data_offset;    // 0xE + sub header size, 0x8A
} __attribute__((packed)) BmpHeader_t; // 0xE

typedef struct {
	uint32_t sub_header_size;  // 0x28
	uint32_t image_width_pix;
	uint32_t image_height_pix;
	uint16_t addr_0x1A_only_1; // 1
	uint16_t bit;              // 32 or 24
	uint32_t compression_type; // zero
	uint32_t image_size;
	char rsv1[0x10];
} __attribute__((packed)) BmpSubHeader28_t; // 0x28

int write_bmp_header(SceUID fd, SceUInt32 width, SceUInt32 height){
	BmpHeader_t BmpHeader;
	BmpSubHeader28_t BmpSubHeader28;

	memset(&BmpHeader, 0, sizeof(BmpHeader_t));
	memset(&BmpSubHeader28, 0, sizeof(BmpSubHeader28_t));

	BmpHeader.magic[0] = 'B';
	BmpHeader.magic[1] = 'M';
	BmpHeader.full_file_size = sizeof(BmpHeader_t) + sizeof(BmpSubHeader28_t) + (width * height * 4);
	BmpHeader.image_data_offset = sizeof(BmpHeader_t) + sizeof(BmpSubHeader28_t);

	BmpSubHeader28.sub_header_size  = sizeof(BmpSubHeader28);
	BmpSubHeader28.image_width_pix  = width;
	BmpSubHeader28.image_height_pix = height;
	BmpSubHeader28.addr_0x1A_only_1 = 1;
	BmpSubHeader28.bit              = 32;
	BmpSubHeader28.compression_type = 0;
	BmpSubHeader28.image_size       = (width * height * 4);

	ksceIoWrite(fd, &BmpHeader, sizeof(BmpHeader));
	ksceIoWrite(fd, &BmpSubHeader28, sizeof(BmpSubHeader28));

	return 0;
}

int fapsCoredumpCreateDisplayInfo(FapsCoredumpContext *context, const SceDisplayFrameBufInfo *info){

	context->temp[FAPS_COREDUMP_TEMP_MAX_LENGTH] = 0;
	snprintf(context->temp, FAPS_COREDUMP_TEMP_MAX_LENGTH, "%s/%s", context->path, "display_info.txt");
	if(LogOpen(context->temp) < 0)
		return -1;

	if(fapsCoredumpIsFullDump(context) != 0){
		LogWrite("paddr      : %p\n", info->paddr);
		LogWrite("pid        : 0x%08X\n", info->pid);
		LogWrite("resolution : 0x%08X\n", info->resolution);
		LogWrite("vblankcount: 0x%08X\n", info->vblankcount);
	}

	LogWrite("base       : %p\n", info->framebuf.base);
	LogWrite("width      : %d\n", info->framebuf.width);
	LogWrite("height     : %d\n", info->framebuf.height);
	LogWrite("pitch      : %d\n", info->framebuf.pitch);
	LogWrite("pixelformat: 0x%X\n", info->framebuf.pixelformat);

	LogClose();

	return 0;
}

int fapsCoredumpCreateProcessDisplayInfo(FapsCoredumpContext *context){

	int res, head;
	SceUID fd, memid;
	SceDisplayFrameBufInfo info_display;

	memset(&info_display, 0, sizeof(info_display));
	info_display.size = sizeof(info_display);

	head = ksceDisplayGetPrimaryHead();

	res = ksceDisplayGetProcFrameBufInternal(context->pid, head, 0, &info_display);
	if(res < 0 || info_display.paddr == 0)
		res = ksceDisplayGetProcFrameBufInternal(context->pid, head, 1, &info_display);

	if(res < 0)
		return res;

	res = fapsCoredumpCreateDisplayInfo(context, &info_display);
	if(res < 0)
		return res;

	if(fapsCoredumpIsManyDump(context) == 0 || info_display.framebuf.base == NULL)
		return 0;

	SceSize fb_size = info_display.framebuf.pitch * info_display.framebuf.height * sizeof(SceUInt32);


	memid = ksceKernelAllocMemBlock("FapsScreenShotBuffer", 0x1050D006, 0x400000, NULL);
	if(memid < 0){
		ksceDebugPrintf("%s: %s=0x%X\n", __FUNCTION__, "sceKernelAllocMemBlock", memid);
		return memid;
	}

	SceUInt32 *ss_base, *pFb;

	ksceKernelGetMemBlockBase(memid, (void **)&ss_base);



	void *data;
	FapsProcessMappingContext map_context;

	res = faps_process_mapping_map(&map_context, context->pid, &data, info_display.framebuf.base, fb_size);
	if(res < 0){
		goto mem_free;
	}

	pFb = data + (info_display.framebuf.pitch * info_display.framebuf.height * 4);

	for(int j=0;j<info_display.framebuf.height;j++){
		pFb -= info_display.framebuf.pitch;

		for(int i=0;i<info_display.framebuf.width;i++){
			*ss_base++ = 0xFF000000 | (pFb[i] & 0xFF00FF00) | ((pFb[i] & 0xFF) << 16) | ((pFb[i] >> 16) & 0xFF);
		}
	}

	faps_process_mapping_unmap(&map_context);
	data = NULL;
	pFb = NULL;

	ksceKernelGetMemBlockBase(memid, (void **)&ss_base);

	context->temp[FAPS_COREDUMP_TEMP_MAX_LENGTH] = 0;
	snprintf(context->temp, FAPS_COREDUMP_TEMP_MAX_LENGTH, "%s/%s", context->path, "screenshot.bmp");

	fd = ksceIoOpen(context->temp, SCE_O_WRONLY | SCE_O_CREAT | SCE_O_TRUNC, 0666);
	if(fd < 0){
		res = fd;
		goto mem_free;
	}

	write_bmp_header(fd, info_display.framebuf.width, info_display.framebuf.height);
	write_file_proc_by_fd(SCE_GUID_KERNEL_PROCESS_ID, fd, ss_base, fb_size);

	ksceIoClose(fd);

	res = 0;

mem_free:
	ksceKernelFreeMemBlock(memid);

	return res;
}
