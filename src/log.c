/*
 * faps-coredump log.c
 * Copyright (C) 2021, Princess of Sleeping
 */

#include <psp2kern/kernel/threadmgr.h>
#include <psp2kern/kernel/sysclib.h>
#include <psp2kern/io/fcntl.h>
#include "log.h"

typedef void (* SceKernelVsnprintfCallback)(void *argp, int ch);

int __vsnprintf_internal(SceKernelVsnprintfCallback cb, void *argp, const char *fmt, va_list list);

typedef struct FapsLogWriteParam {
	char *log_buffer;
	int log_buffer_size;
	int log_current_pos;
	SceUID fd;
} FapsLogWriteParam;

#define FAPS_COREDUMP_LOG_BUFFER_SIZE (0x1000)

FapsLogWriteParam log_write_param;
char log_buffer[FAPS_COREDUMP_LOG_BUFFER_SIZE] __attribute__((aligned(0x40)));

void fapsCoredumpLogWriteInternal(void *argp, int ch){

	if(ch < 0x200){

		FapsLogWriteParam *param = argp;

		char *log_buffer = param->log_buffer;
		int log_current_pos = param->log_current_pos;

		if(log_current_pos == param->log_buffer_size){
			ksceIoWrite(param->fd, log_buffer, param->log_buffer_size);
			log_current_pos = 0;
		}

		log_buffer[log_current_pos] = ch;
		param->log_current_pos = log_current_pos + 1;
	}

	return;
}

int LogIsOpened(void){
	return (log_write_param.fd == 0) ? 0 : 1;
}

int LogOpen(const char *path){

	if(LogIsOpened() == 0){
		SceUID fd = ksceIoOpen(path, SCE_O_WRONLY | SCE_O_CREAT | SCE_O_APPEND, 0666);

		log_write_param.log_buffer      = log_buffer;
		log_write_param.log_buffer_size = FAPS_COREDUMP_LOG_BUFFER_SIZE;
		log_write_param.log_current_pos = 0;
		log_write_param.fd = (fd < 0) ? 0 : fd;

		if(fd < 0)
			return fd;
	}else{
		return -1;
	}

	return 0;
}

int LogWrite(const char *fmt, ...){

	va_list args;

	if(LogIsOpened() == 0)
		return -1;

	va_start(args, fmt);
	__vsnprintf_internal(fapsCoredumpLogWriteInternal, &log_write_param, fmt, args);
	va_end(args);

	return 0;
}

int LogClose(void){
	if(LogIsOpened() != 0){
		if(log_write_param.log_current_pos != 0){
			ksceIoWrite(log_write_param.fd, log_write_param.log_buffer, log_write_param.log_current_pos);
		}

		ksceIoClose(log_write_param.fd);
		log_write_param.fd = 0;
	}

	return 0;
}
