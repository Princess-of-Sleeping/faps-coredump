/*
 * faps-coredump log.h
 * Copyright (C) 2021, Princess of Sleeping
 */

#ifndef _FAPS_COREDUMP_LOG_H_
#define _FAPS_COREDUMP_LOG_H_

int LogIsOpened(void);
int LogOpen(const char *path);
int LogWrite(const char *fmt, ...);
int LogClose(void);

#endif /* _FAPS_COREDUMP_LOG_H_ */
