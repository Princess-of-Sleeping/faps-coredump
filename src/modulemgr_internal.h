/*
 * PS Vita kernel module manager RE
 * Copyright (C) 2019, Princess of Sleeping
 */

#ifndef _PSP2_KERNEL_MODULEMGR_INTERNAL_H_
#define _PSP2_KERNEL_MODULEMGR_INTERNAL_H_

#include <psp2kern/types.h>

#define SCE_KERNEL_MODULE_STATE_READY_LOAD   1
#define SCE_KERNEL_MODULE_STATE_READY_START  2
#define SCE_KERNEL_MODULE_STATE_DONE_START   3

#define SCE_KERNEL_MODULE_STATE_READY_STOP   4
#define SCE_KERNEL_MODULE_STATE_READY_UNLOAD 5
#define SCE_KERNEL_MODULE_STATE_DONE_UNLOAD  0

typedef struct SceModuleInfoInternal SceModuleInfoInternal;
typedef struct SceModuleLibraryInfo SceModuleLibraryInfo;

typedef int (* SceKernelModuleEntry)(SceSize args, void *argp);
typedef int (* SceKernelModuleDebugCallback)(SceModuleInfoInternal *pModuleInfo);

typedef struct SceModuleImport1 {
	uint16_t size;               // 0x34
	uint16_t version;
	uint16_t flags;
	uint16_t entry_num_function;
	uint16_t entry_num_variable;
	uint16_t entry_num_tls;
	uint32_t rsvd1;
	uint32_t libnid;
	const char *libname;
	uint32_t rsvd2;
	uint32_t *table_func_nid;
	void    **table_function;
	uint32_t *table_vars_nid;
	void    **table_variable;
	uint32_t *table_tls_nid;
	void    **table_tls;
} SceModuleImport1;

typedef struct SceModuleImport2 {
	uint16_t size; // 0x24
	uint16_t version;
	uint16_t flags;
	uint16_t entry_num_function;
	uint16_t entry_num_variable;
	uint16_t data_0x0A; // unused?
	uint32_t libnid;
	const char *libname;
	uint32_t *table_func_nid;
	void    **table_function;
	uint32_t *table_vars_nid;
	void    **table_variable;
} SceModuleImport2;

typedef union SceModuleImport {
	uint16_t size;
	SceModuleImport1 type1;
	SceModuleImport2 type2;
} SceModuleImport;

typedef struct SceModuleExport {
	uint16_t size; // 0x20

/*
	uint16_t libver[2];
*/
	uint16_t version;
	uint16_t flags; // 0x4000:user export
	uint16_t entry_num_function;
	uint16_t entry_num_variable;
	uint16_t data_0x0A; // unused?
	uint32_t data_0x0C; // unused?
	uint32_t libnid;
	const char *libname;
	uint32_t *table_nid;
	void    **table_entry;
} SceModuleExport;

typedef struct SceModuleImportInfo {
	struct SceModuleImportInfo *next;
	SceUID stubid;
	SceModuleImport *pImportInfo;
	SceModuleLibraryInfo *pLibraryInfo;
	SceModuleInfoInternal *pModuleInfo;
	int data_0x14; // zero?
} SceModuleImportInfo;

typedef struct SceModuleLibraryInfo { // size is 0x2C
	struct SceModuleLibraryInfo *next;
	struct SceModuleLibraryInfo *data_0x04; // maybe
	SceModuleExport *pExportInfo;

	/*
	 * (syscall_idx &  0xFFF):syscall idx
	 * (syscall_idx & 0x1000):has syscall flag?
	 * (syscall_idx == 0) -> kernel export
	 */
	uint16_t syscall_info;
	uint16_t data_0x0E;

	/*
	 * Number of times this export was imported into another module
	 */
	SceSize number_of_imported;
	SceModuleImportInfo *pImportedInfo;
	SceUID libid_kernel;
	SceUID libid_user;
	SceModuleInfoInternal *pModuleInfo;
	int data_0x24; // zero?
	int data_0x28; // zero?
} SceModuleLibraryInfo;

typedef struct SceModuleSharedInfo { // size is 0x10
	struct SceModuleSharedInfo *next;
	SceModuleInfoInternal *pModuleInfo;
	SceSize info_linked_number;
	void *cached_segment_data;
} SceModuleSharedInfo;

typedef struct SceSegmentInfoInternal { // size is 0x14
	SceSize filesz;
	SceSize memsz;
	uint8_t perms[4];
	void *vaddr;
	SceUID memblk_id;
} SceSegmentInfoInternal;

typedef struct SceModuleDebugPointExportsInfo { // size is 0x8 bytes on FWs 0.931-3.73
	SceUInt32 version;    // ex: 1
	SceUInt32 numEntries; // ex: 1, 5, 7, 16
} SceModuleDebugPointExportsInfo;

typedef struct SceModuleDebugPointExport { // size is 0x28-bytes on FWs 0.931-3.73
	void *unk_0x0;            // maybe pointer to a structure or could be a SceUInt32
	const char *type_name;    // "__proc_", "__interrupt_", "__sched_"
	const char *command_name; // Name of the operation. ex: "exec__failure
	const void *addr;         // Pointer to the exported instructions
	void *storage;            // Can be used in the exported instructions
	void *unk_0x14;           // Seems unused
	void *unk_0x18;           // Seems unused
	void *unk_0x1C;           // Seems unused
	void *unk_0x20;           // Seems unused
	void *unk_0x24;           // Seems unused
} SceModuleDebugPointExport;

typedef struct SceModuleEntryCallParam { // size is 0x14-bytes
	SceUInt32 version; // should be 4
	SceUInt32 threadPriority;
	SceUInt32 threadStackSize;
	SceUInt32 data_0x0C;
	SceUInt32 cpuAffinityMask;
} SceModuleEntryCallParam;

typedef struct SceModuleInfoInternal { // size is 0xE8-bytes
	struct SceModuleInfoInternal *next;
	uint16_t flags;
	uint8_t state;
	uint8_t data_0x07;
	SceUInt32 version;	// ex : 0x03600011
	SceUID modid_kernel;	// This is only used by kernel modules

	// 0x10
	SceUID modid_user;	// This is only used by   user modules
	SceUID pid;
	uint16_t attr;
	uint8_t minor;
	uint8_t major;
	char *module_name;

	// 0x20
	void *libent_top;
	void *libent_btm;
	void *libstub_top;
	void *libstub_btm;

	// 0x30
	SceUInt32 fingerprint;
	void *tlsInit;
	SceSize tlsInitSize;
	SceSize tlsAreaSize;

	// 0x40
	void *exidxTop;
	void *exidxBtm;
	void *extabTop;
	void *extabBtm;

	// 0x50
	SceUInt16 lib_export_num;           // Includes noname library
	SceUInt16 lib_import_num;
	SceModuleExport *data_0x54;
	SceModuleExport *data_0x58;         // export relation
	SceModuleLibraryInfo *pLibraryInfo;

	// 0x60
	SceModuleImport *data_0x60;         // first_import?
	SceModuleImportInfo *import_list;


	char *path;
	struct { // size is 0x48-bytes
	int segments_num;

	// 0x70
	SceSegmentInfoInternal segments[3]; // 0x14 * 3 : 0x3C
	int data_0xAC;

	// 0xB0
	int data_0xB0;
	};
	SceKernelModuleEntry module_start;
	SceKernelModuleEntry module_stop;
	SceKernelModuleEntry module_exit;

	SceKernelModuleEntry module_bootstart;
	void *module_proc_param;
	SceModuleEntryCallParam *module_start_thread_param; // noname export. NID:0x1A9822A4
	SceModuleEntryCallParam *module_stop_thread_param; // noname export. NID:0xD20886EB

	void *arm_exidx; // need dipsw 0xD2
	SceModuleSharedInfo *pSharedInfo; // allocated by sceKernelAlloc
	int data_0xD8;
	SceModuleDebugPointExportsInfo *pDbgPointInfo;

	SceModuleDebugPointExport **pDbgPointList; // noname export. NID:0x8CE938B1
	int data_0xE4;
} SceModuleInfoInternal;

typedef struct SceModuleObject { // size is 0xF4-bytes
	uint32_t sce_reserved[2];
	SceModuleInfoInternal obj_base;
	int data_0xE8;
} SceModuleObject;

typedef struct SceModuleLibraryObject {
	uint32_t sce_reserved[2];
	SceModuleLibraryInfo *pLibraryInfo;
	SceUID modid;
} SceModuleLibraryObject;

typedef struct SceModuleLibStubObject {
	uint32_t sce_reserved[2];
	SceUID modid;
	SceSize num; // maybe nonlinked import num
} SceModuleLibStubObject;

#define SCE_KERNEL_PRELOAD_INHIBIT_LIBC        (0x10000)
#define SCE_KERNEL_PRELOAD_INHIBIT_LIBDBG      (0x20000)
#define SCE_KERNEL_PRELOAD_INHIBIT_LIBSHELLSVC (0x80000)
#define SCE_KERNEL_PRELOAD_INHIBIT_LIBCDLG     (0x100000)
#define SCE_KERNEL_PRELOAD_INHIBIT_LIBFIOS2    (0x200000)
#define SCE_KERNEL_PRELOAD_INHIBIT_APPUTIL     (0x400000)
#define SCE_KERNEL_PRELOAD_INHIBIT_LIBSCEFT2   (0x800000)
#define SCE_KERNEL_PRELOAD_INHIBIT_LIBPVF      (0x1000000)
#define SCE_KERNEL_PRELOAD_INHIBIT_LIBPERF     (0x2000000)

// used by sceKernelLoadPreloadingModules

typedef struct SceKernelPreloadModuleInfo { // size is 0x24
	const char *module_name;
	const char *path[6];
	SceUInt32 inhibit;
	int flags;
} SceKernelPreloadModuleInfo;

typedef struct SceLoadProcessParam { // maybe size is 0x7C
	int sdk_version;
	char thread_name[0x20];
	int thread_priority;
	SceSize stack_size;
	uint8_t data_174[0x8];
	uint8_t data_17C[0x1C];
	uint8_t data_198[0x4];
	char process_name[0x20]; // not titleid
	uint32_t preload_inhibit;
	void *module_proc_param;
} SceLoadProcessParam;

#endif /* _PSP2_KERNEL_MODULEMGR_INTERNAL_H_ */
