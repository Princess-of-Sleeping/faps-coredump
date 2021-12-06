cmake_minimum_required(VERSION 3.0)

if(NOT DEFINED CMAKE_TOOLCHAIN_FILE)
  if(DEFINED ENV{VITASDK})
    set(CMAKE_TOOLCHAIN_FILE "$ENV{VITASDK}/share/vita.toolchain.cmake" CACHE PATH "toolchain file")
  else()
    message(FATAL_ERROR "Please define VITASDK to point to your SDK path!")
  endif()
endif()

project(faps-coredump)
include("${VITASDK}/share/vita.cmake" REQUIRED)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wl,-q -Wall -Os -fno-inline")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fno-rtti -fno-exceptions")

add_executable(faps-coredump
  src/main.c
  src/coredump.c
  src/coredump_func.c
  src/log.c
  src/utility.c
  src/process_mapping.c
  src/summary.c
  src/dump_crash_thread_stack.c
  src/dump_crash_thread_info.c
  src/process_info.c
  src/process_iofile.c
  src/process_address_space.c
  src/process_module.c
  src/process_memblock.c
  src/process_screenshot.c
  src/process_semaphore.c
  src/process_eventflag.c
  src/process_mutex.c
  src/process_lwmutex.c
  src/process_msgpipe.c
  src/process_lwcond.c
  src/process_thread.c
  src/hw_info.c
  src/event_log.c
  src/tty_info.c
)

target_link_libraries(faps-coredump
  SceCpuForDriver_stub
  SceCtrlForDriver_stub
  SceDisplayForDriver_stub
  SceDebugForDriver_stub
  SceIofilemgrForDriver_stub
  SceProcessmgrForDriver_stub
  SceModulemgrForDriver_stub
  SceSysclibForDriver_stub
  SceSysrootForDriver_stub
  SceSysrootForKernel_stub
  SceSysmemForDriver_stub
  SceThreadmgrForDriver_stub
  SceTouchForDriver_stub
  ScePervasiveForDriver_stub
  SceSblAIMgrForDriver_stub
  SceRegMgrForDriver_stub
  SceRtcForDriver_stub
  taihenForKernel_stub
  taihenModuleUtils_stub
  ${CMAKE_CURRENT_BINARY_DIR}/../extra/libSceKernelThreadMgr_stub.a
  ${CMAKE_CURRENT_BINARY_DIR}/../extra/libSceSysmem_stub.a
)

set_target_properties(faps-coredump
  PROPERTIES LINK_FLAGS "-nostdlib"
  COMPILE_FLAGS "-D__PSP2_KERNEL__"
)

vita_create_self(faps-coredump.skprx faps-coredump
  CONFIG exports.yml
  UNSAFE
  STRIPPED
)

vita_create_stubs(stubs faps-coredump ${CMAKE_CURRENT_SOURCE_DIR}/exports.yml KERNEL)
