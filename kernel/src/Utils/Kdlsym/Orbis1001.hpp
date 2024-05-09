#pragma once
#include <Boot/Config.hpp>

#if MIRA_PLATFORM==MIRA_PLATFORM_ORBIS_BSD_1001
/*
    These are the required functions in order for the Oni Framework to operate properly
    These are all offsets into the base of the kernel. They expect all standard FreeBSD 9 prototypes

    The reason we do not hardcode offsets here, is due to the different platforms that are supported, and
    for the platforms that do enable kernel ASLR (Address Space Layout Randomization?)
*/

#define kdlsym_addr__mtx_lock_flags  0x1dfb50
#define kdlsym_addr__mtx_lock_sleep  0x1dfbe0
#define kdlsym_addr__mtx_lock_spin_flags  0x1dff60
#define kdlsym_addr__mtx_unlock_flags  0x1dfe00
#define kdlsym_addr__mtx_unlock_sleep  0x1dff00
#define kdlsym_addr__mtx_unlock_spin_flags  0x1e0100
#define kdlsym_addr__sceSblAuthMgrGetSelfInfo  0x641e30
#define kdlsym_addr__sceSblAuthMgrSmStart  0x63d790
#define kdlsym_addr__sx_init_flags  0xa9800
#define kdlsym_addr__sx_slock  0xa9610
#define kdlsym_addr__sx_sunlock  0xa9b90
#define kdlsym_addr__sx_xlock  0xa9a80
#define kdlsym_addr__sx_xunlock  0xa9c40
#define kdlsym_addr__thread_lock_flags  0x1e0270
#define kdlsym_addr__vm_map_lock_read  0x38d070
#define kdlsym_addr__vm_map_unlock_read  0x38d0c0
#define kdlsym_addr_AesCbcCfb128Decrypt  0x3ba030
#define kdlsym_addr_AesCbcCfb128Encrypt  0x3b9e00
// #define xref_kdlsym_addr_allproc  0x4696e0
#define kdlsym_addr_allproc  0x22d9b40
// #define xref_kdlsym_addr_allproc_lock  0x4696e0
#define kdlsym_addr_allproc_lock  0x02d9ae0
#define kdlsym_addr_avcontrol_sleep  0x6e32a0
#define kdlsym_addr_cloneuio  0x234c30
// #define xref_kdlsym_addr_console_cdev  0x40a760
#define kdlsym_addr_console_cdev  0x22e2cc0
#define kdlsym_addr_console_write  0x40ba10
#define kdlsym_addr_contigfree  0x1d8e60
#define kdlsym_addr_contigmalloc  0x1d8ac0
#define kdlsym_addr_copyin  0x472f10
#define kdlsym_addr_copyinstr  0x4733c0
#define kdlsym_addr_copyout  0x472e20
#define kdlsym_addr_critical_enter  0x3f4a0
#define kdlsym_addr_critical_exit  0x3f4c0
#define kdlsym_addr_deci_tty_write  0x48b400
#define kdlsym_addr_destroy_dev  0x3cb4d0
#define kdlsym_addr_dmem_start_app_process  0x4209c0
#define kdlsym_addr_dynlib_do_dlsym  0x1bc0e0
#define kdlsym_addr_dynlib_find_obj_by_handle  0x1bd260
#define kdlsym_addr_eventhandler_deregister  0x226d30
#define kdlsym_addr_eventhandler_find_list  0x226f20
#define kdlsym_addr_eventhandler_register  0x2269a0
#define kdlsym_addr_exec_new_vmspace  0x31de00
#define kdlsym_addr_faultin  0x2dbde0
#define kdlsym_addr_fget_unlocked  0x340b90
// #define xref_kdlsym_addr_fpu_kern_ctx  0x625070
#define kdlsym_addr_fpu_kern_ctx  0x2660040
#define kdlsym_addr_fpu_kern_enter  0x26c7d0
#define kdlsym_addr_fpu_kern_leave  0x26c890
#define kdlsym_addr_free  0x109c20
// #define xref_kdlsym_addr_gdt  0x6d7d0
#define kdlsym_addr_gdt  0x1b82af0
// #define xref_kdlsym_addr_gpu_va_page_list  0x619cd0
#define kdlsym_addr_gpu_va_page_list  0x2646258
#define kdlsym_addr_icc_nvs_read  0x2e0850
#define kdlsym_addr_kern_close  0x33e4e0
#define kdlsym_addr_kern_ioctl  0x260c60
#define kdlsym_addr_kern_mkdirat  0x2132b0
#define kdlsym_addr_kern_open  0x20e110
#define kdlsym_addr_kern_openat  0x20e170
#define kdlsym_addr_kern_readv  0x260530
#define kdlsym_addr_kern_reboot  0x480ce0
#define kdlsym_addr_kern_sysents  0xd02060 // sv_table
#define kdlsym_addr_kern_thr_create  0x182f0
// #define xref_kdlsym_addr_kernel_map  0x2db2f0
#define kdlsym_addr_kernel_map  0x227bef8
#define kdlsym_addr_kernel_mount  0x196660
#define kdlsym_addr_killproc  0x1f1880
#define kdlsym_addr_kmem_alloc  0x33b040
#define kdlsym_addr_kmem_free  0x33b210
#define kdlsym_addr_kproc_create  0x207d90
#define kdlsym_addr_kproc_exit  0x208000
#define kdlsym_addr_kthread_add  0x2082f0
#define kdlsym_addr_kthread_exit  0x2085e0
// #define xref_kdlsym_addr_M_IOV  0x4a960 // sys_nmount
#define kdlsym_addr_M_IOV  0x1a55840
// #define xref_kdlsym_addr_M_LINKER  0x127a30
#define kdlsym_addr_M_LINKER  0x151e630
// #define xref_kdlsym_addr_M_MOUNT  0x193140
#define kdlsym_addr_M_MOUNT  0x153e840
// #define xref_kdlsym_addr_M_TEMP  0x194650 // sys_mount
#define kdlsym_addr_M_TEMP  0x1532c00
#define kdlsym_addr_make_dev_p  0x3cafb0
#define kdlsym_addr_malloc  0x109a60
#define kdlsym_addr_memcmp  0x109940
#define kdlsym_addr_memcpy  0x472d20
#define kdlsym_addr_memmove  0x1fae90
#define kdlsym_addr_memset  0x3e6f0
#define kdlsym_addr_mini_syscore_self_binary  0xd5da48 // 4f 15 3d 1d (sus '-')
#define kdlsym_addr_mount_arg  0x1963d0
#define kdlsym_addr_mount_argb  0x195b70
#define kdlsym_addr_mount_argf  0x1964c0
#define kdlsym_addr_mtx_destroy  0x1e0630
#define kdlsym_addr_mtx_init  0x1e05c0
#define kdlsym_addr_mtx_lock_sleep  0x1dfbe0
#define kdlsym_addr_mtx_unlock_sleep  0x1dff00
#define kdlsym_addr_name_to_nids  0x1bc3c0
#define kdlsym_addr_pause  0x286350
#define kdlsym_addr_pfind  0x3cec30
#define kdlsym_addr_pmap_activate  0xeb270
#define kdlsym_addr_printf  0xc50f0
// #define xref_kdlsym_addr_prison0  0x481780
#define kdlsym_addr_prison0  0x111b8b0 // sus ^ 2
// #define xref_kdlsym_addr_proc0  0x207d90
#define kdlsym_addr_proc0  0x226ae50
#define kdlsym_addr_proc_reparent  0x4190
#define kdlsym_addr_proc_rwmem  0x44dc40
#define kdlsym_addr_realloc  0x109d20
// #define xref_kdlsym_addr_rootvnode 0x20dfa0
#define kdlsym_addr_rootvnode  0x1b25bd0
// #define xref_kdlsym_addr_RsaesPkcs1v15Dec2048CRT 0x6c780
#define kdlsym_addr_RsaesPkcs1v15Dec2048CRT  0x6ca20 // b9 40 00 00 00
// #define xref_kdlsym_addr_sbl_eap_internal_partition_key  0x6513d0
#define kdlsym_addr_sbl_eap_internal_partition_key  0x26c4d00
// #define xref_kdlsym_addr_sbl_keymgr_buf_gva  0x620cc0
#define kdlsym_addr_sbl_keymgr_buf_gva  0x265c808
// #define xref_kdlsym_addr_sbl_keymgr_buf_va  0x620cc0
#define kdlsym_addr_sbl_keymgr_buf_va  0x265c000
// #define xref_kdlsym_addr_sbl_keymgr_key_rbtree  0x621220
#define kdlsym_addr_sbl_keymgr_key_rbtree  0x26583c8
// #define xref_kdlsym_addr_sbl_keymgr_key_slots  0x621560
#define kdlsym_addr_sbl_keymgr_key_slots  0x26583b8
// #define xref_kdlsym_addr_sbl_pfs_sx  0x62ca30
#define kdlsym_addr_sbl_pfs_sx  0x267c088
// #define xref_kdlsym_addr_sbl_drv_msg_mtx  0x619c70
#define kdlsym_addr_sbl_drv_msg_mtx  0x2646260
#define kdlsym_addr_sceSblACMgrGetPathId  0xa5d10
#define kdlsym_addr_sceSblAuthMgrIsLoadable2  0x6415f0
#define kdlsym_addr_sceSblAuthMgrSmVerifyHeader  0x63f510
#define kdlsym_addr_sceSblAuthMgrVerifyHeader  0x641650
#define kdlsym_addr_sceSblDriverSendMsg  0x6194a0
#define kdlsym_addr_sceSblGetEAPInternalPartitionKey  0x627c20
#define kdlsym_addr_sceSblKeymgrClearKey  0x621560
#define kdlsym_addr_sceSblKeymgrSetKeyForPfs  0x621220
#define kdlsym_addr_sceSblKeymgrSetKeyStorage  0x624ca0
#define kdlsym_addr_sceSblKeymgrSmCallfunc  0x620df0
#define kdlsym_addr_sceSblPfsSetKeys  0x62cb00
#define kdlsym_addr_sceSblRngGetRandomNumber  0x646a70
#define kdlsym_addr_sceSblServiceMailbox  0x62dbe0
#define kdlsym_addr_sched_prio  0x1d5d50
#define kdlsym_addr_self_orbis_sysvec  0x126ab88 // sysentvec
#define kdlsym_addr_Sha256Hmac  0x13a3d0
#define kdlsym_addr_snprintf  0xc53f0
#define kdlsym_addr_spinlock_exit  0x7cfa0
#define kdlsym_addr_sprintf  0xc5330
#define kdlsym_addr_sscanf  0x25f100
#define kdlsym_addr_strcmp  0x40d170
#define kdlsym_addr_strdup  0x32dd00
#define kdlsym_addr_strlen  0x2e0340
#define kdlsym_addr_strncmp  0x1219b0
#define kdlsym_addr_strstr  0x3f7490
#define kdlsym_addr_sys_accept  0x1a3780
#define kdlsym_addr_sys_bind  0x1a2e10
#define kdlsym_addr_sys_close  0x33e4d0
#define kdlsym_addr_sys_dup2  0x33c6d0
#define kdlsym_addr_sys_fstat  0x33ea50
#define kdlsym_addr_sys_getdents  0x213a70
#define kdlsym_addr_sys_kill  0x1ef150
#define kdlsym_addr_sys_listen  0x1a3050
#define kdlsym_addr_sys_lseek  0x210140
#define kdlsym_addr_sys_mkdir  0x213230
#define kdlsym_addr_sys_mlock  0xee1a0
#define kdlsym_addr_sys_mlockall  0xee250
#define kdlsym_addr_sys_mmap  0xed1c0
#define kdlsym_addr_sys_munmap  0xed8d0
#define kdlsym_addr_sys_nmount  0x193070
#define kdlsym_addr_sys_open  0x20e0f0
#define kdlsym_addr_sys_ptrace  0x44e2e0
#define kdlsym_addr_sys_read  0x25fda0
#define kdlsym_addr_sys_recvfrom  0x1a4a20
#define kdlsym_addr_sys_rmdir  0x2135b0
#define kdlsym_addr_sys_sendto  0x1a4300
#define kdlsym_addr_sys_setuid  0x267630
#define kdlsym_addr_sys_shutdown  0x1a4c70
#define kdlsym_addr_sys_socket  0x1a2410
#define kdlsym_addr_sys_stat  0x210720
#define kdlsym_addr_sys_unlink  0x20fb00
#define kdlsym_addr_sys_unmount  0x1949a0
#define kdlsym_addr_sys_wait4  0x42d0
#define kdlsym_addr_sys_write  0x2602b0
#define kdlsym_addr_trap_fatal  0x1eb900
#define kdlsym_addr_utilUSleep  0x67dc20
#define kdlsym_addr_vm_fault_disable_pagefaults  0x4311d0
#define kdlsym_addr_vm_fault_enable_pagefaults  0x431200
#define kdlsym_addr_vm_map_lookup_entry  0x38d6b0
#define kdlsym_addr_vmspace_acquire_ref  0x38cee0
#define kdlsym_addr_vmspace_alloc  0x38ca50
#define kdlsym_addr_vmspace_free  0x38cd10
#define kdlsym_addr_vn_fullpath  0x246a00
#define kdlsym_addr_vsnprintf  0xc5490
#define kdlsym_addr_wakeup  0x286370
#define kdlsym_addr_Xfast_syscall  0x1b4780

// PS4GDB
#define kdlsym_addr_bzero  0x472c60
#define kdlsym_addr_sys_getpid  0x28d830
#define kdlsym_addr_sys_sysctl  0x5f3e0

// Kernel Hooks
// #define xref_kdlsym_addr_printf_hook  0x48b740
#define kdlsym_addr_printf_hook  0x1a7ad78

// FakeSelf Hooks
// #define xref_kdlsym_addr_sceSblAuthMgrIsLoadable__sceSblACMgrGetPathId_hook  0x63a7c0
#define kdlsym_addr_sceSblAuthMgrIsLoadable__sceSblACMgrGetPathId_hook  0x63a7fc
// #define xref_kdlsym_addr_sceSblAuthMgrIsLoadable2_hook  0x63a7c0
#define kdlsym_addr_sceSblAuthMgrIsLoadable2_hook  0x63a94e
// #define xref_kdlsym_addr_sceSblAuthMgrSmLoadSelfBlock__sceSblServiceMailbox_hook  0x63fdc0
#define kdlsym_addr_sceSblAuthMgrSmLoadSelfBlock__sceSblServiceMailbox_hook  0x640818
// #define xref_kdlsym_addr_sceSblAuthMgrSmLoadSelfSegment__sceSblServiceMailbox_hook  0x63f950
#define kdlsym_addr_sceSblAuthMgrSmLoadSelfSegment__sceSblServiceMailbox_hook  0x63fbdd
// #define xref_kdlsym_addr_sceSblAuthMgrVerifyHeader_hookA  0x63abd0
#define kdlsym_addr_sceSblAuthMgrVerifyHeader_hookA  0x63b0e6
// #define xref_kdlsym_addr_sceSblAuthMgrVerifyHeader_hookB  0x63bc70
#define kdlsym_addr_sceSblAuthMgrVerifyHeader_hookB  0x63bdc9

// FakePkg Hooks
// #define xref_kdlsym_addr_sceSblKeymgrSetKeyStorage__sceSblDriverSendMsg_hook  0x624ca0
#define kdlsym_addr_sceSblKeymgrSetKeyStorage__sceSblDriverSendMsg_hook  0x624d45
// #define xref_kdlsym_addr_sceSblKeymgrInvalidateKey__sx_xlock_hook  0x6223a0
#define kdlsym_addr_sceSblKeymgrInvalidateKey__sx_xlock_hook  0x6223dd
// #define xref_kdlsym_addr_npdrm_decrypt_isolated_rif__sceSblKeymgrSmCallfunc_hook  0x64ac90
#define kdlsym_addr_npdrm_decrypt_isolated_rif__sceSblKeymgrSmCallfunc_hook  0x64ad10
// #define xref_kdlsym_addr_npdrm_decrypt_rif_new__sceSblKeymgrSmCallfunc_hook  0x64b950
#define kdlsym_addr_npdrm_decrypt_rif_new__sceSblKeymgrSmCallfunc_hook  0x64bade
// #define xref_kdlsym_addr_mountpfs__sceSblPfsSetKeys_hookA  0x68ca40
#define kdlsym_addr_mountpfs__sceSblPfsSetKeys_hookA  0x68e4c9
// #define xref_kdlsym_addr_mountpfs__sceSblPfsSetKeys_hookB  0x68ca40
#define kdlsym_addr_mountpfs__sceSblPfsSetKeys_hookB  0x68e6fa

// sceRegMgr
#define kdlsym_addr_sceRegMgrGetInt  0x4ed8a0
#define kdlsym_addr_sceRegMgrSetInt  0x4ec5d0
#define kdlsym_addr_sceRegMgrGetBin  0x4edfc0
#define kdlsym_addr_sceRegMgrSetBin  0x4edf10
#define kdlsym_addr_sceRegMgrGetStr  0x4ede40
// #define xref_kdlsym_addr_sceRegMgrSetStr  0x4f8ef0 // sys_regmgr_call
#define kdlsym_addr_sceRegMgrSetStr  0x4f9881

// SceShellCore patches - call sceKernelIsGenuineCEX
#define ssc_sceKernelIsGenuineCEX_patchA                   0x16b6a4
#define ssc_sceKernelIsGenuineCEX_patchB                   0x8594c4
#define ssc_sceKernelIsGenuineCEX_patchC                   0x8a8602
#define ssc_sceKernelIsGenuineCEX_patchD                   0xa080b4

// SceShellCore patches - call nidf_libSceDipsw
#define ssc_nidf_libSceDipsw_patchA                        0x16b6d2
#define ssc_nidf_libSceDipsw_patchB                        0x247e5c
#define ssc_nidf_libSceDipsw_patchC                        0x8594f2
#define ssc_nidf_libSceDipsw_patchD                        0xa080e2

#define ssc_enable_fakepkg_patch                           0x3d26bf

// SceShellCore patches - use free prefix instead fake
#define ssc_fake_to_free_patch                             0xfb08d9

// SceShellCore patches - enable remote pkg installer
#define ssc_enable_data_mount_patch                        0x31b320

// SceShellCore patches - enable VR without spoof
// #define ssc_enable_vr_patch                                0xDB0B80 // missing

// SceShellCore patches - enable official external HDD support (Support added in 4.50
// #define ssc_external_hdd_pkg_installer_patch               0x00A10A80
// #define ssc_external_hdd_version_patchA                    0x006180FD
// #define ssc_external_hdd_version_patchB                    0xDEADC0DE

// SceShellUI patches - debug patches
#define ssu_sceSblRcMgrIsAllowDebugMenuForSettings_patch   0x1ce50
#define ssu_sceSblRcMgrIsStoreMode_patch                   0x1d1b0

// SceShellUI - remote play related patching
// #define ssu_CreateUserForIDU_patch                         0xDEADC0DE
// #define ssu_remote_play_menu_patch                         0xDEADC0DE

// SceRemotePlay - enabler patches
// #define srp_enabler_patchA                                 0xDEADC0DE
// #define srp_enabler_patchB                                 0xDEADC0DE

#endif
