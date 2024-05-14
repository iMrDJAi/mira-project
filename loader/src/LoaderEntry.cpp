// This is an open source non-commercial project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++, C#, and Java: http://www.viva64.com

extern "C"
{
	#include <Utils/_Syscall.hpp>
};

#include <Utils/New.hpp>
#include <Utils/Kdlsym.hpp>
#include <Utils/Kernel.hpp>
#include <Utils/SysWrappers.cpp>
#include <Boot/Patches.hpp>
#include <Boot/InitParams.hpp>

#include <Utils/Dynlib.hpp>
#include <Utils/Logger.hpp>

#include <sys/elf64.h>
#include <sys/socket.h>
#include <sys/proc.h>
#include <sys/unistd.h>
#include <sys/proc.h>
#include <sys/kthread.h>
#include <sys/imgact.h>
#include <sys/filedesc.h>
#include <sys/malloc.h>
#include <sys/sysent.h>
#include <sys/sysproto.h>
#include <sys/time.h>
#include <vm/vm.h>
#include <vm/vm_page.h>
#include <vm/pmap.h>
#include <vm/vm_map.h>
#include <vm/vm_param.h>
#include <unistd.h>
#include <sys/fcntl.h>
#include <sys/mman.h>
#include <netinet/in.h>
#include <machine/stdarg.h>

#include <Boot/MiraLoader.hpp>

using namespace Mira::Utils;
using namespace MiraLoader;

#define ALLOC_3MB	0x300000
#define ALLOC_5MB	0x500000

uint8_t* gKernelBase = nullptr;

struct kexec_uap
{
	void* func;
	void* arg0;
};

int(*sceNetSocket)(const char *, int, int, int) = nullptr;
int(*sceNetSocketClose)(int) = nullptr;
int(*sceNetBind)(int, struct sockaddr *, int) = nullptr;
int(*sceNetListen)(int, int) = nullptr;
int(*sceNetAccept)(int, struct sockaddr *, unsigned int *) = nullptr;
int(*sceNetRecv)(int, void *, size_t, int) = nullptr;

int(*snprintf)(char *str, size_t size, const char *format, ...) = nullptr;

void miraloader_kernelInitialization(struct thread* td, struct kexec_uap* uap);

void sleep(struct thread * td, time_t time)
{
	// auto sv = (struct sysentvec*)kdlsym(self_orbis_sysvec);
	// struct sysent* sysents = sv->sv_table;
	// auto sys_nanosleep = (int(*)(struct thread*, struct timespec*, struct timespec*))sysents[SYS_NANOSLEEP].sy_call;

	// td->td_retval[0] = 0;

	gKernelBase = (uint8_t*)kernelRdmsr(0xC0000082) - kdlsym_addr_Xfast_syscall;
	auto kern_nanosleep = (int(*)(struct thread*, struct timespec*, struct timespec*))kdlsym(kern_nanosleep);

	struct timespec time_to_sleep;
	time_to_sleep.tv_sec = time;
	time_to_sleep.tv_nsec = 0;

	struct timespec time_remaining = { 0 };

	int retval;
	do {
		retval = kern_nanosleep(td, &time_to_sleep, &time_remaining);
	} while (retval == 4);

	// int error = sys_nanosleep(td, &time_to_sleep, nullptr);
	// if (error) return -error;

	// return td->td_retval[0];
}

// by OSM-Made
typedef struct {
  int type;
  int reqId;
  int priority;
  int msgId;
  int targetId;
  int userId;
  int unk1;
  int unk2;
  int appId;
  int errorNum;
  int unk3;
  unsigned char useIconImageUri;
  char message[1024];
  char iconUri[1024];
  char unk[1024];
} OrbisNotificationRequest;

void notify(struct thread* td, const char *fmt, ...)
{
  gKernelBase = (uint8_t*)kernelRdmsr(0xC0000082) - kdlsym_addr_Xfast_syscall;
	auto vsprintf = (void(*)(const char *format, ...))kdlsym(vsprintf);
	auto printf = (void(*)(const char *format, ...))kdlsym(printf);
	auto sceKernelSendNotificationRequest = (int(*)(int device, OrbisNotificationRequest* req, int size , int blocking))kdlsym(sceKernelSendNotificationRequest);

  OrbisNotificationRequest buf;

  va_list args;
  va_start(args, fmt);
  vsprintf(buf.message, fmt, args);
  va_end(args);
	printf(buf.message);

  buf.type = 0;
  buf.unk3 = 0;
  buf.useIconImageUri = 0;
  buf.targetId = -1;

  sceKernelSendNotificationRequest(0, &buf, sizeof(buf), 0);
	sleep(td, 10);
}

void mira_escape(struct thread* td, void* uap)
{
	gKernelBase = (uint8_t*)kernelRdmsr(0xC0000082) - kdlsym_addr_Xfast_syscall;
	auto printf = (void(*)(const char *format, ...))kdlsym(printf);

	printf("[+] mira_escape\n");

	struct ucred* cred = td->td_proc->p_ucred;
	struct filedesc* fd = td->td_proc->p_fd;

	cred->cr_uid = 0;
	cred->cr_ruid = 0;
	cred->cr_rgid = 0;
	cred->cr_groups[0] = 0;

	cred->cr_prison = *(struct prison**)kdlsym(prison0);
	fd->fd_rdir = fd->fd_jdir = *(struct vnode**)kdlsym(rootvnode);

	// set diag auth ID flags
	td->td_ucred->cr_sceAuthID = SceAuthenticationId_t::Decid;

	// make system credentials
	td->td_ucred->cr_sceCaps[0] = SceCapabilities_t::Max;
	td->td_ucred->cr_sceCaps[1] = SceCapabilities_t::Max;

	// Apply patches
	cpu_disable_wp();

	Mira::Boot::Patches::install_prePatches();

	cpu_enable_wp();

	notify(td, "applied patches!!!");
}

extern char _mira_elf_start, _mira_elf_end;
size_t g_MiraElfSize;

extern "C" void* mira_entry(void* args)
{
	struct thread* td = curthread; // get current kernel thread context

	// THIS NEEDS TO HAPPEN FIRST
	mira_escape(td, nullptr);

	auto printf = (void(*)(const char *format, ...))kdlsym(printf);
	vm_map_t map = (vm_map_t)(*(uint64_t *)(kdlsym(kernel_map)));
	auto kmem_alloc = (vm_offset_t(*)(vm_map_t map, vm_size_t size))kdlsym(kmem_alloc);
	auto kthread_exit = (void(*)(void))kdlsym(kthread_exit);
	auto kproc_create = (int(*)(void(*func)(void*), void* arg, struct proc** newpp, int flags, int pages, const char* fmt, ...))kdlsym(kproc_create);
	auto kmemset = (void(*)(void *s, int c, size_t n))kdlsym(memset);
	auto kmemcpy = (void* (*)(void *dst, const void *src, size_t len))kdlsym(memcpy);

	// We need to calculate the elf size on the fly, otherwise it's 0 for some odd reason
	g_MiraElfSize = (uint64_t)&_mira_elf_end - (uint64_t)&_mira_elf_start;
	notify(td, "&mira_elf_*: %p %p", &_mira_elf_start, &_mira_elf_end);
	notify(td, "calculated elf size: %lld", g_MiraElfSize); // 413000

	uint8_t* buffer = static_cast<uint8_t*>(MiraLoader::Loader::k_malloc(g_MiraElfSize));
	notify(td, "buffer allocated %p", buffer);

	kmemset(buffer, 0, g_MiraElfSize); // crashes here..
	notify(td, "buffer memset");

	kmemcpy(buffer, &_mira_elf_start, g_MiraElfSize);
	notify(td, "buffer memcpy");

	// Determine if we launch a elf or a payload
	if (buffer[0] == ELFMAG0 &&
		buffer[1] == ELFMAG1 &&
		buffer[2] == ELFMAG2 &&
		buffer[3] == ELFMAG3) // 0x7F 'ELF'
	{
		// Determine if we are launching kernel
		bool isLaunchingKernel = true;

		if (isLaunchingKernel)
		{
			Mira::Boot::InitParams initParams = { 0 };
			initParams.isElf = true;
			initParams.isRunning = false;
			initParams.payloadBase = buffer;
			initParams.payloadSize = g_MiraElfSize;
			initParams.process = nullptr;
			initParams.elfLoader = nullptr;
			initParams.entrypoint = nullptr;

			notify(td, "InitParams created");

			// initParams.osKernelTextBase = _g_osKernelTextBase;
			// initParams.osKernelTextSize = _g_osKernelTextSize;
			// initParams.osKernelDataBase = _g_osKernelDataBase;
			// initParams.osKernelDataSize = _g_osKernelDataSize;
			// initParams.osKernelPrison0 = _g_osKernelPrison0;
			// initParams.osKernelRootvnode = _g_osKernelRootvnode;

			// Allocate a new logger for the MiraLoader
			auto s_Logger = Mira::Utils::Logger::GetInstance();
			if (!s_Logger)
			{
				// WriteLog(LL_Debug,"[-] could not allocate logger");
				kthread_exit();
				return nullptr;
			}
			printf("logger created\n");
			notify(td, "logger created");

			// Create launch parameters, this is floating in "free kernel space" so the other process should
			// be able to grab and use the pointer directly
			Mira::Boot::InitParams*  kernelInitParams = (Mira::Boot::InitParams*)kmem_alloc(map, sizeof(Mira::Boot::InitParams));
			if (!kernelInitParams)
			{
				// WriteLog(LL_Error, "could not allocate initialization parameters.\n");
				return nullptr;
			}
			notify(td, "kmem_alloc InitParams");
			kmemset(kernelInitParams, 0, sizeof(*kernelInitParams));
			notify(td, "memset InitParams");

			// Copy over our initparams from stack to allocated
			kmemcpy(kernelInitParams, &initParams, sizeof(initParams));
			notify(td, "memcpy InitParams");

			// // WriteLog(LL_Debug, "prison0: (%p), rootvnode: (%p).", kernelInitParams->osKernelPrison0, kernelInitParams->osKernelRootvnode);

			// Determine if we launch a elf or a payload
			// uint32_t magic = *(uint32_t*)kernelInitParams->payloadBase;
			// if (magic != 0x464C457F)
			// {
			// 	// WriteLog(LL_Debug,"invalid elf header.\n");
			// 	return nullptr;
			// }
			// // WriteLog(LL_Debug, "elf header: %X\n", magic);

			// Launch ELF
			MiraLoader::Loader* loader = new MiraLoader::Loader(kernelInitParams->payloadBase, kernelInitParams->payloadSize, ElfLoaderType_t::KernelProc);
			if (!loader)
			{
				notify(td, "!loader");
				// WriteLog(LL_Debug,"could not allocate loader\n");
				return nullptr;
			}
			notify(td, "loader created");

			// Update the loader
			kernelInitParams->elfLoader = loader;
			kernelInitParams->entrypoint = reinterpret_cast<void(*)(void*)>(loader->GetEntrypoint());
			notify(td, "loader GetEntrypoint");
			// kernelInitParams->kernelElfRelocatedBase = static_cast<uint8_t*>(loader->GetAllocatedMap());
			// kernelInitParams->kernelElfRelocatedSize = loader->GetAllocatedMapSize();

			// Update the initial running state
			kernelInitParams->isRunning = false;

			auto s_EntryPoint = kernelInitParams->entrypoint;
			if (s_EntryPoint != nullptr)
			{
				notify(td, "Entrypoint");
				printf("[+]entrypoint: %p", s_EntryPoint);
				return nullptr;
				(void)kproc_create(s_EntryPoint, kernelInitParams, &kernelInitParams->process, 0, 200, "miraldr2"); // 8MiB stack
			}
			else
			{
				notify(td, "[-]could not get entry point.");
				printf("[-]could not get entry point.\n");
			}	

		}
	}

	return nullptr;
}

void miraloader_kernelInitialization(struct thread* td, struct kexec_uap* uap)
{
	// If we do not have a valid parameter passed, kick back
	if (!uap || !uap->arg0)
		return;

	Mira::Boot::InitParams* userInitParams = reinterpret_cast<Mira::Boot::InitParams*>(uap->arg0);

	// Thread should already be escaped from earlier

	// Fill the kernel base address
	gKernelBase = (uint8_t*)kernelRdmsr(0xC0000082) - kdlsym_addr_Xfast_syscall;
	//void(*critical_enter)(void) = kdlsym(critical_enter);
	//void(*crtical_exit)(void) = kdlsym(critical_exit);
	auto kmem_alloc = (vm_offset_t(*)(vm_map_t map, vm_size_t size))kdlsym(kmem_alloc);
	auto kmem_free = (void(*)(void* map, void* addr, size_t size))kdlsym(kmem_free);
	auto printf = (void(*)(const char *format, ...))kdlsym(printf);
	auto kproc_create = (int(*)(void(*func)(void*), void* arg, struct proc** newpp, int flags, int pages, const char* fmt, ...))kdlsym(kproc_create);
	vm_map_t map = (vm_map_t)(*(uint64_t *)(kdlsym(kernel_map)));
	auto kmemset = (void(*)(void *s, int c, size_t n))kdlsym(memset);
	auto copyin = (int(*)(const void* uaddr, void* kaddr, size_t len))kdlsym(copyin);
	auto kthread_exit = (void(*)(void))kdlsym(kthread_exit);

	// Allocate a new logger for the MiraLoader
	auto s_Logger = Mira::Utils::Logger::GetInstance();
	if (!s_Logger)
	{
		printf("[-] could not allocate logger\n");
		kthread_exit();
		return;
	}
	printf("logger created\n");

	// Create launch parameters, this is floating in "free kernel space" so the other process should
	// be able to grab and use the pointer directly
	Mira::Boot::InitParams* initParams = (Mira::Boot::InitParams*)kmem_alloc(map, sizeof(Mira::Boot::InitParams));
	if (!initParams)
	{
		// WriteLog(LL_Error, "could not allocate initialization parameters.\n");
		return;
	}
	kmemset(initParams, 0, sizeof(*initParams));

	// Copyin our new arguments from userland
	int copyResult = copyin(userInitParams, initParams, sizeof(*initParams));
	if (copyResult != 0)
	{
		kmem_free(map, initParams, sizeof(*initParams));
		// WriteLog(LL_Error, "could not copyin initalization parameters (%d)\n", copyResult);
		return;
	}

	// initparams are read from the uap in this syscall func
	uint64_t payloadSize = initParams->payloadSize;
	uint8_t *payloadBase = initParams->payloadBase;

	// Allocate some memory
	uint8_t* kernelElf = (uint8_t*)kmem_alloc(map, payloadSize);
	if (!kernelElf)
	{
		// Free the previously allocated initialization parameters
		kmem_free(map, initParams, sizeof(*initParams));
		// WriteLog(LL_Error, "could not allocate kernel payload.\n");
		return;
	}
	kmemset(kernelElf, 0, payloadSize);
	// WriteLog(LL_Debug, "payloadBase: %p payloadSize: %llx kernelElf: %p\n", payloadBase, payloadSize, kernelElf);

	// Copy the ELF data from userland
	copyResult = copyin((const void*)payloadBase, kernelElf, payloadSize);
	if (copyResult != 0)
	{
		// Intentionally blow the fuck up
		// WriteLog(LL_Error, "fuck, this is bad...\n");
		for (;;)
			__asm__("nop");
	}

	// WriteLog(LL_Debug, "finished allocating and copying ELF from userland");

	// Determine if we launch a elf or a payload
	uint32_t magic = *(uint32_t*)kernelElf;
	if (magic != 0x464C457F)
	{
		printf("invalid elf header.\n");
		return;
	}
	// WriteLog(LL_Debug, "elf header: %X\n", magic);

	// Launch ELF
	MiraLoader::Loader* loader = new MiraLoader::Loader(kernelElf, payloadSize, ElfLoaderType_t::KernelProc); //malloc(sizeof(ElfLoader_t), M_LINKER, M_WAITOK);
	if (!loader)
	{
		printf("could not allocate loader\n");
		return;
	}

	// Update the loader
	initParams->elfLoader = loader;
	initParams->entrypoint = reinterpret_cast<void(*)(void*)>(loader->GetEntrypoint());
	initParams->allocatedBase = reinterpret_cast<uint64_t>(loader->GetAllocatedMap());
	initParams->payloadBase = reinterpret_cast<uint8_t*>(kernelElf);
	initParams->payloadSize = payloadSize;

	// Update the initial running state
	initParams->isRunning = false;

	auto s_EntryPoint = initParams->entrypoint;
	if (s_EntryPoint != nullptr)
	{
		printf("[+]entrypoint: %p", s_EntryPoint);
		(void)kproc_create(s_EntryPoint, initParams, &initParams->process, 0, 200, "miraldr2"); // 8MiB stack
	}
	else
	{
		printf("[-]could not get entry point.\n");
	}
}
