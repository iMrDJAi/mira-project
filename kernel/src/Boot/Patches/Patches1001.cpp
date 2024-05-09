// This is an open source non-commercial project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++, C#, and Java:	 http://www.viva64.com

#include <Boot/Patches.hpp>

/*
	Please, please, please!
	Keep patches consistent with the used patch style for readability.
*/
void Mira::Boot::Patches::install_prerunPatches_1001()
{
#if MIRA_PLATFORM==MIRA_PLATFORM_ORBIS_BSD_1001
	// You must assign the kernel base pointer before anything is done
	if (!gKernelBase)
		return;

	// Use "kmem" for all patches
	uint8_t *kmem;

	// Enable UART
	kmem = (uint8_t *)&gKernelBase[0x1a78a78]; //
	kmem[0] = 0x00;
	// kmem[1] = 0x00; // Why?
	// kmem[2] = 0x00;
	// kmem[3] = 0x00;

	// Patch sys_dynlib_dlsym: Allow from anywhere
	kmem = (uint8_t *)&gKernelBase[0x19025f]; //
	kmem[0] = 0xEB;
	kmem[1] = 0x4C;

	kmem = (uint8_t *)&gKernelBase[0x1bea40]; //
	kmem[0] = 0x31;
	kmem[1] = 0xC0;
	kmem[2] = 0xC3;

	// Patch sys_mmap: Allow RWX (read-write-execute) mapping
	kmem = (uint8_t *)&gKernelBase[0xed59a]; //
	kmem[0] = 0x37;
	kmem[3] = 0x37;

	// Patch setuid: Don't run kernel exploit more than once/privilege escalation
	// kmem = (uint8_t *)&gKernelBase[0x000019FF]; // Probably safe to do (or not? ;p)
	// kmem[0] = 0xB8;
	// kmem[1] = 0x00;
	// kmem[2] = 0x00;
	// kmem[3] = 0x00;
	// kmem[4] = 0x00;

	// Enable RWX (kmem_alloc) mapping
	kmem = (uint8_t *)&gKernelBase[0x33B10C]; //
	kmem[0] = 0x07;

	kmem = (uint8_t *)&gKernelBase[0x33B114]; //
	kmem[0] = 0x07;

	// Patch copyin/copyout: Allow userland + kernel addresses in both params
	// copyin
	kmem = (uint8_t *)&gKernelBase[0x472f67]; //
	kmem[0] = 0x90;
	kmem[1] = 0x90;

	kmem = (uint8_t *)&gKernelBase[0x472f73]; //
	kmem[0] = 0x90;
	kmem[1] = 0x90;
	kmem[2] = 0x90;

	// copyout
	kmem = (uint8_t *)&gKernelBase[0x472e72]; //
	kmem[0] = 0x90;
	kmem[1] = 0x90;

	kmem = (uint8_t *)&gKernelBase[0x472e7e]; //
	kmem[0] = 0x90;
	kmem[1] = 0x90;
	kmem[2] = 0x90;

	// Patch copyinstr
	kmem = (uint8_t *)&gKernelBase[0x473413]; //
	kmem[0] = 0x90;
	kmem[1] = 0x90;

	kmem = (uint8_t *)&gKernelBase[0x47341f]; //
	kmem[0] = 0x90;
	kmem[1] = 0x90;
	kmem[2] = 0x90;

	kmem = (uint8_t *)&gKernelBase[0x473450]; //
	kmem[0] = 0x90;
	kmem[1] = 0x90;

	// Patch memcpy stack
	kmem = (uint8_t *)&gKernelBase[0x472d2d]; //
	kmem[0] = 0xEB;

	// ptrace patches
	/*kmem = (uint8_t *)&gKernelBase[0x0010F879]; // Why?
	kmem[0] = 0xEB;*/
	kmem = (uint8_t*)&gKernelBase[0x44e63d]; //
	kmem[0] = 0x90;
	kmem[1] = 0x90;
	kmem[2] = 0x90;
	kmem[3] = 0x90;
	kmem[4] = 0x90;
	kmem[5] = 0x90;

	// second ptrace patch
	// via DeathRGH
	kmem = (uint8_t *)&gKernelBase[0x44EB11]; //
	kmem[0] = 0xE9;
	kmem[1] = 0x7C;
	kmem[2] = 0x02;
	kmem[3] = 0x00;
	kmem[4] = 0x00;

	// setlogin patch (for autolaunch check)
	kmem = (uint8_t *)&gKernelBase[0x26a40c]; //
	kmem[0] = 0x48;
	kmem[1] = 0x31;
	kmem[2] = 0xC0;
	kmem[3] = 0x90;
	kmem[4] = 0x90;

	// Patch to remove vm_fault: fault on nofault entry, addr %llx
	kmem = (uint8_t *)&gKernelBase[0x42cec6]; //
	kmem[0] = 0x90;
	kmem[1] = 0x90;
	kmem[2] = 0x90;
	kmem[3] = 0x90;
	kmem[4] = 0x90;
	kmem[5] = 0x90;

	// Patch mprotect: Allow RWX (mprotect) mapping
	kmem = (uint8_t *)&gKernelBase[0x39207B]; //
	kmem[0] = 0x90;
	kmem[1] = 0x90;
	kmem[2] = 0x90;
	kmem[3] = 0x90;
	kmem[4] = 0x90;
	kmem[5] = 0x90;

	// flatz disable pfs signature check
	kmem = (uint8_t *)&gKernelBase[0x6926e0]; //
	kmem[0] = 0x31;
	kmem[1] = 0xC0;
	kmem[2] = 0xC3;

	// flatz enable debug RIFs
	kmem = (uint8_t *)&gKernelBase[0x64a510]; //
	kmem[0] = 0xB0;
	kmem[1] = 0x01;
	kmem[2] = 0xC3;

	kmem = (uint8_t *)&gKernelBase[0x64a540];	//
	kmem[0] = 0xB0;
	kmem[1] = 0x01;
	kmem[2] = 0xC3;

	// Enable *all* debugging logs (in vprintf)
	// Patch by: SiSTRo
	kmem = (uint8_t *)&gKernelBase[0xc51d7]; //
	kmem[0] = 0xEB;
	kmem[1] = 0x3B;

	// flatz allow mangled symbol in dynlib_do_dlsym
	kmem = (uint8_t *)&gKernelBase[0x1bc1a7]; //
	kmem[0] = 0x90;
	kmem[1] = 0x90;
	kmem[2] = 0x90;
	kmem[3] = 0x90;
	kmem[4] = 0x90;
	kmem[5] = 0x90;

	// Enable mount for unprivileged user
	kmem = (uint8_t *)&gKernelBase[0x1934f7]; //
	kmem[0] = 0x90;
	kmem[1] = 0x90;
	kmem[2] = 0x90;
	kmem[3] = 0x90;
	kmem[4] = 0x90;
	kmem[5] = 0x90;

	// patch suword_lwpid
	// has a check to see if child_tid/parent_tid is in kernel memory, and it in so patch it
	// Patch by: JOGolden
	kmem = (uint8_t *)&gKernelBase[0x473232]; // sus
	kmem[0] = 0x90;
	kmem[1] = 0x90;

	kmem = (uint8_t *)&gKernelBase[0x473241]; // sus
	kmem[0] = 0x90;
	kmem[1] = 0x90;

	// Patch debug setting errors
	kmem = (uint8_t *)&gKernelBase[0x4ec908]; //
	kmem[0] = 0x00;
	kmem[1] = 0x00;
	kmem[2] = 0x00;
	kmem[3] = 0x00;

	kmem = (uint8_t *)&gKernelBase[0x4ed9cc]; // sus
	kmem[0] = 0x00;
	kmem[1] = 0x00;
	kmem[2] = 0x00;
	kmem[3] = 0x00;

#endif
}
