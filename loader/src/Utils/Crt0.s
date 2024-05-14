.intel_syntax noprefix
.text

.global _start, _mira_elf_start, _mira_elf_end

.org 0
_start:
	jmp		mira_entry

_mira_elf_start:
  .incbin "Mira_Orbis_MIRA_PLATFORM_ORBIS_BSD_1001.elf"
_mira_elf_end:
