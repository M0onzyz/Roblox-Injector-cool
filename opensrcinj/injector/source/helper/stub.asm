.code
EXTERN idx_rd:DWORD
EXTERN idx_wr:DWORD
EXTERN idx_pr:DWORD
EXTERN idx_qs:DWORD
EXTERN idx_mv:DWORD
EXTERN idx_cs:DWORD
EXTERN sys_rd:QWORD
EXTERN sys_wr:QWORD
EXTERN sys_pr:QWORD
EXTERN sys_qs:QWORD
EXTERN sys_mv:QWORD
EXTERN sys_cs:QWORD
PUBLIC NtReadVirtualMemory
NtReadVirtualMemory PROC
	mov r10, rcx
	mov eax, [idx_rd]
	jmp qword ptr [sys_rd]
NtReadVirtualMemory ENDP
PUBLIC NtWriteVirtualMemory
NtWriteVirtualMemory PROC
	mov r10, rcx
	mov eax, [idx_wr]
	jmp qword ptr [sys_wr]
NtWriteVirtualMemory ENDP
PUBLIC NtProtectVirtualMemory
NtProtectVirtualMemory PROC
	mov r10, rcx
	mov eax, [idx_pr]
	jmp qword ptr [sys_pr]
NtProtectVirtualMemory ENDP
PUBLIC NtQuerySystemInformation
NtQuerySystemInformation PROC
	mov r10, rcx
	mov eax, [idx_qs]
	jmp qword ptr [sys_qs]
NtQuerySystemInformation ENDP
PUBLIC NtMapViewOfSection
NtMapViewOfSection PROC
	mov r10, rcx
	mov eax, [idx_mv]
	jmp qword ptr [sys_mv]
NtMapViewOfSection ENDP
PUBLIC NtCreateSection
NtCreateSection PROC
	mov r10, rcx
	mov eax, [idx_cs]
	jmp qword ptr [sys_cs]
NtCreateSection ENDP
END
