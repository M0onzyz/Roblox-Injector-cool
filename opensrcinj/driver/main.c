 //ALL CREDITS GO FOR X4V I DIDN'T CODE THIS DRIVER, ITS ALSO NOT USED BY THE INJECTOR, YOU CAN MAKE THIS USE THE DRIVER BY DOING SOME MODIFICATIONS

#include <ntifs.h>
#include <ntddk.h>
#include "../../../shared/ioctls.h"

typedef struct _VAD_OFFSETS {
    ULONG VadRoot;
    ULONG VadHint;
    ULONG VadCount;
    ULONG AddrLock;
    ULONG StartVpn;
    ULONG EndVpn;
    ULONG StartVpnHigh;
    ULONG EndVpnHigh;
} VAD_OFFSETS;

typedef struct _HIDDEN_VAD {
    PRTL_BALANCED_NODE Node;
    PEPROCESS Process;
    HANDLE Pid;
    ULONG_PTR VpnStart;
    BOOLEAN InUse;
} HIDDEN_VAD;

#define MAX_HIDDEN 32
#define DEPTH_LIMIT 256
#define MAX_PID 0x100000

static VAD_OFFSETS g_Off = { 0 };
static BOOLEAN g_VadReady = FALSE;
static HIDDEN_VAD g_Hidden[MAX_HIDDEN] = { 0 };
static KSPIN_LOCK g_HiddenLock;

NTSYSAPI NTSTATUS NTAPI ZwProtectVirtualMemory(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);
NTSYSAPI NTSTATUS NTAPI ZwFreeVirtualMemory(HANDLE, PVOID*, PSIZE_T, ULONG);
NTSTATUS MmCopyVirtualMemory(PEPROCESS, PVOID, PEPROCESS, PVOID, SIZE_T, KPROCESSOR_MODE, PSIZE_T);

NTKERNELAPI VOID ExfAcquirePushLockExclusive(PEX_PUSH_LOCK PushLock);
NTKERNELAPI VOID ExfReleasePushLockExclusive(PEX_PUSH_LOCK PushLock);

NTSYSAPI VOID NTAPI RtlAvlRemoveNode(PRTL_AVL_TABLE Tree, PRTL_BALANCED_NODE Node);
NTSYSAPI BOOLEAN NTAPI RtlAvlInsertNodeEx(PRTL_AVL_TABLE Tree, PRTL_BALANCED_NODE Parent, BOOLEAN Right, PRTL_BALANCED_NODE Node);

NTKERNELAPI NTSTATUS IoCreateDriver(PUNICODE_STRING n, PDRIVER_INITIALIZE i);

static ULONG_PTR VadStart(PRTL_BALANCED_NODE Node) {
    ULONG lo = *(ULONG*)((PUCHAR)Node + g_Off.StartVpn);
    UCHAR hi = *(UCHAR*)((PUCHAR)Node + g_Off.StartVpnHigh);
    return ((ULONG_PTR)hi << 32) | lo;
}

static ULONG_PTR VadEnd(PRTL_BALANCED_NODE Node) {
    ULONG lo = *(ULONG*)((PUCHAR)Node + g_Off.EndVpn);
    UCHAR hi = *(UCHAR*)((PUCHAR)Node + g_Off.EndVpnHigh);
    return ((ULONG_PTR)hi << 32) | lo;
}

static POBJECT_TYPE* ResolvePsProcessType() {
    UNICODE_STRING name = RTL_CONSTANT_STRING(L"PsProcessType");
    return (POBJECT_TYPE*)MmGetSystemRoutineAddress(&name);
}

static NTSTATUS OpenProcessHandle(PEPROCESS Process, PHANDLE Out) {
    POBJECT_TYPE* pType = ResolvePsProcessType();
    if (!pType) return STATUS_NOT_SUPPORTED;
    return ObOpenObjectByPointer(Process, OBJ_KERNEL_HANDLE, NULL, PROCESS_ALL_ACCESS, *pType, KernelMode, Out);
}

static PRTL_BALANCED_NODE FindVadNode(PEPROCESS Process, ULONG_PTR Address) {
    ULONG_PTR vpn = Address >> PAGE_SHIFT;
    PRTL_BALANCED_NODE node = *(PRTL_BALANCED_NODE*)((PUCHAR)Process + g_Off.VadRoot);
    ULONG depth = 0;
    while (node && depth < DEPTH_LIMIT) {
        if (!MmIsAddressValid(node) || !MmIsAddressValid((PUCHAR)node + g_Off.EndVpnHigh)) return NULL;
        ULONG_PTR s = VadStart(node);
        ULONG_PTR e = VadEnd(node);
        if (vpn >= s && vpn <= e) return node;
        node = (vpn < s) ? node->Left : node->Right;
        depth++;
    }
    return NULL;
}

static BOOLEAN ReinsertVadNode(PEPROCESS Process, HIDDEN_VAD* Entry) {
    PUCHAR proc = (PUCHAR)Process;
    PEX_PUSH_LOCK lock = (PEX_PUSH_LOCK)(proc + g_Off.AddrLock);
    PVOID vadTree = (PVOID)(proc + g_Off.VadRoot);
    if (!MmIsAddressValid(lock) || !MmIsAddressValid(vadTree)) return FALSE;
    PRTL_BALANCED_NODE node = Entry->Node;
    ULONG_PTR vpnStart = Entry->VpnStart;
    KeEnterCriticalRegion();
    ExfAcquirePushLockExclusive(lock);
    BOOLEAN success = FALSE;
    __try {
        PRTL_BALANCED_NODE parent = NULL;
        PRTL_BALANCED_NODE curr = *(PRTL_BALANCED_NODE*)vadTree;
        BOOLEAN right = FALSE;
        ULONG depth = 0;
        while (curr && depth < DEPTH_LIMIT) {
            if (!MmIsAddressValid(curr)) break;
            parent = curr;
            if (vpnStart < VadStart(curr)) { right = FALSE; curr = curr->Left; }
            else { right = TRUE; curr = curr->Right; }
            depth++;
        }
        node->Left = NULL; node->Right = NULL; node->ParentValue &= 3;
        RtlAvlInsertNodeEx((PRTL_AVL_TABLE)vadTree, parent, right, node);
        PRTL_BALANCED_NODE* hintPtr = (PRTL_BALANCED_NODE*)(proc + g_Off.VadHint);
        if (MmIsAddressValid(hintPtr)) *hintPtr = node;
        PULONGLONG countPtr = (PULONGLONG)(proc + g_Off.VadCount);
        if (MmIsAddressValid(countPtr)) InterlockedIncrement64((volatile LONGLONG*)countPtr);
        success = TRUE;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) { success = FALSE; }
    ExfReleasePushLockExclusive(lock);
    KeLeaveCriticalRegion();
    return success;
}

static VOID RestoreAllForProcess(HANDLE ProcessId) {
    HIDDEN_VAD localCopy[MAX_HIDDEN];
    ULONG count = 0;
    KIRQL irql;
    KeAcquireSpinLock(&g_HiddenLock, &irql);
    for (int i = 0; i < MAX_HIDDEN; i++) {
        if (g_Hidden[i].InUse && g_Hidden[i].Pid == ProcessId) {
            localCopy[count++] = g_Hidden[i];
            g_Hidden[i].InUse = FALSE;
        }
    }
    KeReleaseSpinLock(&g_HiddenLock, irql);
    for (ULONG i = 0; i < count; i++) {
        ReinsertVadNode(localCopy[i].Process, &localCopy[i]);
        ObfDereferenceObject(localCopy[i].Process);
    }
}

static VOID ProcessNotify(HANDLE ParentId, HANDLE ProcessId, BOOLEAN Create) {
    UNREFERENCED_PARAMETER(ParentId);
    if (!Create) RestoreAllForProcess(ProcessId);
}

static BOOLEAN Resolve() {
    RTL_OSVERSIONINFOW v = { 0 };
    v.dwOSVersionInfoSize = sizeof(v);
    if (!NT_SUCCESS(RtlGetVersion(&v))) return FALSE;
    g_Off.StartVpn = 0x18; g_Off.EndVpn = 0x1C; g_Off.StartVpnHigh = 0x20; g_Off.EndVpnHigh = 0x21;
    if (v.dwBuildNumber >= 26100) {
        g_Off.VadRoot = 0x558; g_Off.VadHint = 0x560; g_Off.VadCount = 0x568; g_Off.AddrLock = 0x258;
    }
    else {
        g_Off.VadRoot = 0x7D8; g_Off.VadHint = 0x7E0; g_Off.VadCount = 0x7E8; g_Off.AddrLock = 0x288;
    }
    return TRUE;
}

static NTSTATUS AcquireProcess(HANDLE Pid, PEPROCESS* Out) {
    *Out = NULL;
    if (!Pid || (ULONG_PTR)Pid > MAX_PID) return STATUS_INVALID_PARAMETER;
    NTSTATUS status = PsLookupProcessByProcessId(Pid, Out);
    if (!NT_SUCCESS(status)) return status;
    if (PsGetProcessExitStatus(*Out) != STATUS_PENDING) { ObfDereferenceObject(*Out); *Out = NULL; return STATUS_PROCESS_IS_TERMINATING; }
    return STATUS_SUCCESS;
}

static NTSTATUS ReadMem(PREAD_MEMORY_REQ req) {
    if (req->Size == 0) return STATUS_SUCCESS;
    if (req->Size > 0x800000) return STATUS_INVALID_PARAMETER;

    PEPROCESS proc; NTSTATUS status = AcquireProcess(req->TargetPid, &proc);
    if (!NT_SUCCESS(status)) return status;

    PVOID buf = NULL;
    UCHAR stackBuf[1024];
    if (req->Size <= sizeof(stackBuf)) {
        buf = stackBuf;
    }
    else {
        buf = ExAllocatePool2(POOL_FLAG_NON_PAGED, req->Size, 'rbxD');
    }

    if (!buf) { ObfDereferenceObject(proc); return STATUS_INSUFFICIENT_RESOURCES; }

    SIZE_T cop = 0;
    status = MmCopyVirtualMemory(proc, req->RemoteBase, PsGetCurrentProcess(), buf, req->Size, KernelMode, &cop);
    if (NT_SUCCESS(status)) {
        __try { ProbeForWrite(req->Buffer, req->Size, 1); RtlCopyMemory(req->Buffer, buf, req->Size); }
        __except (EXCEPTION_EXECUTE_HANDLER) { status = GetExceptionCode(); }
    }

    if (buf != stackBuf) ExFreePoolWithTag(buf, 'rbxD');
    ObfDereferenceObject(proc); return status;
}

static NTSTATUS WriteMem(PWRITE_MEMORY_REQ req) {
    if (req->Size == 0) return STATUS_SUCCESS;
    if (req->Size > 0x800000) return STATUS_INVALID_PARAMETER;

    PEPROCESS proc; NTSTATUS status = AcquireProcess(req->TargetPid, &proc);
    if (!NT_SUCCESS(status)) return status;

    PVOID buf = NULL;
    UCHAR stackBuf[1024];
    if (req->Size <= sizeof(stackBuf)) {
        buf = stackBuf;
    }
    else {
        buf = ExAllocatePool2(POOL_FLAG_NON_PAGED, req->Size, 'rbxD');
    }

    if (!buf) { ObfDereferenceObject(proc); return STATUS_INSUFFICIENT_RESOURCES; }

    __try { ProbeForRead(req->Buffer, req->Size, 1); RtlCopyMemory(buf, req->Buffer, req->Size); }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        if (buf != stackBuf) ExFreePoolWithTag(buf, 'rbxD');
        ObfDereferenceObject(proc); return GetExceptionCode();
    }

    SIZE_T cop = 0;
    status = MmCopyVirtualMemory(PsGetCurrentProcess(), buf, proc, req->RemoteBase, req->Size, KernelMode, &cop);

    if (buf != stackBuf) ExFreePoolWithTag(buf, 'rbxD');
    ObfDereferenceObject(proc); return status;
}

static NTSTATUS ProtMem(PPROTECT_MEMORY_REQ req) {
    PEPROCESS proc; NTSTATUS status = AcquireProcess(req->TargetPid, &proc);
    if (!NT_SUCCESS(status)) return status;
    HANDLE h; status = OpenProcessHandle(proc, &h);
    if (!NT_SUCCESS(status)) { ObfDereferenceObject(proc); return status; }
    PVOID base = req->RemoteBase; SIZE_T sz = req->Size; ULONG old = 0;
    status = ZwProtectVirtualMemory(h, &base, &sz, req->NewProtect, &old);
    if (NT_SUCCESS(status)) req->OldProtect = old;
    ZwClose(h); ObfDereferenceObject(proc); return status;
}

static NTSTATUS AllocMem(PALLOCATE_MEMORY_REQ req) {
    PEPROCESS proc; NTSTATUS status = AcquireProcess(req->TargetPid, &proc);
    if (!NT_SUCCESS(status)) return status;
    HANDLE h; status = OpenProcessHandle(proc, &h);
    if (!NT_SUCCESS(status)) { ObfDereferenceObject(proc); return status; }
    PVOID base = NULL; SIZE_T sz = req->Size;
    status = ZwAllocateVirtualMemory(h, &base, 0, &sz, MEM_COMMIT | MEM_RESERVE, req->Protect);
    if (NT_SUCCESS(status)) { req->RemoteBase = base; req->Size = sz; }
    ZwClose(h); ObfDereferenceObject(proc); return status;
}

static NTSTATUS FreeMem(PFREE_MEMORY_REQ req) {
    PEPROCESS proc; NTSTATUS status = AcquireProcess(req->TargetPid, &proc);
    if (!NT_SUCCESS(status)) return status;
    HANDLE h; status = OpenProcessHandle(proc, &h);
    if (!NT_SUCCESS(status)) { ObfDereferenceObject(proc); return status; }
    PVOID base = req->RemoteBase; SIZE_T sz = 0;
    status = ZwFreeVirtualMemory(h, &base, &sz, MEM_RELEASE);
    ZwClose(h); ObfDereferenceObject(proc); return status;
}

static NTSTATUS UnlinkVad(PUNLINK_VAD_REQ req) {
    if (!g_VadReady) return STATUS_NOT_SUPPORTED;
    PEPROCESS proc; NTSTATUS status = AcquireProcess(req->TargetPid, &proc);
    if (!NT_SUCCESS(status)) return status;
    ObfReferenceObject(proc);
    PUCHAR p = (PUCHAR)proc;
    PEX_PUSH_LOCK lock = (PEX_PUSH_LOCK)(p + g_Off.AddrLock);
    PVOID tree = (PVOID)(p + g_Off.VadRoot);
    if (!MmIsAddressValid(lock) || !MmIsAddressValid(tree)) { ObfDereferenceObject(proc); ObfDereferenceObject(proc); return STATUS_INVALID_ADDRESS; }
    KeEnterCriticalRegion(); ExfAcquirePushLockExclusive(lock);
    __try {
        PRTL_BALANCED_NODE node = FindVadNode(proc, (ULONG_PTR)req->RemoteBase);
        if (!node) { status = STATUS_NOT_FOUND; __leave; }
        ULONG_PTR vpnStart = VadStart(node);
        RtlAvlRemoveNode((PRTL_AVL_TABLE)tree, node);
        PRTL_BALANCED_NODE* hint = (PRTL_BALANCED_NODE*)(p + g_Off.VadHint);
        if (MmIsAddressValid(hint) && *hint == node) *hint = *(PRTL_BALANCED_NODE*)tree;
        PULONGLONG count = (PULONGLONG)(p + g_Off.VadCount);
        if (MmIsAddressValid(count) && *count > 0) InterlockedDecrement64((volatile LONGLONG*)count);
        KIRQL irql; KeAcquireSpinLock(&g_HiddenLock, &irql);
        BOOLEAN saved = FALSE;
        for (int i = 0; i < MAX_HIDDEN; i++) {
            if (!g_Hidden[i].InUse) {
                g_Hidden[i].Node = node; g_Hidden[i].Process = proc;
                g_Hidden[i].Pid = req->TargetPid; g_Hidden[i].VpnStart = vpnStart;
                g_Hidden[i].InUse = TRUE; saved = TRUE; break;
            }
        }
        KeReleaseSpinLock(&g_HiddenLock, irql);
        status = saved ? STATUS_SUCCESS : STATUS_INSUFFICIENT_RESOURCES;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) { status = GetExceptionCode(); }
    ExfReleasePushLockExclusive(lock); KeLeaveCriticalRegion();
    if (!NT_SUCCESS(status)) ObfDereferenceObject(proc);
    ObfDereferenceObject(proc); return status;
}

PDEVICE_OBJECT g_DevObj = NULL;
UNICODE_STRING g_Name, g_Sym;
WCHAR g_BufD[64], g_BufV[64];

void Unload(PDRIVER_OBJECT d) {
    UNREFERENCED_PARAMETER(d);
    PsSetCreateProcessNotifyRoutine(ProcessNotify, TRUE);
    HIDDEN_VAD copy[MAX_HIDDEN]; ULONG count = 0; KIRQL irql;
    KeAcquireSpinLock(&g_HiddenLock, &irql);
    for (int i = 0; i < MAX_HIDDEN; i++) { if (g_Hidden[i].InUse) { copy[count++] = g_Hidden[i]; g_Hidden[i].InUse = FALSE; } }
    KeReleaseSpinLock(&g_HiddenLock, irql);
    for (ULONG i = 0; i < count; i++) {
        if (PsGetProcessExitStatus(copy[i].Process) == STATUS_PENDING) ReinsertVadNode(copy[i].Process, &copy[i]);
        ObfDereferenceObject(copy[i].Process);
    }
    IoDeleteSymbolicLink(&g_Sym); IoDeleteDevice(g_DevObj);
}

NTSTATUS Dispatch(PDEVICE_OBJECT d, PIRP i) {
    UNREFERENCED_PARAMETER(d);
    i->IoStatus.Status = STATUS_SUCCESS; i->IoStatus.Information = 0;
    IoCompleteRequest(i, IO_NO_INCREMENT); return STATUS_SUCCESS;
}

NTSTATUS Control(PDEVICE_OBJECT d, PIRP i) {
    UNREFERENCED_PARAMETER(d);
    PIO_STACK_LOCATION st = IoGetCurrentIrpStackLocation(i);
    ULONG code = st->Parameters.DeviceIoControl.IoControlCode;
    ULONG inLen = st->Parameters.DeviceIoControl.InputBufferLength;
    PVOID buf = i->AssociatedIrp.SystemBuffer;
    NTSTATUS s = STATUS_INVALID_DEVICE_REQUEST;
    ULONG_PTR info = 0;
    if (!buf) { s = STATUS_INVALID_PARAMETER; goto done; }
    switch (code) {
    case IOCTL_ALLOCATE_MEMORY: if (inLen >= sizeof(ALLOCATE_MEMORY_REQ)) { s = AllocMem((PALLOCATE_MEMORY_REQ)buf); if (NT_SUCCESS(s)) info = sizeof(ALLOCATE_MEMORY_REQ); } break;
    case IOCTL_WRITE_MEMORY: if (inLen >= sizeof(WRITE_MEMORY_REQ)) { s = WriteMem((PWRITE_MEMORY_REQ)buf); if (NT_SUCCESS(s)) info = sizeof(WRITE_MEMORY_REQ); } break;
    case IOCTL_READ_MEMORY: if (inLen >= sizeof(READ_MEMORY_REQ)) { s = ReadMem((PREAD_MEMORY_REQ)buf); if (NT_SUCCESS(s)) info = sizeof(READ_MEMORY_REQ); } break;
    case IOCTL_PROTECT_MEMORY: if (inLen >= sizeof(PROTECT_MEMORY_REQ)) { s = ProtMem((PPROTECT_MEMORY_REQ)buf); if (NT_SUCCESS(s)) info = sizeof(PROTECT_MEMORY_REQ); } break;
    case IOCTL_FREE_MEMORY: if (inLen >= sizeof(FREE_MEMORY_REQ)) { s = FreeMem((PFREE_MEMORY_REQ)buf); if (NT_SUCCESS(s)) info = sizeof(FREE_MEMORY_REQ); } break;
    case IOCTL_UNLINK_VAD: if (inLen >= sizeof(UNLINK_VAD_REQ)) { s = UnlinkVad((PUNLINK_VAD_REQ)buf); if (NT_SUCCESS(s)) info = sizeof(UNLINK_VAD_REQ); } break;
    case IOCTL_RELINK_VAD: s = STATUS_SUCCESS; break;
    }
done:
    i->IoStatus.Status = s; i->IoStatus.Information = info;
    IoCompleteRequest(i, IO_NO_INCREMENT); return s;
}

NTSTATUS Init(PDRIVER_OBJECT d, PUNICODE_STRING r) {
    UNREFERENCED_PARAMETER(r);
    if (!Resolve()) return STATUS_NOT_SUPPORTED;
    KeInitializeSpinLock(&g_HiddenLock);
    LARGE_INTEGER tick; KeQueryTickCount(&tick);
    g_BufV[0] = L'\\'; g_BufV[1] = L'D'; g_BufV[2] = L'e'; g_BufV[3] = L'v'; g_BufV[4] = L'i'; g_BufV[5] = L'c'; g_BufV[6] = L'e'; g_BufV[7] = L'\\';
    g_BufV[8] = L'r'; g_BufV[9] = L'b'; g_BufV[10] = L'x'; g_BufV[11] = L'd'; g_BufV[12] = L'r'; g_BufV[13] = L'v'; g_BufV[14] = L'_';
    ULONG val = tick.LowPart;
    for (int i = 0; i < 8; i++) {
        ULONG nibble = (val >> (28 - i * 4)) & 0xF;
        g_BufV[15 + i] = (WCHAR)(nibble < 10 ? L'0' + nibble : L'A' + (nibble - 10));
    }
    g_BufV[23] = L'\0';
    RtlInitUnicodeString(&g_Name, g_BufV); RtlInitUnicodeString(&g_Sym, L"\\DosDevices\\RivieraDriver");
    IoDeleteSymbolicLink(&g_Sym);
    NTSTATUS status = IoCreateDevice(d, 0, &g_Name, RBX_DEVICE_TYPE, 0, FALSE, &g_DevObj);
    if (!NT_SUCCESS(status)) return status;
    status = IoCreateSymbolicLink(&g_Sym, &g_Name);
    if (!NT_SUCCESS(status)) { IoDeleteDevice(g_DevObj); return status; }
    PsSetCreateProcessNotifyRoutine(ProcessNotify, FALSE);
    d->MajorFunction[IRP_MJ_CREATE] = Dispatch;
    d->MajorFunction[IRP_MJ_CLOSE] = Dispatch;
    d->MajorFunction[IRP_MJ_DEVICE_CONTROL] = Control;
    d->DriverUnload = Unload;
    g_DevObj->Flags |= DO_BUFFERED_IO; g_DevObj->Flags &= ~DO_DEVICE_INITIALIZING;
    g_VadReady = TRUE;
    return STATUS_SUCCESS;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT d, PUNICODE_STRING r) {
    UNREFERENCED_PARAMETER(d); UNREFERENCED_PARAMETER(r);
    LARGE_INTEGER tick; KeQueryTickCount(&tick);
    g_BufD[0] = L'\\'; g_BufD[1] = L'D'; g_BufD[2] = L'r'; g_BufD[3] = L'i'; g_BufD[4] = L'v'; g_BufD[5] = L'e'; g_BufD[6] = L'r'; g_BufD[7] = L'\\';
    g_BufD[8] = L'r'; g_BufD[9] = L'b'; g_BufD[10] = L'x'; g_BufD[11] = L'd'; g_BufD[12] = L'r'; g_BufD[13] = L'v'; g_BufD[14] = L'_';
    ULONG val = tick.LowPart ^ 0xDEADBEEF;
    for (int i = 0; i < 8; i++) {
        ULONG nibble = (val >> (28 - i * 4)) & 0xF;
        g_BufD[15 + i] = (WCHAR)(nibble < 10 ? L'0' + nibble : L'A' + (nibble - 10));
    }
    g_BufD[23] = L'\0';
    UNICODE_STRING dn; RtlInitUnicodeString(&dn, g_BufD);
    return IoCreateDriver(&dn, &Init);
}
