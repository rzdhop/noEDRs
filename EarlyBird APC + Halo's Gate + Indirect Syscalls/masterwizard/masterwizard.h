#pragma once 
#include <windows.h>
#include <ntdef.h>
#include <winternl.h>

typedef _Function_class_(PS_APC_ROUTINE)
VOID NTAPI PS_APC_ROUTINE(
    _In_opt_ PVOID ApcArgument1,
    _In_opt_ PVOID ApcArgument2,
    _In_opt_ PVOID ApcArgument3
    );
typedef PS_APC_ROUTINE* PPS_APC_ROUTINE;

typedef struct _SYSCALL_STUB {
    DWORD SyscallId;
    PVOID SyscallFunc;
} SYSCALL_STUB, *PSYSCALL_STUB;

// windows-internals-book:"Chapter 5"
typedef enum _PS_CREATE_STATE
{
    PsCreateInitialState,
    PsCreateFailOnFileOpen,
    PsCreateFailOnSectionCreate,
    PsCreateFailExeFormat,
    PsCreateFailMachineMismatch,
    PsCreateFailExeName, // Debugger specified
    PsCreateSuccess,
    PsCreateMaximumStates
} PS_CREATE_STATE;


//https://ntdoc.m417z.com/ps_create_info
typedef struct _PS_CREATE_INFO
{
    SIZE_T Size;
    PS_CREATE_STATE State;
    union
    {
        // PsCreateInitialState
        struct
        {
            union
            {
                ULONG InitFlags;
                struct
                {
                    UCHAR WriteOutputOnExit : 1;
                    UCHAR DetectManifest : 1;
                    UCHAR IFEOSkipDebugger : 1;
                    UCHAR IFEODoNotPropagateKeyState : 1;
                    UCHAR SpareBits1 : 4;
                    UCHAR SpareBits2 : 8;
                    USHORT ProhibitedImageCharacteristics : 16;
                };
            };
            ACCESS_MASK AdditionalFileAccess;
        } InitState;

        // PsCreateFailOnSectionCreate
        struct
        {
            HANDLE FileHandle;
        } FailSection;

        // PsCreateFailExeFormat
        struct
        {
            USHORT DllCharacteristics;
        } ExeFormat;

        // PsCreateFailExeName
        struct
        {
            HANDLE IFEOKey;
        } ExeName;

        // PsCreateSuccess
        struct
        {
            union
            {
                ULONG OutputFlags;
                struct
                {
                    UCHAR ProtectedProcess : 1;
                    UCHAR AddressSpaceOverride : 1;
                    UCHAR DevOverrideEnabled : 1; // from Image File Execution Options
                    UCHAR ManifestDetected : 1;
                    UCHAR ProtectedProcessLight : 1;
                    UCHAR SpareBits1 : 3;
                    UCHAR SpareBits2 : 8;
                    USHORT SpareBits3 : 16;
                };
            };
            HANDLE FileHandle;
            HANDLE SectionHandle;
            ULONGLONG UserProcessParametersNative;
            ULONG UserProcessParametersWow64;
            ULONG CurrentParameterFlags;
            ULONGLONG PebAddressNative;
            ULONG PebAddressWow64;
            ULONGLONG ManifestAddress;
            ULONG ManifestSize;
        } SuccessState;
    };
} PS_CREATE_INFO, *PPS_CREATE_INFO;

typedef struct _PS_ATTRIBUTE
{
    ULONG_PTR Attribute;
    SIZE_T Size;
    union
    {
        ULONG_PTR Value;
        PVOID ValuePtr;
    };
    PSIZE_T ReturnLength;
} PS_ATTRIBUTE, *PPS_ATTRIBUTE;

typedef struct _PS_ATTRIBUTE_LIST
{
    SIZE_T TotalLength;
    PS_ATTRIBUTE Attributes[1];
} PS_ATTRIBUTE_LIST, *PPS_ATTRIBUTE_LIST;

extern "C" VOID NTAPI RtlInitUnicodeString(
        PUNICODE_STRING DestinationString,
        PCWSTR SourceString
    );


//=============== stub definitions ================
DWORD g_SSN_NtAllocateVirtualMemory     = 0;
LPVOID g_SYSADDR_NtAllocateVirtualMemory        = 0;
extern "C" NTSTATUS stubNtAllocateVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect);

DWORD g_SSN_NtWriteVirtualMemory        = 0;
LPVOID g_SYSADDR_NtWriteVirtualMemory   = 0;
extern "C" NTSTATUS stubNtWriteVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, PUCHAR Buffer, SIZE_T NumberOfBytesToWrite, PULONG NumberOfBytesWritten);

DWORD g_SSN_NtProtectVirtualMemory      = 0;
LPVOID g_SYSADDR_NtProtectVirtualMemory = 0;
extern "C" NTSTATUS stubNtProtectVirtualMemory(_In_ HANDLE ProcessHandle, _Inout_ PVOID *BaseAddress, _Inout_ PSIZE_T RegionSize, _In_ ULONG NewProtection, _Out_ PULONG OldProtection);

DWORD g_SSN_NtResumeThread      = 0;
LPVOID g_SYSADDR_NtResumeThread = 0;
extern "C" NTSTATUS stubNtResumeThread(_In_ HANDLE ThreadHandle, _Out_opt_ PULONG PreviousSuspendCount);

DWORD g_SSN_NtWaitForSingleObject       = 0;
LPVOID g_SYSADDR_NtWaitForSingleObject  = 0;
extern "C" NTSTATUS stubNtWaitForSingleObject(HANDLE Handle, BOOLEAN Alertable, PLARGE_INTEGER Timeout);

DWORD g_SSN_NtQueueApcThread    = 0;
LPVOID g_SYSADDR_NtQueueApcThread       = 0;
extern "C" NTSTATUS stubNtQueueApcThread(HANDLE ThreadHandle, PPS_APC_ROUTINE ApcRoutine, PVOID ApcArgument1, PVOID ApcArgument2, PVOID ApcArgument3);
//=================================================
