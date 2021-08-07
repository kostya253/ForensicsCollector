//
// Copyright 2021 Nina Tessler and Kostya Zhuruev.
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice,
//    this list of conditions and the following disclaimer.
// 
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
// 
// 3. Neither the name of the copyright holder nor the names of its
//    contributors may be used to endorse or promote products derived from this
//    software without specific prior written permission.
// 
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" 
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED.IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE 
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR 
// CONSEQUENTIAL DAMAGES(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
// SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS 
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
// CONTRACT, STRICT LIABILITY, OR TORT(INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE 
// POSSIBILITY OF SUCH DAMAGE
// 

#include <ntifs.h>
#include <ntddk.h>
#include <wdm.h>
#include <fltKernel.h>

#pragma region Definitions
//
// Defines
//

// Until we reach production level, either BSOD or break into the debugger
#if 1
    #define ASSERT_NT_SUCCESS(x) if(!NT_SUCCESS(x)) __debugbreak();
#else
    #define ASSERT_NT_SUCCESS(x) if(!NT_SUCCESS(x)) DbgPrint("ASSERTED at %d with Status: 0x%x\n", __LINE__, x);
#endif

#define POOL_TAG 'tpPF'

#ifndef Add2Ptr
#define Add2Ptr(P,I) ((PVOID)((PUCHAR)(P) + (I)))
#endif

#ifndef ROUND_TO_SIZE
#define ROUND_TO_SIZE(_length, _alignment)    \
            (((_length) + ((_alignment)-1)) & ~((_alignment) - 1))
#endif

#ifndef FlagOn
#define FlagOn(_F,_SF)        ((_F) & (_SF))
#endif

#define MAX_EVENTS 5000

#pragma endregion

#pragma region Function Declarations
//
// Declaration section
//
DRIVER_INITIALIZE DriverEntry;
VOID DriverUnloadFunction(PDRIVER_OBJECT DriverObject);
#pragma endregion

#pragma region Statistics

//
// Simulation Process Id
//

HANDLE SimulationProcessId = 0;

#define FORENSICS_STATS_TAG 'ssPF'

//
// Filter Manager event
//

typedef struct _FilterManagerEvent
{
    LARGE_INTEGER StartTime;
    LARGE_INTEGER EndTime;
} FilterManagerEvent, *PFilterManagerEvent;
LONG FilterManagerEventIndex = 0;
LONG FilterManagerMisses = 0;
PFilterManagerEvent FilterManagerEvents[MAX_EVENTS] = { 0 };

//
// Create process event
//
typedef struct _CreationEvent
{
    LARGE_INTEGER  StartTime;
    LARGE_INTEGER  EndTime;
} CreationEvent, * PCreationEvent;
LONG CreationEventIndex = 0;
LONG CreationEventMisses = 0;
PCreationEvent CreationEvents[MAX_EVENTS] = { 0 };

//
// Load image event
//
typedef struct _LoadImageEvent
{
    LARGE_INTEGER  StartTime;
    LARGE_INTEGER  EndTime;
} LoadImageEvent, * PLoadImageEvent;
LONG LoadEventIndex = 0;
LONG LoadEventMisses = 0;
PLoadImageEvent LoadImageEvents[MAX_EVENTS] = { 0 };

//
// Object manager event
//
typedef struct _ObjectManagerEvent
{
    LARGE_INTEGER  StartTime;
    LARGE_INTEGER  EndTime;
} ObjectManagerEvent, * PObjectManagerEvent;
LONG ObjectManagerEventIndex = 0;
LONG ObjectManagerMisses = 0;
PObjectManagerEvent ObjectManagerEvents[MAX_EVENTS] = { 0 };

typedef struct _RegistryManagerEvent
{
    LARGE_INTEGER  StartTime;
    LARGE_INTEGER  EndTime;
} RegistryManagerEvent, * PRegistryManagerEvent;
LONG RegistryManagerEventIndex = 0;
LONG RegistryManagerMisses = 0;
PRegistryManagerEvent RegistryManagerEvents[MAX_EVENTS] = { 0 };


VOID InitializeStatistics()
{
    //
    // Create all stats in advance
    //

    for (ULONG index = 0; index < MAX_EVENTS; ++index)
    {
        //
        // Create Filter Manager events stats placeholders
        //
        FilterManagerEvents[index] = ExAllocatePoolWithTag(NonPagedPool, sizeof(FilterManagerEvent), FORENSICS_STATS_TAG);

        if (FilterManagerEvents[index] == NULL)
        {
            DbgPrint("%s Failed to allocate memory for event\n", __FUNCTION__);
            ASSERT(0);
        }

        RtlZeroMemory(FilterManagerEvents[index], sizeof(FilterManagerEvent));

        //
        // Create create process events placeholders
        //
        CreationEvents[index] = ExAllocatePoolWithTag(NonPagedPool, sizeof(CreationEvent), FORENSICS_STATS_TAG);

        if (CreationEvents[index] == NULL)
        {
            DbgPrint("%s Failed to allocate event\n", __FUNCTION__);
            ASSERT(0);
        }

        RtlZeroMemory(CreationEvents[index], sizeof(CreationEvent));

        //
        // Load Image Notify routine events placeholders
        //

        LoadImageEvents[index] = ExAllocatePoolWithTag(NonPagedPool, sizeof(LoadImageEvent), FORENSICS_STATS_TAG);

        if (LoadImageEvents[index] == NULL)
        {
            DbgPrint("%s Failed to allocate event\n", __FUNCTION__);
            ASSERT(0);
        }

        RtlZeroMemory(LoadImageEvents[index], sizeof(LoadImageEvent));

        //
        // Object create/duplicate events place holders
        //
        ObjectManagerEvents[index] = ExAllocatePoolWithTag(NonPagedPool, sizeof(ObjectManagerEvent), FORENSICS_STATS_TAG);

        if (ObjectManagerEvents[index] == NULL)
        {
            DbgPrint("%s Failed to allocate event\n", __FUNCTION__);
            ASSERT(0);
        }

        RtlZeroMemory(ObjectManagerEvents[index], sizeof(ObjectManagerEvent));

        //
        // Registry callbacks events placeholders
        //
        RegistryManagerEvents[index] = ExAllocatePoolWithTag(NonPagedPool, sizeof(RegistryManagerEvent), FORENSICS_STATS_TAG);

        if (RegistryManagerEvents[index] == NULL)
        {
            DbgPrint("%s Failed to allocate event\n", __FUNCTION__);
            ASSERT(0);
        }

        RtlZeroMemory(RegistryManagerEvents[index], sizeof(RegistryManagerEvent));
    }
}

#pragma endregion

#pragma region CodeIntegrity

//
// Declare the function we use from nt, to list the loaded modules
// See: https://www.geoffchappell.com/studies/windows/km/ntoskrnl/api/ex/sysinfo/query.htm
//
NTSYSAPI NTSTATUS NTAPI ZwQuerySystemInformation(
    ULONG	SystemInformationClass,
    PVOID	SystemInformation,
    ULONG	Length,
    PULONG	ReturnLength
);

typedef struct _SYSTEM_MODULE_INFORMATION_ENTRY
{
    ULONG Unknow1;
    ULONG Unknow2;
    ULONG Unknow3;
    ULONG Unknow4;
    PVOID Base;
    ULONG Size;
    ULONG Flags;
    USHORT Index;
    USHORT NameLength;
    USHORT LoadCount;
    USHORT ModuleNameOffset;
    char ImageName[256];
} SYSTEM_MODULE_INFORMATION_ENTRY, * PSYSTEM_MODULE_INFORMATION_ENTRY;

//
// See: https://www.geoffchappell.com/studies/windows/km/ntoskrnl/api/rtl/ldrreloc/process_modules.htm
//
typedef struct _SYSTEM_MODULE_INFORMATION
{
    ULONG NumberOfModules;
    SYSTEM_MODULE_INFORMATION_ENTRY Modules[1];
} SYSTEM_MODULE_INFORMATION, * PSYSTEM_MODULE_INFORMATION;

//
// GetBaseAddress provides loaded module base address, by enumarating loaded modules using
// above undocumented structures
//
// We will use 0xB for our query information,
// See: https://www.geoffchappell.com/studies/windows/km/ntoskrnl/api/ex/sysinfo/query.htm
//

ULONG64 GetBaseAddress(char* ModuleName)
{
    NTSTATUS Status = STATUS_SUCCESS;
    PVOID ModuleInformationBuffer = NULL;
    ULONG Index = 0;
    PCHAR DriverName = NULL;
    ULONG64 ImageBaseAddress = 0;
    ULONG SystemModuleInformation = 11;
    ULONG BufferSize = sizeof(SYSTEM_MODULE_INFORMATION_ENTRY) * 200; // Assume we need a space for 200 modules
    ULONG RequiredBufferSize = 0;

    PSYSTEM_MODULE_INFORMATION pSystemModuleInformation;

    do
    {
        ModuleInformationBuffer = ExAllocatePoolWithTag(NonPagedPool, BufferSize, POOL_TAG);

        if (ModuleInformationBuffer == NULL)
            break; 

        Status = ZwQuerySystemInformation(SystemModuleInformation, ModuleInformationBuffer, BufferSize, &RequiredBufferSize);

        if (Status == STATUS_INFO_LENGTH_MISMATCH)
        {
            ExFreePoolWithTag(ModuleInformationBuffer, POOL_TAG);
            
            //
            // Increase the buffer size by factor 2, and according to the documentation - RequiredBufferSize is unreliable 
            // so we use here a very crude way to increase the buffer
            //
            BufferSize *= 2; 
        }
        else if (!NT_SUCCESS(Status))
        {
            ExFreePoolWithTag(ModuleInformationBuffer, POOL_TAG);
            break;
        }
    } while (Status == STATUS_INFO_LENGTH_MISMATCH); // TODO(Nina): break loose?

    pSystemModuleInformation = (PSYSTEM_MODULE_INFORMATION)ModuleInformationBuffer;

    for (; Index < pSystemModuleInformation->NumberOfModules; ++Index)
    {
        DriverName = pSystemModuleInformation->Modules[Index].ImageName +
            pSystemModuleInformation->Modules[Index].ModuleNameOffset;

        if (_stricmp(ModuleName, DriverName) == 0)
        {
            ImageBaseAddress = (ULONG64)pSystemModuleInformation->Modules[Index].Base;
        }
    }

    return ImageBaseAddress;
}

#pragma endregion

#pragma region Filter Manager Callbacks

#define LOG_SIZE 1024
#define MAX_PATH_SIZE ROUND_TO_SIZE( (LOG_SIZE - sizeof(LOG_SIZE)), sizeof( PVOID ))

typedef struct _FilterManagerContext
{
    PDRIVER_OBJECT DriverObject;
    PFLT_FILTER Filter;
} FilterManagerContext, * PFilterManagerContext;

FilterManagerContext FPFilterManagerContext = { 0 };

FLT_PREOP_CALLBACK_STATUS
PreOperationCallback(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext
)
{
    UNREFERENCED_PARAMETER(CompletionContext);
    FLT_PREOP_CALLBACK_STATUS Status = FLT_POSTOP_FINISHED_PROCESSING; //assume we are NOT going to call our completion routine
    PFLT_FILE_NAME_INFORMATION FileNameInfo = NULL;
    PUNICODE_STRING FileNameToLog = NULL;
    NTSTATUS status;

    //
    // Ignore anything that is not simulating forensics report
    //
    if (PsGetCurrentProcessId() != SimulationProcessId)
    {
        InterlockedIncrement(&FilterManagerMisses);
        goto Exit;
    }

    // TODO (Nina): are we really ok here? check if we are racing
    PFilterManagerEvent record;
    LONG CurrentEventIndex = InterlockedIncrement(&FilterManagerEventIndex);

    if (CurrentEventIndex < MAX_EVENTS)
        record = FilterManagerEvents[CurrentEventIndex];
    else 
        goto Exit;

    record->StartTime = KeQueryPerformanceCounter(NULL);

    DbgPrint("--> %s\n", __FUNCTION__);

    if (FltObjects->FileObject != NULL) {

        status = FltGetFileNameInformation(Data,
            FLT_FILE_NAME_NORMALIZED |
            FLT_FILE_NAME_QUERY_ALWAYS_ALLOW_CACHE_LOOKUP,
            &FileNameInfo);
    }
    else 
    {
        status = STATUS_UNSUCCESSFUL;
    }

    if (NT_SUCCESS(status)) 
    {
        FileNameToLog = &FileNameInfo->Name;

        FltParseFileNameInformation(FileNameInfo);
    }

    if (NULL != FileNameInfo) 
    {
        if (NULL != FileNameToLog)
        {
            DbgPrint("\tPid: 0x%p, FileName: %wZ\n", PsGetCurrentProcessId(), FileNameToLog->Buffer);
        }

        FltReleaseFileNameInformation(FileNameInfo);
    }

    DbgPrint("<-- %s\n", __FUNCTION__);
    record->EndTime = KeQueryPerformanceCounter(NULL);

Exit:
    return Status;
}

FLT_POSTOP_CALLBACK_STATUS
PostOperationCallback(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
)
{
    UNREFERENCED_PARAMETER(Data);
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);
    UNREFERENCED_PARAMETER(Flags);

    //TODO(Nina): Should we even use it?

    return FLT_POSTOP_FINISHED_PROCESSING;
}

NTSTATUS
FilterUnload(
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
)
{
    {
        UNREFERENCED_PARAMETER(Flags);

        FltUnregisterFilter(FPFilterManagerContext.Filter);

        return STATUS_SUCCESS;
    }
}

NTSTATUS
QueryTeardown(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);
    return STATUS_SUCCESS;
}

CONST FLT_OPERATION_REGISTRATION Callbacks[] = {
    { IRP_MJ_CREATE,
      0,
      PreOperationCallback,
      PostOperationCallback },

    { IRP_MJ_CLEANUP,
      0,
      PreOperationCallback,
      PostOperationCallback },

      { IRP_MJ_OPERATION_END }
};


CONST FLT_REGISTRATION FilterRegistration = {

    sizeof(FLT_REGISTRATION),               //  Size
    FLT_REGISTRATION_VERSION,               //  Version   
    0,                                      //  Flags

    NULL,                                   //  Context
    Callbacks,                              //  Operation callbacks

    FilterUnload,                           //  FilterUnload

    NULL,                                   //  InstanceSetup
    QueryTeardown,                          //  InstanceQueryTeardown
    NULL,                                   //  InstanceTeardownStart
    NULL,                                   //  InstanceTeardownComplete

    NULL,                                   //  GenerateFileName
    NULL,                                   //  GenerateDestinationFileName
    NULL                                    //  NormalizeNameComponent
};


#pragma endregion

#pragma region Creation Callback
//
// Process Creation callback
//
BOOLEAN PsCreateProcessEx2NotifyRoutineRegistered = FALSE;

VOID
PsCreateProcessNotifyRoutineEx2Callback(
    _Inout_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _In_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo
)
{

    if (PsGetCurrentProcessId() != SimulationProcessId)
    {
        InterlockedIncrement(&CreationEventMisses);
        goto Exit;
    }

    PCreationEvent record;
    LONG CurrentEventIndex = InterlockedIncrement(&CreationEventIndex);

    if (CurrentEventIndex < MAX_EVENTS)
        record = CreationEvents[CurrentEventIndex];
    else
        goto Exit;

    DbgPrint("--> %s\n", __FUNCTION__);

    record->StartTime = KeQueryPerformanceCounter(NULL);

    if (CreateInfo) // Process Created
    {
        DbgPrint("\t%Process Created: EPROCESS: 0x%p, PPid: 0x%p Pid: 0x%p", Process, CreateInfo->ParentProcessId, ProcessId);

        /*
        * We can decide what we want to put in our Forensics data structure
        * Currently we will focus on: Parent pid, Current pid, Image file name and Command line
            typedef struct _PS_CREATE_NOTIFY_INFO {
                _In_ SIZE_T Size;
                union {
                    _In_ ULONG Flags;
                    struct {
                        _In_ ULONG FileOpenNameAvailable : 1;
                        _In_ ULONG IsSubsystemProcess : 1;
                        _In_ ULONG Reserved : 30;
                    };
                };
                _In_ HANDLE ParentProcessId;
                _In_ CLIENT_ID CreatingThreadId;
                _Inout_ struct _FILE_OBJECT *FileObject;
                _In_ PCUNICODE_STRING ImageFileName;
                _In_opt_ PCUNICODE_STRING CommandLine;
                _Inout_ NTSTATUS CreationStatus;
            } PS_CREATE_NOTIFY_INFO, *PPS_CREATE_NOTIFY_INFO;
        */

        // TODO(Kostya) consider adding command line to events recorded
        if (CreateInfo->CommandLine != NULL)
        {
            DbgPrint("\tPid: 0x%p, Command line: %wZ\n", ProcessId, CreateInfo->CommandLine);
        }

        DbgPrint("\tPid: 0x%p, Image Name: %wZ\n", ProcessId, CreateInfo->ImageFileName);
    }
    else // Process Terminated
    {
        DbgPrint("\tProcess Exit: EPROCESS: 0x%p, Pid: 0x%p", Process, ProcessId);
    }

    DbgPrint("<-- %s\n", __FUNCTION__);

    record->EndTime = KeQueryPerformanceCounter(NULL);

Exit:

}

#pragma endregion

#pragma region Load Image Callback

//
// Load Image Notify Routine Callback
//

BOOLEAN LoadImageNotifyRoutineRegistered = FALSE;

VOID
LoadImageNotifyRoutineCallback(
    _In_ PUNICODE_STRING FullImageName,
    _In_ HANDLE ProcessId,
    _In_ PIMAGE_INFO ImageInfo
)
{
    UNREFERENCED_PARAMETER(ImageInfo);

    if (PsGetCurrentProcessId() != SimulationProcessId)
    {
        InterlockedIncrement(&LoadEventMisses);
        goto Exit;
    }

    PLoadImageEvent record;
    LONG CurrentEventIndex = InterlockedIncrement(&LoadEventIndex);

    if (CurrentEventIndex < MAX_EVENTS)
        record = LoadImageEvents[CurrentEventIndex];
    else
        goto Exit;

    DbgPrint("--> %s\n", __FUNCTION__);
    
    record->StartTime = KeQueryPerformanceCounter(NULL);

    if (FullImageName)
    {
        DbgPrint("\t%wZ loaded in process 0x%p\n", FullImageName, ProcessId);
    }

    DbgPrint("<-- %s\n", __FUNCTION__);

    record->EndTime = KeQueryPerformanceCounter(NULL);

Exit:
    
}

#pragma endregion

#pragma region Object Manager Callback

typedef struct _OB_CALLBACK_CONTEXT {
    ULONG            MagicNumber;
    PVOID            RegistrationHandle;
    BOOLEAN          CallbackRegistered;
}OB_CALLBACK_CONTEXT, * POB_CALLBACK_CONTEXT;

#define OB_CALLBACK_CONTEXT_MAGIC   0x17171717 // Molcho ;)

OB_CALLBACK_CONTEXT ObCallbackContext;

//
// Convert Object manager's objects into strings
//
PWCHAR
ObjectManagerObjectTypeToString(POBJECT_TYPE ObjectType)
{
    if (ObjectType == *IoFileObjectType) 
    {
        return L"IoFileObjectType";
    }
    
    if (ObjectType == *ExEventObjectType) 
    {
        return L"ExEventObjectType";
    }
    
    if (ObjectType == *ExSemaphoreObjectType) 
    {
        return L"ExSemaphoreObjectType";
    }
    
    if (ObjectType == *TmTransactionManagerObjectType) 
    {
        return L"TmTransactionManagerObjectType";
    }
    
    if (ObjectType == *TmResourceManagerObjectType) 
    {
        return L"TmResourceManagerObjectType";
    }
    
    if (ObjectType == *TmEnlistmentObjectType) 
    {
        return L"TmEnlistmentObjectType";
    }
    
    if (ObjectType == *TmTransactionObjectType) 
    {
        return L"TmTransactionObjectType";
    }
    
    if (ObjectType == *PsProcessType) 
    {
        return L"PsProcessType";
    }
    
    if (ObjectType == *PsThreadType) 
    {
        return L"PsThreadType";
    }

    //
    // Assuming something new
    // We will be testing on 20H2, so we might not reach here
    //
    return L"Unknown";
}

OB_PREOP_CALLBACK_STATUS
ObjectManagerPreCallback(
    _In_ PVOID RegistrationContext,
    _In_ POB_PRE_OPERATION_INFORMATION OperationInformation
)
{
    POB_PRE_OPERATION_PARAMETERS         OperationParams;
    POB_PRE_CREATE_HANDLE_INFORMATION    CreateParams;
    POB_PRE_DUPLICATE_HANDLE_INFORMATION DuplicateHandleParams;

    UNREFERENCED_PARAMETER(RegistrationContext);

    if (PsGetCurrentProcessId() != SimulationProcessId)
    {
        InterlockedIncrement(&ObjectManagerMisses);
        goto Exit;
    }

    PObjectManagerEvent record;
    LONG CurrentEventIndex = InterlockedIncrement(&ObjectManagerEventIndex);

    if (CurrentEventIndex < MAX_EVENTS)
        record = ObjectManagerEvents[CurrentEventIndex];
    else
        goto Exit;

    record->StartTime = KeQueryPerformanceCounter(NULL);

    DbgPrint("--> %s", __FUNCTION__);

    OperationParams = OperationInformation->Parameters;

    switch (OperationInformation->Operation) 
    {
        case OB_OPERATION_HANDLE_CREATE: 
        {

            CreateParams = &OperationParams->CreateHandleInformation;

            DbgPrint("\tPre %s handle open 0x%p (%ls). Desired access is 0x%x\n",
                OperationInformation->KernelHandle ? "Kernel" : "User",
                OperationInformation->Object,
                ObjectManagerObjectTypeToString(OperationInformation->ObjectType),
                CreateParams->OriginalDesiredAccess);
            break;
        }
        case OB_OPERATION_HANDLE_DUPLICATE: 
        {
        
            DuplicateHandleParams = &OperationParams->DuplicateHandleInformation;

            DbgPrint("\tPre %s handle duplicate 0x%p (%ls). Desired access is 0x%x. From 0x%p to 0x%p Process\n",
                OperationInformation->KernelHandle ? "Kernel" : "User",
                OperationInformation->Object,
                ObjectManagerObjectTypeToString(OperationInformation->ObjectType),
                DuplicateHandleParams->OriginalDesiredAccess,
                DuplicateHandleParams->SourceProcess,
                DuplicateHandleParams->TargetProcess);
            break;
        }
  
        default: 
        {
            DbgPrint("\tUnknown operation 0x%x!\n",
                OperationInformation->Operation);
            break;
        }
    }

    DbgPrint("<-- %s", __FUNCTION__);

    record->EndTime = KeQueryPerformanceCounter(NULL);

Exit:
   
    return OB_PREOP_SUCCESS;
}

VOID
ObjectManagerPostCallback(
    _In_ PVOID RegistrationContext,
    _In_ POB_POST_OPERATION_INFORMATION OperationInformation
)
{
    POB_POST_OPERATION_PARAMETERS         OperationParams;
    POB_POST_CREATE_HANDLE_INFORMATION    CreateParams;
    POB_POST_DUPLICATE_HANDLE_INFORMATION DuplicateParams;

    UNREFERENCED_PARAMETER(RegistrationContext);

    DbgPrint("--> %s", __FUNCTION__);

    OperationParams = OperationInformation->Parameters;

    switch (OperationInformation->Operation) 
    {
        case OB_OPERATION_HANDLE_CREATE: 
        {

            CreateParams = &OperationParams->CreateHandleInformation;

            //
            // Granted access might be truncted comparing to the original request
            // this is the favourite way by AM software to ensure "security"
            //
            DbgPrint("\tPost %s handle creation to object 0x%p (%ls). Result was 0x%x, Granted Access 0x%x\n",
                OperationInformation->KernelHandle ? "Kernel" : "User",
                OperationInformation->Object,
                ObjectManagerObjectTypeToString(OperationInformation->ObjectType),
                OperationInformation->ReturnStatus,
                CreateParams->GrantedAccess);
            break;
        }
        case OB_OPERATION_HANDLE_DUPLICATE: 
        {
            DuplicateParams = &OperationParams->DuplicateHandleInformation;
            DbgPrint("\tPost %s Handle duplication to object 0x%p (%ls). Result was 0x%x Granted Access 0x%x\n",
                OperationInformation->KernelHandle ? "Kernel" : "User",
                OperationInformation->Object,
                ObjectManagerObjectTypeToString(OperationInformation->ObjectType),
                OperationInformation->ReturnStatus,
                DuplicateParams->GrantedAccess);
            break;
        }
        default: 
        {
            DbgPrint("\tUnknown operation 0x%x!\n",
                OperationInformation->Operation);
            break;
        }
    }
    
    DbgPrint("<-- %s", __FUNCTION__);
}

#pragma endregion 

#pragma region Registry Callbacks

typedef struct _CM_CALLBACK_CONTEXT {
    ULONG          MagicNumber;
    LARGE_INTEGER  CallbackRegistrationCookie;
    BOOLEAN        CallbackRegistered;
}CM_CALLBACK_CONTEXT, * PCM_CALLBACK_CONTEXT;

#define CM_CALLBACK_CONTEXT_MAGIC   0x0BADF00D // be careful 

CM_CALLBACK_CONTEXT CmCallbackContext;

PWCHAR
RegNotifyClassToString(
    REG_NOTIFY_CLASS RegNotifyClass)
{
    switch (RegNotifyClass) {
    case RegNtPreDeleteKey:
        return L"RegNtPreDeleteKey";
    case RegNtPreSetValueKey:
        return L"RegNtPreSetValueKey";
    case RegNtPreDeleteValueKey:
        return L"RegNtPreDeleteValueKey";
    case RegNtPreSetInformationKey:
        return L"RegNtPreSetInformationKey";
    case RegNtPreRenameKey:
        return L"RegNtPreRenameKey";
    case RegNtPreEnumerateKey:
        return L"RegNtPreEnumerateKey";
    case RegNtPreEnumerateValueKey:
        return L"RegNtPreEnumerateValueKey";
    case RegNtPreQueryKey:
        return L"RegNtPreQueryKey";
    case RegNtPreQueryValueKey:
        return L"RegNtPreQueryValueKey";
    case RegNtPreQueryMultipleValueKey:
        return L"RegNtPreQueryMultipleValueKey";
    case RegNtPreCreateKey:
        return L"RegNtPreCreateKey";
    case RegNtPostCreateKey:
        return L"RegNtPostCreateKey";
    case RegNtPreOpenKey:
        return L"RegNtPreOpenKey";
    case RegNtPostOpenKey:
        return L"RegNtPostOpenKey";
    case RegNtPreKeyHandleClose:
        return L"RegNtPreKeyHandleClose";
    case RegNtPostDeleteKey:
        return L"RegNtPostDeleteKey";
    case RegNtPostSetValueKey:
        return L"RegNtPostSetValueKey";
    case RegNtPostDeleteValueKey:
        return L"RegNtPostDeleteValueKey";
    case RegNtPostSetInformationKey:
        return L"RegNtPostSetInformationKey";
    case RegNtPostRenameKey:
        return L"RegNtPostRenameKey";
    case RegNtPostEnumerateKey:
        return L"RegNtPostEnumerateKey";
    case RegNtPostEnumerateValueKey:
        return L"RegNtPostEnumerateValueKey";
    case RegNtPostQueryKey:
        return L"RegNtPostQueryKey";
    case RegNtPostQueryValueKey:
        return L"RegNtPostQueryValueKey";
    case RegNtPostQueryMultipleValueKey:
        return L"RegNtPostQueryMultipleValueKey";
    case RegNtPostKeyHandleClose:
        return L"RegNtPostKeyHandleClose";
    case RegNtPreCreateKeyEx:
        return L"RegNtPreCreateKeyEx";
    case RegNtPostCreateKeyEx:
        return L"RegNtPostCreateKeyEx";
    case RegNtPreOpenKeyEx:
        return L"RegNtPreOpenKeyEx";
    case RegNtPostOpenKeyEx:
        return L"RegNtPostOpenKeyEx";
    case RegNtPreFlushKey:
        return L"RegNtPreFlushKey";
    case RegNtPostFlushKey:
        return L"RegNtPostFlushKey";
    case RegNtPreLoadKey:
        return L"RegNtPreLoadKey";
    case RegNtPostLoadKey:
        return L"RegNtPostLoadKey";
    case RegNtPreUnLoadKey:
        return L"RegNtPreUnLoadKey";
    case RegNtPostUnLoadKey:
        return L"RegNtPostUnLoadKey";
    case RegNtPreQueryKeySecurity:
        return L"RegNtPreQueryKeySecurity";
    case RegNtPostQueryKeySecurity:
        return L"RegNtPostQueryKeySecurity";
    case RegNtPreSetKeySecurity:
        return L"RegNtPreSetKeySecurity";
    case RegNtPostSetKeySecurity:
        return L"RegNtPostSetKeySecurity";
    case RegNtCallbackObjectContextCleanup:
        return L"RegNtCallbackObjectContextCleanup";
    default:
        return L"Unknown";
    }
}


NTSTATUS
CmRegistryCallback(
    _In_ PVOID CallbackContext,
    _In_ PVOID Argument1,
    _In_ PVOID Argument2
)
{

    REG_NOTIFY_CLASS RegistryNotifyClass;

    UNREFERENCED_PARAMETER(CallbackContext);
    UNREFERENCED_PARAMETER(Argument2);

    if (PsGetCurrentProcessId() != SimulationProcessId)
    {
        InterlockedIncrement(&RegistryManagerMisses);
        goto Exit;
    }

    PRegistryManagerEvent record;
    LONG CurrentEventIndex = InterlockedIncrement(&RegistryManagerEventIndex);

    if (CurrentEventIndex < MAX_EVENTS)
        record = RegistryManagerEvents[CurrentEventIndex];
    else
        goto Exit;

    record->StartTime = KeQueryPerformanceCounter(NULL);

    DbgPrint("--> %s\n", __FUNCTION__);

    //
    // The REG_NOTIFY_CLASS enumeration type specifies the type of registry 
    // operation that the configuration manager is passing to a RegistryCallback routine.
    //
    // Registry notificationsn classes are documented in below msdn page
    // See: https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ne-wdm-_reg_notify_class
    //
 
    RegistryNotifyClass = (REG_NOTIFY_CLASS)PtrToUlong(Argument1);

    DbgPrint("CmRegistryCallback: Called for %ls (0x%x)\n",
        RegNotifyClassToString(RegistryNotifyClass), RegistryNotifyClass);

    DbgPrint("<-- %s\n", __FUNCTION__);

    record->EndTime = KeQueryPerformanceCounter(NULL);

Exit:
    return STATUS_SUCCESS;
}

#pragma endregion

#pragma region Driver Entry and Unload Routines 

VOID UnregisterAllCallbacks()
{
    if (CmCallbackContext.CallbackRegistered == TRUE) 
    {
        ASSERT_NT_SUCCESS(
            CmUnRegisterCallback(
                CmCallbackContext.CallbackRegistrationCookie
            )
        );
    }

    if (ObCallbackContext.CallbackRegistered == TRUE)
    {
        //
        // Does not fail?! What if we stuck in Pre/Post Callback
        //
        ObUnRegisterCallbacks(ObCallbackContext.RegistrationHandle);
    }

    if (PsCreateProcessEx2NotifyRoutineRegistered == TRUE)
    {
        ASSERT_NT_SUCCESS(
            PsSetCreateProcessNotifyRoutineEx2(
                PsCreateProcessNotifySubsystems,
                (PVOID)PsCreateProcessNotifyRoutineEx2Callback,
                TRUE // Remove
            )
        );
    }

    if (LoadImageNotifyRoutineRegistered == TRUE)
    {
        ASSERT_NT_SUCCESS(
            PsRemoveLoadImageNotifyRoutine(
                LoadImageNotifyRoutineCallback
            )
        );
    }
}

//
// This driver is built for Windows 10 only! 
//
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    NTSTATUS Status = STATUS_SUCCESS;
    OB_CALLBACK_REGISTRATION   ObjectManagerCallbackRegistration;
    POB_OPERATION_REGISTRATION ObjectManagerOperationRegistration = NULL;
    ULONG                      ObjectManagerCallbackTypesSize;

    UNICODE_STRING CmAltitude; // Registry callback altitude

    //
    // Currently unused
    //
    UNREFERENCED_PARAMETER(RegistryPath);

    DbgPrint("Forensics Collector Driver Entry\n");

    //
    // Initialize statistics  
    // 
    InitializeStatistics();

    //
    // Register process creation/exit callback
    //

    // DESNOTE(Kostya -> Nina, make sure driver is compiled with /INTEGRITYCHECK)
    Status = PsSetCreateProcessNotifyRoutineEx2(
        PsCreateProcessNotifySubsystems,
        (PVOID)PsCreateProcessNotifyRoutineEx2Callback,
        FALSE // Remove
    );

    if (!NT_SUCCESS(Status)) {
        DbgPrint("Forensics Collector: PsSetCreateProcessNotifyRoutineEx2 failed: 0x%x\n", Status);
        goto Exit;
    }

    PsCreateProcessEx2NotifyRoutineRegistered = TRUE; // remember for unload routine

    //
    // Set Load image notify routine
    //
    Status = PsSetLoadImageNotifyRoutine(LoadImageNotifyRoutineCallback);

    if (!NT_SUCCESS(Status)) {
        DbgPrint("Forensics Collector: PsSetLoadImageNotifyRoutine failed: 0x%x\n", Status);
        goto Exit;
    }

    LoadImageNotifyRoutineRegistered = TRUE; // remember for unload routine
    
    //
    // Object Manager registration
    //

    ObCallbackContext.MagicNumber = OB_CALLBACK_CONTEXT_MAGIC;

    //
    // Registration version for Vista SP1 and Windows Server 2007 (from declaration header)
    //
    ObjectManagerCallbackRegistration.Version = OB_FLT_REGISTRATION_VERSION;

    ObjectManagerCallbackRegistration.OperationRegistrationCount = 2; //Pre+Post

    ObjectManagerCallbackRegistration.RegistrationContext = &ObCallbackContext;

    //
    // Refered to: https://docs.microsoft.com/en-us/windows-hardware/drivers/ifs/allocated-altitudes
    // To pick a suitable altitude
    //
    RtlInitUnicodeString(&ObjectManagerCallbackRegistration.Altitude, L"84666"); 

    ObjectManagerCallbackTypesSize = (sizeof(OB_OPERATION_REGISTRATION) * 2 /*Pre+Post*/);
    
    //
    // Allocate memory for Object manager rgistration structure
    //
    ObjectManagerOperationRegistration = (POB_OPERATION_REGISTRATION)ExAllocatePoolWithTag(
        NonPagedPool,
        ObjectManagerCallbackTypesSize,
        'NKob'
    );

    if (ObjectManagerOperationRegistration == NULL)
    {
        DbgPrint("Forensics Collector: Failed to allocate memory for Object Manager registration\n");
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto Exit;
    }

    ObjectManagerCallbackRegistration.OperationRegistration = ObjectManagerOperationRegistration;

    //
    // Fill the Callback information and register them
    //

    for (ULONG i = 0; i < 2; i++) 
    {
        ObjectManagerOperationRegistration[i].Operations = 
            OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;

        ObjectManagerOperationRegistration[i].PreOperation = ObjectManagerPreCallback;
        ObjectManagerOperationRegistration[i].PostOperation = ObjectManagerPostCallback;
    }

    ObjectManagerOperationRegistration[0 /*Process Object*/].ObjectType = PsProcessType;
    ObjectManagerOperationRegistration[1 /*Thread Object*/].ObjectType  = PsThreadType;

    Status = ObRegisterCallbacks(&ObjectManagerCallbackRegistration,
        &ObCallbackContext.RegistrationHandle);

    if (!NT_SUCCESS(Status)) 
    {
        DbgPrint("Forensics Collector : ObRegisterCallbacks failed! Status 0x%x\n", Status);
        goto Exit;
    }

    ObCallbackContext.CallbackRegistered = TRUE;

    //
    // Registry notifiation callbacks
    //
    CmCallbackContext.MagicNumber = CM_CALLBACK_CONTEXT_MAGIC;
    
    RtlInitUnicodeString(&CmAltitude,
        L"17000");

    Status = CmRegisterCallbackEx(
        CmRegistryCallback,
        &CmAltitude,
        DriverObject,
        &CmCallbackContext,
        &CmCallbackContext.CallbackRegistrationCookie,
        NULL);

    if (!NT_SUCCESS(Status))
    {
        DbgPrint("Forensics Collector : CmRegisterCallbackEx failed! Status 0x%x\n", Status);
        goto Exit;
    }

    CmCallbackContext.CallbackRegistered = TRUE;

    //
    // Set Driver Unload routine
    //
    DriverObject->DriverUnload = DriverUnloadFunction;

Exit:

    if (!NT_SUCCESS(Status))
    {
        UnregisterAllCallbacks();

        if (ObjectManagerOperationRegistration)
        {
            ExFreePoolWithTag(ObjectManagerOperationRegistration, 'NKob');
        }
    }

    return Status;
}

//
// Driver Unload function
// Basic stuff, unregister everything and release all memory
//
VOID DriverUnloadFunction(PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);

    UnregisterAllCallbacks();
}

#pragma endregion