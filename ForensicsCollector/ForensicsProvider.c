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

#include "ForensicsCollector.h"

#pragma region Chosen Event Scheme

#define ETW_ON_FLAG 1
#define FLT_ON_FLAG 2
#define CMT_ON_FLAG 4

ULONG64 gEventScheme = 0;


//
// Non-Buffered events scheme
//
#define USE_BUFFERED_EVENTS 1

//
// Completion Events scheme
//

#define USE_COMPLETION_EVENTS 0

#pragma endregion

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

#define MAX_EVENTS 5001

#define NT_DEVICE_NAME      L"\\Device\\ForensicsCollector"
#define DOS_DEVICE_NAME     L"\\DosDevices\\ForensicsCollector"

#define FORENSICS_COLLECTOR_TYPE 17000

#define GET_FLTMGR_EVENT   CTL_CODE( FORENSICS_COLLECTOR_TYPE, 0x901, METHOD_BUFFERED, FILE_ANY_ACCESS  )
#define GET_CREATE_EVENT   CTL_CODE( FORENSICS_COLLECTOR_TYPE, 0x902, METHOD_BUFFERED, FILE_ANY_ACCESS  )
#define GET_LOAD_EVENT     CTL_CODE( FORENSICS_COLLECTOR_TYPE, 0x903, METHOD_BUFFERED, FILE_ANY_ACCESS  )
#define GET_OBJECT_EVENT   CTL_CODE( FORENSICS_COLLECTOR_TYPE, 0x904, METHOD_BUFFERED, FILE_ANY_ACCESS  )
#define GET_REGISTRY_EVENT CTL_CODE( FORENSICS_COLLECTOR_TYPE, 0x905, METHOD_BUFFERED, FILE_ANY_ACCESS  )
#define GET_ALL_MISSES     CTL_CODE( FORENSICS_COLLECTOR_TYPE, 0x906, METHOD_BUFFERED, FILE_ANY_ACCESS  )
#define SET_SIM_PS_ID      CTL_CODE( FORENSICS_COLLECTOR_TYPE, 0x907, METHOD_BUFFERED, FILE_ANY_ACCESS  )
#define CLS_SIM_DATA       CTL_CODE( FORENSICS_COLLECTOR_TYPE, 0x908, METHOD_BUFFERED, FILE_ANY_ACCESS  )
#define IS_SIM_DONE        CTL_CODE( FORENSICS_COLLECTOR_TYPE, 0x909, METHOD_BUFFERED, FILE_ANY_ACCESS  )
#define GET_ALL_INDEXES    CTL_CODE( FORENSICS_COLLECTOR_TYPE, 0x910, METHOD_BUFFERED, FILE_ANY_ACCESS  )
#define SET_SCHEME         CTL_CODE( FORENSICS_COLLECTOR_TYPE, 0x911, METHOD_BUFFERED, FILE_ANY_ACCESS  )

#pragma endregion

#pragma region Function Declarations
//
// Declaration section
//
DRIVER_INITIALIZE DriverEntry;
VOID DriverUnloadFunction(PDRIVER_OBJECT DriverObject);


_Dispatch_type_(IRP_MJ_CREATE)
_Dispatch_type_(IRP_MJ_CLOSE)
DRIVER_DISPATCH CreateCloseDispatch;

_Dispatch_type_(IRP_MJ_DEVICE_CONTROL)
DRIVER_DISPATCH DeviceControlDispatch;

_Dispatch_type_(IRP_MJ_READ)
DRIVER_DISPATCH ReadDispatch;

_Dispatch_type_(IRP_MJ_CLEANUP)
DRIVER_DISPATCH CleanUpDispatch;

#pragma endregion

#pragma region Statistics

//
// Simulation Process Id
//

HANDLE SimulationProcessId = 0;

#define FORENSICS_STATS_TAG 'ssPF'

//
// See https://docs.microsoft.com/en-us/windows/win32/sysinfo/acquiring-high-resolution-time-stamps
//
// Limited to < 1 microsecond
// 
#define TimeOpStart() {                                             \
    LARGE_INTEGER StartingTime, EndingTime, ElapsedMicroseconds;    \
    LARGE_INTEGER Frequency;                                        \
    StartingTime = KeQueryPerformanceCounter(&Frequency); __debugbreak(); \

#define TimeOpStop(s)                                                \
    EndingTime = KeQueryPerformanceCounter(NULL);                   \
    ElapsedMicroseconds.QuadPart = EndingTime.QuadPart - StartingTime.QuadPart; \
    ElapsedMicroseconds.QuadPart *= 1000000;                        \
    ElapsedMicroseconds.QuadPart /= Frequency.QuadPart;             \
    s = ElapsedMicroseconds.QuadPart;                               \
    }                                                               

//#define TimeOpStart() {                                             \
//    LARGE_INTEGER StartingTime, EndingTime, ElapsedMicroseconds;    \
//    StartingTime = KeQueryPerformanceCounter(NULL);                 \
//
//#define TimeOpStop(s)                                                \
//    EndingTime = KeQueryPerformanceCounter(NULL);                   \
//    ElapsedMicroseconds.QuadPart = EndingTime.QuadPart - StartingTime.QuadPart; \
//    s = ElapsedMicroseconds.QuadPart;                               \
//    }                                                               

//
// Filter Manager event
//

typedef struct _FilterManagerEvent
{
    LARGE_INTEGER ElapsedMicroseconds;
} FilterManagerEvent, * PFilterManagerEvent;
LONG64 FilterManagerEventIndex = 0;
LONG64 FilterManagerMisses = 0;
FilterManagerEvent FilterManagerEvents[MAX_EVENTS + 1] = { 0 };

//
// Create process event
//
typedef struct _CreationEvent
{
    LARGE_INTEGER ElapsedMicroseconds;
} CreationEvent, * PCreationEvent;
LONG64 CreationEventIndex = 0;
LONG64 CreationEventMisses = 0;
CreationEvent CreationEvents[MAX_EVENTS + 1] = { 0 };

//
// Load image event
//
typedef struct _LoadImageEvent
{
    LARGE_INTEGER ElapsedMicroseconds;
} LoadImageEvent, * PLoadImageEvent;
LONG64 LoadEventIndex = 0;
LONG64 LoadEventMisses = 0;
LoadImageEvent LoadImageEvents[MAX_EVENTS + 1] = { 0 };

//
// Object manager event
//
typedef struct _ObjectManagerEvent
{
    LARGE_INTEGER ElapsedMicroseconds;
} ObjectManagerEvent, * PObjectManagerEvent;
LONG64 ObjectManagerEventIndex = 0;
LONG64 ObjectManagerMisses = 0;
ObjectManagerEvent ObjectManagerEvents[MAX_EVENTS + 1] = { 0 };

typedef struct _RegistryManagerEvent
{
    LARGE_INTEGER ElapsedMicroseconds;
} RegistryManagerEvent, * PRegistryManagerEvent;
LONG64 RegistryManagerEventIndex = 0;
LONG64 RegistryManagerMisses = 0;
RegistryManagerEvent RegistryManagerEvents[MAX_EVENTS + 1] = { 0 };


VOID InitializeStatistics()
{
    //
    // Create all stats in advance
    //
    // Allocate additional stat data in case it's needed
}

VOID CleanStatisticalData()
{
    //
    // Reset events for subsequent collection
    //
    RtlZeroMemory(FilterManagerEvents, sizeof(FilterManagerEvents));
    RtlZeroMemory(CreationEvents, sizeof(CreationEvents));
    RtlZeroMemory(LoadImageEvents, sizeof(LoadImageEvents));
    RtlZeroMemory(RegistryManagerEvents, sizeof(RegistryManagerEvents));
    RtlZeroMemory(ObjectManagerEvents, sizeof(ObjectManagerEvents));
}

// TODO (Nina) run verifier on unload of the driver to ensure all resources were freed
VOID ReleaseStatistics()
{
    //
    // Create all stats in advance
    //
    // Fill in case you decide to allocate anything in the initialize function
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

#pragma region Buffered Forensics 

//
// Important definitions
// Since this one file do it all, we will not keep this in a struct
//

#define FC_PORT_NAME                   L"\\ForensicsCollectorPort"

KSPIN_LOCK BufferedEventsLock;
LIST_ENTRY BufferedEventsList;

#define MAX_NAME_SIZE 256

//
// We need 5 * 5000, I assume we will not have issues with out of memory
//
NPAGED_LOOKASIDE_LIST BufferedEventsAllocationList;

#define FC_BUFFERED_EVENT_TAG 'ebCF'

//
// Buffered Forensics collection mechanism
//

#define FILTERMGR_EVENT_TYPE 0x10000000
#define CREATEPS_EVENT_TYPE  0x20000000
#define LOADIMAGE_EVENT_TYPE 0x40000000
#define OBJECTMGR_EVENT_TYPE 0x80000000
#define REG_MNGR_EVENT_TYPE  0x01000000

// Extra flags
#define CREATEPS_CREATE_BOOL    0x20000001
#define OBJECTMGR_KERNEL_HANDLE 0x80000001
#define OBJECTMGR_CREATE_HANDLE 0x80000002

typedef struct _EVENT_DATA {

    //
    // Depending on the operation, we might need 
    // additional infrmaion in terms of boolean
    //

    ULONG64 TypeAndFlags;

    ULONG64 ProcessId;
    ULONG64 ThreadId;

    //
    // Create Process Specific params
    // EPROCESS/Parent PID
    //
    // Object Manager specific params
    // Desired access, handle
    //
    // Registry manager specific param
    // NotifyClass
    ULONG64 ExParam1;
    ULONG64 ExParam2;

    //
    // Take one of the possible strings
    // FileName, Command Line, Image File Name, Operation Type, Notirfy Class Name
    //
    // We will play with the limit to see if it helps the speed
    WCHAR Name1[MAX_NAME_SIZE];
    WCHAR Name2[MAX_NAME_SIZE];

} EVENT_DATA, * PEVENT_DATA;

typedef struct _EVENTS_LIST {

    LIST_ENTRY List;

    EVENT_DATA Event;

} EVENTS_LIST, * PEVENTS_LIST;

PEVENTS_LIST
AllocateBufferedEvent()
{
    PEVENTS_LIST EventList = ExAllocateFromNPagedLookasideList(&BufferedEventsAllocationList);

    if (EventList == NULL)
    {
        // Unexpected, don't run verifier with low memory simulation
        DbgPrint("%s Failed to allocate memory\n", __FUNCTION__);
        ASSERT(0);
    }
    else
    {
        RtlZeroMemory(&EventList->Event, sizeof(EVENT_DATA));
    }

    return EventList;
}

VOID
RetainEventList(
    _In_ PEVENTS_LIST EventList
)
{
    KIRQL oldIrql;

    KeAcquireSpinLock(&BufferedEventsLock, &oldIrql);
    InsertTailList(&BufferedEventsList, &EventList->List);
    KeReleaseSpinLock(&BufferedEventsLock, oldIrql);
}

VOID
ReleaseAllocatedBufferedEvents()
{
    PLIST_ENTRY pList;
    PEVENTS_LIST Event;
    KIRQL oldIrql;

    KeAcquireSpinLock(&BufferedEventsLock, &oldIrql);

    while (!IsListEmpty(&BufferedEventsList))
    {
        pList = RemoveHeadList(&BufferedEventsList);
        KeReleaseSpinLock(&BufferedEventsLock, oldIrql);

        Event = CONTAINING_RECORD(pList, EVENTS_LIST, List);

        ExFreeToNPagedLookasideList(&BufferedEventsAllocationList, Event);

        KeAcquireSpinLock(&BufferedEventsLock, &oldIrql);
    }

    KeReleaseSpinLock(&BufferedEventsLock, oldIrql);
}

#pragma endregion

#pragma region Event Driven Forensics

PDEVICE_OBJECT g_pDeviceObject = NULL;

//
// Driver extension will be used by the event driven forensics collector
//
typedef struct _DEVICE_EXTENSION {

    BOOLEAN EnableEvents;

    KSPIN_LOCK Lock;
    KIRQL OldIrql;

    LIST_ENTRY PendingReadOp;

    PIRP       PendingIrp;
}  DEVICE_EXTENSION, * PDEVICE_EXTENSION;

VOID LockDeviceExtension(PDEVICE_EXTENSION DeviceExtension)
{
    KeAcquireSpinLock(&DeviceExtension->Lock, &DeviceExtension->OldIrql);
}

VOID UnlockDeviceExtension(PDEVICE_EXTENSION DeviceExtension)
{
    KeReleaseSpinLock(&DeviceExtension->Lock, DeviceExtension->OldIrql);
}

PIRP PopPeningIRP(PDEVICE_EXTENSION DeviceExtension)
{
    PIRP PendingIRP = NULL;

    if (DeviceExtension->PendingIrp)
    {
        PendingIRP = DeviceExtension->PendingIrp;
        DeviceExtension->PendingIrp = NULL;
        IoSetCancelRoutine(PendingIRP, NULL);
    }

    return PendingIRP;
}

VOID ReleaseResources(PDEVICE_EXTENSION DeviceExtension)
{
    //
    // We are shutting down, free all pending IRPs and signal on pending IRP
    //

    //
    // We already relesed our resources
    //
    if (DeviceExtension->EnableEvents == FALSE)
        return;

    DeviceExtension->EnableEvents = FALSE;

    PLIST_ENTRY List_Entry = NULL;

    //
    // Free all PendingIRPs 
    //
    while ((List_Entry = RemoveHeadList(&DeviceExtension->PendingReadOp)) != &DeviceExtension->PendingReadOp)
    {
        UnlockDeviceExtension(DeviceExtension);

        PEVENTS_LIST Event = CONTAINING_RECORD(List_Entry, EVENTS_LIST, List);
        ExFreeToNPagedLookasideList(&BufferedEventsAllocationList, Event);

        LockDeviceExtension(DeviceExtension);
    }

    PIRP PendingIRP = PopPeningIRP(DeviceExtension);

    //
    // Make sure we don't deadlock, when completing the pending IRP
    //
    UnlockDeviceExtension(DeviceExtension);

    if (PendingIRP)
    {
        PendingIRP->IoStatus.Information = 0;
        PendingIRP->IoStatus.Status = STATUS_INVALID_HANDLE;
        IoCompleteRequest(PendingIRP, IO_NO_INCREMENT);
    }

    LockDeviceExtension(DeviceExtension);
}

NTSTATUS
CreateCloseDispatch(
    PDEVICE_OBJECT DeviceObject,
    PIRP Irp
)
{
    PIO_STACK_LOCATION  irpStack;
    NTSTATUS            Status = STATUS_SUCCESS;

    PDEVICE_EXTENSION DeviceExtension = DeviceObject->DeviceExtension;

    irpStack = IoGetCurrentIrpStackLocation(Irp);

    switch (irpStack->MajorFunction)
    {
    case IRP_MJ_CREATE:
    {
        LockDeviceExtension(DeviceExtension);

        //
        // Allow only one Event Driven Forensics collector
        //
        if (DeviceExtension->EnableEvents == FALSE)
        {
            DeviceExtension->EnableEvents = TRUE;
        }
        else
        {
            //
            // For simplicity we support one instance
            //
            Status = STATUS_SHARING_VIOLATION;
        }

        UnlockDeviceExtension(DeviceExtension);
    } break;

    case IRP_MJ_CLOSE:
    {
        LockDeviceExtension(DeviceExtension);
        ReleaseResources(DeviceExtension);
        UnlockDeviceExtension(DeviceExtension);
    } break;

    default:
        Status = STATUS_INVALID_PARAMETER;
        break;
    }

    //
    // Save Status for return and complete Irp
    //
    Irp->IoStatus.Status = Status;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return Status;
}

VOID
CancelIRPRoutine(PDEVICE_OBJECT PDeviceObject, PIRP Irp)
{
    KIRQL cancelIrql = Irp->CancelIrql;
    IoReleaseCancelSpinLock(cancelIrql);

    PDEVICE_EXTENSION DeviceExtension = PDeviceObject->DeviceExtension;

    LockDeviceExtension(DeviceExtension);

    //
    // Essential check, we don't do something crazy
    //
    if (DeviceExtension->PendingIrp == Irp)
    {
        DeviceExtension->PendingIrp = NULL;
    }

    UnlockDeviceExtension(DeviceExtension);

    Irp->IoStatus.Information = 0;
    Irp->IoStatus.Status = STATUS_CANCELLED;

    IoCompleteRequest(Irp, IO_NO_INCREMENT);
}

VOID
CompleteReadOpIrp(PIRP Irp, PEVENTS_LIST Event)
{
    PEVENT_DATA UserModeReadEvent = (PEVENT_DATA)Irp->AssociatedIrp.SystemBuffer;
    RtlCopyMemory(UserModeReadEvent, &Event->Event, sizeof(EVENT_DATA));

    ExFreeToNPagedLookasideList(&BufferedEventsAllocationList, Event);

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = sizeof(EVENT_DATA);

    IoCompleteRequest(Irp, IO_NO_INCREMENT);
}

//
// The essence of the Event Driven approach, allow multiple reads in different threads
// to consume forensics events
//
NTSTATUS
ReadDispatch(
    PDEVICE_OBJECT DeviceObject,
    PIRP Irp
)
{
    PIO_STACK_LOCATION  irpStack;
    NTSTATUS            Status = STATUS_SUCCESS;
    ULONG_PTR           ReadBytes = 0;

    PDEVICE_EXTENSION DeviceExtension = DeviceObject->DeviceExtension;

    irpStack = IoGetCurrentIrpStackLocation(Irp);

    if (irpStack)
    {
        PVOID PReadBuffer = Irp->AssociatedIrp.SystemBuffer;
        ULONG BufferSize = irpStack->Parameters.Read.Length;

        //
        // Lets check usermode has enough space and buffer valid
        //
        if (PReadBuffer != NULL
            &&
            BufferSize == sizeof(EVENT_DATA))
        {
            PEVENTS_LIST Event = NULL;

            LockDeviceExtension(DeviceExtension);

            //
            // Copy buffers, if we started collecting them
            // 
            if (DeviceExtension->EnableEvents)
            {
                PLIST_ENTRY List_Entry = RemoveHeadList(&DeviceExtension->PendingReadOp);

                if (List_Entry != &DeviceExtension->PendingReadOp)
                {
                    Event = CONTAINING_RECORD(List_Entry, EVENTS_LIST, List);
                }
                else
                {
                    //
                    // The list is empty, pend the read operation
                    //

                    if (DeviceExtension->PendingIrp == NULL)
                    {
                        IoSetCancelRoutine(Irp, CancelIRPRoutine);
                        IoMarkIrpPending(Irp);

                        DeviceExtension->PendingIrp = Irp;
                        Status = STATUS_PENDING;
                    }
                    else
                    {
                        //
                        // We already have pending IRP, fail current request
                        //
                        Status = STATUS_REQUEST_OUT_OF_SEQUENCE;
                    }
                }
            }
            else
            {
                //
                // Might be a race where, read serviced before create done
                //
                Status = STATUS_DEVICE_NOT_CONNECTED;
            }

            UnlockDeviceExtension(DeviceExtension);

            if (Event)
            {
                //
                // We have data to send to usermode
                //
                PEVENT_DATA UserModeReadEvent = (PEVENT_DATA)Irp->AssociatedIrp.SystemBuffer;
                RtlCopyMemory(UserModeReadEvent, &Event->Event, sizeof(EVENT_DATA));
                ReadBytes = sizeof(EVENT_DATA);

                //
                // And free resources
                //
                ExFreeToNPagedLookasideList(&BufferedEventsAllocationList, Event);
            }
        }
        else
        {
            Status = STATUS_INVALID_PARAMETER;
        }
    }

    if (Status != STATUS_PENDING)
    {
        Irp->IoStatus.Status = Status;
        Irp->IoStatus.Information = ReadBytes;

        IoCompleteRequest(Irp, IO_NO_INCREMENT);
    }

    return Status;
}

NTSTATUS
CleanupDispatch(
    PDEVICE_OBJECT DeviceObject,
    PIRP Irp
)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;

    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}

//
// Save or send event immidiately to user mode
//
VOID
PendEvent(_In_ PEVENTS_LIST EventList)
{
    PIRP PendingIrp = NULL;
    PDEVICE_EXTENSION DeviceExtension = g_pDeviceObject->DeviceExtension;

    LockDeviceExtension(DeviceExtension);

    if (DeviceExtension->EnableEvents)
    {
        //
        // Check if we have pending IRP to complete now
        //
        PendingIrp = PopPeningIRP(DeviceExtension);

        if (PendingIrp == NULL)
        {
            //
            // Save event until next read operation
            //
            InsertTailList(&DeviceExtension->PendingReadOp, &EventList->List);
        }
    }

    UnlockDeviceExtension(DeviceExtension);

    if (PendingIrp)
    {
        CompleteReadOpIrp(PendingIrp, EventList);
    }
}


#pragma endregion

#pragma region Filter Manager Callbacks

#define LOG_SIZE 1024
#define MAX_PATH_SIZE ROUND_TO_SIZE( (LOG_SIZE - sizeof(LOG_SIZE)), sizeof( PVOID ))

typedef struct _FilterManagerContext
{
    PDRIVER_OBJECT DriverObject;
    PFLT_FILTER Filter;
    PFLT_PORT ServerPort;
    PFLT_PORT ClientPort;

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
        InterlockedIncrement64(&FilterManagerMisses);
        goto Exit;
    }

    // TODO (Nina): are we really ok here? check if we are racing
    LONG64 CurrentEventIndex = InterlockedIncrement64(&FilterManagerEventIndex);

    if (CurrentEventIndex > MAX_EVENTS)
        goto Exit;

    TimeOpStart();

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

            if (FlagOn(gEventScheme, CMT_ON_FLAG) || FlagOn(gEventScheme, FLT_ON_FLAG))
            {
                PEVENTS_LIST EventList = AllocateBufferedEvent();

                if (EventList != NULL)
                {
                    EventList->Event.ProcessId = (ULONG64)PsGetCurrentProcessId();
                    EventList->Event.ThreadId = (ULONG64)PsGetCurrentThreadId();
                    EventList->Event.TypeAndFlags |= FILTERMGR_EVENT_TYPE;
                    RtlCopyMemory(EventList->Event.Name1, FileNameToLog->Buffer, min(MAX_NAME_SIZE, FileNameToLog->Length));


                    if (FlagOn(gEventScheme, FLT_ON_FLAG))
                        RetainEventList(EventList);

                    if (FlagOn(gEventScheme, CMT_ON_FLAG))
                        PendEvent(EventList);

                }
            }

            if (FlagOn(gEventScheme, ETW_ON_FLAG))
                EventWriteFileOp((ULONG64)PsGetCurrentProcessId(), (ULONG64)PsGetCurrentThreadId(), FileNameToLog->Buffer);

            FltReleaseFileNameInformation(FileNameInfo);
        }

        TimeOpStop(FilterManagerEvents[CurrentEventIndex].ElapsedMicroseconds.QuadPart);

        DbgPrint("<-- %s (%I64u)\n", __FUNCTION__, FilterManagerEvents[CurrentEventIndex].ElapsedMicroseconds.QuadPart);

    Exit:
        return Status;
    }
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

NTSTATUS
InstanceSetup(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
)
{

    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);
    UNREFERENCED_PARAMETER(VolumeDeviceType);
    UNREFERENCED_PARAMETER(VolumeFilesystemType);

    //
    // Attach to everything, we filter by process anyhow 
    //
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

    InstanceSetup,                          //  InstanceSetup
    QueryTeardown,                          //  InstanceQueryTeardown
    NULL,                                   //  InstanceTeardownStart
    NULL,                                   //  InstanceTeardownComplete

    NULL,                                   //  GenerateFileName
    NULL,                                   //  GenerateDestinationFileName
    NULL                                    //  NormalizeNameComponent
};

NTSTATUS
FCConnect(
    _In_ PFLT_PORT ClientPort,
    _In_ PVOID ServerPortCookie,
    _In_reads_bytes_(SizeOfContext) PVOID ConnectionContext,
    _In_ ULONG SizeOfContext,
    _Flt_ConnectionCookie_Outptr_ PVOID* ConnectionCookie
)
{
    UNREFERENCED_PARAMETER(ServerPortCookie);
    UNREFERENCED_PARAMETER(ConnectionContext);
    UNREFERENCED_PARAMETER(SizeOfContext);
    UNREFERENCED_PARAMETER(ConnectionCookie);

    FLT_ASSERT(FPFilterManagerContext.ClientPort == NULL);
    FPFilterManagerContext.ClientPort = ClientPort;
    return STATUS_SUCCESS;
}

VOID
FCDisconnect(
    _In_opt_ PVOID ConnectionCookie
)
{
    UNREFERENCED_PARAMETER(ConnectionCookie);

    FltCloseClientPort(FPFilterManagerContext.Filter, &FPFilterManagerContext.ClientPort);
}

//
// The heart of Buffered event schema of transferring events to usermode
// See: https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/fltkernel/nf-fltkernel-fltcreatecommunicationport
//
NTSTATUS
FCMessage(
    _In_ PVOID ConnectionCookie,
    _In_reads_bytes_opt_(InputBufferSize) PVOID InputBuffer,
    _In_ ULONG InputBufferSize,
    _Out_writes_bytes_to_opt_(OutputBufferSize, *ReturnOutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferSize,
    _Out_ PULONG ReturnOutputBufferLength
)

{
    NTSTATUS Status = STATUS_SUCCESS;
    KIRQL OldIrql;
    PLIST_ENTRY Event_List = NULL;
    PEVENTS_LIST Event = NULL;

    UNREFERENCED_PARAMETER(ConnectionCookie);
    UNREFERENCED_PARAMETER(InputBuffer);
    UNREFERENCED_PARAMETER(InputBufferSize);

    for (;;)
    {
        BOOLEAN FoundRetainedEvent = FALSE;

        if ((OutputBuffer == NULL) || (OutputBufferSize == 0)) {

            Status = STATUS_INVALID_PARAMETER;
            break;
        }

        if (!IS_ALIGNED(OutputBuffer, sizeof(PVOID))) {

            Status = STATUS_DATATYPE_MISALIGNMENT;
            break;
        }

        //
        // Get the buffers to usermode
        //
        KeAcquireSpinLock(&BufferedEventsLock, &OldIrql);

        if (!IsListEmpty(&BufferedEventsList))
        {
            Event_List = RemoveHeadList(&BufferedEventsList);

            Event = CONTAINING_RECORD(Event_List, EVENTS_LIST, List);

            FoundRetainedEvent = TRUE;
        }

        KeReleaseSpinLock(&BufferedEventsLock, OldIrql);

        if (FoundRetainedEvent)
        {
            try
            {
                RtlCopyMemory(OutputBuffer, &Event->Event, sizeof(EVENT_DATA));
            }
            except(EXCEPTION_EXECUTE_HANDLER)
            {
                //
                // Something failed, let save the event again
                //
                KeAcquireSpinLock(&BufferedEventsLock, &OldIrql);
                InsertHeadList(&BufferedEventsList, Event_List);
                KeReleaseSpinLock(&BufferedEventsLock, OldIrql);

                return GetExceptionCode();
            }

            *ReturnOutputBufferLength = sizeof(EVENT_DATA);

            ExFreeToNPagedLookasideList(&BufferedEventsAllocationList, Event);
        }
        else
        {
            Status = STATUS_MESSAGE_NOT_FOUND;
        }
        break;
    }

    return Status;
}

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
        InterlockedIncrement64(&CreationEventMisses);
        goto Exit;
    }

    LONG64 CurrentEventIndex = InterlockedIncrement64(&CreationEventIndex);

    if (CurrentEventIndex > MAX_EVENTS)
        goto Exit;

    DbgPrint("--> %s\n", __FUNCTION__);

    TimeOpStart();

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

            if (FlagOn(gEventScheme, ETW_ON_FLAG))
                EventWriteCreateOp(
                    (ULONG64)PsGetCurrentProcessId(),
                    (ULONG64)PsGetCurrentThreadId(),
                    (ULONG64)Process,
                    (ULONG64)CreateInfo->ParentProcessId,
                    TRUE, // Create Process
                    (PCWSTR)CreateInfo->CommandLine->Buffer,
                    (PCWSTR)CreateInfo->ImageFileName->Buffer
                );

            if (FlagOn(gEventScheme, CMT_ON_FLAG) || FlagOn(gEventScheme, FLT_ON_FLAG)) {
                PEVENTS_LIST EventList = AllocateBufferedEvent();

                if (EventList != NULL)
                {
                    EventList->Event.ProcessId = (ULONG64)PsGetCurrentProcessId();
                    EventList->Event.ThreadId = (ULONG64)PsGetCurrentThreadId();
                    EventList->Event.TypeAndFlags |= CREATEPS_CREATE_BOOL;
                    RtlCopyMemory(EventList->Event.Name1, CreateInfo->CommandLine->Buffer, min(MAX_NAME_SIZE, CreateInfo->CommandLine->Length));
                    RtlCopyMemory(EventList->Event.Name2, CreateInfo->ImageFileName->Buffer, min(MAX_NAME_SIZE, CreateInfo->ImageFileName->Length));

                    if (FlagOn(gEventScheme, FLT_ON_FLAG))
                        RetainEventList(EventList);

                    if (FlagOn(gEventScheme, CMT_ON_FLAG))
                        PendEvent(EventList);

                }

            }

            DbgPrint("\tPid: 0x%p, Image Name: %wZ\n", ProcessId, CreateInfo->ImageFileName);
        }
        else // Process Terminated
        {
            DbgPrint("\tProcess Exit: EPROCESS: 0x%p, Pid: 0x%p", Process, ProcessId);

            if (FlagOn(gEventScheme, CMT_ON_FLAG) || FlagOn(gEventScheme, FLT_ON_FLAG)) {
                PEVENTS_LIST EventList = AllocateBufferedEvent();

                if (EventList != NULL)
                {
                    EventList->Event.ProcessId = (ULONG64)PsGetCurrentProcessId();
                    EventList->Event.ThreadId = (ULONG64)PsGetCurrentThreadId();
                    EventList->Event.TypeAndFlags |= CREATEPS_EVENT_TYPE;

                    if (FlagOn(gEventScheme, FLT_ON_FLAG))
                        RetainEventList(EventList);

                    if (FlagOn(gEventScheme, CMT_ON_FLAG))
                        PendEvent(EventList);

                }
            }

            if (FlagOn(gEventScheme, ETW_ON_FLAG))
                EventWriteCreateOp(
                    (ULONG64)PsGetCurrentProcessId(),
                    (ULONG64)PsGetCurrentThreadId(),
                    (ULONG64)Process,
                    0,
                    FALSE, // Create Process
                    NULL,
                    NULL
                );

            TimeOpStop(CreationEvents[CurrentEventIndex].ElapsedMicroseconds.QuadPart);

            DbgPrint("<-- %s (%I64u)\n", __FUNCTION__, CreationEvents[CurrentEventIndex].ElapsedMicroseconds.QuadPart);
        Exit:
            return;
        }
    }
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
        InterlockedIncrement64(&LoadEventMisses);
        goto Exit;
    }

    LONG64 CurrentEventIndex = InterlockedIncrement64(&LoadEventIndex);

    if (CurrentEventIndex > MAX_EVENTS)
        goto Exit;

    TimeOpStart();

    DbgPrint("--> %s\n", __FUNCTION__);

    if (FullImageName)
    {
        DbgPrint("\t%wZ loaded in process 0x%p\n", FullImageName, ProcessId);

        if (FlagOn(gEventScheme, ETW_ON_FLAG))
            EventWriteLoadOp(
                (ULONG64)PsGetCurrentProcessId(),
                (ULONG64)PsGetCurrentThreadId(),
                (PCWSTR)FullImageName->Buffer
            );

        if (FlagOn(gEventScheme, CMT_ON_FLAG) || FlagOn(gEventScheme, FLT_ON_FLAG)) {
            PEVENTS_LIST EventList = AllocateBufferedEvent();

            if (EventList != NULL)
            {
                EventList->Event.ProcessId = (ULONG64)PsGetCurrentProcessId();
                EventList->Event.ThreadId = (ULONG64)PsGetCurrentThreadId();
                EventList->Event.TypeAndFlags |= LOADIMAGE_EVENT_TYPE;
                RtlCopyMemory(EventList->Event.Name1, FullImageName->Buffer, min(MAX_NAME_SIZE, FullImageName->Length));

                if (FlagOn(gEventScheme, FLT_ON_FLAG))
                    RetainEventList(EventList);

                if (FlagOn(gEventScheme, CMT_ON_FLAG))
                    PendEvent(EventList);

            }

        }

        TimeOpStop(LoadImageEvents[CurrentEventIndex].ElapsedMicroseconds.QuadPart);

        DbgPrint("<-- %s (%I64u)\n", __FUNCTION__, LoadImageEvents[CurrentEventIndex].ElapsedMicroseconds.QuadPart);
    Exit:
        return;
    }
}
#pragma endregion

#pragma region Object Manager Callback

typedef struct _OB_CALLBACK_CONTEXT {
    ULONG            MagicNumber;
    PVOID            RegistrationHandle;
    POB_OPERATION_REGISTRATION ObjectManagerCallbackRegistrationPtr;
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
        InterlockedIncrement64(&ObjectManagerMisses);
        goto Exit;
    }

    LONG64 CurrentEventIndex = InterlockedIncrement64(&ObjectManagerEventIndex);

    if (CurrentEventIndex > MAX_EVENTS)
        goto Exit;

    TimeOpStart();

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

        if (FlagOn(gEventScheme, ETW_ON_FLAG))
            EventWriteObjectOp(
                (ULONG64)PsGetCurrentProcessId(),
                (ULONG64)PsGetCurrentThreadId(),
                (ULONG64)OperationInformation->KernelHandle,
                (ULONG64)OperationInformation->Object,
                ObjectManagerObjectTypeToString(OperationInformation->ObjectType),
                (ULONG64)CreateParams->OriginalDesiredAccess,
                (BOOLEAN)OperationInformation->Operation
            );

        if (FlagOn(gEventScheme, CMT_ON_FLAG) || FlagOn(gEventScheme, FLT_ON_FLAG)) {
            PEVENTS_LIST EventList = AllocateBufferedEvent();

            if (EventList != NULL)
            {
                EventList->Event.ProcessId = (ULONG64)PsGetCurrentProcessId();
                EventList->Event.ThreadId = (ULONG64)PsGetCurrentThreadId();
                EventList->Event.TypeAndFlags |= OBJECTMGR_CREATE_HANDLE;
                EventList->Event.TypeAndFlags |= OperationInformation->KernelHandle ? OBJECTMGR_KERNEL_HANDLE : 0;
                EventList->Event.ExParam1 = (ULONG64)OperationInformation->Object;
                EventList->Event.ExParam2 = (ULONG64)CreateParams->OriginalDesiredAccess;
                PWCHAR ObjectTypeRequested = ObjectManagerObjectTypeToString(OperationInformation->ObjectType);
                RtlCopyMemory(EventList->Event.Name1, ObjectTypeRequested, min(MAX_NAME_SIZE, wcslen(ObjectTypeRequested)));

                if (FlagOn(gEventScheme, FLT_ON_FLAG))
                    RetainEventList(EventList);

                if (FlagOn(gEventScheme, CMT_ON_FLAG))
                    PendEvent(EventList);

            }
        }
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


        // TODO(Kostya) consider adding duplicate event            
        if (FlagOn(gEventScheme, ETW_ON_FLAG))
            EventWriteObjectOp(
                (ULONG64)PsGetCurrentProcessId(),
                (ULONG64)PsGetCurrentThreadId(),
                (ULONG64)OperationInformation->KernelHandle,
                (ULONG64)OperationInformation->Object,
                ObjectManagerObjectTypeToString(OperationInformation->ObjectType),
                (ULONG64)DuplicateHandleParams->OriginalDesiredAccess,
                (BOOLEAN)OperationInformation->Operation
            );

        if (FlagOn(gEventScheme, CMT_ON_FLAG) || FlagOn(gEventScheme, FLT_ON_FLAG)) {
            PEVENTS_LIST EventList = AllocateBufferedEvent();

            if (EventList != NULL)
            {
                EventList->Event.ProcessId = (ULONG64)PsGetCurrentProcessId();
                EventList->Event.ThreadId = (ULONG64)PsGetCurrentThreadId();
                EventList->Event.TypeAndFlags |= OBJECTMGR_EVENT_TYPE;
                EventList->Event.TypeAndFlags |= OperationInformation->KernelHandle ? OBJECTMGR_KERNEL_HANDLE : 0;
                EventList->Event.ExParam1 = (ULONG64)OperationInformation->Object;
                EventList->Event.ExParam2 = (ULONG64)DuplicateHandleParams->OriginalDesiredAccess;
                PWCHAR ObjectTypeRequested = ObjectManagerObjectTypeToString(OperationInformation->ObjectType);
                RtlCopyMemory(EventList->Event.Name1, ObjectTypeRequested, min(MAX_NAME_SIZE, wcslen(ObjectTypeRequested)));

                if (FlagOn(gEventScheme, FLT_ON_FLAG))
                    RetainEventList(EventList);

                if (FlagOn(gEventScheme, CMT_ON_FLAG))
                    PendEvent(EventList);

            }
        }
        break;
    }

    default:
    {
        DbgPrint("\tUnknown operation 0x%x!\n",
            OperationInformation->Operation);
        break;
    }
    }

    TimeOpStop(ObjectManagerEvents[CurrentEventIndex].ElapsedMicroseconds.QuadPart);

    DbgPrint("<-- %s (%I64u)\n", __FUNCTION__, ObjectManagerEvents[CurrentEventIndex].ElapsedMicroseconds.QuadPart);
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

    if (PsGetCurrentProcessId() != SimulationProcessId)
    {
        InterlockedIncrement64(&ObjectManagerMisses);
        goto Exit;
    }

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

Exit:
    return;
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
        InterlockedIncrement64(&RegistryManagerMisses);
        goto Exit;
    }

    LONG64 CurrentEventIndex = InterlockedIncrement64(&RegistryManagerEventIndex);

    if (CurrentEventIndex > MAX_EVENTS)
        goto Exit;

    TimeOpStart();

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

    if (FlagOn(gEventScheme, ETW_ON_FLAG))
        EventWriteRegOp(
            (ULONG64)PsGetCurrentProcessId(),
            (ULONG64)PsGetCurrentThreadId(),
            RegNotifyClassToString(RegistryNotifyClass),
            (ULONG64)RegistryNotifyClass
        );

    if (FlagOn(gEventScheme, CMT_ON_FLAG) || FlagOn(gEventScheme, FLT_ON_FLAG)) {
        PEVENTS_LIST EventList = AllocateBufferedEvent();

        if (EventList != NULL)
        {
            EventList->Event.ProcessId = (ULONG64)PsGetCurrentProcessId();
            EventList->Event.ThreadId = (ULONG64)PsGetCurrentThreadId();
            EventList->Event.TypeAndFlags |= REG_MNGR_EVENT_TYPE;
            PWCHAR NotificationClass = RegNotifyClassToString(RegistryNotifyClass);
            RtlCopyMemory(EventList->Event.Name1, NotificationClass, min(MAX_NAME_SIZE, wcslen(NotificationClass)));

            if (FlagOn(gEventScheme, FLT_ON_FLAG))
                RetainEventList(EventList);

            if (FlagOn(gEventScheme, CMT_ON_FLAG))
                PendEvent(EventList);

        }
    }
    TimeOpStop(RegistryManagerEvents[CurrentEventIndex].ElapsedMicroseconds.QuadPart);

    DbgPrint("<-- %s (%I64u)\n", __FUNCTION__, RegistryManagerEvents[CurrentEventIndex].ElapsedMicroseconds.QuadPart);
Exit:
    return STATUS_SUCCESS;
}

#pragma endregion

#pragma region Driver Entry and Unload Routines 

//
// Keep track of all register/unregister operations for safe unloading
//

BOOLEAN DriverDeviceRegistered = FALSE;
BOOLEAN DriverSymbolicLinkRegistered = FALSE;
BOOLEAN LookAsideListRegistered = FALSE;
BOOLEAN FltMgrRegistered = FALSE;
BOOLEAN FltCommunicationPortRegistered = FALSE;

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

        if (ObCallbackContext.ObjectManagerCallbackRegistrationPtr)
        {
            ExFreePoolWithTag(ObCallbackContext.ObjectManagerCallbackRegistrationPtr, 'NKob');
        }

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
    NTSTATUS                   Status = STATUS_SUCCESS;
    UNICODE_STRING             DeviceUnicodeString;
    UNICODE_STRING             Win32NameString;
    PDEVICE_OBJECT             DeviceObject = NULL;
    OB_CALLBACK_REGISTRATION   ObjectManagerCallbackRegistration;
    POB_OPERATION_REGISTRATION ObjectManagerOperationRegistration = NULL;
    ULONG                      ObjectManagerCallbackTypesSize;
    PDEVICE_EXTENSION          DeviceExtension;

    UNICODE_STRING CmAltitude; // Registry callback altitude

    //
    // Currently unused
    //
    UNREFERENCED_PARAMETER(RegistryPath);

    DbgPrint("Forensics Collector Driver Entry\n");

    RtlInitUnicodeString(&DeviceUnicodeString, NT_DEVICE_NAME);

    Status = IoCreateDevice(
        DriverObject,                   // Our Driver Object
        sizeof(DEVICE_EXTENSION),       // We use this for Event Driven Forensics
        &DeviceUnicodeString,           // Device name "\Device\SIOCTL"
        FILE_DEVICE_UNKNOWN,            // Device type
        FILE_DEVICE_SECURE_OPEN,        // Device characteristics
        FALSE,                          // Not an exclusive device
        &DeviceObject);                 // Returned ptr to Device Object

    DriverDeviceRegistered = TRUE;

    //
    // Save for Event driven forensics
    //
    g_pDeviceObject = DeviceObject;

    if (!NT_SUCCESS(Status))
    {
        //
        // We can still exit at this point without issues
        //
        DbgPrint(("Couldn't create the device object\n"));
        return Status;
    }

    DeviceExtension = DeviceObject->DeviceExtension;

    //
    // Initialize the driver object with this driver's entry points.
    //

    DriverObject->MajorFunction[IRP_MJ_CREATE] = CreateCloseDispatch;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = CreateCloseDispatch;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DeviceControlDispatch;

    //
    // Dedicated for event driven events
    //
    DriverObject->MajorFunction[IRP_MJ_READ] = ReadDispatch;
    DriverObject->MajorFunction[IRP_MJ_CLEANUP] = CleanupDispatch;

    // TODO(kostya) Should we handle IRP_MJ_SHUTDOWN for our tests or we assume the system
    // never shuts down

    //
    // Copy buffers, before sending to usermode
    //
    DeviceObject->Flags |= DO_BUFFERED_IO;

    //
    // Event Driven initialization of internal structrures
    //
    KeInitializeSpinLock(&DeviceExtension->Lock);

    InitializeListHead(&DeviceExtension->PendingReadOp);

    RtlInitUnicodeString(&Win32NameString, DOS_DEVICE_NAME);

    Status = IoCreateSymbolicLink(
        &Win32NameString,
        &DeviceUnicodeString
    );

    DriverSymbolicLinkRegistered = TRUE;

    if (!NT_SUCCESS(Status))
    {
        //
        // Delete everything that this routine has allocated.
        //
        DbgPrint("Couldn't create symbolic link\n");
        IoDeleteDevice(DeviceObject);
        return Status;
    }

    //
    // Initialize statistics  
    // 
    InitializeStatistics();

    //
    // Register ETW events
    //							 
    EventRegisterForensics_Collector_Provider();


    //
    // Filter Manager registaration and buffered events logic initialize 
    //

    InitializeListHead(&BufferedEventsList);
    KeInitializeSpinLock(&BufferedEventsLock);

    ExInitializeNPagedLookasideList(&BufferedEventsAllocationList,
        NULL,
        NULL,
        POOL_NX_ALLOCATION,
        sizeof(EVENT_DATA) + sizeof(LIST_ENTRY),
        FC_BUFFERED_EVENT_TAG,
        0);

    LookAsideListRegistered = TRUE;

    FPFilterManagerContext.DriverObject = DriverObject;

    Status = FltRegisterFilter(
        DriverObject,
        &FilterRegistration,
        &FPFilterManagerContext.Filter
    );

    if (!NT_SUCCESS(Status))
    {
        DbgPrint(("Couldn't \"attach\" to filter manager\n"));
        goto Exit;
    }

    FltMgrRegistered = TRUE;

    PSECURITY_DESCRIPTOR sd;
    Status = FltBuildDefaultSecurityDescriptor(&sd,
        FLT_PORT_ALL_ACCESS);

    if (!NT_SUCCESS(Status))
    {
        DbgPrint(("Couldn't create port default security description\n"));
        goto Exit;
    }

    UNICODE_STRING ForensicsCollectorPortName;
    RtlInitUnicodeString(&ForensicsCollectorPortName, FC_PORT_NAME);
    OBJECT_ATTRIBUTES oa;

    InitializeObjectAttributes(&oa,
        &ForensicsCollectorPortName,
        OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
        NULL,
        sd);

    Status = FltCreateCommunicationPort(FPFilterManagerContext.Filter,
        &FPFilterManagerContext.ServerPort,
        &oa,
        NULL,
        FCConnect,
        FCDisconnect,
        FCMessage,
        1);

    FltFreeSecurityDescriptor(sd);

    if (!NT_SUCCESS(Status))
    {
        DbgPrint(("Could not create Flt communication port\n"));
        goto Exit;
    }

    FltCommunicationPortRegistered = TRUE;

    //
    //  We are now ready to start filtering
    //

    Status = FltStartFiltering(FPFilterManagerContext.Filter);

    if (!NT_SUCCESS(Status))
    {
        DbgPrint(("Failed to start filtering the file system\n"));
        goto Exit;
    }

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
    ObjectManagerOperationRegistration[1 /*Thread Object*/].ObjectType = PsThreadType;

    Status = ObRegisterCallbacks(&ObjectManagerCallbackRegistration,
        &ObCallbackContext.RegistrationHandle);

    if (!NT_SUCCESS(Status))
    {
        DbgPrint("Forensics Collector : ObRegisterCallbacks failed! Status 0x%x\n", Status);
        goto Exit;
    }

    ObCallbackContext.ObjectManagerCallbackRegistrationPtr = ObjectManagerOperationRegistration;
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
        DriverUnloadFunction(DriverObject);

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
    UNICODE_STRING DosDeviceNameString;

    UnregisterAllCallbacks();

    ReleaseStatistics();

    ReleaseAllocatedBufferedEvents();

    if (DriverSymbolicLinkRegistered == TRUE)
    {
        RtlInitUnicodeString(&DosDeviceNameString, DOS_DEVICE_NAME);

        IoDeleteSymbolicLink(&DosDeviceNameString);
    }

    if (DriverDeviceRegistered == TRUE)
    {
        PDEVICE_OBJECT DeviceObject = DriverObject->DeviceObject;

        if (DeviceObject != NULL)
        {
            IoDeleteDevice(DeviceObject);
        }
    }

    if (FltCommunicationPortRegistered == TRUE)
    {
        FltCloseCommunicationPort(FPFilterManagerContext.ServerPort);
    }

    if (FltMgrRegistered == TRUE)
    {
        FltUnregisterFilter(FPFilterManagerContext.Filter);
    }

    if (LookAsideListRegistered == TRUE)
    {
        ExDeleteNPagedLookasideList(&BufferedEventsAllocationList);
    }


    EventUnregisterForensics_Collector_Provider();
}

NTSTATUS
DeviceControlDispatch(
    PDEVICE_OBJECT DeviceObject,
    PIRP Irp
)
{
    PIO_STACK_LOCATION  IrpSp;// Pointer to current stack location
    NTSTATUS            Status = STATUS_SUCCESS;// Assume success

    ULONG               InputBufferLength;
    ULONG               OutputBufferLength;

    UNREFERENCED_PARAMETER(DeviceObject);

    IrpSp = IoGetCurrentIrpStackLocation(Irp);
    InputBufferLength = IrpSp->Parameters.DeviceIoControl.InputBufferLength;
    OutputBufferLength = IrpSp->Parameters.DeviceIoControl.OutputBufferLength;

    switch (IrpSp->Parameters.DeviceIoControl.IoControlCode)
    {
    case GET_FLTMGR_EVENT:
    {
        if ((InputBufferLength != sizeof(ULONG64))
            &&
            (OutputBufferLength != sizeof(ULONG64)))
        {
            Status = STATUS_INVALID_PARAMETER;
            goto End;
        }
        else
        {
            ULONG64 Index = 0;
            PVOID OutputBuffer = Irp->AssociatedIrp.SystemBuffer;

            Index = *(PULONG64)Irp->AssociatedIrp.SystemBuffer;

            RtlCopyBytes(OutputBuffer, &FilterManagerEvents[(LONG)Index].ElapsedMicroseconds.QuadPart, sizeof(ULONG64));

            Irp->IoStatus.Information = OutputBufferLength;
        }
    } break;

    case GET_CREATE_EVENT:
    {
        if ((InputBufferLength != sizeof(ULONG64))
            &&
            (OutputBufferLength != sizeof(ULONG64)))
        {
            Status = STATUS_INVALID_PARAMETER;
            goto End;
        }
        else
        {
            ULONG64 Index = 0;
            PVOID OutputBuffer = Irp->AssociatedIrp.SystemBuffer;

            Index = *(PULONG64)Irp->AssociatedIrp.SystemBuffer;

            RtlCopyBytes(OutputBuffer, &CreationEvents[(LONG)Index].ElapsedMicroseconds.QuadPart, sizeof(ULONG64));

            Irp->IoStatus.Information = OutputBufferLength;
        }
    } break;

    case GET_LOAD_EVENT:
    {
        if ((InputBufferLength != sizeof(ULONG64))
            &&
            (OutputBufferLength != sizeof(ULONG64)))
        {
            Status = STATUS_INVALID_PARAMETER;
            goto End;
        }
        else
        {
            ULONG64 Index = 0;
            PVOID OutputBuffer = Irp->AssociatedIrp.SystemBuffer;

            Index = *(PULONG64)Irp->AssociatedIrp.SystemBuffer;

            RtlCopyBytes(OutputBuffer, &LoadImageEvents[(LONG)Index].ElapsedMicroseconds.QuadPart, sizeof(ULONG64));

            Irp->IoStatus.Information = OutputBufferLength;
        }
    }   break;

    case GET_OBJECT_EVENT:
    {
        if ((InputBufferLength != sizeof(ULONG64))
            &&
            (OutputBufferLength != sizeof(ULONG64)))
        {
            Status = STATUS_INVALID_PARAMETER;
            goto End;
        }
        else
        {
            ULONG64 Index = 0;
            PVOID OutputBuffer = Irp->AssociatedIrp.SystemBuffer;

            Index = *(PULONG64)Irp->AssociatedIrp.SystemBuffer;

            RtlCopyBytes(OutputBuffer, &ObjectManagerEvents[(LONG)Index].ElapsedMicroseconds.QuadPart, sizeof(ULONG64));

            Irp->IoStatus.Information = OutputBufferLength;
        }
    }   break;

    case GET_REGISTRY_EVENT:
    {
        if ((InputBufferLength != sizeof(ULONG64))
            &&
            (OutputBufferLength != sizeof(ULONG64)))
        {
            Status = STATUS_INVALID_PARAMETER;
            goto End;
        }
        else
        {
            ULONG64 Index = 0;
            PVOID OutputBuffer = Irp->AssociatedIrp.SystemBuffer;

            Index = *(PULONG64)Irp->AssociatedIrp.SystemBuffer;

            RtlCopyBytes(OutputBuffer, &RegistryManagerEvents[(LONG)Index].ElapsedMicroseconds.QuadPart, sizeof(ULONG64));

            Irp->IoStatus.Information = OutputBufferLength;
        }
    }   break;

    case GET_ALL_MISSES:
    {
        if (OutputBufferLength != (5 * sizeof(ULONG64)))
        {
            Status = STATUS_INVALID_PARAMETER;
            goto End;
        }

        PVOID OutputBuffer = Irp->AssociatedIrp.SystemBuffer;

        RtlCopyBytes(OutputBuffer, &FilterManagerMisses, sizeof(ULONG64));

        OutputBuffer = Add2Ptr(OutputBuffer, sizeof(ULONG64));
        RtlCopyBytes(OutputBuffer, &CreationEventMisses, sizeof(ULONG64));

        OutputBuffer = Add2Ptr(OutputBuffer, sizeof(ULONG64));
        RtlCopyBytes(OutputBuffer, &LoadEventMisses, sizeof(ULONG64));

        OutputBuffer = Add2Ptr(OutputBuffer, sizeof(ULONG64));
        RtlCopyBytes(OutputBuffer, &ObjectManagerMisses, sizeof(ULONG64));

        OutputBuffer = Add2Ptr(OutputBuffer, sizeof(ULONG64));
        RtlCopyBytes(OutputBuffer, &RegistryManagerMisses, sizeof(ULONG64));

        Irp->IoStatus.Information = OutputBufferLength;

    }   break;

    case GET_ALL_INDEXES:
    {
        if (OutputBufferLength != (5 * sizeof(ULONG64)))
        {
            Status = STATUS_INVALID_PARAMETER;
            goto End;
        }

        PVOID OutputBuffer = Irp->AssociatedIrp.SystemBuffer;

        RtlCopyBytes(OutputBuffer, &FilterManagerEventIndex, sizeof(ULONG64));

        OutputBuffer = Add2Ptr(OutputBuffer, sizeof(ULONG64));
        RtlCopyBytes(OutputBuffer, &CreationEventIndex, sizeof(ULONG64));

        OutputBuffer = Add2Ptr(OutputBuffer, sizeof(ULONG64));
        RtlCopyBytes(OutputBuffer, &LoadEventIndex, sizeof(ULONG64));

        OutputBuffer = Add2Ptr(OutputBuffer, sizeof(ULONG64));
        RtlCopyBytes(OutputBuffer, &ObjectManagerEventIndex, sizeof(ULONG64));

        OutputBuffer = Add2Ptr(OutputBuffer, sizeof(ULONG64));
        RtlCopyBytes(OutputBuffer, &RegistryManagerEventIndex, sizeof(ULONG64));

        Irp->IoStatus.Information = OutputBufferLength;

    } break;

    case SET_SIM_PS_ID:
    {
        if (InputBufferLength != sizeof(ULONG64))
        {
            Status = STATUS_INVALID_PARAMETER;
            goto End;
        }

        ULONG64 InputBuffer;
        InputBuffer = (ULONG64)Irp->AssociatedIrp.SystemBuffer;

        SimulationProcessId = *(HANDLE*)InputBuffer;

        Irp->IoStatus.Information = 0;
    } break;

    case SET_SCHEME:
    {
        if (InputBufferLength != sizeof(ULONG64))
        {
            Status = STATUS_INVALID_PARAMETER;
            goto End;
        }

        ULONG64 InputBuffer;
        InputBuffer = (ULONG64)Irp->AssociatedIrp.SystemBuffer;

        gEventScheme = *(ULONG64*)InputBuffer;

        Irp->IoStatus.Information = 0;
    } break;

    case CLS_SIM_DATA:
    {
        SimulationProcessId = 0;

        FilterManagerEventIndex = 0;
        CreationEventIndex = 0;
        ObjectManagerEventIndex = 0;
        LoadEventIndex = 0;
        RegistryManagerEventIndex = 0;

        RegistryManagerMisses = 0;
        ObjectManagerMisses = 0;
        LoadEventMisses = 0;
        CreationEventMisses = 0;
        FilterManagerMisses = 0;

        CleanStatisticalData();

        Irp->IoStatus.Information = 0;
    } break;

    case IS_SIM_DONE:
    {
        if (FilterManagerEventIndex < MAX_EVENTS
            ||
            CreationEventIndex < MAX_EVENTS
            ||
            ObjectManagerEventIndex < MAX_EVENTS
            ||
            LoadEventMisses < MAX_EVENTS
            ||
            RegistryManagerEventIndex < MAX_EVENTS)
        {
            Status = STATUS_INFO_LENGTH_MISMATCH;
            goto End;
        }

        Irp->IoStatus.Information = 0;

    } break;

    default:
        Status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

End:
    Irp->IoStatus.Status = Status;

    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return Status;
}

#pragma endregion