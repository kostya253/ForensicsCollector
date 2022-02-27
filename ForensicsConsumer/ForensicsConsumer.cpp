//
// Copyright 2022 Nina Tessler and Kostya Zhuruev.
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

#include <Windows.h>
#include <psapi.h>
#include <fltUser.h>
#include <stdio.h>

#include <fstream>
#include <string>
#include <memory>
#include <thread>
#include <sstream>
#include <regex>
#include <functional>
#include <vector>

//
// For ETW we need to hook an internal API
//
#include "detours.h"

//
// ETW 
//
#include <Wmistr.h>		
#define INITGUID		
#include <evntrace.h>
#include <evntprov.h>

#pragma comment (lib, "fltlib.lib")

#pragma region NTFunctions
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

typedef struct _CLIENT_ID {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID;
typedef CLIENT_ID* PCLIENT_ID;

typedef LONG KPRIORITY;

typedef enum _KWAIT_REASON {
    Executive,
    FreePage,
    PageIn,
    PoolAllocation,
    DelayExecution,
    Suspended,
    UserRequest,
    WrExecutive,
    WrFreePage,
    WrPageIn,
    WrPoolAllocation,
    WrDelayExecution,
    WrSuspended,
    WrUserRequest,
    WrSpare0,
    WrQueue,
    WrLpcReceive,
    WrLpcReply,
    WrVirtualMemory,
    WrPageOut,
    WrRendezvous,
    WrKeyedEvent,
    WrTerminated,
    WrProcessInSwap,
    WrCpuRateControl,
    WrCalloutStack,
    WrKernel,
    WrResource,
    WrPushLock,
    WrMutex,
    WrQuantumEnd,
    WrDispatchInt,
    WrPreempted,
    WrYieldExecution,
    WrFastMutex,
    WrGuardedMutex,
    WrRundown,
    WrAlertByThreadId,
    WrDeferredPreempt,
    WrPhysicalFault,
    MaximumWaitReason
} KWAIT_REASON;

typedef struct _SYSTEM_THREAD_INFORMATION
{
    LARGE_INTEGER KernelTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER CreateTime;
    ULONG WaitTime;
    PVOID StartAddress;
    CLIENT_ID ClientId;
    KPRIORITY Priority;
    LONG BasePriority;
    ULONG ContextSwitches;
    ULONG ThreadState;
    KWAIT_REASON WaitReason;
} SYSTEM_THREAD_INFORMATION, * PSYSTEM_THREAD_INFORMATION;

ULONG GetCurrentThreadContextSwitches() 
{
    NTSTATUS status = 0;
    typedef NTSTATUS(WINAPI* tNtQueryInformationThread)(HANDLE, LONG, PVOID, ULONG, PULONG);
    
    SYSTEM_THREAD_INFORMATION sti = { 0 };

    static tNtQueryInformationThread NtQueryInformationThread =
        reinterpret_cast<tNtQueryInformationThread>(GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationThread"));

    status = NtQueryInformationThread(GetCurrentThread(), (THREAD_INFORMATION_CLASS)40 /*ThreadSystemThreadInformation*/, &sti, sizeof(SYSTEM_THREAD_INFORMATION), 0); //NT_ERROR

    if (NT_SUCCESS(status))
    {
        return sti.ContextSwitches;
    }

    return 0;
}

DWORD GetCurrentProcessPageFaultCount() 
{
    PROCESS_MEMORY_COUNTERS pmc = { 0 };
    static HANDLE CurrentHandle = GetCurrentProcess();
    if (GetProcessMemoryInfo(CurrentHandle, &pmc, sizeof(pmc)))
            return pmc.PageFaultCount;

    return 0;
}

#pragma endregion

#pragma region ETW Private Definitions

// Missing in evntrace.h on the contrary to the documentation on MSDN
#define PROCESS_TRACE_MODE_REAL_TIME 0x00000100
#define PROCESS_TRACE_MODE_RAW_TIMESTAMP 0x00001000
#define PROCESS_TRACE_MODE_EVENT_RECORD 0x10000000

typedef struct _EVENT_HEADER_EXTENDED_DATA_ITEM {
    USHORT      Reserved1;                      // Reserved for internal use
    USHORT      ExtType;                        // Extended info type 
    struct {
        USHORT  Linkage : 1;       // Indicates additional extended 
                                                // data item
        USHORT  Reserved2 : 15;
    };
    USHORT      DataSize;                       // Size of extended info data
    ULONGLONG   DataPtr;                        // Pointer to extended info data
} EVENT_HEADER_EXTENDED_DATA_ITEM, * PEVENT_HEADER_EXTENDED_DATA_ITEM;

typedef struct _EVENT_HEADER {
    USHORT              Size;                   // Event Size
    USHORT              HeaderType;             // Header Type
    USHORT              Flags;                  // Flags
    USHORT              EventProperty;          // User given event property
    ULONG               ThreadId;               // Thread Id
    ULONG               ProcessId;              // Process Id
    LARGE_INTEGER       TimeStamp;              // Event Timestamp
    GUID                ProviderId;             // Provider Id
    EVENT_DESCRIPTOR    EventDescriptor;        // Event Descriptor
    union {
        struct {
            ULONG       KernelTime;             // Kernel Mode CPU ticks
            ULONG       UserTime;               // User mode CPU ticks
        } DUMMYSTRUCTNAME;
        ULONG64         ProcessorTime;          // Processor Clock 
                                                // for private session events
    } DUMMYUNIONNAME;
    GUID                ActivityId;             // Activity Id
} EVENT_HEADER, * PEVENT_HEADER;

typedef struct _EVENT_RECORD {
    EVENT_HEADER        EventHeader;            // Event header
    ETW_BUFFER_CONTEXT  BufferContext;          // Buffer context
    USHORT              ExtendedDataCount;      // Number of extended
                                                // data items
    USHORT              UserDataLength;         // User data length
    PEVENT_HEADER_EXTENDED_DATA_ITEM            // Pointer to an array of 
        ExtendedData;           // extended data items                                               
    PVOID               UserData;               // Pointer to user data
    PVOID               UserContext;            // Context from OpenTrace
} EVENT_RECORD, * PEVENT_RECORD;

#pragma endregion

#pragma region Open Source functions

// https://stackoverflow.com/questions/29242/off-the-shelf-c-hex-dump-code
void hexdump(const void* ptr, int buflen) {
    unsigned char* buf = (unsigned char*)ptr;
    int i, j;
    for (i = 0; i < buflen; i += 16) {
        printf("%06x: ", i);
        for (j = 0; j < 16; j++)
            if (i + j < buflen)
                printf("%02x ", buf[i + j]);
            else
                printf("   ");
        printf(" ");
        for (j = 0; j < 16; j++)
            if (i + j < buflen)
                printf("%c", isprint(buf[i + j]) ? buf[i + j] : '.');
        printf("\n");
    }
}

#pragma endregion

#pragma region Definitions

#ifndef Add2Ptr
#define Add2Ptr(P,I) ((PVOID)((PUCHAR)(P) + (I)))
#endif

#define FC_ASSERT(x) if (!x) DebugBreak();

#define DRIVER_NAME L"\\\\.\\ForensicsCollector"

#define PAGE_SIZE   4096
#define MAX_EVENTS  5000
#define MAX_PULL_EVENTS  (5*MAX_EVENTS)

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

#define ETW_ON_FLAG 1
#define FLT_ON_FLAG 2
#define CMT_ON_FLAG 4

#define WRITE_DB 0

//
// C++ 11 Magic
//
struct AutoCloseHandle
{
    void operator()(HANDLE handle) const
    {
        if (handle != INVALID_HANDLE_VALUE)
        {
            CloseHandle(handle);
        }
    }
};

using AutoHandle = std::unique_ptr<void, AutoCloseHandle>;

AutoHandle CreateAutoHandle(HANDLE handle)
{
    if (nullptr == handle || INVALID_HANDLE_VALUE == handle)
        return nullptr;

    return AutoHandle(handle); // return unique ptr
}

#pragma endregion

#pragma region Statistics

typedef struct _PullEvents
{
    LARGE_INTEGER ElapsedMicroseconds;
} PullEvents, * PPullEvents;
LONG64 PullEventIndex = 0;
PullEvents PulledEventsStats[MAX_PULL_EVENTS + 1] = { 0 };

typedef struct _CycleEvents
{
    ULONG64 Cycles;
} CycleEvents, * PCycleEvents;
LONG64 CycleEventIndex = 0;
CycleEvents CycleEventsStats[MAX_PULL_EVENTS + 1] = { 0 };

typedef struct _CSEvents
{
    ULONG CS;
} CSEvents, * PCSEvents;
LONG64 CSEventIndex = 0;
CSEvents CSEventsStats[MAX_PULL_EVENTS + 1] = { 0 };

typedef struct _PFEvents
{
    ULONG PFC;
} PFEvents, * PPFEvents;
LONG64 PFEventIndex = 0;
PFEvents PFEventsStats[MAX_PULL_EVENTS + 1] = { 0 };

//
// See https://docs.microsoft.com/en-us/windows/win32/sysinfo/acquiring-high-resolution-time-stamps
//
// Limited to < 1 microsecond
// 
#define TimeOpStart() {                                             \
    ULONG64 StartCycleTime = 0;                                          \
    ULONG64 EndCycleTime = 0;                                          \
    ULONG StartCS = 0;                                                 \
    ULONG EndCS = 0;                                                    \
    DWORD StartPF = 0, EndPF = 0;                                       \
    LARGE_INTEGER StartingTime = {0}, EndingTime = {0}, ElapsedMicroseconds = {0};    \
    LARGE_INTEGER Frequency;                                        \
    QueryPerformanceFrequency(&Frequency);                          \
    QueryPerformanceCounter(&StartingTime);                         \
    QueryThreadCycleTime(GetCurrentThread(), &StartCycleTime);      \
    StartCS = GetCurrentThreadContextSwitches();                    \
    StartPF = GetCurrentProcessPageFaultCount();                    \

#define TimeOpStop(s,c,cs,pf)                                          \
    QueryPerformanceCounter(&EndingTime);                            \
    ElapsedMicroseconds.QuadPart = EndingTime.QuadPart - StartingTime.QuadPart; \
    QueryThreadCycleTime(GetCurrentThread(), &EndCycleTime);            \
    EndCS = GetCurrentThreadContextSwitches();                          \
    EndPF = GetCurrentProcessPageFaultCount();                          \
    s = ElapsedMicroseconds.QuadPart;                                 \
    c = EndCycleTime - StartCycleTime;                                  \
    cs = EndCS-StartCS;                                                 \
    pf = EndPF-StartPF;                                                 \
    }  


void ClearPullStats() {
    PullEventIndex = 0;
    CycleEventIndex = 0;
    CSEventIndex = 0;
    PFEventIndex = 0;
    RtlZeroMemory(PulledEventsStats, MAX_PULL_EVENTS);
    RtlZeroMemory(CycleEventsStats, MAX_PULL_EVENTS);
    RtlZeroMemory(CSEventsStats, MAX_PULL_EVENTS);
    RtlZeroMemory(PFEventsStats, MAX_PULL_EVENTS);
}

int GetMisses(const char* name, int round)
{
    DWORD le = 0;

    auto driver_handle = CreateAutoHandle(CreateFileW(DRIVER_NAME,
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL));

    if (!driver_handle) // op bool
    {

        DWORD le = GetLastError();

        printf("Failed to open a handle to ForensicsCollector : %d\n", le);

        return 1;
    }

    DWORD dwBytesReturned = 0;
    constexpr size_t MISSES_ARRAY_SIZE = 5;
    ULONG64 MissesData[MISSES_ARRAY_SIZE] = { 0 };
    if (!DeviceIoControl(driver_handle.get(), GET_ALL_MISSES, NULL, 0, &MissesData, sizeof(ULONG64) * MISSES_ARRAY_SIZE, &dwBytesReturned, NULL))
    {
        printf("Failed to clear simulation data with error: %d\n", GetLastError());
        return 2;
    }

    FILE* output_white_noise = nullptr;
    std::stringstream ss;
    ss << name << "." << round;

    if (fopen_s(&output_white_noise, ss.str().c_str(), "w") != 0)
    {
        DWORD le = GetLastError();

        printf("Failed to open csv output file : %d\n", le);

        return 2;
    }

    // Save white noise stats
    {
        char buffer[MAX_PATH] = { 0 };
        sprintf_s(buffer, MAX_PATH, "FilterManager  misses: %I64u\n", MissesData[0]);
        fwrite(buffer, sizeof(char), strnlen_s(buffer, MAX_PATH), output_white_noise);
    }

    {
        char buffer[MAX_PATH] = { 0 };
        sprintf_s(buffer, MAX_PATH, "CreationEvent  misses: %I64u\n", MissesData[1]);
        fwrite(buffer, sizeof(char), strnlen_s(buffer, MAX_PATH), output_white_noise);
    }

    {
        char buffer[MAX_PATH] = { 0 };
        sprintf_s(buffer, MAX_PATH, "LoadEvent      misses: %I64u\n", MissesData[2]);
        fwrite(buffer, sizeof(char), strnlen_s(buffer, MAX_PATH), output_white_noise);
    }

    {
        char buffer[MAX_PATH] = { 0 };
        sprintf_s(buffer, MAX_PATH, "ObjectManager  misses: %I64u\n", MissesData[3]);
        fwrite(buffer, sizeof(char), strnlen_s(buffer, MAX_PATH), output_white_noise);
    }

    {
        char buffer[MAX_PATH] = { 0 };
        sprintf_s(buffer, MAX_PATH, "RegistryManage misses: %I64u\n", MissesData[4]);
        fwrite(buffer, sizeof(char), strnlen_s(buffer, MAX_PATH), output_white_noise);
    }

    fclose(output_white_noise);

    return 0;
}

int SetPSId(ULONG64 pid)
{
    DWORD le = 0;

    auto driver_handle = CreateAutoHandle(CreateFileW(DRIVER_NAME,
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL));

    if (!driver_handle) // op bool
    {
        DWORD le = GetLastError();

        printf("Failed to open a handle to ForensicsCollector : %d\n", le);

        return 1;
    }

    DWORD dwBytesReturned = 0;
    if (!DeviceIoControl(driver_handle.get(), SET_SIM_PS_ID, &pid, sizeof(ULONG64), NULL, 0, &dwBytesReturned, NULL))
    {
        printf("Failed to set simulation pid with error: %d\n", GetLastError());
        return 2;
    }

    return 0;
}

//
// Set forensics operation mode: ETW, FLTMgr, Compltion events
//
int SetScheme(ULONG64 mode)
{
    DWORD le = 0;

    auto driver_handle = CreateAutoHandle(CreateFileW(DRIVER_NAME,
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL));

    if (!driver_handle) // op bool
    {
        DWORD le = GetLastError();

        printf("Failed to open a handle to ForensicsCollector : %d\n", le);

        return 1;
    }

    DWORD dwBytesReturned = 0;
    if (!DeviceIoControl(driver_handle.get(), SET_SCHEME, &mode, sizeof(ULONG64), NULL, 0, &dwBytesReturned, NULL))
    {
        printf("Failed to set scheme mode with error: %d\n", GetLastError());
        return 2;
    }

    return 0;
}

int ClearStats()
{
    DWORD le = 0;

    auto driver_handle = CreateAutoHandle(CreateFileW(DRIVER_NAME,
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL));

    if (!driver_handle) // op bool
    {
        DWORD le = GetLastError();

        printf("Failed to open a handle to ForensicsCollector : %d\n", le);

        return 1;
    }

    DWORD dwBytesReturned = 0;
    if (!DeviceIoControl(driver_handle.get(), CLS_SIM_DATA, NULL, 0, NULL, 0, &dwBytesReturned, NULL))
    {
        printf("Failed to clear simulation data with error: %d\n", GetLastError());
        return 2;
    }

    return 0;
}

int GetCSVFile(const char* filename)
{
    DWORD le = 0;

    auto driver_handle = CreateAutoHandle(CreateFileW(DRIVER_NAME,
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL));

    if (!driver_handle) // op bool
    {
        DWORD le = GetLastError();

        printf("Failed to open a handle to ForensicsCollector : %d\n", le);

        return 1;
    }

    //
    // Save Forensics data to disk as CSV file
    //

    //
    // CSV File format
    // 
    // Type, Index, Latency 
    //

    FILE* output_csv = nullptr;

    if (fopen_s(&output_csv, filename, "w") != 0)
    {
        DWORD le = GetLastError();

        printf("Failed to open csv output file : %d\n", le);

        return 2;
    }

    //
    // Build the CSV Header
    //
    {
        const char* header = "Type,Index,RLatency,PLatency,Cycles,CS,PF\n";
        fwrite(header, sizeof(char), strnlen_s(header, MAX_PATH), output_csv);
    }

    ULONG64 CurrentPullIndex = 0;

    for (ULONG64 index = 1; index < MAX_EVENTS; ++index)
    {
        DWORD dwBytesReturned = 0;

        ULONG64 latency = 0;
        char buffer[MAX_PATH] = { 0 };

        if (DeviceIoControl(driver_handle.get(), GET_FLTMGR_EVENT, &index, sizeof(ULONG64), &latency, sizeof(ULONG64), &dwBytesReturned, NULL))
        {
            sprintf_s(buffer, MAX_PATH, "FltMgr,%I64u,%I64u,%I64u,%I64u,%lu,%d\n", index, latency, 
                PulledEventsStats[CurrentPullIndex].ElapsedMicroseconds.QuadPart, 
                CycleEventsStats[CurrentPullIndex].Cycles,
                CSEventsStats[CurrentPullIndex].CS,
                PFEventsStats[CurrentPullIndex].PFC);
            CurrentPullIndex++;

            fwrite(buffer, sizeof(char), strnlen_s(buffer, MAX_PATH), output_csv);
        }
    }

    for (ULONG64 index = 1; index < MAX_EVENTS; ++index)
    {
        DWORD dwBytesReturned = 0;
        ULONG64 latency = 0;
        char buffer[MAX_PATH] = { 0 };

        if (DeviceIoControl(driver_handle.get(), GET_CREATE_EVENT, &index, sizeof(ULONG64), &latency, sizeof(ULONG64), &dwBytesReturned, NULL))
        {
            sprintf_s(buffer, MAX_PATH, "CreateProc,%I64u,%I64u,%I64u,%I64u,%lu,%d\n", index, latency,
                PulledEventsStats[CurrentPullIndex].ElapsedMicroseconds.QuadPart,
                CycleEventsStats[CurrentPullIndex].Cycles,
                CSEventsStats[CurrentPullIndex].CS,
                PFEventsStats[CurrentPullIndex].PFC);
            CurrentPullIndex++;

            fwrite(buffer, sizeof(char), strnlen_s(buffer, MAX_PATH), output_csv);
        }
    }

    for (ULONG64 index = 1; index < MAX_EVENTS; ++index)
    {
        DWORD dwBytesReturned = 0;
        ULONG64 latency = 0;
        char buffer[MAX_PATH] = { 0 };

        if (DeviceIoControl(driver_handle.get(), GET_LOAD_EVENT, &index, sizeof(ULONG64), &latency, sizeof(ULONG64), &dwBytesReturned, NULL))
        {
            sprintf_s(buffer, MAX_PATH, "LoadImage,%I64u,%I64u,%I64u,%I64u,%lu,%d\n", index, latency,
                PulledEventsStats[CurrentPullIndex].ElapsedMicroseconds.QuadPart,
                CycleEventsStats[CurrentPullIndex].Cycles,
                CSEventsStats[CurrentPullIndex].CS,
                PFEventsStats[CurrentPullIndex].PFC);
            CurrentPullIndex++;

            fwrite(buffer, sizeof(char), strnlen_s(buffer, MAX_PATH), output_csv);
        }
    }

    for (ULONG64 index = 1; index < MAX_EVENTS; ++index)
    {
        DWORD dwBytesReturned = 0;
        ULONG64 latency = 0;
        char buffer[MAX_PATH] = { 0 };

        if (DeviceIoControl(driver_handle.get(), GET_OBJECT_EVENT, &index, sizeof(ULONG64), &latency, sizeof(ULONG64), &dwBytesReturned, NULL))
        {
            sprintf_s(buffer, MAX_PATH, "ObjectOp,%I64u,%I64u,%I64u,%I64u,%lu,%d\n", index, latency,
                PulledEventsStats[CurrentPullIndex].ElapsedMicroseconds.QuadPart,
                CycleEventsStats[CurrentPullIndex].Cycles,
                CSEventsStats[CurrentPullIndex].CS,
                PFEventsStats[CurrentPullIndex].PFC);
            CurrentPullIndex++;

            fwrite(buffer, sizeof(char), strnlen_s(buffer, MAX_PATH), output_csv);
        }
    }

    for (ULONG64 index = 1; index < MAX_EVENTS; ++index)
    {
        DWORD dwBytesReturned = 0;
        ULONG64 latency = 0;
        char buffer[MAX_PATH] = { 0 };

        if (DeviceIoControl(driver_handle.get(), GET_REGISTRY_EVENT, &index, sizeof(ULONG64), &latency, sizeof(ULONG64), &dwBytesReturned, NULL))
        {
            sprintf_s(buffer, MAX_PATH, "Reg,%I64u,%I64u,%I64u,%I64u,%lu,%d\n", index, latency,
                PulledEventsStats[CurrentPullIndex].ElapsedMicroseconds.QuadPart,
                CycleEventsStats[CurrentPullIndex].Cycles,
                CSEventsStats[CurrentPullIndex].CS,
                PFEventsStats[CurrentPullIndex].PFC);
            CurrentPullIndex++;

            fwrite(buffer, sizeof(char), strnlen_s(buffer, MAX_PATH), output_csv);
        }
    }

    fclose(output_csv);

    return 0;
}

int ParseCVSFile(const wchar_t* filename)
{
    std::wifstream infile(filename);

    if (infile.good())
    {
        wchar_t type[24] = { 0 };
        ULONG index = 0;
        ULONG latency = 0;

        printf("File %S open for parsing\n", filename);

        std::wstring line;

        //
        // FltMgr,1,1338
        //
        while (std::getline(infile, line))
        {
            const std::wregex base_regex(L"(\\w+),([0-9]+),([0-9]+)");
            std::wsmatch base_match;

            if (std::regex_match(line, base_match, base_regex))
            {
                if (base_match.size() == 4)
                {
                    std::wssub_match type_sub_match = base_match[1];
                    std::wstring type = type_sub_match.str();

                    std::wssub_match index_sub_match = base_match[2];
                    std::wstring index = index_sub_match.str();

                    std::wssub_match latency_sub_match = base_match[3];
                    std::wstring latency = latency_sub_match.str();

                    printf("%S %S %S\n", type.c_str(), index.c_str(), latency.c_str());
                }
            }
        }
    }
    else
    {
        printf("Failed to open %S for parsing (le:%d)\n", filename, GetLastError());
        return 1;
    }
    return 0;
}

enum event_type { FLTMGR, PSCRT, LDIMG, OBMGR, REGMGR };
int FixMissingEvents(std::function<bool(event_type event, ULONG64)> fn)
{
    DWORD le = 0;

    auto driver_handle = CreateAutoHandle(CreateFileW(DRIVER_NAME,
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL));

    if (!driver_handle) // op bool
    {

        DWORD le = GetLastError();

        printf("Failed to open a handle to ForensicsCollector : %d\n", le);

        return 1;
    }

    DWORD dwBytesReturned = 0;
    constexpr size_t INDEX_ARRAY_SIZE = 5;
    ULONG64 MissesData[INDEX_ARRAY_SIZE] = { 0 };
    if (
        !DeviceIoControl(
            driver_handle.get(),
            GET_ALL_INDEXES,
            NULL,
            0,
            &MissesData,
            sizeof(ULONG64) * INDEX_ARRAY_SIZE,
            &dwBytesReturned,
            NULL
        )
        )
    {
        printf("Failed to get index data with error: %d\n", GetLastError());
        return 2;
    }

    printf("FilterManager  index: %I64u\n", MissesData[0]);

    if (MissesData[0] < MAX_EVENTS)
        fn(FLTMGR, MAX_EVENTS - MissesData[0]);

    printf("CreationEvent  index: %I64u\n", MissesData[1]);

    if (MissesData[1] < MAX_EVENTS)
        fn(PSCRT, MAX_EVENTS - MissesData[1]);

    printf("LoadEvent      index: %I64u\n", MissesData[2]);

    if (MissesData[2] < MAX_EVENTS)
        fn(LDIMG, MAX_EVENTS - MissesData[2]);

    printf("ObjectManager  index: %I64u\n", MissesData[3]);

    if (MissesData[3] < MAX_EVENTS)
        fn(OBMGR, MAX_EVENTS - MissesData[3]);

    printf("RegistryManage index: %I64u\n", MissesData[4]);

    if (MissesData[4] < MAX_EVENTS)
        fn(OBMGR, MAX_EVENTS - MissesData[4]);

    return 0;
}

#pragma endregion

#pragma region ETW
DEFINE_GUID( /* a81a60b5-b6c0-47b0-a009-7e5414298da5 */    ForensicsProvider, 0xa81a60b5, 0xb6c0, 0x47b0, 0xa0, 0x09, 0x7e, 0x54, 0x14, 0x29, 0x8d, 0xa5);
#define ETWSessionName "ForensicsProvider"
#define ETWSessionNameWide L"ForensicsProvider"

typedef unsigned __int8(__fastcall* pEtwpGetNextEvent)(PVOID a1 /*struct _WMI_BUFFER_HEADER**/, PVOID a2 /*struct _TRACELOG_CONTEXT* */, unsigned int* a3, PVOID a4 /*struct _ETW_EVENT_INFO* */);

pEtwpGetNextEvent OriginalEtwpGetNextEvent = nullptr;

unsigned __int8 __fastcall HookedEtwpGetNextEvent(PVOID a1 /*struct _WMI_BUFFER_HEADER**/, PVOID a2 /*struct _TRACELOG_CONTEXT* */, unsigned int* a3, PVOID a4 /*struct _ETW_EVENT_INFO* */)
{
    unsigned __int8 ret = 0;
    LONG64 CurrentEventIndex = InterlockedIncrement64(&PullEventIndex);
    if (CurrentEventIndex > MAX_PULL_EVENTS) CurrentEventIndex = MAX_PULL_EVENTS;
    TimeOpStart();

    ret = OriginalEtwpGetNextEvent(a1, a2, a3, a4);

    // Using %, not 100% sure we might be called for all events
    TimeOpStop(PulledEventsStats[CurrentEventIndex % MAX_PULL_EVENTS].ElapsedMicroseconds.QuadPart, 
        CycleEventsStats[CurrentEventIndex % MAX_PULL_EVENTS].Cycles,
        CSEventsStats[CurrentEventIndex % MAX_PULL_EVENTS].CS,
        PFEventsStats[CurrentEventIndex % MAX_PULL_EVENTS].PFC);

    return ret;
}

PEVENT_TRACE_PROPERTIES AllocateETWSession()
{
    PEVENT_TRACE_PROPERTIES pProperties = NULL;
    size_t size = 0;


    size = sizeof(EVENT_TRACE_PROPERTIES) + sizeof(ETWSessionName);
    pProperties = (PEVENT_TRACE_PROPERTIES)malloc(size);
    if (NULL == pProperties)
    {
        printf("FATAL ERROR: unable to allocate memory (error code: %d)\n", GetLastError());
        return NULL;
    }

    memset(pProperties, 0, size);

    pProperties->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
    pProperties->Wnode.BufferSize = (ULONG)size;
    pProperties->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    pProperties->Wnode.ClientContext = 1;
    pProperties->Wnode.Guid = ForensicsProvider;
    pProperties->BufferSize = 1024;
    pProperties->MinimumBuffers = 4;
    pProperties->MaximumBuffers = 64;
    pProperties->MaximumFileSize = 0;
    pProperties->LogFileMode = EVENT_TRACE_REAL_TIME_MODE |
        EVENT_TRACE_NO_PER_PROCESSOR_BUFFERING | EVENT_TRACE_SYSTEM_LOGGER_MODE;
    pProperties->EnableFlags = 0xffffff;
    pProperties->FlushTimer = 0;
    pProperties->LogFileNameOffset = 0;


    strcpy_s((char*)pProperties + pProperties->LoggerNameOffset,
        size - pProperties->LoggerNameOffset, ETWSessionName);

    return pProperties;
}

TRACEHANDLE StartETWSession()
{
    PEVENT_TRACE_PROPERTIES pProperties;

    pProperties = AllocateETWSession();
    if (nullptr == pProperties)
    {
        return 0;
    }

    TRACEHANDLE hTraceSession;
    ULONG ret = StartTraceA(&hTraceSession, ETWSessionName, pProperties);

    if (ERROR_ALREADY_EXISTS == ret)
    {
        printf("Session already started (le: %d)\n", GetLastError());
        free(pProperties);
        return 0;
    }

    if (ERROR_SUCCESS != ret)
    {
        printf("Error starting trace session (le: %d)\n", GetLastError());
        free(pProperties);
        return 0;
    }

    ret = EnableTraceEx2(hTraceSession, &ForensicsProvider, EVENT_CONTROL_CODE_ENABLE_PROVIDER, TRACE_LEVEL_VERBOSE, 0, 0, 0, NULL);

    if (ERROR_SUCCESS != ret)
    {
        printf("Error enabling trace session (le: %d)\n", GetLastError());
        free(pProperties);
        return 0;
    }

    // Todo(Nina): Use C++11
    free(pProperties);
    return hTraceSession;
}

PEVENT_TRACE_PROPERTIES StopETWSession(TRACEHANDLE hTraceSession)
{
    PEVENT_TRACE_PROPERTIES pProperties;

    pProperties = AllocateETWSession();
    if (NULL == pProperties)
    {
        return NULL;
    }

    ULONG ret;

    ret = ControlTrace(hTraceSession, NULL, pProperties, EVENT_TRACE_CONTROL_FLUSH);
    if (ERROR_SUCCESS != ret) {
        printf("Error flushing trace session (le: %d)\n", GetLastError());
    }

    ret = ControlTrace(hTraceSession, NULL, pProperties, EVENT_TRACE_CONTROL_STOP);
    if (ERROR_SUCCESS != ret)
    {
        // Might return ERROR_MORE_DATA (We are ok with it)

        printf("Error stopping trace session (le: %d)\n", GetLastError());
        return NULL;
    }

    return pProperties;
}

bool PullETWEvents()
{
    TRACEHANDLE handles[1];
    EVENT_TRACE_LOGFILE MemoryLogFile;

    memset(&MemoryLogFile, 0, sizeof(EVENT_TRACE_LOGFILE));

    MemoryLogFile.LoggerName = (LPWSTR)ETWSessionNameWide;
    MemoryLogFile.LogFileName = NULL;

    //
    // See: https://docs.microsoft.com/en-us/windows/win32/api/evntrace/ns-evntrace-event_trace_logfilea
    //
    MemoryLogFile.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_RAW_TIMESTAMP | PROCESS_TRACE_MODE_EVENT_RECORD;

    // typedef VOID (WINAPI *PEVENT_RECORD_CALLBACK) (PEVENT_RECORD EventRecord);
    MemoryLogFile.EventRecordCallback = [](PEVENT_RECORD EventRecord) {

#if 0 //Debugging
        // The beauty of C++11
        auto& header = EventRecord->EventHeader;

        if (EventRecord->UserData) {
            printf("[%d:%d]: ", header.ProcessId, header.ThreadId);
            hexdump(EventRecord->UserData, EventRecord->UserDataLength);
            printf("\n");
        }
#endif
    };

    // typedef ULONG (WINAPI * PEVENT_TRACE_BUFFER_CALLBACKW) (PEVENT_TRACE_LOGFILEW Logfile);
    // https://docs.microsoft.com/en-us/windows/win32/api/evntrace/nc-evntrace-pevent_trace_buffer_callbackw
    // Return TRUE To continue processing events.
    MemoryLogFile.BufferCallback = [](PEVENT_TRACE_LOGFILEW Logfile) -> ULONG {return 1; };

    MemoryLogFile.IsKernelTrace = true;

    handles[0] = OpenTrace(&MemoryLogFile);
    if ((TRACEHANDLE)INVALID_HANDLE_VALUE == handles[0])
    {
        printf("ETW ERROR: OpenTrace failed (error code: %d)\n", GetLastError());
        return false;
    }
    else
    {
        printf("Retrieving ETW events\n");

        //
        // Hook unsigned __int8 __fastcall EtwpGetNextEvent(struct _WMI_BUFFER_HEADER *, struct _TRACELOG_CONTEXT *, unsigned int *, struct _ETW_EVENT_INFO *)
        //

        HMODULE sechost = LoadLibrary(L"sechost.dll");

        if (sechost)
        {
            OriginalEtwpGetNextEvent = (pEtwpGetNextEvent)Add2Ptr(sechost, 0x34ac);

            DetourTransactionBegin();
            DetourUpdateThread(GetCurrentThread());
            DetourAttach(&(PVOID&)OriginalEtwpGetNextEvent, HookedEtwpGetNextEvent);
            LONG error = DetourTransactionCommit();

            if (error == NO_ERROR) {
                printf("Successfully hooked EtwpGetNextEvent\n");
            }
            else {
                printf("Failed to hook EtwpGetNextEvent, error = %ld\n", error);
            }
        }

        ProcessTrace(handles, 1, 0, 0); //Blocing! Until StopETWSession occurs

        if (sechost)
        {
            DetourTransactionBegin();
            DetourUpdateThread(GetCurrentThread());
            DetourDetach(&(PVOID&)OriginalEtwpGetNextEvent, HookedEtwpGetNextEvent);
            LONG error = DetourTransactionCommit();

            if (error == NO_ERROR) {
                printf("Successfully UNhooked EtwpGetNextEvent\n");
            }
            else {
                printf("Failed to UNhook EtwpGetNextEvent, error = %ld\n", error);
            }
        }

        printf("Stopped retrieving ETW events\n");
        CloseTrace(handles[0]);
    }

    return true;
}

#pragma endregion

#pragma region Buffered Events Handlers

#define FC_PORT_NAME                   L"\\ForensicsCollectorPort"
#define MAX_NAME_SIZE 256
#define POLL_LATENCY  100              // 100 milliseconds
#define DB_BUFFER_MAX_SIZE 1024

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
#define OBJECTMGR_CRKRNL_HANDLE 0x80000003

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

bool IsSimulationFinished()
{
    DWORD le = 0;

    auto driver_handle = CreateAutoHandle(CreateFileW(DRIVER_NAME,
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL));

    if (!driver_handle) // op bool
    {
        DWORD le = GetLastError();

        printf("Failed to open a handle to ForensicsCollector : %d\n", le);

        return false;
    }

    DWORD dwBytesReturned = 0;
    if (!DeviceIoControl(driver_handle.get(), IS_SIM_DONE, NULL, 0, NULL, 0, &dwBytesReturned, NULL))
    {
        // Simulation still running
        return false;
    }

    return true;
}

LONG64 g_flt_shutdown_event = 0;

void PullBufferedEvents()
{
    std::thread t([&]
        {
            HRESULT result = S_OK;
            HANDLE port = INVALID_HANDLE_VALUE;
            DWORD bytesReturned = 0;
            PVOID EventBuffer[sizeof(EVENT_DATA) / sizeof(PVOID)];
            PCHAR buffer = (PCHAR)EventBuffer;
            FILE* dummy_db = nullptr;
            PVOID DummyInput = nullptr;
            char db_buffer[DB_BUFFER_MAX_SIZE];

#if (WRITE_DB == 1)
            if (fopen_s(&dummy_db, "dummy_flt.db", "w") != 0)
            {
                printf("Failed to create dummy db le:%d\n", GetLastError());
                return;
            }
#endif

            result = FilterConnectCommunicationPort(FC_PORT_NAME,
                0,
                NULL,
                0,
                NULL,
                &port);

            if (IS_ERROR(result))
            {
                printf("Could not connect to Forensics Collector: 0x%08x\n", result);
                return;
            }

            for (;;)
            {
                //
                // Break when we reach 100% events
                //
                if (1 == InterlockedCompareExchange64(&g_flt_shutdown_event, 0, 1))
                {
                    InterlockedDecrement64(&g_flt_shutdown_event);
                    printf("Closing Buffered Events collection\n");

#if (WRITE_DB == 1)
                    fclose(dummy_db);
#endif
                    break;
                }

                //
                // Time the pulling operation from kernel to usermode
                //
                LONG64 CurrentEventIndex = InterlockedIncrement64(&PullEventIndex);
                if (CurrentEventIndex > MAX_PULL_EVENTS) CurrentEventIndex = MAX_PULL_EVENTS;
                TimeOpStart();

                result = FilterSendMessage(port,
                    &DummyInput,
                    sizeof(PVOID),
                    buffer,
                    sizeof(EventBuffer),
                    &bytesReturned);

                TimeOpStop(PulledEventsStats[CurrentEventIndex].ElapsedMicroseconds.QuadPart, 
                    CycleEventsStats[CurrentEventIndex].Cycles,
                    CSEventsStats[CurrentEventIndex].CS,
                    PFEventsStats[CurrentEventIndex].PFC);

                if (IS_ERROR(result))
                {

                    if (HRESULT_FROM_WIN32(ERROR_INVALID_HANDLE) == result)
                    {

                        printf("Forensics Collector unloaded\n");
                        break;
                    }
                    else
                    {
                        Sleep(POLL_LATENCY);
                    }

                    continue;
                }

                //
                // We read event one by one from the driver
                // We might consider reading several at once
                // It would be best if they can fit one page (4k)
                // You can actually fit 7 logs in one call
                //

                // TODO(Nina)!!!: fill the events in one page in the driver
                // Check single event size first

                PEVENT_DATA received_event = (PEVENT_DATA)buffer;
                RtlZeroMemory(db_buffer, DB_BUFFER_MAX_SIZE);

                if (received_event) // just in case?!
                {
                    switch (received_event->TypeAndFlags)
                    {
                    case FILTERMGR_EVENT_TYPE:
                    {
                        sprintf_s(db_buffer, DB_BUFFER_MAX_SIZE,
                            "FilterManager Event: [%I64u:%I64u] %S \n",
                            received_event->ProcessId,
                            received_event->ThreadId,
                            received_event->Name1 ? received_event->Name1 : L" EMPTY "
                        );

                    } break;

                    case CREATEPS_EVENT_TYPE:
                    {
                        sprintf_s(db_buffer, DB_BUFFER_MAX_SIZE,
                            "CreateProcess Event: Process Destroyed [%I64u:%I64u]\n",
                            received_event->ProcessId,
                            received_event->ThreadId
                        );

                    } break;

                    case LOADIMAGE_EVENT_TYPE:
                    {
                        sprintf_s(db_buffer, DB_BUFFER_MAX_SIZE,
                            "Load Image Event: [%I64u:%I64u] %S Loaded\n",
                            received_event->ProcessId,
                            received_event->ThreadId,
                            received_event->Name1 ? received_event->Name1 : L" EMPTY "
                        );

                    } break;

                    case OBJECTMGR_CRKRNL_HANDLE:
                    case OBJECTMGR_CREATE_HANDLE:
                    case OBJECTMGR_KERNEL_HANDLE:
                    case OBJECTMGR_EVENT_TYPE:
                    {
                        sprintf_s(db_buffer, DB_BUFFER_MAX_SIZE,
                            "Ob Event: [%I64u:%I64u] KM/UM Object:%I64u Access:%I64u OP:%S \n",
                            received_event->ProcessId,
                            received_event->ThreadId,
                            received_event->ExParam1,
                            received_event->ExParam2,
                            received_event->Name1 ? received_event->Name1 : L" EMPTY "
                        );

                    } break;

                    case REG_MNGR_EVENT_TYPE:
                    {
                        sprintf_s(db_buffer, DB_BUFFER_MAX_SIZE,
                            "Registry Manager Event: [%I64u:%I64u] Registry OP:%S \n",
                            received_event->ProcessId,
                            received_event->ThreadId,
                            received_event->Name1 ? received_event->Name1 : L" EMPTY "
                        );
                    } break;

                    case CREATEPS_CREATE_BOOL:
                    {
                        sprintf_s(db_buffer, DB_BUFFER_MAX_SIZE,
                            "Create Process Event: [%I64u:%I64u] %S (%S) Created\n",
                            received_event->ProcessId,
                            received_event->ThreadId,
                            received_event->Name1 ? received_event->Name2 : L" EMPTY ",
                            received_event->Name1 ? received_event->Name1 : L" EMPTY "
                        );

                    } break;

                    default:
                        printf("ERROR!!! Wrong Type or Event registered\n");
                        FC_ASSERT(0);
                    };

                    // Retain the event in the dummy db
#if (WRITE_DB == 1)
                    db_buffer[DB_BUFFER_MAX_SIZE - 1] = '\0';
                    fwrite(db_buffer, sizeof(char), strnlen_s(db_buffer, DB_BUFFER_MAX_SIZE), dummy_db);
                    fflush(dummy_db);
#endif
                }
            }
        }
    );

    t.detach();
}

#pragma endregion

#pragma region Event Driven Handlers

HANDLE g_driver_handle = nullptr;
LONG64 g_evt_shut_down = 0;
void PullDrivenEvents()
{
    if (g_driver_handle == nullptr)
    {
        DWORD le = 0;

        g_driver_handle = CreateFileW(DRIVER_NAME,
            GENERIC_READ | GENERIC_WRITE,
            0,
            NULL,
            CREATE_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            NULL);

        if (INVALID_HANDLE_VALUE == g_driver_handle)
        {

            DWORD le = GetLastError();

            printf("Failed to open a handle to ForensicsCollector : %d\n", le);

            return;
        }
    }

    std::thread t([&]
        {
            HRESULT result = S_OK;
            HANDLE port = INVALID_HANDLE_VALUE;
            DWORD bytesReturned = 0;
            PVOID EventBuffer[sizeof(EVENT_DATA) / sizeof(PVOID)];
            PCHAR buffer = (PCHAR)EventBuffer;
            FILE* dummy_db = nullptr;
            char db_buffer[DB_BUFFER_MAX_SIZE];

#if (WRITE_DB == 1)
            if (fopen_s(&dummy_db, "dummy_evt.db", "w") != 0)
            {
                printf("Failed to create dummy db le:%d\n", GetLastError());
                return;
            }
#endif
            HANDLE read_event = CreateEvent(NULL, TRUE, FALSE, NULL);

            if (read_event == NULL)
            {
                printf("Failed to create read event le:%d\n", GetLastError());
                return;
            }

            for (;;)
            {
                //
                // Break when we reach 100% events
                //
                if (1 == InterlockedCompareExchange64(&g_evt_shut_down, 0, 1))
                {
                    InterlockedDecrement64(&g_evt_shut_down);
                    printf("Closing evt db\n");
#if (WRITE_DB == 1)
                    fclose(dummy_db);
#endif
                    break;
                }

                //
                // Welcome to the async world ;)
                //
                OVERLAPPED overlapped;
                ZeroMemory(&overlapped, sizeof(OVERLAPPED));
                ResetEvent(read_event);

                overlapped.hEvent = read_event;

                //
                // Time the pulling operation from kernel to usermode
                //
                LONG64 CurrentEventIndex = InterlockedIncrement64(&PullEventIndex);
                if (CurrentEventIndex > MAX_PULL_EVENTS) CurrentEventIndex = MAX_PULL_EVENTS;

                TimeOpStart();

                BOOL read_result = ReadFile(g_driver_handle, EventBuffer, sizeof(EVENT_DATA), &bytesReturned, &overlapped);
                DWORD last_error = GetLastError();

                if (read_result)
                {
                    // Success
                }
                else if (last_error == ERROR_IO_PENDING)
                {
                    DWORD bytes_received = 0;
                    if (GetOverlappedResult(g_driver_handle, &overlapped, &bytes_received, TRUE /*WAIT HERE*/) == FALSE)
                    {
                        //
                        // We failed, bail out of here
                        //
                        DWORD overlapped_error = GetLastError();

                        if (ERROR_OPERATION_ABORTED == overlapped_error || ERROR_INVALID_HANDLE == overlapped_error)
                            break;

                        //
                        // Disable all pending IRPs
                        //
                        CancelIo(g_driver_handle);

                        printf("Failed to get pending events, bailing out le: %d ole: %d\n", last_error, overlapped_error);
                    }

                    last_error = GetLastError();
                    bytesReturned = bytes_received;
                }
                else if (ERROR_OPERATION_ABORTED == last_error || ERROR_INVALID_HANDLE == last_error)
                {
                    break;
                }
                else
                {
                    printf("Failed to read from the file, le: %d\n", last_error);
                }

                if (bytesReturned != sizeof(EVENT_DATA))
                {
                    //
                    // Oops, size does not match
                    //
                    FC_ASSERT(0);
                }

                TimeOpStop(PulledEventsStats[CurrentEventIndex].ElapsedMicroseconds.QuadPart, 
                    CycleEventsStats[CurrentEventIndex].Cycles,
                    CSEventsStats[CurrentEventIndex].CS,
                    PFEventsStats[CurrentEventIndex].PFC);

                PEVENT_DATA received_event = (PEVENT_DATA)EventBuffer;
                RtlZeroMemory(db_buffer, DB_BUFFER_MAX_SIZE);

                if (received_event) // just in case?!
                {
                    switch (received_event->TypeAndFlags)
                    {
                    case FILTERMGR_EVENT_TYPE:
                    {
                        sprintf_s(db_buffer, DB_BUFFER_MAX_SIZE,
                            "FilterManager Event: [%I64u:%I64u] %S \n",
                            received_event->ProcessId,
                            received_event->ThreadId,
                            received_event->Name1 ? received_event->Name1 : L" EMPTY "
                        );

                    } break;

                    case CREATEPS_EVENT_TYPE:
                    {
                        sprintf_s(db_buffer, DB_BUFFER_MAX_SIZE,
                            "CreateProcess Event: Process Destroyed [%I64u:%I64u]\n",
                            received_event->ProcessId,
                            received_event->ThreadId
                        );

                    } break;

                    case LOADIMAGE_EVENT_TYPE:
                    {
                        sprintf_s(db_buffer, DB_BUFFER_MAX_SIZE,
                            "Load Image Event: [%I64u:%I64u] %S Loaded\n",
                            received_event->ProcessId,
                            received_event->ThreadId,
                            received_event->Name1 ? received_event->Name1 : L" EMPTY "
                        );

                    } break;

                    case OBJECTMGR_CRKRNL_HANDLE:
                    case OBJECTMGR_CREATE_HANDLE:
                    case OBJECTMGR_KERNEL_HANDLE:
                    case OBJECTMGR_EVENT_TYPE:
                    {
                        sprintf_s(db_buffer, DB_BUFFER_MAX_SIZE,
                            "Ob Event: [%I64u:%I64u] KM/UM Object:%I64u Access:%I64u OP:%S \n",
                            received_event->ProcessId,
                            received_event->ThreadId,
                            received_event->ExParam1,
                            received_event->ExParam2,
                            received_event->Name1 ? received_event->Name1 : L" EMPTY "
                        );

                    } break;

                    case REG_MNGR_EVENT_TYPE:
                    {
                        sprintf_s(db_buffer, DB_BUFFER_MAX_SIZE,
                            "Registry Manager Event: [%I64u:%I64u] Registry OP:%S \n",
                            received_event->ProcessId,
                            received_event->ThreadId,
                            received_event->Name1 ? received_event->Name1 : L" EMPTY "
                        );
                    } break;

                    case CREATEPS_CREATE_BOOL:
                    {
                        sprintf_s(db_buffer, DB_BUFFER_MAX_SIZE,
                            "Create Process Event: [%I64u:%I64u] %S (%S) Created\n",
                            received_event->ProcessId,
                            received_event->ThreadId,
                            received_event->Name1 ? received_event->Name2 : L" EMPTY ",
                            received_event->Name1 ? received_event->Name1 : L" EMPTY "
                        );

                    } break;

                    default:
                        printf("ERROR!!! Wrong Type or Event registered\n");
                        FC_ASSERT(0);
                    };

                    // Retain the event in the dummy db
#if (WRITE_DB == 1)
                    db_buffer[DB_BUFFER_MAX_SIZE - 1] = '\0';
                    fwrite(db_buffer, sizeof(char), strnlen_s(db_buffer, DB_BUFFER_MAX_SIZE), dummy_db);
                    fflush(dummy_db);
#endif
                }
            }
        }
    );

    t.detach();
}

#pragma endregion

#pragma region EventGenerators 

//
// Event generators
//
struct FileEvent
{
    HANDLE hFile = INVALID_HANDLE_VALUE;

    FileEvent()
    {
        //
        // Create random file
        //
        DWORD written = 0;

        std::stringstream ss;
        int random_number = rand() % (1 << 31) + 1;

        ss << random_number;

        hFile = CreateFileA(ss.str().c_str(), GENERIC_ALL, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL | FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_DELETE_ON_CLOSE, NULL);

        if (hFile) WriteFile(hFile, &random_number, sizeof(int), &written, NULL);
    }

    ~FileEvent()
    {
        if (INVALID_HANDLE_VALUE != hFile)
            CloseHandle(hFile);
    }
};

struct RegistryOperation
{
    DWORD type = REG_SZ;
    HKEY hkey = nullptr;
    const char* sub_key = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion";
    const char* key = "ProgramFilesDir";

    RegistryOperation()
    {
        if (RegOpenKeyA(HKEY_LOCAL_MACHINE, sub_key, &hkey) == ERROR_SUCCESS)
        {
            char key_value[256] = { 0 };
            DWORD key_size = sizeof(key_value);

            if (RegQueryValueExA(
                hkey,
                key,
                NULL,
                NULL,
                reinterpret_cast<LPBYTE>(&key_value),
                &key_size)
                != ERROR_SUCCESS)
            {
                printf("QueryReg failed (%d).\n", GetLastError());
            }
        }
    }

    ~RegistryOperation()
    {
        if (hkey) RegCloseKey(hkey);
    }
};

struct CreationEvent
{
    const char* program = "C:\\Windows\\System32\\notepad.exe";
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;

    CreationEvent()
    {
        ZeroMemory(&si, sizeof(si));
        si.cb = sizeof(si);
        ZeroMemory(&pi, sizeof(pi));

        if (!CreateProcessA(NULL,   // No module name (use command line)
            (LPSTR)program,        // Command line
            NULL,           // Process handle not inheritable
            NULL,           // Thread handle not inheritable
            FALSE,          // Set handle inheritance to FALSE
            CREATE_SUSPENDED, // Suspend the created process to save time
            NULL,           // Use parent's environment block
            NULL,           // Use parent's starting directory 
            &si,            // Pointer to STARTUPINFO structure
            &pi)           // Pointer to PROCESS_INFORMATION structure
            )
        {
            printf("CreateProcess failed (%d).\n", GetLastError());
        }
    }

    ~CreationEvent()
    {
        WaitForSingleObject(pi.hProcess, 10);
        TerminateProcess(pi.hProcess, 0);
        WaitForSingleObject(pi.hProcess, 10);

        if (pi.hProcess) CloseHandle(pi.hProcess);
        if (pi.hThread)  CloseHandle(pi.hThread);
    }
};

struct LoadImageEvent
{
    HMODULE dll = nullptr;

    LoadImageEvent()
    {
        dll = LoadLibraryA("C:\\Windows\\System32\\Drivers\\ForensicsCollector.sys");

        if (dll == nullptr)
        {
            printf("Failed to load ForensicsCollector.sys le: %d\n", GetLastError());
        }
        else
        {
            //
            // Simulate work
            //
            FARPROC far_proc = GetProcAddress(dll, "DummyFunction");
            if (far_proc) far_proc = GetProcAddress(dll, "DummyFunction2");
        }
    }

    ~LoadImageEvent()
    {
        if (dll)
        {
            for (int i = 0; i < 5; ++i)
            {
                BOOL Freed = FreeLibrary(dll);

                if (Freed != FALSE)
                    break;
                else
                    printf("Failed to unload ForensicsCollector.sys le: %d\n", GetLastError());
            }
        }
    }
};

struct ObjectManagerEvent
{
    HANDLE process = nullptr;
    HANDLE target_handle = nullptr;
    ObjectManagerEvent()
    {
        process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, GetCurrentProcessId());

        if (NULL == process)
        {
            printf("Failed to open a handle to myself le: %d\n", GetLastError());
        }
        else
        {
            DuplicateHandle(GetCurrentProcess(), process, GetCurrentProcess(), &target_handle, 0, FALSE, DUPLICATE_SAME_ACCESS);

            if (NULL == target_handle)
            {
                printf("Failed to duplicate a handle to myself le: %d\n", GetLastError());
            }
        }
    }

    ~ObjectManagerEvent()
    {
        if (process)       CloseHandle(process);
        if (target_handle) CloseHandle(target_handle);
    }
};

int GenerateEvents()
{
    srand(1);

    for (int i = 0; i < MAX_EVENTS + 1; ++i)
    {
        {
            FileEvent fe;
        }

        {
            RegistryOperation ro;
        }

        {
            CreationEvent ce;
        }

        {
            LoadImageEvent le;
        }

        {
            ObjectManagerEvent oe;
        }
    }

    return 0;
}

int GenerateETWEvents(int rounds)
{
    printf("Running: GenerateETWEvents\n");
    SetScheme(ETW_ON_FLAG);
    //system("logman create trace \"FC\" -ow -o file.etl -p \"{A81A60B5-B6C0-47B0-A009-7E5414298DA5}\" 0xffffffff 0xff -ets");
    auto ETWTraceHandle = StartETWSession();

    // Start pulling ETW Events
    std::thread t([&] {
        PullETWEvents();
        });
    t.detach();

    for (int i = 0; i < rounds; ++i)
    {
        std::stringstream ss;
        //
        // Can fail if ran for the first time
        //
        ClearStats();
        ClearPullStats();

        if (SetPSId(GetCurrentProcessId()) != 0)
        {
            printf("Error setting pid for stats\n");
            return 2;
        }

        if (GenerateEvents() != 0)
        {
            printf("Error generating events for the driver\n");
            return 3;
        }

        FixMissingEvents(
            [](event_type event, ULONG64 misses)
            {
                for (int i = 0; i < misses + 1; ++i)
                {
                    switch (event)
                    {
                    case FLTMGR:
                    {
                        FileEvent fe;
                    } break;

                    case PSCRT:
                    {
                        CreationEvent ce;
                    } break;

                    case LDIMG:
                    {
                        LoadImageEvent le;
                    } break;

                    case OBMGR:
                    {
                        ObjectManagerEvent oe;
                    } break;

                    case REGMGR:
                    {
                        RegistryOperation ro;
                    } break;

                    default:
                        printf("Wrong event type\n");
                        FC_ASSERT(0);
                    };
                }

                return true;
            }
        );

        printf("Flushing events\n");

        ss << "etw." << i;

        if (GetCSVFile(ss.str().c_str()) != 0)
        {
            printf("Error generating CSV file\n");
            return 4;
        }

        printf("White Noise stats\n");

        if (GetMisses("wh_etw", i) != 0)
        {
            printf("Failed getting misses information\n");
            return 5;
        }

    }

    //system("logman stop \"FC\" -ets");
    StopETWSession(ETWTraceHandle);

    printf("Finished running: GenerateETWEvents\n\n");
    return 0;
}

int GenerateBufEvents(int rounds)
{
    printf("Running: GenerateFltEvents\n");

    SetScheme(FLT_ON_FLAG);

    PullBufferedEvents();

    for (int i = 0; i < rounds; ++i)
    {
        std::stringstream ss;

        //
        // Can fail if ran for the first time
        //
        ClearStats();
        ClearPullStats();

        if (SetPSId(GetCurrentProcessId()) != 0)
        {
            printf("Error setting pid for stats\n");
            return 2;
        }

        if (GenerateEvents() != 0)
        {
            printf("Error generating events for the driver\n");
        }

        FixMissingEvents(
            [](event_type event, ULONG64 misses)
            {
                for (int i = 0; i < misses + 1; ++i)
                {
                    switch (event)
                    {
                    case FLTMGR:
                    {
                        FileEvent fe;
                    } break;

                    case PSCRT:
                    {
                        CreationEvent ce;
                    } break;

                    case LDIMG:
                    {
                        LoadImageEvent le;
                    } break;

                    case OBMGR:
                    {
                        ObjectManagerEvent oe;
                    } break;

                    case REGMGR:
                    {
                        RegistryOperation ro;
                    } break;

                    default:
                        printf("Wrong event type\n");
                        FC_ASSERT(0);
                    };
                }

                return true;
            }
        );

        printf("Flushing events\n");

        ss << "buf." << i;

        if (GetCSVFile(ss.str().c_str()) != 0)
        {
            printf("Error generating CSV file\n");
            return 4;
        }

        printf("White Noise stats\n");

        if (GetMisses("wh_flt", i) != 0)
        {
            printf("Failed getting misses information\n");
            return 5;
        }
    }

    InterlockedIncrement64(&g_flt_shutdown_event);

    printf("Finished running GenerateFltEvents\n\n");
    return 0;
}

//
// Use with performance analyzer:
// CollectWPR.cmd "ForensicsConsumer.exe SIM_EVT"
//
int GenerateEvtEvents(int run_index)
{
    //
    // Can fail if ran for the first time
    //
    ClearStats();
    ClearPullStats();

    if (SetPSId(GetCurrentProcessId()) != 0)
    {
        printf("Error setting pid for stats\n");
        return 2;
    }

    std::thread t([]
        {
            if (GenerateEvents() != 0)
            {
                printf("Error generating events for the driver\n");
            }
        }
    );

    {
        PullDrivenEvents();
        t.join();

        //
        // We must close the handle here, because we can open the driver handle once!
        //
        if (g_driver_handle)
        {
            InterlockedIncrement64(&g_evt_shut_down);
            CancelIoEx(g_driver_handle, NULL);
            CloseHandle(g_driver_handle);
            g_driver_handle = nullptr;
        }
    }

    printf("Flushing events\n");

    std::stringstream ss;

    ss << "evt." << run_index;

    if (GetCSVFile(ss.str().c_str()) != 0)
    {
        printf("Error generating CSV file\n");
        return 4;
    }

    printf("White Noise stats\n");

    if (GetMisses("wh_evt", run_index) != 0)
    {
        printf("Failed getting misses information\n");
        return 5;
    }

    return 0;
}

int GenerateAllEvents(int rounds)
{
    int result = ERROR_SUCCESS;

    for (;;) {
        result = GenerateETWEvents(rounds);
        if (result) break;

        result = GenerateBufEvents(rounds);
        if (result) break;

        SetScheme(CMT_ON_FLAG);
        for (auto i = 0; i < rounds; ++i)
        {
            result = GenerateEvtEvents(i);
            if (result) break;
        }

        break;
    }

    return result;
}

#pragma endregion

int wmain(int argc, wchar_t* argv[])
{
    printf("Forensics Consumer ver 1.0\n");

    if (argc < 2)
    {
        printf("Usage:\n");
        printf("CLS_STAT: clear statistical data\n");
        printf("SET_PS_ID: set simulation id\n");
        printf("GET_MISSES: get the misses stats\n");
        printf("GET_CSV: create csv with simulated data\n");
        printf("GET_BUF: Fetch all buffered events\n");
        printf("GEN_EVT: generate events\n");
        printf("SIM_ETW: Generate evetns for ETW consumer\n");
        printf("SIM_BUF: Generate events for FltMgr consumer\n");
        printf("SIM_EVT: Generate evetns for Event Driven consumer\n");
        printf("SIM_ALL: Generate all evetns for EVT, ETW, FLTMgr\n");
        printf("PRS_CSV: Parse CSV file\n");
        printf("FIX_IND: Show Index data\n");

        return 1;
    }

    const std::wstring command = argv[1];

    if (command == L"CLS_STAT")
        return ClearStats();
    else if (command == L"SET_PS_ID")
        return SetPSId(_wtoi64(argv[2]));
    else if (command == L"GET_MISSES")
        return GetMisses("wh", 0);
    else if (command == L"GET_CSV")
        return GetCSVFile("output.csv");
    else if (command == L"GEN_EVT")
        return GenerateEvents();
    else if (command == L"SIM_ETW")
        return GenerateETWEvents(_wtoi(argv[2]));
    else if (command == L"SIM_BUF")
        return GenerateBufEvents(_wtoi(argv[2]));
    else if (command == L"SIM_EVT")
        return GenerateEvtEvents(_wtoi(argv[2]));
    else if (command == L"SIM_ALL")
        return GenerateAllEvents(_wtoi(argv[2]) != 0 ? _wtoi(argv[2]) : 2);
    else if (command == L"FIX_IND")
        return FixMissingEvents([](event_type type, ULONG64 index_value) { return true; });
    else if (command == L"PRS_CSV")
        return ParseCVSFile(argv[2]);
    else
    {
        printf("Could not find the option: %S\n", command.c_str());
    }
    return 0;
}