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

#include <Windows.h>
#include <fltUser.h>
#include <stdio.h>

#include <string>
#include <memory>
#include <thread>

#pragma comment (lib, "fltlib.lib")

#define FC_ASSERT(x) if (!x) DebugBreak();

#define DRIVER_NAME L"\\\\.\\ForensicsCollector"

#define PAGE_SIZE   4096
#define MAX_EVENTS  5000

#define GET_FLTMGR_EVENT   CTL_CODE( FILE_DEVICE_UNKNOWN, 0x901, METHOD_BUFFERED, FILE_ANY_ACCESS  )
#define GET_CREATE_EVENT   CTL_CODE( FILE_DEVICE_UNKNOWN, 0x902, METHOD_BUFFERED, FILE_ANY_ACCESS  )
#define GET_LOAD_EVENT     CTL_CODE( FILE_DEVICE_UNKNOWN, 0x903, METHOD_BUFFERED, FILE_ANY_ACCESS  )
#define GET_OBJECT_EVENT   CTL_CODE( FILE_DEVICE_UNKNOWN, 0x904, METHOD_BUFFERED, FILE_ANY_ACCESS  )
#define GET_REGISTRY_EVENT CTL_CODE( FILE_DEVICE_UNKNOWN, 0x905, METHOD_BUFFERED, FILE_ANY_ACCESS  )
#define GET_ALL_MISSES     CTL_CODE( FILE_DEVICE_UNKNOWN, 0x906, METHOD_BUFFERED, FILE_ANY_ACCESS  )
#define SET_SIM_PS_ID      CTL_CODE( FILE_DEVICE_UNKNOWN, 0x907, METHOD_BUFFERED, FILE_ANY_ACCESS  )
#define CLS_SIM_DATA       CTL_CODE( FILE_DEVICE_UNKNOWN, 0x908, METHOD_BUFFERED, FILE_ANY_ACCESS  )
#define IS_SIM_DONE        CTL_CODE( FILE_DEVICE_UNKNOWN, 0x909, METHOD_BUFFERED, FILE_ANY_ACCESS  )

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

#pragma region Statistics
int GetMisses()
{
    DWORD le = 0;

    auto driver_handle = CreateAutoHandle(CreateFileW(DRIVER_NAME,
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL));

    if(!driver_handle) // op bool
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

    printf("FilterManager  misses: %I64u\n", MissesData[0]);
    printf("CreationEvent  misses: %I64u\n", MissesData[1]);
    printf("LoadEvent      misses: %I64u\n", MissesData[2]);
    printf("ObjectManager  misses: %I64u\n", MissesData[3]);
    printf("RegistryManage misses: %I64u\n", MissesData[4]);

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

int GetCSVFile()
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

    if (fopen_s(&output_csv, "output.csv", "w") != 0)
    {
        DWORD le = GetLastError();

        printf("Failed to open csv output file : %d\n", le);

        return 2;
    }

    //
    // Build the CSV Header
    //
    {
        const char* header = "Type,Index,Latency\n";
        fwrite(header, sizeof(char), strnlen_s(header, MAX_PATH), output_csv);
    }

    for (int index = 0; index < MAX_EVENTS; ++index)
    {
        DWORD dwBytesReturned = 0;
        ULONG64 latency = 0;
        char buffer[MAX_PATH] = { 0 };

        if (DeviceIoControl(driver_handle.get(), GET_FLTMGR_EVENT, NULL, 0, &latency, sizeof(ULONG64), &dwBytesReturned, NULL))
        {
            sprintf_s(buffer, MAX_PATH, "FltMgr,%d,%I64u\n", index, latency);

            fwrite(buffer, sizeof(char), strnlen_s(buffer, MAX_PATH), output_csv);
        }
    }

    for (int index = 0; index < MAX_EVENTS; ++index)
    {
        DWORD dwBytesReturned = 0;
        ULONG64 latency = 0;
        char buffer[MAX_PATH] = { 0 };

        if (DeviceIoControl(driver_handle.get(), GET_CREATE_EVENT, NULL, 0, &latency, sizeof(ULONG64), &dwBytesReturned, NULL))
        {
            sprintf_s(buffer, MAX_PATH, "CreateProc,%d,%I64u\n", index, latency);

            fwrite(buffer, sizeof(char), strnlen_s(buffer, MAX_PATH), output_csv);
        }
    }

    for (int index = 0; index < MAX_EVENTS; ++index)
    {
        DWORD dwBytesReturned = 0;
        ULONG64 latency = 0;
        char buffer[MAX_PATH] = { 0 };

        if (DeviceIoControl(driver_handle.get(), GET_LOAD_EVENT, NULL, 0, &latency, sizeof(ULONG64), &dwBytesReturned, NULL))
        {
            sprintf_s(buffer, MAX_PATH, "LoadImage,%d,%I64u\n", index, latency);

            fwrite(buffer, sizeof(char), strnlen_s(buffer, MAX_PATH), output_csv);
        }
    }

    for (int index = 0; index < MAX_EVENTS; ++index)
    {
        DWORD dwBytesReturned = 0;
        ULONG64 latency = 0;
        char buffer[MAX_PATH] = { 0 };

        if (DeviceIoControl(driver_handle.get(), GET_OBJECT_EVENT, NULL, 0, &latency, sizeof(ULONG64), &dwBytesReturned, NULL))
        {
            sprintf_s(buffer, MAX_PATH, "ObjectOp,%d,%I64u\n", index, latency);

            fwrite(buffer, sizeof(char), strnlen_s(buffer, MAX_PATH), output_csv);
        }
    }

    for (int index = 0; index < MAX_EVENTS; ++index)
    {
        DWORD dwBytesReturned = 0;
        ULONG64 latency = 0;
        char buffer[MAX_PATH] = { 0 };

        if (DeviceIoControl(driver_handle.get(), GET_REGISTRY_EVENT, NULL, 0, &latency, sizeof(ULONG64), &dwBytesReturned, NULL))
        {
            sprintf_s(buffer, MAX_PATH, "Reg,%d,%I64u\n", index, latency);

            fwrite(buffer, sizeof(char), strnlen_s(buffer, MAX_PATH), output_csv);
        }
    }

    fclose(output_csv);

    return 0;
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

void PullBufferedEvents(HANDLE shutdown_event)
{
    std::thread t([&] 
        {
            HRESULT result = S_OK;
            HANDLE port = INVALID_HANDLE_VALUE;
            DWORD bytesReturned = 0;
            PVOID EventBuffer[sizeof(EVENT_DATA) / sizeof(PVOID)];
            PCHAR buffer = (PCHAR)EventBuffer;
            FILE* dummy_db = nullptr;
            char db_buffer[DB_BUFFER_MAX_SIZE];

            if (fopen_s(&dummy_db, "dummy.db", "w") != 0)
            {
                printf("Failed to create dummy db le:%d\n", GetLastError());
                return;
            }

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
                if (WAIT_OBJECT_0 == WaitForSingleObject(shutdown_event, 0))
                {
                    fclose(dummy_db);
                    break;
                }

                result = FilterSendMessage(port,
                    NULL,
                    0,
                    buffer,
                    sizeof(EventBuffer),
                    &bytesReturned);

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
                    buffer[DB_BUFFER_MAX_SIZE - 1] = '\0';
                    fwrite(db_buffer, sizeof(char), strnlen_s(buffer, DB_BUFFER_MAX_SIZE), dummy_db);
                }
            }
        }
    );

    t.detach();
}

int GenerateBufEvents()
{
    // TBD
    return 0;
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
        printf("BUF_EVT: create buffered events\n");

        return 1;
    }

    const std::wstring command = argv[1];

    if (command == L"CLS_STAT")
        return ClearStats();
    if (command == L"SET_PS_ID")
        return SetPSId(_wtoi64(argv[2]));
    if (command == L"GET_MISSES")
        return GetMisses();
    if (command == L"GET_CSV")
        return GetCSVFile();
    if (command == L"BUF_EVT")
        return GenerateBufEvents();

    return 0;
}