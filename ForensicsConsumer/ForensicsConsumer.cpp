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
#include <stdio.h>

#include <string>

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

int GetMisses()
{
    HANDLE hDriver = NULL;
    DWORD le = 0;

    if ((hDriver = CreateFileW(L"\\\\.\\ForensicsCollector",
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL)) == INVALID_HANDLE_VALUE)
    {

        DWORD le = GetLastError();

        printf("Failed to open a handle to ForensicsCollector : %d\n", le);

        return 1;
    }

    DWORD dwBytesReturned = 0;
    constexpr size_t MISSES_ARRAY_SIZE = 5;
    ULONG64 MissesData[MISSES_ARRAY_SIZE] = { 0 };
    if (!DeviceIoControl(hDriver, GET_ALL_MISSES, NULL, 0, &MissesData, sizeof(ULONG64) * MISSES_ARRAY_SIZE, &dwBytesReturned, NULL))
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
    HANDLE hDriver = NULL;
    DWORD le = 0;

    if ((hDriver = CreateFileW(L"\\\\.\\ForensicsCollector",
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL)) == INVALID_HANDLE_VALUE)
    {

        DWORD le = GetLastError();

        printf("Failed to open a handle to ForensicsCollector : %d\n", le);

        return 1;
    }

    DWORD dwBytesReturned = 0;
    if (!DeviceIoControl(hDriver, SET_SIM_PS_ID, &pid, sizeof(ULONG64), NULL, 0, &dwBytesReturned, NULL))
    {
        printf("Failed to set simulation pid with error: %d\n", GetLastError());
        return 2;
    }

    return 0;
}

int ClearStats()
{
    HANDLE hDriver = NULL;
    DWORD le = 0;

    if ((hDriver = CreateFileW(L"\\\\.\\ForensicsCollector",
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL)) == INVALID_HANDLE_VALUE)
    {

        DWORD le = GetLastError();

        printf("Failed to open a handle to ForensicsCollector : %d\n", le);

        return 1;
    }

    DWORD dwBytesReturned = 0;
    if (!DeviceIoControl(hDriver, CLS_SIM_DATA, NULL, 0, NULL, 0, &dwBytesReturned, NULL))
    {
        printf("Failed to clear simulation data with error: %d\n", GetLastError());
        return 2;
    }

    return 0;
}

int GetCSVFile()
{
    HANDLE hDriver = NULL;
    DWORD le = 0;

    if ((hDriver = CreateFileW(L"\\\\.\\ForensicsCollector",
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL)) == INVALID_HANDLE_VALUE)
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

        if (DeviceIoControl(hDriver, GET_FLTMGR_EVENT, NULL, 0, &latency, sizeof(ULONG64), &dwBytesReturned, NULL))
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

        if (DeviceIoControl(hDriver, GET_CREATE_EVENT, NULL, 0, &latency, sizeof(ULONG64), &dwBytesReturned, NULL))
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

        if (DeviceIoControl(hDriver, GET_LOAD_EVENT, NULL, 0, &latency, sizeof(ULONG64), &dwBytesReturned, NULL))
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

        if (DeviceIoControl(hDriver, GET_OBJECT_EVENT, NULL, 0, &latency, sizeof(ULONG64), &dwBytesReturned, NULL))
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

        if (DeviceIoControl(hDriver, GET_REGISTRY_EVENT, NULL, 0, &latency, sizeof(ULONG64), &dwBytesReturned, NULL))
        {
            sprintf_s(buffer, MAX_PATH, "Reg,%d,%I64u\n", index, latency);

            fwrite(buffer, sizeof(char), strnlen_s(buffer, MAX_PATH), output_csv);
        }
    }

    fclose(output_csv);
}

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

    return 0;
}