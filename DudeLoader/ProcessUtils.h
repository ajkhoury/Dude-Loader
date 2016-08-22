#pragma once

#include <Windows.h>
#include <TlHelp32.h>

namespace ProcessUtils
{
	
	DWORD GetPidByNameW(const wchar_t* name, bool caseSensitive = true)
	{
		PROCESSENTRY32W pe32 = { 0 };
		DWORD pid = 0;

		HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		if (hProcessSnap == INVALID_HANDLE_VALUE)
			return 0;

		pe32.dwSize = sizeof(PROCESSENTRY32);
		if (!Process32FirstW(hProcessSnap, &pe32))
			return 0;

		do
		{
			int ret = caseSensitive ? wcscmp(pe32.szExeFile, name) : _wcsicmp(pe32.szExeFile, name);
			if (ret == 0)
			{
				pid = pe32.th32ProcessID;
				break;
			}
		} while (Process32NextW(hProcessSnap, &pe32));

		CloseHandle(hProcessSnap);
		if (!pid)
			return 0;

		return pid;
	}

	DWORD GetPidByNameA(const char* name, bool caseSensitive = true)
	{
		wchar_t szName[MAX_PATH] = { 0 };
		size_t converted = 0;
		mbstowcs_s(&converted, szName, name, MAX_PATH);
		return GetPidByNameW(szName, caseSensitive);
	}

#ifdef UNICODE
#define GetPidByName GetPidByNameW
#else
#define GetPidByName GetPidByNameA
#endif

	HANDLE Open(DWORD access, DWORD pid)
	{
		return OpenProcess(access, FALSE, pid);
	}

	BOOL Close(HANDLE handle)
	{
		if (handle)
			return CloseHandle(handle);
		return FALSE;
	}

	PVOID FindProcessDesktopHeap(HANDLE ProcessHandle, SIZE_T HeapSize)
	{
		BYTE *Addr = (BYTE*)0x1000;
		MEMORY_BASIC_INFORMATION MemInfo = { 0 };
		ULONG OldProt = 0;

		while (VirtualQueryEx(ProcessHandle, Addr, &MemInfo, sizeof(MemInfo)))
		{
			if (MemInfo.Protect == PAGE_READONLY && MemInfo.Type == MEM_MAPPED && MemInfo.State == MEM_COMMIT && MemInfo.RegionSize == HeapSize)
			{
				// Double check.
				if (!VirtualProtectEx(ProcessHandle, Addr, 0x1000, PAGE_READWRITE, &OldProt))
					return MemInfo.BaseAddress;
				else
					VirtualProtectEx(ProcessHandle, Addr, 0x1000, OldProt, &OldProt);
			}
			Addr += MemInfo.RegionSize;
		}

		return NULL;
	}


}


