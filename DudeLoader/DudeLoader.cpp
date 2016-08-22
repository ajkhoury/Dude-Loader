#include "DudeLoader.h"
#include "Loader.h"

//C:\Users\Owner\Documents\Visual Studio 2013\Projects\TestDll\vs2013\bin\TestDll64.dll
TCHAR dllLocation[] = _T("C:\\Users\\Owner\\Documents\\Visual Studio 2013\\Projects\\TestDll\\vs2013\\bin\\TestDll64.dll");

int APIENTRY _tWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPTSTR lpCmdLine, int nCmdShow)
{
	UNREFERENCED_PARAMETER(hPrevInstance);
	UNREFERENCED_PARAMETER(lpCmdLine);

	Loader* pLoader = new Loader(hInstance);
	pLoader->Inject(dllLocation);
	delete pLoader;

	Sleep(1000);

	TerminateProcess(NULL, 1);
	
	return TRUE;
}
