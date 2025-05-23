#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>
#include <string>

DWORD GetProcId(const wchar_t* dllName) {
	DWORD procId = 0;
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	if (hSnap != INVALID_HANDLE_VALUE) {
		PROCESSENTRY32 procEntry;
		procEntry.dwSize = sizeof(procEntry);

		if (Process32First(hSnap, &procEntry)) {
			do {
				if (_wcsicmp(dllName, procEntry.szExeFile) == 0) {
					procId = procEntry.th32ProcessID;
				}
			} while (Process32Next(hSnap, &procEntry));
		}
	}
	CloseHandle(hSnap);

	return procId;
}

int main() {
	DWORD procId = 0;
	const char* dllPath = "C:\\dev\\testsDLL\\x64\\Release\\testsDLL.dll";
	const wchar_t* procName = L"notepad.exe";
	
	std::cout << "[+] Looking for process...\n";

	while (!procId) {
		procId = GetProcId(procName);
		Sleep(10);
	}

	std::cout << "[+] Process ID found " << procId << "\n";

	HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, 0, procId);

	if (!hProc) {
		std::cout << "[+] Process couldn't be opened\n";
		Sleep(5000);
		ExitProcess(-1);
	}

	std::cout << "[+] Process opened with all access\n";

	void* alloc = VirtualAllocEx(hProc, 0, MAX_PATH, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	if (!alloc) {
		std::cout << "[+] Memory couldn't be allocated\n";
		Sleep(5000);
		ExitProcess(-1);
	}

	std::cout << "[+] Memory allocated successfully\n";
	std::cout << "      [-] Address: 0x" << std::hex << (uintptr_t)alloc << std::dec << "\n";

	WriteProcessMemory(hProc, alloc, dllPath, strlen(dllPath) + 1, 0);

	std::cout << "[+] DLL data allocated at specified address\n";

	CreateRemoteThread(hProc, 0, 0, (LPTHREAD_START_ROUTINE)LoadLibraryA, alloc, 0, 0);

	std::cout << "[+] Thread created\n";

	if (hProc)
		CloseHandle(hProc);

	std::getchar();
}