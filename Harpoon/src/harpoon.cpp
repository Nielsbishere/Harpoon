#define PSAPI_VERSION 1
#include "harpoon.h"
#include <locale>
#include <codecvt>
#include <assert.h>
#include <process.h>
#include <fstream>
#include <psapi.h>
#pragma comment(lib, "Psapi.lib")
using namespace hp;

template<typename T>
void check(T func, char *str) {

	if (func == 0) {
		printf("%s\n", str);
		assert(false && "Error thrown");
	}
}

std::string getProcessName(DWORD id) {

	char processName[MAX_PATH];

	HANDLE process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, id);

	if (process != NULL) {

		HMODULE module;
		DWORD nameLength;

		if (EnumProcessModules(process, &module, sizeof(module), &nameLength)) {
			GetModuleBaseNameA(process, module, processName, MAX_PATH);
			return processName;
		}
	}

	CloseHandle(process);

	return "";
}

DWORD findProcess(std::string str) {

	DWORD processes[1024], processCount;

	if (!EnumProcesses(processes, sizeof(processes), &processCount))
		return 0;

	DWORD current = 0;

	for (DWORD i = 0; i < processCount; ++i)
		if (getProcessName(current = processes[i]) == str)
			return current;

	return 0;
}

LPVOID allocString(HANDLE process, std::string str) {

	DWORD size = (DWORD) str.size() + 1;
	LPVOID remote = VirtualAllocEx(process, NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	check(remote, "Couldn't allocate space into process");
	check(WriteProcessMemory(process, remote, (PVOID) str.c_str(), size, NULL), "Couldn't write string into memory");

	return remote;
}

void Harpoon::hook(DWORD processId, std::string dllPath) 
{
	std::string dllName = dllPath.substr(dllPath.find_last_of('\\') + 1);
	std::string dllBase = dllPath.substr(0, dllPath.find_last_of('\\'));

	//Figure out where the initialize function is located in the dll
	//So we can run it later

	HMODULE loc = LoadLibraryA(dllPath.c_str());
	printf("Checking for library at path %s\n", dllPath.c_str());
	check(loc, "Can't load dll");

	FARPROC dllFunc = GetProcAddress(loc, "initialize");
	check(dllFunc, "Can't load dll function");

	size_t dllFuncOff = (size_t)dllFunc - (size_t)loc;
	printf("%s::initialize found at %p\n", dllPath.c_str(), (void*) dllFuncOff);

	//Get process
	HANDLE process = OpenProcess(
		PROCESS_QUERY_INFORMATION | PROCESS_CREATE_THREAD | 
		PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
		FALSE, processId
	);

	check(process, "Couldn't open process");

	//Copy the string into the other process
	LPVOID dllStr = allocString(process, dllPath);

	//Load the dll into memory
	PTHREAD_START_ROUTINE loadLibraryProc = (PTHREAD_START_ROUTINE) GetProcAddress(GetModuleHandle(TEXT("kernel32")), "LoadLibraryA");
	check(loadLibraryProc, "Couldn't get 'load library'");

	//Run the load library function
	HANDLE thread = CreateRemoteThread(process, NULL, 0, loadLibraryProc, dllStr, 0, NULL);
	check(thread, "Couldn't start library on remote process");

	//Wait for it to finish and stop
	WaitForSingleObject(thread, INFINITE);

	//Check if it was successfully injected

	HMODULE handles[2048];
	DWORD needed = 0;
	EnumProcessModules(process, handles, sizeof(handles), &needed);

	char name[1024];

	for (int i = 0; i < needed / sizeof(handles[0]); ++i) {

		GetModuleBaseName(process, handles[i], name, sizeof(name));

		if (std::string(name) == dllName) {

			PTHREAD_START_ROUTINE remoteInitialize = (PTHREAD_START_ROUTINE)(((char*) handles[i]) + dllFuncOff);

			printf("Found injected DLL in process (%s with address %p)\n", name, (void*) handles[i]);
			printf("Running initialize at %p\n", remoteInitialize);

			HANDLE dllThread = CreateRemoteThread(process, NULL, 0, remoteInitialize, NULL, 0, NULL);
			check(dllThread, "Couldn't run initialize on remote thread");

			WaitForSingleObject(dllThread, INFINITE);
			CloseHandle(dllThread);
		}
	}

	VirtualFreeEx(process, dllStr, 0, MEM_RELEASE);
	CloseHandle(thread);
	CloseHandle(process);

}

int help(std::string error, bool showDefault = true) {

	printf("%s\n", error.c_str());

	if (showDefault) {

		printf("Commands:\n");
		printf("-hookid <pId> <dllPath>\nHooks Harpoon into an exe, to hook it so you can execute code.\n");
		printf("-hook <pName> <dllPath>\nHooks Harpoon into an exe, to hook it so you can execute code.\n");

	}

	return 0;
}

int main(int argc, char *argv[]) {

	if (argc < 2)
		return help("Not enough arguments");

	std::string arg = argv[1];

	char fullPathBuffer[MAX_PATH];

	int bytes = GetModuleFileName(NULL, fullPathBuffer, sizeof(fullPathBuffer));

	std::string fullPath = fullPathBuffer;
	fullPath = fullPath.substr(0, fullPath.find_last_of('\\'));

	if (arg == "-hookid") {

		if (argc < 4) return help("Syntax: -hookid <pId> <dllPath>", false);

		std::string pid = argv[2];
		std::string dll = fullPath + "\\" + argv[3];

		int id = std::stoi(pid);

		if (id == 0) return help("Syntax: -hookid <pId> <dllPath>", false);

		Harpoon::hook((DWORD)id, dll);
		return 1;
	} else if (arg == "-hook") {

		if (argc < 4) return help("Syntax: -hook <pName> <dllPath>", false);

		std::string pid = argv[2];
		std::string dll = fullPath + "\\" + argv[3];

		DWORD id = findProcess(pid);

		if (id == 0) {
			printf("Couldn't resolve \"%s\"\n", pid.c_str());
			return help("Syntax: -hook <pName> <dllPath>", false);
		}

		printf("Resolved %s as %u\n", pid.c_str(), id);

		Harpoon::hook(id, dll);
		return 1;
	}

	return help("Couldn't find a matching argument (case sensitive)");
}