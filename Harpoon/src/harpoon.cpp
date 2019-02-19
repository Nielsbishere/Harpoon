#define PSAPI_VERSION 1
#include "harpoon.h"
#include <locale>
#include <codecvt>
#include <assert.h>
#include <process.h>
#include <fstream>
#include <psapi.h>
#include <vector>
#include <unordered_map>
#pragma comment(lib, "Psapi.lib")
using namespace hp;

template<typename T>
void check(T func, char *str) {

	if (func == 0) {

		HRESULT last = GetLastError();
		printf("%s", str);

		LPTSTR errorText = NULL;

		FormatMessage(
			FORMAT_MESSAGE_FROM_SYSTEM
			| FORMAT_MESSAGE_ALLOCATE_BUFFER
			| FORMAT_MESSAGE_IGNORE_INSERTS,
			NULL, last, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
			(LPTSTR)&errorText,  0, NULL);

		if (errorText != NULL) {
			printf(": %s", errorText);
			LocalFree(errorText);
		} else printf("\n");

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

LPVOID allocBuffer(HANDLE process, void *start, DWORD length, bool exec) {

	LPVOID remote = VirtualAllocEx(process, NULL, length, MEM_COMMIT | MEM_RESERVE, exec ? PAGE_EXECUTE_READWRITE : PAGE_READWRITE);
	check(remote, "Couldn't allocate space into process");
	check(WriteProcessMemory(process, remote, (LPVOID)start, length, NULL), "Couldn't write buffer into memory");
	
	DWORD oldProtection;
	check(VirtualProtectEx(process, remote, length, exec ? PAGE_EXECUTE_READ : PAGE_READONLY, &oldProtection), "Couldn't make page non-writable");
	
	return remote;
}

struct CopyDll {

	HINSTANCE current;
	size_t length;

	PVOID remote;

};

CopyDll loadCopyDll(const char *path, HANDLE process, bool copyToProcess = true) {

	//Load library into our memory
	HINSTANCE loc = LoadLibraryA(path);
	printf("Checking for library at path %s\n", path);
	check(loc, "Can't load dll");

	//Get our dll's module info
	MODULEINFO info;
	check(GetModuleInformation(GetCurrentProcess(), loc, &info, (DWORD) sizeof(info)), "Couldn't get module info");

	return { loc, (size_t)info.SizeOfImage, !copyToProcess ? nullptr : allocBuffer(process, loc, info.SizeOfImage, true) };
}

PVOID getRemoteFunc(CopyDll dll, const char *func) {

	//Get the function in our dll
	FARPROC proc = GetProcAddress(dll.current, func);
	check(proc, "Can't load dll function");

	//Get dif to current dll
	size_t dif = size_t((char*)proc - (char*)dll.current);

	return (char*)dll.remote + dif;

}

struct RemoteDll {
	std::string name, fileName;
	HINSTANCE remote;
};

RemoteDll getRemoteDll(HANDLE process, std::string module) {

	for (char &c : module)
		c = toupper(c);

	HINSTANCE handles[2048];
	DWORD needed = 0;
	EnumProcessModulesEx(process, handles, sizeof(handles), &needed, LIST_MODULES_ALL);

	char name[MAX_PATH + 1], fileName[MAX_PATH + 1];

	for (int i = 0; i < needed / sizeof(handles[0]); ++i) {

		GetModuleBaseNameA(process, handles[i], name, sizeof(name));
		GetModuleFileNameExA(process, handles[i], fileName, sizeof(fileName));

		MODULEINFO modInfo;
		GetModuleInformation(process, handles[i], &modInfo, sizeof(modInfo));

		std::string mname = name;

		for (char &c : mname)
			c = toupper(c);

		#ifdef _DEBUG
			printf("%s\n", mname);
		#endif

		if (module == mname)
			return { name, fileName, handles[i] };

	}

	check(false, "Couldn't find specified module");
	return {};
}

 
#ifdef _WIN64
#define padptr "\0\0\0\0\0\0\0\0"
#else
#define padptr "\0\0\0\0"
#endif

void getFunctions(RemoteDll dll, std::vector<std::string> functions, std::unordered_map<std::string, void*> &funcs) {

	HINSTANCE local = LoadLibraryExA(dll.fileName.c_str(), NULL, DONT_RESOLVE_DLL_REFERENCES);
	if (local == NULL) {
		printf("Couldn't load remote library\n");
		return;
	}

	funcs.clear();

	for (std::string &str : functions) {

		char *addr = (char*)GetProcAddress(local, str.c_str());

		if (addr == nullptr)
			continue;

		funcs[str] = (void*)(addr - (char*)local + (char*)dll.remote);
	}

	FreeLibrary(local);
	return;

}

void Harpoon::hook(DWORD processId, std::string dllPath, std::string dllName) {

	//Get process

	HANDLE process = OpenProcess(
		PROCESS_QUERY_INFORMATION | PROCESS_CREATE_THREAD |
		PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
		FALSE, processId
	);

	check(process, "Couldn't open process");

	/*IMAGE_NT_HEADERS *headers = ImageNtHeader(process);

	bool is64bit = headers->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64;

	#ifdef _WIN64
	check(is64bit, "Couldn't inject into a 32-bit process from a 64-bit harpoon");
	#else
	check(!is64bit, "Couldn't inject into a 64-bit process from a 32-bit harpoon");
	#endif*/

	//TODO: check is64bit

	#ifdef REFLECTIVE_INJECTION

		//Load our dll into the host's process
		CopyDll harpoon = loadCopyDll(dllPath.c_str(), process);

	#endif

	#ifdef CSHARP_MONO

		RemoteDll mono = getRemoteDll(process, "mono.dll");

		//Setup a command to get our functions from DLL
		std::vector<std::string> funcs = {
			"mono_domain_get",
			"mono_thread_attach",
			"mono_get_root_domain",
			"mono_domain_assembly_open",
			"mono_class_from_name",
			"mono_class_get_method_from_name",
			"mono_runtime_invoke",
			"mono_assembly_get_image"
		};

		std::unordered_map<std::string, void*> functionMap;
		getFunctions(mono, funcs, functionMap);

		check(functionMap.size() == funcs.size(), "Couldn't get functions from dll");

		//These are our strings (and functions); but we can't use those directly
		//This is because this program will be moved and any address (not to kernel32) will have to be moved
		char data[] = {
			"Harpoon.Core\0"						//0
			"HarpoonCore\0"							//13
			"Initialize\0"							//25
			"Harpoon.Core.dll\0"					//36
			padptr									//53;	fmono_domain_get
			padptr									//		fmono_thread_attach
			padptr									//		fmono_get_root_domain
			padptr									//		fmono_domain_assembly_open
			padptr									//		fmono_class_from_name
			padptr									//		fmono_class_get_method_from_name
			padptr									//		fmono_runtime_invoke
			padptr									//		fmono_assembly_get_image
		};

		constexpr size_t pad = sizeof(void*);

		*(void**)(data + 53) = functionMap["mono_domain_get"];
		*(void**)(data + 53 + pad) = functionMap["mono_thread_attach"];
		*(void**)(data + 53 + pad * 2) = functionMap["mono_get_root_domain"];
		*(void**)(data + 53 + pad * 3) = functionMap["mono_domain_assembly_open"];
		*(void**)(data + 53 + pad * 4) = functionMap["mono_class_from_name"];
		*(void**)(data + 53 + pad * 5) = functionMap["mono_class_get_method_from_name"];
		*(void**)(data + 53 + pad * 6) = functionMap["mono_runtime_invoke"];
		*(void**)(data + 53 + pad * 7) = functionMap["mono_assembly_get_image"];;

	#else

		char data[] = {
			padptr
		};

		RemoteDll kernel32 = getRemoteDll(process, "Kernel32.dll");

		std::vector<std::string> funcs = {
			"AllocConsole"
		};

		std::unordered_map<std::string, void*> functionMap;
		getFunctions(kernel32, funcs, functionMap);

		check(functionMap.size() == funcs.size(), "Couldn't get functions from dll");

		*(void**)data = functionMap["AllocConsole"];

	#endif

	//Add required function pointers

	LPVOID dat = allocBuffer(process, data, (DWORD) sizeof(data), false);

	//Get initialize function

	#ifdef REFLECTIVE_INJECTION
	
		//Get injected initialize function

		PTHREAD_START_ROUTINE initialize = (PTHREAD_START_ROUTINE)getRemoteFunc(harpoon, "initialize");

	#else

		//Add lib name onto process's heap

		LPVOID libName = allocBuffer(process, (void*)dllPath.c_str(), dllPath.size() + 1, false);

		//LoadLibrary is located in kernel32 (which is always located at the same place)

		LPTHREAD_START_ROUTINE loadLibrary = (LPTHREAD_START_ROUTINE) GetProcAddress(GetModuleHandleA("kernel32"), "LoadLibraryA");
		check(loadLibrary, "Couldn't get load library address");

		//Run loadLibrary with our libName

		HANDLE loadLib = CreateRemoteThread(process, NULL, 0, loadLibrary, libName, 0, NULL);
		check(loadLib, "Couldn't load library into process");

		//Wait for it to finish and clean up

		WaitForSingleObject(loadLib, INFINITE);
		VirtualFreeEx(process, libName, 0, MEM_RELEASE);
		CloseHandle(loadLib);

		//Get function from remote DLL

		RemoteDll harpoon = getRemoteDll(process, dllName);

		funcs = {
			"initialize"
		};

		getFunctions(harpoon, funcs, functionMap);

		check(functionMap.size() == funcs.size(), "Couldn't get functions from dll");

		PTHREAD_START_ROUTINE initialize = (PTHREAD_START_ROUTINE) functionMap["initialize"];

	#endif

	//Run our remote function
	printf("Running %s::initialize at %p\n", dllPath.c_str(), (void*)initialize);

	HANDLE thread = CreateRemoteThread(process, NULL, 0, initialize, dat, 0, NULL);
	check(thread, "Couldn't start library on remote process");

	//Wait for it to finish and stop
	WaitForSingleObject(thread, INFINITE);

	VirtualFreeEx(process, dat, 0, MEM_RELEASE);

	#ifdef REFLECTIVE_INJECTION
		VirtualFreeEx(process, harpoon.remote, 0, MEM_RELEASE);
		FreeLibrary(harpoon.current);
	#endif

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
		std::string dll = fullPath + "\\" + argv[3] + ".dll";

		int id = std::stoi(pid);

		if (id == 0) return help("Syntax: -hookid <pId> <dllPath>", false);

		Harpoon::hook((DWORD)id, dll, std::string(argv[3]) + ".dll");
		return 1;
	}
	else if (arg == "-hook") {

		if (argc < 4) return help("Syntax: -hook <pName> <dllPath>", false);

		std::string pid = argv[2];
		std::string dll = fullPath + "\\" + argv[3] + ".dll";

		DWORD id = findProcess(pid);

		if (id == 0) {
			printf("Couldn't resolve \"%s\"\n", pid.c_str());
			return help("Syntax: -hook <pName> <dllPath>", false);
		}

		printf("Resolved %s as %u\n", pid.c_str(), id);

		Harpoon::hook(id, dll, std::string(argv[3]) + ".dll");
		return 1;
	}

	return help("Couldn't find a matching argument (case sensitive)");
}