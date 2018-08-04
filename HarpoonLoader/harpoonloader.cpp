#include <windows.h>
#include <string>
#include <assert.h>
#include <functional>
#include <vector>

#define __DEBUG_MODE__
#define __namespace__ "Harpoon.Core"
#define __class__ "HarpoonCore"
#define __function__ "Initialize"
#define __dll__ "Harpoon.Core"

std::vector<std::pair<bool(*)(), const char*>> funcsToInit;

bool addFuncToInit(bool (*f)(), const char *str) {
	funcsToInit.push_back(std::pair<bool(*)(), const char*>(f, str));
	return true;
}

HMODULE mono;

#define MONO_FUNC_T(x, params, y) 														\
x (*y)(params) = nullptr;																\
bool y##_func(){ y = (x (*)(params)) GetProcAddress(mono, #y); return y != nullptr; }	\
const bool y##_funcInitb = addFuncToInit(y##_func, #y);

#define MONO_FUNC(params, y) MONO_FUNC_T(PVOID, params, y);

#define _(...) __VA_ARGS__

MONO_FUNC(_(), mono_domain_get);
MONO_FUNC(_(PVOID), mono_thread_attach);
MONO_FUNC(_(), mono_get_root_domain);
MONO_FUNC(_(PVOID, PCHAR), mono_domain_assembly_open);
MONO_FUNC(_(PVOID, PCHAR, PCHAR), mono_class_from_name);
MONO_FUNC(_(PVOID, PCHAR, DWORD), mono_class_get_method_from_name);
MONO_FUNC(_(PVOID, PVOID, PVOID*, PVOID), mono_runtime_invoke);
MONO_FUNC(_(PVOID), mono_assembly_get_image);

#ifdef __DEBUG_MODE__
	#define ERROR_CHECK(var, errorMessage, ...) 											\
	if ((var) == NULL) {																	\
		printf(errorMessage "\n", __VA_ARGS__);												\
		goto failed;																		\
	}
#else
	#define ERROR_CHECK(var, errorMessage, ...) if ((var) == NULL) goto failed;
#endif


BOOL WINAPI DllMain(HINSTANCE, DWORD fdwReason, LPVOID)  {

	switch (fdwReason)  {
	case DLL_PROCESS_ATTACH:
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}

	return TRUE;

}

extern "C" __declspec(dllexport) DWORD initialize(LPVOID param) {

	//Initialize console

	#ifdef __DEBUG_MODE__
	AllocConsole();
	SetConsoleTitleA("Harpoon debug console");

	FILE* fp;
	freopen_s(&fp, "CONOUT$", "w", stdout);
	printf("Loading HarpoonCore\n");
	#endif

	//Initialize error functions

	std::string error = "";
	DWORD errorId = S_OK, res = S_OK;
	LPSTR messageBuffer = nullptr;

	//Intialize mono and its functions

	ERROR_CHECK(mono = LoadLibraryA("mono.dll"), "Couldn't initialize mono");
	
	for(auto f : funcsToInit)
		ERROR_CHECK((void*)f.first(), "Couldn't initialize mono function (%s)", f.second);

	//Run mono on Harpoon.Core

	PVOID rootDomain = mono_get_root_domain();
	ERROR_CHECK(rootDomain, "Couldn't initialize mono root domain");

	mono_thread_attach(rootDomain);

	PVOID monoDomain = mono_domain_get();
	ERROR_CHECK(monoDomain, "Couldn't initialize mono domain");

	PVOID domainAssembly = mono_domain_assembly_open(monoDomain, __dll__ ".dll");
	ERROR_CHECK(domainAssembly, "Couldn't initialize mono domain assembly");

	PVOID image = mono_assembly_get_image(domainAssembly);
	ERROR_CHECK(image, "Couldn't initialize mono image");

	PVOID monoClass = mono_class_from_name(image, __namespace__, __class__);
	ERROR_CHECK(monoClass, "Couldn't initialize mono class (%s.%s)", __namespace__, __class__);

	PVOID monoMethod = mono_class_get_method_from_name(monoClass, __function__, 0);
	ERROR_CHECK(monoMethod, "Couldn't initialize mono method (%s.%s.%s)", __namespace__, __class__, __function__);

	mono_runtime_invoke(monoMethod, NULL, NULL, NULL);

	goto succeeded;

failed:

	error = std::string(messageBuffer, FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, res, MAKELANGID(LANG_ENGLISH, SUBLANG_DEFAULT), (LPSTR)&messageBuffer, 0, NULL));

	#ifdef __DEBUG_MODE__
	printf("%s\n", error.c_str());
	fclose(fp);

	FreeConsole();
	#endif

	LocalFree(messageBuffer);

	CoUninitialize();
	return 0;

succeeded:

	#ifdef __DEBUG_MODE__
	printf("Successfully created C# instance");
	fclose(fp);

	FreeConsole();
	#endif

	CoUninitialize();
	return 1;
}