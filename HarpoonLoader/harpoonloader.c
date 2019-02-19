#ifdef CSHARP_MONO

	#ifdef _WIN64
	#define padptr 8
	#else
	#define padptr 4
	#endif
	
	#define sHarpoon_Core strings + 0
	#define sHarpoonCore strings + 13
	#define sInitialize strings + 25
	#define sHarpoon_Core_dll strings + 36
	#define fmono_domain_get strings + 53
	#define fmono_thread_attach strings + 53 + padptr
	#define fmono_get_root_domain strings + 53 + padptr * 2
	#define fmono_domain_assembly_open strings + 53 + padptr * 3
	#define fmono_class_from_name strings + 53 + padptr * 4
	#define fmono_class_get_method_from_name strings + 53 + padptr * 5
	#define fmono_runtime_invoke strings + 53 + padptr * 6
	#define fmono_assembly_get_image strings + 53 + padptr * 7
	
	//Minimal mono injector
	__declspec(dllexport) unsigned int initialize(char *strings) {
	
		//Attach to root domain
	
		void* (*mono_thread_attach)(void*) = *(void**)(fmono_thread_attach);
		void* (*mono_get_root_domain)() = *(void**)(fmono_get_root_domain);
	
		mono_thread_attach(mono_get_root_domain());
	
		//Get domain
	
		void* (*mono_domain_get)() = *(void**)(fmono_domain_get);
		void* (*mono_domain_assembly_open)(void*, char*) = *(void**)(fmono_domain_assembly_open);
	
		void* domainAssembly = mono_domain_assembly_open(mono_domain_get(), sHarpoon_Core_dll);
	
		//Get function in class
	
		void* (*mono_class_from_name)(void*, char*, char*) = *(void**)(fmono_class_from_name);
		void* (*mono_class_get_method_from_name)(void*, char*, unsigned int) = *(void**)(fmono_class_get_method_from_name);
		void* (*mono_assembly_get_image)(void*) = *(void**)(fmono_assembly_get_image);
	
		void *image = mono_assembly_get_image(domainAssembly);
		void *monoClass = mono_class_from_name(image, sHarpoon_Core, sHarpoonCore);
		void *monoMethod = mono_class_get_method_from_name(monoClass, sInitialize, 0);
	
		//Invoke function
	
		void* (*mono_runtime_invoke)(void*, void*, void**, void*) = *(void**)(fmono_runtime_invoke);
	
		mono_runtime_invoke(monoMethod, 0, 0, 0);
	
		return 1;
	
	}

#else

	#ifdef _WIN64
	#define padptr 8
	#else
	#define padptr 4
	#endif
	
	#define fAllocConsole strings + 0
	

	//Minimal mono injector
	__declspec(dllexport) unsigned int initialize(char *strings) {

		void (*AllocConsole)() = *(void**)(fAllocConsole);
		AllocConsole();

	}

#endif