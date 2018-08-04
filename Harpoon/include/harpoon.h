#pragma once
#include <string>
#include <Windows.h>

namespace hp {

	class Harpoon {

	public:

		//Inject a dll into a process and run it using the function 'entryPoint'
		static void hook(DWORD processId, std::string dll);

	};

}