#pragma once
#include "dynalnk.hpp"
#include <future>

extern "C" bool dlnk_start(void* module, dlnk::reason reason);
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
	if (ul_reason_for_call == DLL_PROCESS_ATTACH)
	{
		dlnk::loader::initialize_dlnk(hModule);
	}
	else if (ul_reason_for_call == DLL_PROCESS_DETACH)
	{
		dlnk::loader::finalize_dlnk();
	}
	return dlnk_start(hModule, static_cast<dlnk::reason>(ul_reason_for_call));
}