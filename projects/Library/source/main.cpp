#include <windows.h>
#include <Log.hpp>
#include <dynalnk_init.hpp>
#include <dynalnk.hpp>

bool dlnk_start(void* module, dlnk::reason reason)
{
	if (reason == dlnk::reason::process_attach)
	{
		DEBUG("Library loaded");
	}
	return true;
}