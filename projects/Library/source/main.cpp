#include <windows.h>
#include <Log.hpp>
#include <dynalnk_init.hpp>
#include <dynalnk.hpp>

class __declspec(dllimport) Tests {
public:
	Tests();
	~Tests();
	int DoAddition(int a, int b);
};

void Start() {
	DEBUG("Library loaded");
	Tests t;
	DEBUG("Library addition to Executable is: {}", t.DoAddition(6, 4));
}

bool dlnk_start(void* module, dlnk::reason reason)
{
	if (reason == dlnk::reason::process_attach)
	{
		CreateThread(nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(&Start), nullptr, 0, nullptr);
	}
	return true;
}