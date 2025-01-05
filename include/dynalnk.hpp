#pragma once
#include <thread>

namespace dlnk {
	enum class reason : uint32_t {
		process_attach = DLL_PROCESS_ATTACH,
		process_detach = DLL_PROCESS_DETACH,
		thread_attach = DLL_THREAD_ATTACH,
		thread_detach = DLL_THREAD_DETACH
	};

	class loader {
		static bool _initialized;
	public:
		static void initialize_dlnk();
		static void finalize_dlnk();
	};
}

bool dlnk::loader::_initialized = false;
void dlnk::loader::initialize_dlnk() {
	if (_initialized)
		throw std::runtime_error("Tried to initialize dlnk more than once!");
	_initialized = true;
	// Do dlnk initialization here
}

void dlnk::loader::finalize_dlnk() {
	if (!_initialized)
		return;
	_initialized = false;
	// Do dlnk finalization here
}