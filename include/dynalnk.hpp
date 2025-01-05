#pragma once
#include <unordered_map>

#define DLNK_DESCRIPTOR_TABLE ".dlnkdt"
#define DLNK_SYMBOL_INDEXER_TABLE ".symidx"
#define DLNK_SYMBOL_DESCRIPTOR_TABLE ".symsdt"
#define DLNK_SYMBOL_NAME_TABLE ".symsnt"
#define DLNK_SYMBOL_DEMANGLED_NAME_TABLE ".symsdnt"
#define DLNK_SYMBOL_POINTER_SIGNATURE_TABLE ".sympst"

namespace dlnk {
	struct symbol_name {
		const char* value = nullptr;
		operator const char*() const {
			return value;
		}
		size_t length() const {
			return strlen(value);
		}
	};

	struct symbol_name_table {
		uint32_t count = 0;
		symbol_name* names = nullptr;
	};

	enum class reason : uint32_t {
		process_attach = DLL_PROCESS_ATTACH,
		process_detach = DLL_PROCESS_DETACH,
		thread_attach = DLL_THREAD_ATTACH,
		thread_detach = DLL_THREAD_DETACH
	};

	class loader {
		static bool _initialized;
		static HMODULE _module;
		static std::unordered_map<uint32_t, symbol_name> _symbolNames;
		static std::unordered_map<uint32_t, symbol_name> _demangledSymbolNames;
	public:
		static void initialize_dlnk(HMODULE hModule);
		static void finalize_dlnk();
	};
}

bool dlnk::loader::_initialized = false;
HMODULE dlnk::loader::_module = nullptr;
std::unordered_map<uint32_t, dlnk::symbol_name> dlnk::loader::_symbolNames = {};
std::unordered_map<uint32_t, dlnk::symbol_name> dlnk::loader::_demangledSymbolNames = {};

void dlnk::loader::initialize_dlnk(HMODULE hModule) {
	if (_initialized)
		return;
	_initialized = true;
	_module = hModule;
	uintptr_t base = reinterpret_cast<uintptr_t>(_module);
	IMAGE_DOS_HEADER* dosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
	IMAGE_NT_HEADERS* ntHeaders = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dosHeader->e_lfanew);
	IMAGE_SECTION_HEADER* sectionHeaders = IMAGE_FIRST_SECTION(ntHeaders);
	uint16_t sectionCount = ntHeaders->FileHeader.NumberOfSections;

	IMAGE_SECTION_HEADER* dlnkDescriptorTableSectionHeader = nullptr;
	IMAGE_SECTION_HEADER* dlnkSymbolIndexerTableSectionHeader = nullptr;
	IMAGE_SECTION_HEADER* dlnkSymbolDescriptorTableSectionHeader = nullptr;
	IMAGE_SECTION_HEADER* dlnkSymbolNameTableSectionHeader = nullptr;
	IMAGE_SECTION_HEADER* dlnkSymbolDemangledNameTableSectionHeader = nullptr;
	IMAGE_SECTION_HEADER* dlnkSymbolPointerSignatureTableSectionHeader = nullptr;

	for (uint16_t i = 0; i < sectionCount; i++) {
		IMAGE_SECTION_HEADER* sectionHeader = &sectionHeaders[i];
		if (strcmp(reinterpret_cast<const char*>(sectionHeader->Name), DLNK_DESCRIPTOR_TABLE) == 0) {
			dlnkDescriptorTableSectionHeader = sectionHeader;
		}
		else if (strcmp(reinterpret_cast<const char*>(sectionHeader->Name), DLNK_SYMBOL_INDEXER_TABLE) == 0) {
			dlnkSymbolIndexerTableSectionHeader = sectionHeader;
		}
		else if (strcmp(reinterpret_cast<const char*>(sectionHeader->Name), DLNK_SYMBOL_DESCRIPTOR_TABLE) == 0) {
			dlnkSymbolDescriptorTableSectionHeader = sectionHeader;
		}
		else if (strcmp(reinterpret_cast<const char*>(sectionHeader->Name), DLNK_SYMBOL_NAME_TABLE) == 0) {
			dlnkSymbolNameTableSectionHeader = sectionHeader;
		}
		else if (strcmp(reinterpret_cast<const char*>(sectionHeader->Name), DLNK_SYMBOL_DEMANGLED_NAME_TABLE) == 0) {
			dlnkSymbolDemangledNameTableSectionHeader = sectionHeader;
		}
		else if (strcmp(reinterpret_cast<const char*>(sectionHeader->Name), DLNK_SYMBOL_POINTER_SIGNATURE_TABLE) == 0) {
			dlnkSymbolPointerSignatureTableSectionHeader = sectionHeader;
		}
	}

	if (!dlnkDescriptorTableSectionHeader || 
		!dlnkSymbolIndexerTableSectionHeader || 
		!dlnkSymbolDescriptorTableSectionHeader || 
		!dlnkSymbolNameTableSectionHeader || 
		!dlnkSymbolDemangledNameTableSectionHeader || 
		!dlnkSymbolPointerSignatureTableSectionHeader)
		return finalize_dlnk();

	symbol_name_table* symbolNameTable = reinterpret_cast<symbol_name_table*>(base + dlnkSymbolNameTableSectionHeader->VirtualAddress);
	symbol_name_table* symbolDemangledNameTable = reinterpret_cast<symbol_name_table*>(base + dlnkSymbolDemangledNameTableSectionHeader->VirtualAddress);

	if (symbolNameTable->count != symbolDemangledNameTable->count)
		throw std::runtime_error("Symbol name table and demangled symbol name table count mismatch");

	uint32_t nameOffset = 0;
	for (uint32_t i = 0; i < symbolNameTable->count; i++) {
		symbol_name name = symbolNameTable->names[nameOffset];
		nameOffset += name.length() + 1;
		_symbolNames.insert({ i + 1, name });
	}

	TRACE("Symbol names loaded: {}", _symbolNames.size());
	for (const auto&[off, name] : _symbolNames) {
		TRACE("Symbol name: {} -> {}", off, name.value);
	}
}

void dlnk::loader::finalize_dlnk() {
	if (!_initialized)
		return;
	// Do dlnk finalization here
	_initialized = false;
	_module = nullptr;
}