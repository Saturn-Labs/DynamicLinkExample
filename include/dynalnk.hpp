#pragma once
#include <windows.h>
#include <unordered_map>
#include <optional>
#include <string>
#include <cassert>
#include <regex>
#include <sstream>
#include <libhat/Scanner.hpp>

#define DLNK_DESCRIPTOR_TABLE ".dlnkdt"
#define DLNK_SYMBOL_INDEXER_TABLE ".symidx"
#define DLNK_SYMBOL_DESCRIPTOR_TABLE ".symsdt"
#define DLNK_SYMBOL_NAME_TABLE ".symsnt"
#define DLNK_SYMBOL_DEMANGLED_NAME_TABLE ".symsdn"
#define DLNK_SYMBOL_POINTER_SIGNATURE_TABLE ".sympst"
#define DLNK_DYNAMIC_IMPORT_DESCRIPTOR ".didata"
#pragma pack(push, 1)
namespace dlnk {
	struct descriptor_entry {
		uint32_t nameOffset;
		uint32_t symbolIndexerOffset;
	};

	struct descriptor_table {
		uint32_t count = 0;
		descriptor_entry entries = {};
	};

	struct symbol_string_table {
		uint32_t count = 0;
		char names = 0;
	};

	struct symbol_indexer_entry {
		uint32_t count = 0;
		uint32_t nameOffset = 0;
	};

	struct symbol_descriptor_entry {
		uint32_t nameOffset;
		uint32_t signatureOffset;
		uint64_t address;
	};

	struct symbol_descriptor_table {
		uint32_t count = 0;
		symbol_descriptor_entry entries = {};
	};

	struct symbol_descriptor_model {
		std::string name;
		std::string demangledName;
		std::optional<std::string> signature;
		uint64_t address;
	};

	struct link_descriptor_model {
		std::string name;
		std::vector<symbol_descriptor_model> symbols;
	};

	struct dynamic_symbol_descriptor_model {
		std::string symbol;
		uintptr_t* address;
	};

	struct dynamic_import_descriptor_model {
		std::string name;
		std::vector<dynamic_symbol_descriptor_model> symbols;
	};

	template<typename T>
	struct type_tools {
		static std::string class_name() {
			if (className.has_value())
				return className.value();

			auto name = std::string(__FUNCSIG__);
			DEBUG("Function signature: {}", name);
			std::regex matchClassNameRegex(R"(dlnk::type_tools<\w+\s+([^>]+)>::class_name)");
			std::smatch match;
			if (std::regex_search(name, match, matchClassNameRegex)) {
				className = match[1].str();
				return className.value();
			}
			return "";
		}

		template<typename... OArgs>
		static std::string ctor_name() {
			size_t hash_value = 0;
			auto name = class_name();
			((hash_value ^= std::hash<std::string>{}(typeid(OArgs).name())), ...);
			hash_value ^= std::hash<std::string>{}(name);
			if (ctorNames.find(hash_value) != ctorNames.end())
				return ctorNames[hash_value];
			std::regex getClassLastName(R"(.*::(?!.*::)(.*))");
			std::smatch match;
			if (std::regex_search(name, match, getClassLastName)) {
				std::string trueName = match[1].str();
				std::ostringstream oss;
				oss << name << "::" << trueName << "(";
				((oss << typeid(OArgs).name() << ", "), ...);
				std::string result = oss.str();
				if (!result.empty()) {
					result.pop_back();
					result.pop_back();
				}
				result += ")";
				ctorNames.insert({ hash_value, result });
				return result;
			}
			return "Unknown";
		}

	private:
		inline static std::optional<std::string> className = {};
		inline static std::unordered_map<size_t, std::string> ctorNames = {};
	};

	enum class reason : uint32_t {
		process_attach = DLL_PROCESS_ATTACH,
		process_detach = DLL_PROCESS_DETACH,
		thread_attach = DLL_THREAD_ATTACH,
		thread_detach = DLL_THREAD_DETACH
	};

	class loader {
	public:
		static bool _initialized;
		static HMODULE _module;
		static std::vector<descriptor_entry*> _descriptors;
		static std::unordered_map<uint32_t, symbol_indexer_entry*> _symbolIndexers;
		static std::unordered_map<uint32_t, symbol_descriptor_entry*> _symbolDescriptors;
		static std::unordered_map<uint32_t, std::string> _symbolNames;
		static std::unordered_map<uint32_t, std::string> _demangledSymbolNames;
		static std::unordered_map<uint32_t, std::string> _signatures;
		static std::vector<link_descriptor_model> _linkDescriptors;
		static std::vector<dynamic_import_descriptor_model> _dynamicImportDescriptors;
		static std::vector<std::string> _patternSearchSections;
		static std::vector<HMODULE> _holdingLibraries;
		static void reset_dynamic_imports();
		static void resolve_dynamic_imports();
		static void initialize_dlnk(HMODULE hModule);
		static void finalize_dlnk();
		static void* get_address_for_symbol(const std::string& symbol);
		static void* get_address_for_demangled_name(const std::string& name);
	};
}

bool dlnk::loader::_initialized = false;
HMODULE dlnk::loader::_module = nullptr;
std::vector<dlnk::descriptor_entry*> dlnk::loader::_descriptors = {};
std::unordered_map<uint32_t, dlnk::symbol_indexer_entry*> dlnk::loader::_symbolIndexers = {};
std::unordered_map<uint32_t, dlnk::symbol_descriptor_entry*> dlnk::loader::_symbolDescriptors = {};
std::unordered_map<uint32_t, std::string> dlnk::loader::_symbolNames = {};
std::unordered_map<uint32_t, std::string> dlnk::loader::_demangledSymbolNames = {};
std::unordered_map<uint32_t, std::string> dlnk::loader::_signatures = {};
std::vector<dlnk::link_descriptor_model> dlnk::loader::_linkDescriptors = {};
std::vector<dlnk::dynamic_import_descriptor_model> dlnk::loader::_dynamicImportDescriptors = {};
std::vector<std::string> dlnk::loader::_patternSearchSections = {
	".text",
	".data",
	".rdata"
};
std::vector<HMODULE> dlnk::loader::_holdingLibraries = {};

void* dlnk::loader::get_address_for_symbol(const std::string& symbol) {
	if (!_initialized)
		return nullptr;
	for (const auto& diDescriptor : _dynamicImportDescriptors) {
		auto diSymbolIt = std::find_if(diDescriptor.symbols.begin(), diDescriptor.symbols.end(), [&](const dynamic_symbol_descriptor_model& dsd) { return dsd.symbol == symbol; });
		if (diSymbolIt != diDescriptor.symbols.end())
			return reinterpret_cast<void*>(*diSymbolIt->address);
	}
	return nullptr;
}

void* dlnk::loader::get_address_for_demangled_name(const std::string& name) {
	if (!_initialized || _dynamicImportDescriptors.size() == 0 || _linkDescriptors.size() == 0)
		return nullptr;
	std::optional<std::string> symbolToMatch = std::nullopt;
	for (const auto& linkDescriptor : _linkDescriptors) {
		auto symbolIt = std::find_if(linkDescriptor.symbols.begin(), linkDescriptor.symbols.end(), [&](const symbol_descriptor_model& sdm) { return sdm.demangledName.find(name) != std::string::npos; });
		if (symbolIt != linkDescriptor.symbols.end()) {
			symbolToMatch = symbolIt->name;
			break;
		}
	}

	if (!symbolToMatch.has_value())
		return nullptr;
	return get_address_for_symbol(symbolToMatch.value());
}

void dlnk::loader::reset_dynamic_imports() {
	for (const auto& diDescriptor : _dynamicImportDescriptors) {
		if (diDescriptor.symbols.size() == 0)
			continue;
		DWORD oldProtect = 0;
		VirtualProtect(diDescriptor.symbols[0].address, sizeof(uintptr_t) * diDescriptor.symbols.size(), PAGE_READWRITE, &oldProtect);
		for (const auto& diSymbol : diDescriptor.symbols) {
			*diSymbol.address = NULL;
		}
		VirtualProtect(diDescriptor.symbols[0].address, sizeof(uintptr_t) * diDescriptor.symbols.size(), oldProtect, &oldProtect);
	}
}

void dlnk::loader::resolve_dynamic_imports() {
	for (const auto& diDescriptor : _dynamicImportDescriptors) {
		if (diDescriptor.symbols.size() == 0)
			continue;
		uintptr_t moduleBase = reinterpret_cast<uintptr_t>(GetModuleHandleA(diDescriptor.name.c_str()));
		if (moduleBase == 0)
			continue;
		_holdingLibraries.push_back(reinterpret_cast<HMODULE>(LoadLibraryA(diDescriptor.name.c_str())));
		auto ldit = std::find_if(_linkDescriptors.begin(), _linkDescriptors.end(), [&](const link_descriptor_model& ldm) { return ldm.name == diDescriptor.name; });
		if (ldit == _linkDescriptors.end())
			continue;
		link_descriptor_model& linkDescriptor = *ldit;
		DWORD oldProtect = 0;
		VirtualProtect(diDescriptor.symbols[0].address, sizeof(uintptr_t) * diDescriptor.symbols.size(), PAGE_READWRITE, &oldProtect);
		for (const auto& diSymbol : diDescriptor.symbols) {
			auto ldsit = std::find_if(linkDescriptor.symbols.begin(), linkDescriptor.symbols.end(), [&](const symbol_descriptor_model& lds) { return lds.name == diSymbol.symbol; });
			if (ldsit == linkDescriptor.symbols.end())
				continue;
			symbol_descriptor_model& ldSymbol = *ldsit;
			if (!ldSymbol.signature.has_value()) {	
				*diSymbol.address =  + ldSymbol.address;
			}
			else {
				auto pattern = hat::parse_signature(*ldSymbol.signature);
				if (!pattern.has_value())
					continue;
				auto module = hat::process::get_module(diDescriptor.name.c_str());
				for (const auto& section : _patternSearchSections) {
					auto result = hat::find_pattern(pattern.value(), section, *module);
					if (result.has_result()) {
						*diSymbol.address = reinterpret_cast<uintptr_t>(result.get());
						break;
					}
				}
			}
		}
		VirtualProtect(diDescriptor.symbols[0].address, sizeof(uintptr_t) * diDescriptor.symbols.size(), oldProtect, &oldProtect);
	}
}

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
	IMAGE_SECTION_HEADER* diDataSection = nullptr;

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
		else if (strcmp(reinterpret_cast<const char*>(sectionHeader->Name), DLNK_DYNAMIC_IMPORT_DESCRIPTOR) == 0) {
			diDataSection = sectionHeader;
		}
	}

	if (!dlnkDescriptorTableSectionHeader || 
		!dlnkSymbolIndexerTableSectionHeader || 
		!dlnkSymbolDescriptorTableSectionHeader || 
		!dlnkSymbolNameTableSectionHeader || 
		!dlnkSymbolDemangledNameTableSectionHeader || 
		!dlnkSymbolPointerSignatureTableSectionHeader)
		return finalize_dlnk();

	symbol_string_table* symbolNameTable = reinterpret_cast<symbol_string_table*>(base + dlnkSymbolNameTableSectionHeader->VirtualAddress);
	symbol_string_table* symbolDemangledNameTable = reinterpret_cast<symbol_string_table*>(base + dlnkSymbolDemangledNameTableSectionHeader->VirtualAddress);
	symbol_string_table* symbolPointerSignatureTable = reinterpret_cast<symbol_string_table*>(base + dlnkSymbolPointerSignatureTableSectionHeader->VirtualAddress);
	descriptor_table* descriptorTable = reinterpret_cast<descriptor_table*>(base + dlnkDescriptorTableSectionHeader->VirtualAddress);
	symbol_descriptor_table* symbolDescriptorTable = reinterpret_cast<symbol_descriptor_table*>(base + dlnkSymbolDescriptorTableSectionHeader->VirtualAddress);

	if (symbolNameTable->count != symbolDemangledNameTable->count)
		throw std::runtime_error("Symbol name table and demangled symbol name table count mismatch");

	uint32_t nameOffset = 0;
	for (uint32_t i = 0; i < symbolNameTable->count; i++) {
		const char* name = &(&symbolNameTable->names)[nameOffset];
		nameOffset += strlen(name) + 1;
		_symbolNames.insert({ i + 1, name });
	}

	uint32_t demangledNameOffset = 0;
	for (uint32_t i = 0; i < symbolDemangledNameTable->count; i++) {
		const char* name = &(&symbolDemangledNameTable->names)[demangledNameOffset];
		demangledNameOffset += strlen(name) + 1;
		_demangledSymbolNames.insert({ i + 1, name });
	}

	uint32_t signatureOffset = 0;
	for (uint32_t i = 0; i < symbolPointerSignatureTable->count; i++) {
		const char* signature = &(&symbolPointerSignatureTable->names)[signatureOffset];
		signatureOffset += strlen(signature) + 1;
		_signatures.insert({ i + 1, signature });
	}

	uint32_t indexerOffset = 0;
	for (uint32_t i = 0; i < descriptorTable->count; i++) {
		descriptor_entry* entry = &(&descriptorTable->entries)[i];
		symbol_indexer_entry* indexer = reinterpret_cast<symbol_indexer_entry*>(base + dlnkSymbolIndexerTableSectionHeader->VirtualAddress + indexerOffset);
		indexerOffset += sizeof(uint32_t) + (indexer->count * sizeof(uint32_t));
		_symbolIndexers.insert({ entry->symbolIndexerOffset, indexer });
		_descriptors.push_back(entry);
	}

	for (uint32_t i = 0; i < symbolDescriptorTable->count; i++) {
		symbol_descriptor_entry* entry = &(&symbolDescriptorTable->entries)[i];
		_symbolDescriptors.insert({ i + 1, entry });
	}

	for (descriptor_entry* descriptor : _descriptors) {
		link_descriptor_model linkDescriptor;
		linkDescriptor.name = reinterpret_cast<const char*>(base + dlnkDescriptorTableSectionHeader->VirtualAddress + descriptor->nameOffset);
		symbol_indexer_entry* indexer = _symbolIndexers[descriptor->symbolIndexerOffset];
		for (uint32_t i = 0; i < indexer->count; i++) {
			uint32_t symbolIndex = (&indexer->nameOffset)[i];
			symbol_descriptor_entry* symbolDescriptor = _symbolDescriptors[symbolIndex];
			linkDescriptor.symbols.push_back({
				.name = _symbolNames[symbolDescriptor->nameOffset],
				.demangledName = _demangledSymbolNames[symbolDescriptor->nameOffset],
				.signature = (symbolDescriptor->signatureOffset != 0 ? std::make_optional(_signatures[symbolDescriptor->signatureOffset]) : std::nullopt),
				.address = symbolDescriptor->address
			});
		}
		_linkDescriptors.push_back(linkDescriptor);
	}

	if (!diDataSection)
		return;

	static IMAGE_IMPORT_DESCRIPTOR zero = { 0 };
	IMAGE_IMPORT_DESCRIPTOR* importDescriptor = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(base + diDataSection->VirtualAddress);
	while (memcmp(importDescriptor, &zero, sizeof(zero)) != 0) {
		std::string moduleName = reinterpret_cast<const char*>(base + importDescriptor->Name);
		dynamic_import_descriptor_model importDescriptorModel{
			.name = moduleName,
			.symbols = {}
		};

		uintptr_t* ilt = reinterpret_cast<uintptr_t*>(base + importDescriptor->OriginalFirstThunk);
		uintptr_t* iat = reinterpret_cast<uintptr_t*>(base + importDescriptor->FirstThunk);
		while (*ilt != 0) {
			if (IMAGE_SNAP_BY_ORDINAL(*ilt)) {
				ilt++;
				iat++;
				continue;
			}

			uintptr_t* address = iat;
			std::string symbolName = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(base + (*ilt))->Name;
			importDescriptorModel.symbols.push_back({
				.symbol = symbolName,
				.address = address
			});
			ilt++;
			iat++;
		}
		_dynamicImportDescriptors.push_back(importDescriptorModel);
		importDescriptor++;
	}

	reset_dynamic_imports();
	resolve_dynamic_imports();
}

void dlnk::loader::finalize_dlnk() {
	if (!_initialized)
		return;
	// Do dlnk finalization here
	_initialized = false;
	_module = nullptr;
	_descriptors.clear();
	_symbolIndexers.clear();
	_symbolDescriptors.clear();
	_symbolNames.clear();
	_demangledSymbolNames.clear();
	_signatures.clear();
	_linkDescriptors.clear();
	_dynamicImportDescriptors.clear();
	for (const auto& lib : _holdingLibraries) {
		FreeLibrary(lib);
	}
	_holdingLibraries.clear();
}
#pragma pack(pop)