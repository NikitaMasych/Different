#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <Windows.h>

#pragma hdrstop

#define MakePtr( cast, ptr, addValue ) (cast)( (long long)(ptr) + (long long)(addValue))

void getFile(std::ifstream& file, std::string& file_name, const std::string& extension) {
	/* Asks for the path to the file and opens it in binary mode*/
	do {
		std::cout << "Enter the " << extension << " file location (without quotes) : ";
		std::getline(std::cin, file_name);
		file.open(file_name, std::ios::binary | std::ios::in);
	} while (!file.is_open() && std::cerr << "Invalid file location!\n");
}

double calculateEntropy(std::ifstream& file) {
	/* Calculates Shannon's entropy of a binary file */
	double entropy = 0;
	char byte;
	std::vector<size_t> byte_counter(256, 0);
	size_t file_size = 0;
	while (!file.eof()) {
		file.read(&byte, 1);
		// cast in order to obtain unsigned indexing
		byte_counter[static_cast<uint_fast8_t>(byte)] ++;
		file_size ++;
	}
	for (auto bc : byte_counter) {
		if (bc == 0) continue;
		double p = (1.0 * bc) / file_size;
		entropy -=  p * log2(p);
	}
	
	return entropy / 8.0; // because we must have been taking the log with 256 base
}

PIMAGE_SECTION_HEADER GetEnclosingSectionHeader(long long rva,
	PIMAGE_NT_HEADERS pNTHeader)
{
	PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(pNTHeader);
	unsigned i;

	for (i = 0; i < pNTHeader->FileHeader.NumberOfSections; i++, section++)
	{
		// Is the RVA within this section?
		if ((rva >= section->VirtualAddress) &&
			(rva < (section->VirtualAddress + section->Misc.VirtualSize)))
			return section;
	}

	return 0;
}

LPVOID GetPtrFromRVA(long long rva, PIMAGE_NT_HEADERS pNTHeader, long long imageBase){
	PIMAGE_SECTION_HEADER pSectionHdr;
	INT delta;

	pSectionHdr = GetEnclosingSectionHeader(rva, pNTHeader);
	if (!pSectionHdr)
		return 0;

	delta = (INT)(pSectionHdr->VirtualAddress - pSectionHdr->PointerToRawData);
	return (PVOID)(imageBase + rva - delta);
}

void DumpImportsSection(long long base, PIMAGE_NT_HEADERS pNTHeader,
						std::vector<std::string>& result){
	PIMAGE_IMPORT_DESCRIPTOR importDesc;
	PIMAGE_SECTION_HEADER pSection;
	long long importsStartRVA;
	PSTR pszTimeDate;

	// Look up where the imports section is (normally in the .idata section)
	// but not necessarily so.  Therefore, grab the RVA from the data dir.
	
	importsStartRVA = pNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
	if (!importsStartRVA)
		return;

	// Get the IMAGE_SECTION_HEADER that contains the imports.  This is
	// usually the .idata section, but doesn't have to be.
	pSection = GetEnclosingSectionHeader(importsStartRVA, pNTHeader);
	if (!pSection)
		return;

	importDesc = (PIMAGE_IMPORT_DESCRIPTOR)
		GetPtrFromRVA(importsStartRVA, pNTHeader, base);
	if (!importDesc)
		return;

	while (1)
	{
		// See if we've reached an empty IMAGE_IMPORT_DESCRIPTOR
		if ((importDesc->TimeDateStamp == 0) && (importDesc->Name == 0))
			break;
		// POTENTIAL PROBLEM:
		std::cout << reinterpret_cast<char*>(GetPtrFromRVA(importDesc->Name, pNTHeader, base));
		result.emplace_back(std::string(reinterpret_cast<char*>(GetPtrFromRVA(importDesc->Name, pNTHeader, base))));

		importDesc++;   // advance to next IMAGE_IMPORT_DESCRIPTOR
	}
}

void DumpExeFile(PIMAGE_DOS_HEADER dosHeader, std::vector<std::string>& result){
	PIMAGE_NT_HEADERS pNTHeader;
	long long base = (long long)dosHeader;
	pNTHeader = MakePtr(PIMAGE_NT_HEADERS, dosHeader, dosHeader->e_lfanew);
	// First, verify that the e_lfanew field gave us a reasonable
	// pointer, then verify the PE signature.
	__try
	{
		if (pNTHeader->Signature != IMAGE_NT_SIGNATURE)
		{
			printf("Not a Portable Executable (PE) EXE\n");
			return;
		}
	}
	__except (TRUE)    // Should only get here if pNTHeader (above) is bogus
	{
		printf("invalid .EXE\n");
		return;
	}
	DumpImportsSection(base, pNTHeader, result);
}

void getAllDLLS(std::string file_name, std::vector<std::string>& result) {
	// Lists all DLL's of the .PE file 

	HANDLE hFile;
	HANDLE hFileMapping;
	LPVOID lpFileBase;
	PIMAGE_DOS_HEADER dosHeader;

	hFile = CreateFileA(file_name.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL,
		OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);

	if (hFile == INVALID_HANDLE_VALUE)
	{
		std::cout << "Couldn't open file with CreateFileA()!\n";
		return;
	}

	hFileMapping = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
	if (hFileMapping == 0)
	{
		CloseHandle(hFile);
		std::cout << "Couldn't open file mapping with CreateFileMapping()!\n";
		return;
	}

	lpFileBase = MapViewOfFile(hFileMapping, FILE_MAP_READ, 0, 0, 0);
	if (lpFileBase == 0)
	{
		CloseHandle(hFileMapping);
		CloseHandle(hFile);
		std::cout << "Couldn't map view of file with MapViewOfFile()!\n";
		return;
	}

	dosHeader = static_cast<PIMAGE_DOS_HEADER>(lpFileBase);

	if (dosHeader->e_magic == IMAGE_DOS_SIGNATURE) DumpExeFile(dosHeader, result);
	
	UnmapViewOfFile(lpFileBase);
	CloseHandle(hFileMapping);
	CloseHandle(hFile);
}

int main() {
	std::ifstream file_exe; std::string file_exe_name; getFile(file_exe, file_exe_name, ".EXE"); 	// C:\Program Files\Sublime Text 3\sublime_text.exe
	std::ifstream file_ico; std::string file_ico_name; getFile(file_ico, file_ico_name, ".ICO"); 	// C:\Users\38099\Downloads\protection_shield_security_secured_padlock_icon_225128.ico
	
	double exe_entropy = calculateEntropy(file_exe);
	double ico_entropy = calculateEntropy(file_ico);
	
	std::cout << exe_entropy << '\n';
	std::cout << ico_entropy << '\n';

	std::vector<std::string> dlls;  getAllDLLS(file_exe_name, dlls);
	for (auto& dll : dlls) {
		std::cout << dll;
	}

	return 0;
}
