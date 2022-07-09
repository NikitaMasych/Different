#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <Windows.h>


#define MakePtr( cast, ptr, addValue ) (cast)( (DWORD)(ptr) + (DWORD)(addValue))

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

void DumpLibFile(LPVOID lpFileBase, std::vector<std::string>& result)
{
	
	PIMAGE_ARCHIVE_MEMBER_HEADER pArchHeader;

	pArchHeader = MakePtr(PIMAGE_ARCHIVE_MEMBER_HEADER, lpFileBase,
		IMAGE_ARCHIVE_START_SIZE);

	while (pArchHeader){
		DWORD thisMemberSize;
		
		result.emplace_back(std::string(reinterpret_cast<char*>(pArchHeader->Name)));

		// Calculate how big this member is 
		
		thisMemberSize = atoi((char*)pArchHeader->Size)
			+ IMAGE_SIZEOF_ARCHIVE_MEMBER_HDR;

		thisMemberSize = (thisMemberSize + 1) & ~1;   // Round up

		// Get a pointer to the next archive member
		pArchHeader = MakePtr(PIMAGE_ARCHIVE_MEMBER_HEADER, pArchHeader,
			thisMemberSize);
	}
}

void getAllDLLS(std::string file_name, std::vector<std::string> result) {
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
	std::cout << (char*)(lpFileBase) << '\n';
	std::cout << IMAGE_ARCHIVE_START;
	
	if (0 == strncmp((char*)(lpFileBase), IMAGE_ARCHIVE_START,
		IMAGE_ARCHIVE_START_SIZE))
	{
		DumpLibFile(lpFileBase, result);
	}
	else
		std::cout << "Unrecognized file format!\n";

	UnmapViewOfFile(lpFileBase);
	CloseHandle(hFileMapping);
	CloseHandle(hFile);
}

int main() {
	
	std::ifstream file_exe; std::string file_exe_name; getFile(file_exe, file_exe_name, ".EXE"); 	// C:\Users\38099\Downloads\NordVPNSetup.exe
	std::ifstream file_ico; std::string file_ico_name; getFile(file_ico, file_ico_name, ".ICO"); 	// C:\Users\38099\Downloads\protection_shield_security_secured_padlock_icon_225128.ico
	
	double exe_entropy = calculateEntropy(file_exe);
	double ico_entropy = calculateEntropy(file_ico);
	
	std::cout << exe_entropy << '\n';
	std::cout << ico_entropy;
	
	std::vector<std::string> dlls;  getAllDLLS(file_exe_name, dlls);
	for (auto dll : dlls) {
		std::cout << dll;
	}
	
	return 0;
}
