#include <iostream>
#include <fstream>
#include "DumpDLLs.h"
#include "ChangeIcon.h"

void getFile(std::ifstream& file, std::string& path_to_file, const std::string& extension) {
	/* Asks for the path to the file and opens it in binary mode*/
	do {
		std::cout << "Enter the " << extension << " file location (without quotes) : ";
		std::getline(std::cin, path_to_file);
		file.open(path_to_file, std::ios::binary | std::ios::in);
	} while (!file.is_open() && std::cerr << "Invalid file location!\n");
}

double calculateEntropy(std::ifstream& file, size_t& file_size) {
	/* Calculates Shannon's entropy of a binary file */

	double entropy = 0;
	char byte;
	std::vector<size_t> byte_counter(256, 0);
	file_size = 0;
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

size_t calculateWinApiW(const std::vector<std::string>& dlls) {
	size_t counter = 0;
	for (const auto& name : dlls) {
		// with respect to the register*
		if (name.find('W') != std::string::npos &&
			LoadLibraryA(name.c_str())) counter++;
	}
	return counter;
}

int main() {
	
	std::ifstream file_exe; std::string path_to_exe; getFile(file_exe, path_to_exe, ".EXE"); 	
	std::ifstream file_ico; std::string path_to_ico; getFile(file_ico, path_to_ico, ".ICO"); 	
	
	size_t exe_size, ico_size;
	double exe_entropy = calculateEntropy(file_exe, exe_size); file_exe.close();
	double ico_entropy = calculateEntropy(file_ico, ico_size); file_ico.close();

	std::cout << "\n.Exe file entropy: " << exe_entropy << '\n';
	std::cout << ".Ico file entropy: " << ico_entropy << '\n';

	try {
		std::vector<std::string> dlls = getDllList(path_to_exe);
		std::cout << "\nIncluded DLL's:" << '\n' << '\n';
		for (const auto& dll : dlls) {
			std::cout << '\t' << dll << "\n";
		}
		std::cout << "\nNumber of WinApi's with W letter in name: ";
		std::cout << calculateWinApiW(dlls) << '\n';
	}
	catch (const std::exception& e) {
		std::cerr << e.what();
	}

	changeIco(path_to_exe, path_to_ico, ico_size);

	return 0;
}