#include "PE64FILE.h"


PE64FILE::PE64FILE(char* _NAME, FILE* Ppefile): NAME(_NAME), Ppefile(Ppefile){  }

void PE64FILE::PrintInfo(){
    ParseDOSHeader();
    ParseNTHeaders();
    ParseSectionHeaders();
    ParseImportDirectory();
    PrintImportTableInfo();
}


int PE64FILE::locate(DWORD VA) {// типу повертаємо індекс секції 
	
	int index;
	
	for (int i = 0; i < PEFILE_NT_HEADERS_FILE_HEADER_NUMBER0F_SECTIONS; i++) {
		if (VA >= PEFILE_SECTION_HEADERS[i].VirtualAddress
			&& VA < (PEFILE_SECTION_HEADERS[i].VirtualAddress + PEFILE_SECTION_HEADERS[i].Misc.VirtualSize)){
			index = i;
			break;
		}
	}
	return index;
}

DWORD PE64FILE::resolve(DWORD VA, int index) {// індекс це нумерація секції

	return (VA - PEFILE_SECTION_HEADERS[index].VirtualAddress) + PEFILE_SECTION_HEADERS[index].PointerToRawData;
	// типу зсув на початок секції
}

// PARSERS
void PE64FILE::ParseDOSHeader() {
	
	fseek(Ppefile, 0, SEEK_SET);
	fread(&PEFILE_DOS_HEADER, sizeof(___IMAGE_DOS_HEADER), 1, Ppefile);

	PEFILE_DOS_HEADER_EMAGIC = PEFILE_DOS_HEADER.e_magic;
	PEFILE_DOS_HEADER_LFANEW = PEFILE_DOS_HEADER.e_lfanew;

}
void PE64FILE::ParseNTHeaders() {
	
	fseek(Ppefile, PEFILE_DOS_HEADER.e_lfanew, SEEK_SET);
	fread(&PEFILE_NT_HEADERS, sizeof(PEFILE_NT_HEADERS), 1, Ppefile);

	PEFILE_NT_HEADERS_SIGNATURE = PEFILE_NT_HEADERS.Signature;
	PEFILE_NT_HEADERS_FILE_HEADER_NUMBER0F_SECTIONS = PEFILE_NT_HEADERS.FileHeader.NumberOfSections;

    PEFILE_IMPORT_DIRECTORY = PEFILE_NT_HEADERS.OptionalHeader.DataDirectory[___IMAGE_DIRECTORY_ENTRY_IMPORT];

}
void PE64FILE::ParseSectionHeaders() {
	
	PEFILE_SECTION_HEADERS = new ___IMAGE_SECTION_HEADER[PEFILE_NT_HEADERS_FILE_HEADER_NUMBER0F_SECTIONS];
	for (int i = 0; i < PEFILE_NT_HEADERS_FILE_HEADER_NUMBER0F_SECTIONS; i++) {
		int offset = (PEFILE_DOS_HEADER.e_lfanew + sizeof(PEFILE_NT_HEADERS)) + (i * ___IMAGE_SIZEOF_SECTION_HEADER);
		fseek(Ppefile, offset, SEEK_SET);
		fread(&PEFILE_SECTION_HEADERS[i], ___IMAGE_SIZEOF_SECTION_HEADER, 1, Ppefile);
	}

}
void PE64FILE::ParseImportDirectory() {
	
	DWORD _import_directory_address = resolve(PEFILE_IMPORT_DIRECTORY.VirtualAddress, locate(PEFILE_IMPORT_DIRECTORY.VirtualAddress));
	_import_directory_count = 0;

	while (true) {
		___IMAGE_IMPORT_DESCRIPTOR tmp;
		int offset = (_import_directory_count * sizeof(___IMAGE_IMPORT_DESCRIPTOR)) + _import_directory_address;
		fseek(Ppefile, offset, SEEK_SET);
		fread(&tmp, sizeof(___IMAGE_IMPORT_DESCRIPTOR), 1, Ppefile);

		if (tmp.Name == 0x00000000 && tmp.FirstThunk == 0x00000000) {
			_import_directory_count -= 1;
			_import_directory_size = _import_directory_count * sizeof(___IMAGE_IMPORT_DESCRIPTOR);
			break;
		}

		_import_directory_count++;
	}
	// на цій секції вже має бути кількість імпортів
	PEFILE_IMPORT_TABLE = new ___IMAGE_IMPORT_DESCRIPTOR[_import_directory_count];

	for (int i = 0; i < _import_directory_count; i++) {
		int offset = (i * sizeof(___IMAGE_IMPORT_DESCRIPTOR)) + _import_directory_address;
		fseek(Ppefile, offset, SEEK_SET);
		fread(&PEFILE_IMPORT_TABLE[i], sizeof(___IMAGE_IMPORT_DESCRIPTOR), 1, Ppefile);
	}
	// а ось тут в нас вже є масив, що містить всі імортовані бібліотеки
}
void PE64FILE::PrintImportTableInfo() {
	
	printf(" IMPORT TABLE:\n");
	printf(" ----------------\n\n");

	for (int i = 0; i < _import_directory_count; i++) {
		DWORD NameAddr = resolve(PEFILE_IMPORT_TABLE[i].Name, locate(PEFILE_IMPORT_TABLE[i].Name));
		int NameSize = 0;

		while (true) {
			char tmp;
			fseek(Ppefile, (NameAddr + NameSize), SEEK_SET);
			fread(&tmp, sizeof(char), 1, Ppefile);

			if (tmp == 0x00) {
				break;
			}

			NameSize++;
		}

		char* Name = new char[NameSize + 2];
		fseek(Ppefile, NameAddr, SEEK_SET);
		fread(Name, (NameSize * sizeof(char)) + 1, 1, Ppefile);
		printf("   * %s:\n", Name);
		delete[] Name;

		printf("       ILT RVA: 0x%X\n", PEFILE_IMPORT_TABLE[i].DUMMYUNIONNAME.OriginalFirstThunk);
		printf("       IAT RVA: 0x%X\n", PEFILE_IMPORT_TABLE[i].FirstThunk);

		if (PEFILE_IMPORT_TABLE[i].TimeDateStamp == 0) {
			printf("       Bound: FALSE\n");
		}
		else if (PEFILE_IMPORT_TABLE[i].TimeDateStamp == -1) {
			printf("       Bound: TRUE\n");
		}

		printf("\n");

		DWORD ILTAddr = resolve(PEFILE_IMPORT_TABLE[i].DUMMYUNIONNAME.OriginalFirstThunk, locate(PEFILE_IMPORT_TABLE[i].DUMMYUNIONNAME.OriginalFirstThunk));
		int entrycounter = 0;

		while (true) {

			ILT_ENTRY_64 entry;

			fseek(Ppefile, (ILTAddr + (entrycounter * sizeof(QWORD))), SEEK_SET);
			fread(&entry, sizeof(ILT_ENTRY_64), 1, Ppefile);

			BYTE flag = entry.ORDINAL_NAME_FLAG;
			DWORD HintRVA = 0x0;
			WORD ordinal = 0x0;

			if (flag == 0x0) {
				HintRVA = entry.FIELD_2.HINT_NAME_TABE;
			}
			else if (flag == 0x01) {
				ordinal = entry.FIELD_2.ORDINAL;
			}

			if (flag == 0x0 && HintRVA == 0x0 && ordinal == 0x0) {
				break;
			}

			printf("\n       Entry:\n");

			if (flag == 0x0) {
				___IMAGE_IMPORT_BY_NAME hint;

				DWORD HintAddr = resolve(HintRVA, locate(HintRVA));
				fseek(Ppefile, HintAddr, SEEK_SET);
				fread(&hint, sizeof(___IMAGE_IMPORT_BY_NAME), 1, Ppefile);
				printf("         Name: %s\n", hint.Name);
				printf("         Hint RVA: 0x%X\n", HintRVA);
				printf("         Hint: 0x%X\n", hint.Hint);
			}
			else if (flag == 1) {
				printf("         Ordinal: 0x%X\n", ordinal);
			}

			entrycounter++;
		}

		printf("\n   ----------------------\n\n");

	}

}