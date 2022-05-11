#pragma once
#include <iostream>
#include <vector>
#include <string>
#include <map>
#include <set>
#include <algorithm>
#include "winntdef.h"
#include "custom_structs.h"

class PE64FILE{
public:
    PE64FILE(char* _NAME, FILE* Ppefile);
    void ParseFile();
    void PrintImporTable() const;
    uint32_t Get_W_Counter() const;
private:
    std::set<std::string> dlls;
    std::map<std::string, std::vector<std::string>> functions;
    
    uint32_t w_counter = 0;

    char* NAME;
    FILE* Ppefile;
    int _import_directory_count, _import_directory_size;
    int _basreloc_directory_count;

    // початкові адреси
    ___IMAGE_DOS_HEADER     PEFILE_DOS_HEADER;
    ___IMAGE_NT_HEADERS64   PEFILE_NT_HEADERS;// зсув на місце початку PE header

    // DOS HEADER
    DWORD PEFILE_DOS_HEADER_EMAGIC;// тип дос файлу
    LONG  PEFILE_DOS_HEADER_LFANEW;// адреса початку PE

    // NT_HEADERS.Signature
    DWORD PEFILE_NT_HEADERS_SIGNATURE;

    // NT_HEADERS.FileHeader
    WORD PEFILE_NT_HEADERS_FILE_HEADER_NUMBER0F_SECTIONS;

    ___IMAGE_DATA_DIRECTORY PEFILE_IMPORT_DIRECTORY;

    // SECTION HEADERS
    ___PIMAGE_SECTION_HEADER PEFILE_SECTION_HEADERS;

    // IMPORT TABLE
    ___PIMAGE_IMPORT_DESCRIPTOR PEFILE_IMPORT_TABLE;
    

    int locate(DWORD VA);
    DWORD resolve(DWORD VA, int index);

    void W_Searcher(const std::string& api);
    void ParseDOSHeader();// розпарсили дос хедери, маємо тепер місце зсуву на початок PE-header
    void ParseNTHeaders();// парсимо NT хедери
    void ParseSectionHeaders();
    void ParseImportDirectory();
    void SaveInfo();
};