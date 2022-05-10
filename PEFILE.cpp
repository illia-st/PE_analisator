#include "PEFILE.h"

int INITPARSE(FILE* PpeFile) {

	___IMAGE_DOS_HEADER TMP_DOS_HEADER;// структура для вмісту дос хедера
	WORD PEFILE_TYPE;// тип нашого файлу 

	fseek(PpeFile, 0, SEEK_SET);// встановлюємо вказівник на початок файлу
	fread(&TMP_DOS_HEADER, sizeof(___IMAGE_DOS_HEADER), 1, PpeFile);// читаємо в нашу структуру вміст файлу

	if (TMP_DOS_HEADER.e_magic != ___IMAGE_DOS_SIGNATURE) {// тут йже перевірка, чи є цей файл PE файлов
		printf("Error. Not a PE file.\n");//  ___IMAGE_DOS_SIGNATURE дефолтне значення для MS-DOS-compatible files
		return 1;
	}

	fseek(PpeFile, (TMP_DOS_HEADER.e_lfanew + sizeof(DWORD) + sizeof(___IMAGE_FILE_HEADER)), SEEK_SET);// вкзівник на початок PE
	fread(&PEFILE_TYPE, sizeof(WORD), 1, PpeFile);// читаємо тип файлу (32біта чи 64біта)

	if (PEFILE_TYPE == ___IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
		return 32;
	}
	else if (PEFILE_TYPE == ___IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
		return 64;
	}
	else {
		throw std::invalid_argument("Error while parsing IMAGE_OPTIONAL_HEADER.Magic. Unknown Type.");
	}

}