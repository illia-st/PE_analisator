#include <iostream>
#include <string>
#include "PEFILE.h"
#include "PE64FILE.h"

int main() {
    try{
        char * path_to_executable = "D:\\programming\\projects.NET\\Laba_BD2\\Laba_BD2\\bin\\Debug\\net6.0-windows\\Laba_BD2.exe"; //temp variant
        
        FILE* PpeFile; 
        fopen_s(&PpeFile, path_to_executable, "rb");

        if (PpeFile == NULL) {
            std::cout << "Can't open file.\n";
            return 1;
        }
        int PEFILE_TYPE = INITPARSE(PpeFile);
        // PE64FILE file(path_to_executable, PpeFile);
        //     file.PrintInfo();
        switch (PEFILE_TYPE)
        {
        case 32:
            break;
        case 64:{
            PE64FILE file(path_to_executable, PpeFile);
            file.PrintInfo();
            fclose(PpeFile);
            break;
        }
        default:
            return 2;
        }
    }
    catch(std::invalid_argument ex){
        std::cerr << ex.what() << std::endl;
    }
    
    return 0;
}
