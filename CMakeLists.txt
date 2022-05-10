cmake_minimum_required(VERSION 3.0.0)
project(PE_analisator VERSION 0.1.0)

include(CTest)
enable_testing()

add_executable(PE_analisator 
                    main.cpp
                    custom_structs.h
                    PEFILE.h
                    PEFILE.cpp
                    winntdef.h
                    PE64FILE.h
                    PE64FILE.cpp)

set(CPACK_PROJECT_NAME ${PROJECT_NAME})
set(CPACK_PROJECT_VERSION ${PROJECT_VERSION})
include(CPack)
