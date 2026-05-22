cmake_minimum_required(VERSION 3.21)

project(InfoGuardTrayApp VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(MSVC)
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
    add_compile_options(/W4 /permissive- /EHsc)
endif()

add_executable(InfoGuardTrayApp WIN32
    src/license_service.cpp
    src/license_service.h
    src/main.cpp
    src/server_api_client.cpp
    src/server_api_client.h
    src/single_instance.cpp
    src/single_instance.h
    src/tray_application.cpp
    src/tray_application.h
)

target_compile_definitions(InfoGuardTrayApp PRIVATE
    UNICODE
    _UNICODE
    NOMINMAX
    WIN32_LEAN_AND_MEAN
)

target_link_libraries(InfoGuardTrayApp PRIVATE
    advapi32
    shell32
    user32
    winhttp
)
