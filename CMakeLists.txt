cmake_minimum_required(VERSION 3.21)

project(InfoGuard VERSION 0.2.0 LANGUAGES C CXX)

if(NOT WIN32)
    message(FATAL_ERROR "The native InfoGuard client and service targets can only be built on Windows.")
endif()

set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(MSVC)
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
    add_compile_options(/W4 /permissive- /EHsc)
endif()

find_program(MIDL_EXECUTABLE NAMES midl.exe midl)
if(NOT MIDL_EXECUTABLE)
    file(GLOB MIDL_CANDIDATES
        "C:/Program Files (x86)/Windows Kits/10/bin/*/x64/midl.exe"
        "C:/Program Files/Windows Kits/10/bin/*/x64/midl.exe")
    if(MIDL_CANDIDATES)
        list(SORT MIDL_CANDIDATES COMPARE NATURAL ORDER DESCENDING)
        list(GET MIDL_CANDIDATES 0 MIDL_EXECUTABLE)
    endif()
endif()

if(NOT MIDL_EXECUTABLE)
    message(FATAL_ERROR "midl.exe was not found. Install the Windows SDK / Visual Studio C++ workload.")
endif()

set(RPC_OUTPUT_DIR "${CMAKE_CURRENT_BINARY_DIR}/generated/rpc")
set(RPC_IDL "${CMAKE_CURRENT_SOURCE_DIR}/rpc/infoguard_service_rpc.idl")
set(RPC_HEADER "${RPC_OUTPUT_DIR}/infoguard_service_rpc.h")
set(RPC_CLIENT_SOURCE "${RPC_OUTPUT_DIR}/infoguard_service_rpc_c.c")
set(RPC_SERVER_SOURCE "${RPC_OUTPUT_DIR}/infoguard_service_rpc_s.c")

add_custom_command(
    OUTPUT
        "${RPC_HEADER}"
        "${RPC_CLIENT_SOURCE}"
        "${RPC_SERVER_SOURCE}"
    COMMAND "${CMAKE_COMMAND}" -E make_directory "${RPC_OUTPUT_DIR}"
    COMMAND
        "${MIDL_EXECUTABLE}"
        /nologo
        /env x64
        /app_config
        /h infoguard_service_rpc.h
        /out "${RPC_OUTPUT_DIR}"
        "${RPC_IDL}"
    MAIN_DEPENDENCY "${RPC_IDL}"
    COMMENT "Generating Windows RPC stubs from infoguard_service_rpc.idl"
    VERBATIM)

add_library(infoguard_service_rpc_client STATIC
    "${RPC_CLIENT_SOURCE}"
    src/rpc_memory.cpp
)
target_include_directories(infoguard_service_rpc_client PUBLIC "${RPC_OUTPUT_DIR}")
target_compile_definitions(infoguard_service_rpc_client PRIVATE
    UNICODE
    _UNICODE
    NOMINMAX
    WIN32_LEAN_AND_MEAN
)
target_link_libraries(infoguard_service_rpc_client PUBLIC Rpcrt4)

add_library(infoguard_service_rpc_server STATIC
    "${RPC_SERVER_SOURCE}"
    src/rpc_memory.cpp
)
target_include_directories(infoguard_service_rpc_server PUBLIC "${RPC_OUTPUT_DIR}")
target_compile_definitions(infoguard_service_rpc_server PRIVATE
    UNICODE
    _UNICODE
    NOMINMAX
    WIN32_LEAN_AND_MEAN
)
target_link_libraries(infoguard_service_rpc_server PUBLIC Rpcrt4)

function(infoguard_apply_common_target_settings target_name)
    target_compile_definitions(${target_name} PRIVATE
        UNICODE
        _UNICODE
        NOMINMAX
        WIN32_LEAN_AND_MEAN
    )
    target_include_directories(${target_name} PRIVATE
        "${CMAKE_CURRENT_SOURCE_DIR}/src"
        "${RPC_OUTPUT_DIR}"
    )
endfunction()

add_executable(InfoGuardTrayApp WIN32
    src/license_service.cpp
    src/license_service.h
    src/main.cpp
    src/service_constants.h
    src/single_instance.cpp
    src/single_instance.h
    src/tray_application.cpp
    src/tray_application.h
    src/windows_service_client.cpp
    src/windows_service_client.h
)
infoguard_apply_common_target_settings(InfoGuardTrayApp)
target_link_libraries(InfoGuardTrayApp PRIVATE
    advapi32
    comdlg32
    shell32
    user32
    winhttp
    infoguard_service_rpc_client
)

add_executable(InfoGuardService
    src/antivirus_engine.cpp
    src/antivirus_engine.h
    src/backend_api_client.cpp
    src/backend_api_client.h
    src/infoguard_service_main.cpp
    src/service_constants.h
    src/service_session_manager.cpp
    src/service_session_manager.h
)
infoguard_apply_common_target_settings(InfoGuardService)
target_link_libraries(InfoGuardService PRIVATE
    advapi32
    bcrypt
    userenv
    wtsapi32
    winhttp
    infoguard_service_rpc_server
)
