cmake_minimum_required(VERSION 3.9 FATAL_ERROR)

project(binaryninja-pcode CXX C)

if((NOT BN_API_PATH) AND (NOT BN_INTERNAL_BUILD))
	set(BN_API_PATH $ENV{BN_API_PATH})
	if(NOT BN_API_PATH)
		message(FATAL_ERROR "Provide path to Binary Ninja API source in BN_API_PATH")
	endif()
endif()

if((NOT BN_INSTALL_DIR) AND (NOT BN_INTERNAL_BUILD) AND WIN32)
	set(BN_INSTALL_DIR $ENV{BN_INSTALL_DIR})
	if(NOT BN_INSTALL_DIR)
		message(FATAL_ERROR "Provide path to Binary Ninja installation in BN_INSTALL_DIR")
	endif()
endif()

if(NOT BN_INTERNAL_BUILD)
	add_subdirectory(${BN_API_PATH} ${PROJECT_BINARY_DIR}/api)
endif()

set(SLEIGH_COMMON
	third_party/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/address.cc
	third_party/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/context.cc
	third_party/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/float.cc
	third_party/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/globalcontext.cc
	third_party/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/opcodes.cc
	third_party/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/pcodecompile.cc
	third_party/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/pcodeparse.cc
	third_party/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/pcoderaw.cc
	third_party/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/semantics.cc
	third_party/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/sleigh.cc
	third_party/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/sleighbase.cc
	third_party/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/slghpatexpress.cc
	third_party/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/slghpattern.cc
	third_party/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/slghsymbol.cc
	third_party/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/space.cc
	third_party/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/translate.cc
	third_party/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/xml.cc
	)

add_executable(sleigh
	third_party/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/filemanage.cc
	third_party/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/slgh_compile.cc
	third_party/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/slghparse.cc
	third_party/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/slghscan.cc
	${SLEIGH_COMMON}
)

# This simply compiles all slaspec after building the sleigh compiler,
# but doesn't check for changes in the actual slaspec files
file(GLOB_RECURSE slaspec_FILES third_party/ghidra/Ghidra/Processors/*.slaspec)
foreach(slaspec ${slaspec_FILES})
    get_filename_component(sla ${slaspec} NAME_WLE)
    file(MAKE_DIRECTORY ${CMAKE_BINARY_DIR}/out/sla)

    add_custom_command(
        TARGET sleigh
        POST_BUILD
        COMMAND ${CMAKE_BINARY_DIR}/sleigh ${slaspec} ${CMAKE_BINARY_DIR}/out/sla/${sla}
    )
endforeach()

include_directories(.)

add_library(${PROJECT_NAME} SHARED
    ${SLEIGH_COMMON}
    src/pcode_architecture.cpp
)

target_link_libraries(${PROJECT_NAME}
    binaryninjaapi)

set_target_properties(${PROJECT_NAME} PROPERTIES
    CXX_STANDARD 17
    CXX_VISIBILITY_PRESET hidden
    CXX_STANDARD_REQUIRED ON
    VISIBILITY_INLINES_HIDDEN ON
    POSITION_INDEPENDENT_CODE ON
    LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/out/bin)

bn_install_plugin(${PROJECT_NAME})
