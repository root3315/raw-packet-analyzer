cmake_minimum_required(VERSION 3.10)
project(raw-packet-analyzer VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

set(CMAKE_CXX_FLAGS_DEBUG "-g -O0 -Wall -Wextra -Wpedantic")
set(CMAKE_CXX_FLAGS_RELEASE "-O2 -Wall -Wextra -Wpedantic")

include_directories(${CMAKE_SOURCE_DIR}/include)

set(SOURCES
    src/main.cpp
    src/packet.cpp
    src/analyzer.cpp
)

set(HEADERS
    include/packet.h
    include/analyzer.h
)

add_executable(packet-analyzer ${SOURCES} ${HEADERS})

target_link_libraries(packet-analyzer PRIVATE pthread)

install(TARGETS packet-analyzer DESTINATION bin)

# Test configuration
enable_testing()

set(TEST_SOURCES
    tests/test_packet.cpp
    src/packet.cpp
    src/analyzer.cpp
)

add_executable(packet-analyzer-tests ${TEST_SOURCES} ${HEADERS})
target_include_directories(packet-analyzer-tests PRIVATE ${CMAKE_SOURCE_DIR}/include)
target_link_libraries(packet-analyzer-tests PRIVATE pthread)

add_test(NAME PacketAnalyzerTests COMMAND packet-analyzer-tests)

# Custom target for running tests
add_custom_target(run-tests
    COMMAND ${CMAKE_CTEST_COMMAND} --output-on-failure
    DEPENDS packet-analyzer-tests
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
)

# Documentation
find_package(Doxygen QUIET)
if(DOXYGEN_FOUND)
    set(DOXYGEN_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/docs)
    set(DOXYGEN_GENERATE_HTML YES)
    set(DOXYGEN_GENERATE_MAN NO)
    
    doxygen_add_docs(docs
        ${CMAKE_SOURCE_DIR}/include
        ${CMAKE_SOURCE_DIR}/src
        COMMENT "Generating API documentation with Doxygen"
    )
endif()

# CPack configuration for packaging
set(CPACK_PACKAGE_NAME "raw-packet-analyzer")
set(CPACK_PACKAGE_VERSION "1.0.0")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "Low-level network packet analyzer")
set(CPACK_PACKAGE_VENDOR "Packet Analyzer Project")
set(CPACK_PACKAGE_CONTACT "packet-analyzer@example.com")
set(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_SOURCE_DIR}/LICENSE")
set(CPACK_RESOURCE_FILE_README "${CMAKE_SOURCE_DIR}/README.md")

include(CPack)
