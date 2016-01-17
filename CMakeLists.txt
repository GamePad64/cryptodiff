cmake_minimum_required(VERSION 3.2)
project(cryptodiff VERSION 0.9.1)

include(GNUInstallDirs)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/cmake")

#============================================================================
# Settable options
#============================================================================

option(BUILD_DOCUMENTATION "Use Doxygen to create the HTML based API documentation" OFF)

#============================================================================
# Internal compiler options
#============================================================================

set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_EXTENSIONS OFF)

include_directories(contrib)

if(MSVC)
	# Force to always compile with W4
	if(CMAKE_CXX_FLAGS MATCHES "/W[0-4]")
		string(REGEX REPLACE "/W[0-4]" "/W4" CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS}")
	else()
		set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /W4")
	endif()
elseif(CMAKE_COMPILER_IS_GNUCC OR CMAKE_COMPILER_IS_GNUCXX)
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wno-long-long")
endif()
if(WIN32)
	add_definitions(-D_WIN32_WINNT=0x600)
endif()

if(CMAKE_COMPILER_IS_GNUCXX)
	# Use -flto flag to enable GCC's link-time optimization.
	set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -flto")
	set(CMAKE_C_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -flto")
	set(CMAKE_EXE_LINKER_FLAGS_RELEASE "${CMAKE_EXE_LINKER_FLAGS_RELEASE} -flto")
	set(CMAKE_MODULE_LINKER_FLAGS_RELEASE "${CMAKE_MODULE_LINKER_FLAGS_RELEASE} -flto")
endif()

#============================================================================
# Sources & headers
#============================================================================

file(GLOB_RECURSE cryptodiff_SOURCES "src/*.cpp")
file(GLOB_RECURSE cryptodiff_HEADERS "include/*.h")

#============================================================================
# Compile targets
#============================================================================

add_library(cryptodiff-object OBJECT ${cryptodiff_SOURCES})
set_target_properties(cryptodiff-object PROPERTIES POSITION_INDEPENDENT_CODE TRUE)

add_library(cryptodiff-static STATIC $<TARGET_OBJECTS:cryptodiff-object>)
add_library(cryptodiff-shared SHARED $<TARGET_OBJECTS:cryptodiff-object>)

target_include_directories(cryptodiff-static PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include> $<INSTALL_INTERFACE:include>)
target_include_directories(cryptodiff-shared PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include> $<INSTALL_INTERFACE:include>)

if(NOT MSVC)
	set_target_properties(cryptodiff-static PROPERTIES
			OUTPUT_NAME cryptodiff
			)

	set_target_properties(cryptodiff-shared PROPERTIES
			SOVERSION ${cryptodiff_VERSION_MAJOR}
			OUTPUT_NAME cryptodiff
			)
endif()

#============================================================================
# Third-party libraries
#============================================================================

# WinSock
if(WIN32)
	target_link_libraries(cryptodiff-static PRIVATE ws2_32)
	target_link_libraries(cryptodiff-shared PRIVATE ws2_32)
endif()

# Threads
find_package(Threads)
target_link_libraries(cryptodiff-static PRIVATE ${CMAKE_THREAD_LIBS_INIT})
target_link_libraries(cryptodiff-shared PRIVATE ${CMAKE_THREAD_LIBS_INIT})

# Boost
set(Boost_COMPONENTS
		system
		filesystem
		iostreams)
set(Boost_USE_MULTITHREADED ON)

# shared executable
find_package(Boost COMPONENTS ${Boost_COMPONENTS} REQUIRED)
target_link_libraries(cryptodiff-shared PRIVATE ${Boost_LIBRARIES})
target_include_directories(cryptodiff-shared PRIVATE ${Boost_INCLUDE_DIRS})
message(STATUS "Boost shared libraries: ${Boost_LIBRARIES}")

# reset
unset(Boost_LIBRARIES)
set(Boost_USE_STATIC_LIBS ON)

# static executable
find_package(Boost COMPONENTS ${Boost_COMPONENTS} REQUIRED)
target_link_libraries(cryptodiff-static PRIVATE ${Boost_LIBRARIES})
target_include_directories(cryptodiff-static PRIVATE ${Boost_INCLUDE_DIRS})
message(STATUS "Boost static libraries: ${Boost_LIBRARIES}")
# /Boost

# CryptoPP
find_package(CryptoPP REQUIRED)

target_link_libraries(cryptodiff-static PRIVATE cryptopp-static)
target_link_libraries(cryptodiff-shared PRIVATE cryptopp-shared)
# /CryptoPP

#============================================================================
# Doxygen documentation
#============================================================================
if(BUILD_DOCUMENTATION)
	find_package(Doxygen REQUIRED)

	configure_file(Doxyfile.in ${PROJECT_BINARY_DIR}/Doxyfile @ONLY IMMEDIATE)
	add_custom_target(docs ALL COMMAND ${DOXYGEN_EXECUTABLE} ${PROJECT_BINARY_DIR}/Doxyfile SOURCES ${PROJECT_BINARY_DIR}/Doxyfile)
endif()

#============================================================================
# Install
#============================================================================
set(export_name "cryptodiff-targets")

# Runtime package
install(TARGETS cryptodiff-shared EXPORT ${export_name} DESTINATION ${CMAKE_INSTALL_LIBDIR})

# Development package
install(TARGETS cryptodiff-static EXPORT ${export_name} DESTINATION ${CMAKE_INSTALL_LIBDIR})
install(FILES ${cryptodiff_HEADERS} DESTINATION include)

# Cmake Package
include(CMakePackageConfigHelpers)
write_basic_package_version_file("${PROJECT_BINARY_DIR}/cryptodiff-config-version.cmake" COMPATIBILITY SameMajorVersion)
install(FILES cmake/cryptodiff-config.cmake ${PROJECT_BINARY_DIR}/cryptodiff-config-version.cmake DESTINATION "lib/cmake/cryptodiff")
install(EXPORT ${export_name} DESTINATION "lib/cmake/cryptodiff")
