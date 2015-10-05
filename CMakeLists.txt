project(cryptodiff)
cmake_minimum_required(VERSION 3.1)

include(GNUInstallDirs)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/cmake")

#============================================================================
# Compilation options
#============================================================================

#-- Add an Option to toggle the generation of the API documentation
option(SINGLE_THREADED "Build single-threaded version of the library" OFF)
if (SINGLE_THREADED)
	add_definitions(-DSINGLE_THREADED)
endif ()

#============================================================================
# Compiler properties
#============================================================================

### Setting compiler properties
SET(CMAKE_CXX_STANDARD_REQUIRED ON)
SET(CMAKE_CXX_STANDARD 14)
SET(CMAKE_CXX_EXTENSIONS OFF)

include_directories(include)
include_directories(contrib/include)
include_directories(${CMAKE_CURRENT_BINARY_DIR})

if (MSVC)
	# Force to always compile with W4
	if (CMAKE_CXX_FLAGS MATCHES "/W[0-4]")
		string(REGEX REPLACE "/W[0-4]" "/W4" CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS}")
	else()
		set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /W4")
	endif ()
elseif(CMAKE_COMPILER_IS_GNUCC OR CMAKE_COMPILER_IS_GNUCXX)
	# Update if necessary
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wno-long-long")
	#SET(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -O0 --coverage")
endif ()

IF (CMAKE_COMPILER_IS_GNUCXX)
	# Use -flto flag to enable GCC's link-time optimization.
	SET(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -flto")
	SET(CMAKE_C_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -flto")
	SET(CMAKE_EXE_LINKER_FLAGS_RELEASE "${CMAKE_EXE_LINKER_FLAGS_RELEASE} -flto")
	SET(CMAKE_MODULE_LINKER_FLAGS_RELEASE "${CMAKE_MODULE_LINKER_FLAGS_RELEASE} -flto")
ENDIF ()

#============================================================================
# Binary generation and installation
#============================================================================

file(GLOB_RECURSE LIBRARY_SRCS "src/*")
list(APPEND LIBRARY_SRCS ${PROTO_COMMON_SOURCES})
list(APPEND LIBRARY_SRCS ${PROTO_COMMON_HEADERS})

add_library(cryptodiff-shared SHARED ${LIBRARY_SRCS})
add_library(cryptodiff-static STATIC ${LIBRARY_SRCS})

SET_TARGET_PROPERTIES(cryptodiff-shared
		PROPERTIES
		VERSION 0.0.1
		SOVERSION 1
		OUTPUT_NAME cryptodiff
)

SET_TARGET_PROPERTIES(cryptodiff-static
		PROPERTIES
		VERSION 0.0.1
		SOVERSION 1
		OUTPUT_NAME cryptodiff
)

install(TARGETS cryptodiff-shared DESTINATION ${CMAKE_INSTALL_LIBDIR})
install(TARGETS cryptodiff-static DESTINATION ${CMAKE_INSTALL_LIBDIR})

install(FILES include/cryptodiff.h DESTINATION include)

#============================================================================
# Third-party Libraries
#============================================================================

# Boost
set(Boost_COMPONENTS
		system
		filesystem
		iostreams)
set(Boost_USE_MULTITHREADED ON)

# shared executable
find_package(Boost COMPONENTS ${Boost_COMPONENTS} REQUIRED)
target_link_libraries(cryptodiff-shared ${Boost_LIBRARIES})
message(STATUS "Boost shared libraries: ${Boost_LIBRARIES}")

# reset
UNSET(Boost_LIBRARIES)
SET(Boost_USE_STATIC_LIBS ON)

# static executable
find_package(Boost COMPONENTS ${Boost_COMPONENTS} REQUIRED)
target_link_libraries(cryptodiff-static ${Boost_LIBRARIES})
message(STATUS "Boost static libraries: ${Boost_LIBRARIES}")

include_directories(${Boost_INCLUDE_DIRS})
# /Boost

# CryptoPP
find_package(CryptoPP REQUIRED)

if (CRYPTOPP_FOUND)
	include_directories(${CRYPTOPP_INCLUDE_DIRS})
	target_link_libraries(cryptodiff-shared ${CRYPTOPP_LIBRARIES})
	target_link_libraries(cryptodiff-static ${CRYPTOPP_LIBRARIES})
endif ()
# /CryptoPP

#============================================================================
# Documentation generation
#============================================================================

#-- Add an Option to toggle the generation of the API documentation
option(BUILD_DOCUMENTATION "Use Doxygen to create the HTML based API documentation" OFF)
if (BUILD_DOCUMENTATION)
	FIND_PACKAGE(Doxygen)
	if (NOT DOXYGEN_FOUND)
		message(FATAL_ERROR
				"Doxygen is needed to build the documentation. Please install it correctly")
	endif ()
	#-- Configure the Template Doxyfile for our specific project
	configure_file(Doxyfile.in ${PROJECT_BINARY_DIR}/Doxyfile @ONLY IMMEDIATE)
	#-- Add a custom target to run Doxygen when ever the project is built
	add_custom_target(docs ALL COMMAND ${DOXYGEN_EXECUTABLE} ${PROJECT_BINARY_DIR}/Doxyfile SOURCES ${PROJECT_BINARY_DIR}/Doxyfile)
	# IF you do NOT want the documentation to be generated EVERY time you build the project
	# then leave out the 'ALL' keyword from the above command.
endif ()
