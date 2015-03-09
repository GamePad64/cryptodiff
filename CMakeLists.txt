project(cryptodiff)
cmake_minimum_required(VERSION 2.8)
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/cmake")

SET(TARGET_LIBRARY_NAME "libcryptodiff")
SET(TARGET_EXECUTABLE_NAME "cryptodiff")

#============================================================================
# Compilation options
#============================================================================

#-- Add an Option to toggle the generation of the API documentation
option(SINGLE_THREADED "Build single-threaded version of the library" OFF)
if(SINGLE_THREADED)
	add_definitions(-DSINGLE_THREADED)
endif()

#============================================================================
# Compiler properties
#============================================================================

### Setting compiler properties
SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -fPIC")
include_directories(${CMAKE_CURRENT_BINARY_DIR})
SET(CMAKE_MODULE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -fPIC")

IF("${CMAKE_CXX_COMPILER_ID}" MATCHES "Clang")
# Use -flto flag to enable GCC's link-time optimization.
	SET(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -use-gold-plugin")
	SET(CMAKE_EXE_LINKER_FLAGS_RELEASE "${CMAKE_EXE_LINKER_FLAGS_RELEASE} -use-gold-plugin")
	SET(CMAKE_MODULE_LINKER_FLAGS_RELEASE "${CMAKE_MODULE_LINKER_FLAGS_RELEASE} -use-gold-plugin")
ENDIF()

IF(CMAKE_COMPILER_IS_GNUCXX OR "${CMAKE_CXX_COMPILER_ID}" MATCHES "Clang")
# Use -flto flag to enable GCC's link-time optimization.
	SET(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -flto")
	SET(CMAKE_EXE_LINKER_FLAGS_RELEASE "${CMAKE_EXE_LINKER_FLAGS_RELEASE} -flto")
	SET(CMAKE_MODULE_LINKER_FLAGS_RELEASE "${CMAKE_MODULE_LINKER_FLAGS_RELEASE} -flto")
ENDIF()

# Protobuf Generator
find_package(Protobuf REQUIRED)
if(PROTOBUF_FOUND)
  file(GLOB_RECURSE PROTO_COMMON_LIST "src/*.proto")
  PROTOBUF_GENERATE_CPP(PROTO_COMMON_SOURCES PROTO_COMMON_HEADERS ${PROTO_COMMON_LIST})
endif()

#============================================================================
# Binary generation and installation
#============================================================================

file(GLOB_RECURSE LIBRARY_SRCS "src/*")
list(APPEND LIBRARY_SRCS ${PROTO_COMMON_SOURCES})
list(APPEND LIBRARY_SRCS ${PROTO_COMMON_HEADERS})
add_library(${TARGET_LIBRARY_NAME} ${LIBRARY_SRCS})

SET_TARGET_PROPERTIES (${TARGET_LIBRARY_NAME}
  PROPERTIES
  VERSION 0.0.1
  SOVERSION 0
  OUTPUT_NAME cryptodiff
)

add_executable(${TARGET_EXECUTABLE_NAME} src/cryptodiff.h cryptodiff.cpp)
target_link_libraries(${TARGET_EXECUTABLE_NAME} ${TARGET_LIBRARY_NAME})

install (TARGETS ${TARGET_LIBRARY_NAME} DESTINATION lib)
install (TARGETS ${TARGET_EXECUTABLE_NAME} DESTINATION bin)
install (FILES src/cryptodiff.h DESTINATION include)

#============================================================================
# Third-party Libraries
#============================================================================

# Boost
set (Boost_COMPONENTS
	system
	filesystem
	date_time
	log
	program_options
	iostreams)

# set (Boost_USE_STATIC_LIBS ON)
set (Boost_USE_MULTITHREADED ON)

add_definitions(-DBOOST_LOG_DYN_LINK)
find_package(Boost COMPONENTS ${Boost_COMPONENTS} REQUIRED)

if(Boost_FOUND)
  include_directories(${Boost_INCLUDE_DIRS})
  target_link_libraries(${TARGET_LIBRARY_NAME} ${Boost_LIBRARIES})
  target_link_libraries(${TARGET_EXECUTABLE_NAME} ${Boost_LIBRARIES})
endif()
# /Boost

# CryptoPP
find_package(CryptoPP REQUIRED)

if(CRYPTOPP_FOUND)
  include_directories(${CRYPTOPP_INCLUDE_DIRS})
  target_link_libraries(${TARGET_LIBRARY_NAME} ${CRYPTOPP_LIBRARIES})
  target_link_libraries(${TARGET_EXECUTABLE_NAME} ${CRYPTOPP_LIBRARIES})
endif()
# /CryptoPP

# Protobuf
# Found lately

if(PROTOBUF_FOUND)
  include_directories(${PROTOBUF_INCLUDE_DIRS})
  target_link_libraries(${TARGET_LIBRARY_NAME} ${PROTOBUF_LIBRARIES})
  target_link_libraries(${TARGET_EXECUTABLE_NAME} ${PROTOBUF_LIBRARIES})
endif()
# /Protobuf

#============================================================================
# Documentation generation
#============================================================================

#-- Add an Option to toggle the generation of the API documentation
option(BUILD_DOCUMENTATION "Use Doxygen to create the HTML based API documentation" OFF)
if(BUILD_DOCUMENTATION)
  FIND_PACKAGE(Doxygen)
  if (NOT DOXYGEN_FOUND)
    message(FATAL_ERROR
      "Doxygen is needed to build the documentation. Please install it correctly")
  endif()
  #-- Configure the Template Doxyfile for our specific project
  configure_file(Doxyfile.in ${PROJECT_BINARY_DIR}/Doxyfile @ONLY IMMEDIATE)
  #-- Add a custom target to run Doxygen when ever the project is built
  add_custom_target (docs ALL COMMAND ${DOXYGEN_EXECUTABLE} ${PROJECT_BINARY_DIR}/Doxyfile SOURCES ${PROJECT_BINARY_DIR}/Doxyfile)
  # IF you do NOT want the documentation to be generated EVERY time you build the project
  # then leave out the 'ALL' keyword from the above command.
endif()
