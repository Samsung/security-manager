# Copyright (c) 2011 Samsung Electronics Co., Ltd All Rights Reserved
#
#    Licensed under the Apache License, Version 2.0 (the "License");
#    you may not use this file except in compliance with the License.
#    You may obtain a copy of the License at
#
#        http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS,
#    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#    See the License for the specific language governing permissions and
#    limitations under the License.
#
# @file        CMakeLists.txt
# @author
# @brief
#

############################# Check minimum CMake version #####################

CMAKE_MINIMUM_REQUIRED(VERSION 2.6)
PROJECT("security-server")

############################# cmake packages ##################################

INCLUDE(FindPkgConfig)

############################# compilation defines #############################

# EMPTY

############################# compiler flags ##################################

SET(CMAKE_C_FLAGS_PROFILING    "-O0 -g -pg")
SET(CMAKE_CXX_FLAGS_PROFILING  "-O0 -std=c++0x -g -pg")
SET(CMAKE_C_FLAGS_DEBUG        "-O0 -g")
SET(CMAKE_CXX_FLAGS_DEBUG      "-O0 -std=c++0x -g")
SET(CMAKE_C_FLAGS_RELEASE      "-O2 -g")
SET(CMAKE_CXX_FLAGS_RELEASE    "-O2 -std=c++0x -g")
SET(CMAKE_C_FLAGS_CCOV         "-O2 -g --coverage")
SET(CMAKE_CXX_FLAGS_CCOV       "-O2 -std=c++0x -g --coverage")

# If supported for the target machine, emit position-independent code,suitable
# for dynamic linking and avoiding any limit on the size of the global offset
# table. This option makes a difference on the m68k, PowerPC and SPARC.
# (BJ: our ARM too?)
ADD_DEFINITIONS("-fPIC")


# Set compiler warning flags
ADD_DEFINITIONS("-Wall")                        # Generate all warnings
ADD_DEFINITIONS("-Wextra")                      # Generate even more extra warnings

STRING(REGEX MATCH "([^.]*)" API_VERSION "${VERSION}")
ADD_DEFINITIONS("-DAPI_VERSION=\"$(API_VERSION)\"")

SET(TARGET_SECURITY_SERVER "security-server")
SET(TARGET_SECURITY_CLIENT "security-server-client")

ADD_SUBDIRECTORY(src)
ADD_SUBDIRECTORY(build)
