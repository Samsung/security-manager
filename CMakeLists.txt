# Copyright (c) 2011 - 2016 Samsung Electronics Co., Ltd All Rights Reserved
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
PROJECT("security-manager")

############################# cmake packages ##################################

INCLUDE(FindPkgConfig)

######################### let's setup directories #############################

SET(LOCAL_STATE_DIR
    "${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_LOCALSTATEDIR}"
    CACHE PATH
    "Modifiable single-machine data directory")

SET(DATA_ROOT_DIR
    "${CMAKE_INSTALL_FULL_DATAROOTDIR}"
    CACHE PATH
    "Read-only data root directory")

SET(POLICY_DIR
    "${DATA_ROOT_DIR}/security-manager/policy"
    CACHE PATH
    "Read-only data root directory")

ADD_DEFINITIONS("-DLOCAL_STATE_DIR=\"${LOCAL_STATE_DIR}\"")
ADD_DEFINITIONS("-DDATA_ROOT_DIR=\"${DATA_ROOT_DIR}\"")
ADD_DEFINITIONS("-DPOLICY_DIR=\"${POLICY_DIR}\"")

############################## file names #####################################

SET(PRIVILEGE_GROUP_LIST_FILE
    "privilege-group.list"
    CACHE PATH
    "File with mapping from privileges into groups")

ADD_DEFINITIONS("-DPRIVILEGE_GROUP_LIST_FILE=\"${PRIVILEGE_GROUP_LIST_FILE}\"")

############################# compiler flags ##################################

SET(CMAKE_CXX_FLAGS_PROFILING  "-g -std=c++0x -O0 -pg -Wp,-U_FORTIFY_SOURCE")
SET(CMAKE_CXX_FLAGS_DEBUG      "-g -std=c++0x -O0 -ggdb -Wp,-U_FORTIFY_SOURCE")
SET(CMAKE_CXX_FLAGS_RELEASE    "-g -std=c++0x -O2")
SET(CMAKE_CXX_FLAGS_CCOV       "-g -std=c++0x -O2 --coverage")
SET(CMAKE_CXX_FLAGS_VALGRIND   "-ggdb -std=c++0x -O0 -fno-inline -Wp,-U_FORTIFY_SOURCE")

# If supported for the target machine, emit position-independent code,suitable
# for dynamic linking and avoiding any limit on the size of the global offset
# table. This option makes a difference on the m68k, PowerPC and SPARC.
# (BJ: our ARM too?)
ADD_DEFINITIONS("-fPIC")

# Set compiler warning flags
ADD_DEFINITIONS("-Werror")                      # Make all warnings into errors.
ADD_DEFINITIONS("-Wall")                        # Generate all warnings
ADD_DEFINITIONS("-Wextra")                      # Generate even more extra warnings

STRING(REGEX MATCH "([^.]*)" API_VERSION "${VERSION}")
ADD_DEFINITIONS("-DAPI_VERSION=\"$(API_VERSION)\"")

ADD_DEFINITIONS("-DSMACK_ENABLED")
ADD_DEFINITIONS("-DASKUSER_ENABLED")

OPTION(DPL_WITH_DLOG "DPL DLOG backend" ON)
OPTION(DPL_WITH_SYSTEMD_JOURNAL "DPL systemd-journal backend" OFF)

IF(DPL_WITH_DLOG)
    ADD_DEFINITIONS("-DDPL_DLOG_ENABLED")
ENDIF(DPL_WITH_DLOG)

IF(DPL_WITH_SYSTEMD_JOURNAL)
    ADD_DEFINITIONS("-DDPL_SYSTEMD_JOURNAL_ENABLED")
ENDIF(DPL_WITH_SYSTEMD_JOURNAL)

IF(DB_LOGS)
    ADD_DEFINITIONS("-DDB_LOGS")
ENDIF(DB_LOGS)

ADD_DEFINITIONS("-DBUILD_TYPE_${CMAKE_BUILD_TYPE}")

SET(INCLUDE_PATH ${PROJECT_SOURCE_DIR}/src/include)
SET(COMMON_PATH  ${PROJECT_SOURCE_DIR}/src/common)
SET(CLIENT_PATH  ${PROJECT_SOURCE_DIR}/src/client)
SET(SERVER_PATH  ${PROJECT_SOURCE_DIR}/src/server)
SET(DPL_PATH     ${PROJECT_SOURCE_DIR}/src/dpl)
SET(CMD_PATH     ${PROJECT_SOURCE_DIR}/src/cmd)
SET(NSS_PATH     ${PROJECT_SOURCE_DIR}/src/nss)

SET(TARGET_SERVER "security-manager")
SET(TARGET_CLIENT "security-manager-client")
SET(TARGET_COMMON "security-manager-commons")
SET(TARGET_CMD    "security-manager-cmd")
SET(TARGET_CLEANUP "security-manager-cleanup")
SET(TARGET_NSS     "security-manager-nss")

ADD_SUBDIRECTORY(src)
ADD_SUBDIRECTORY(pc)
ADD_SUBDIRECTORY(systemd)
ADD_SUBDIRECTORY(db)
ADD_SUBDIRECTORY(policy)
ADD_SUBDIRECTORY(migration)
ADD_SUBDIRECTORY(test)
