# Copyright (c) 2016 - 2017 Samsung Electronics Co., Ltd All Rights Reserved
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
# @author      Radoslaw Bartosiak <r.bartosiak@samsung.com>
# @brief       Cmake for internal security manager tests
#

PKG_CHECK_MODULES(COMMON_DEP
    REQUIRED
    libtzplatform-config
    )

IF(DPL_WITH_DLOG)
    PKG_CHECK_MODULES(DLOG_DEP REQUIRED dlog)
ENDIF(DPL_WITH_DLOG)

ADD_DEFINITIONS( "-DBOOST_TEST_DYN_LINK" )
ADD_DEFINITIONS("-DDB_TEST_DIR=\"${DB_TEST_DIR}\"")


################################################################################

SET(DPL_PATH     ${PROJECT_SOURCE_DIR}/src/dpl)
SET(SM_TEST_SRC  ${PROJECT_SOURCE_DIR}/test)

################################################################################

SET(TARGET_SM_TESTS "security-manager-unit-tests")

SET(SM_TESTS_SOURCES
    ${SM_TEST_SRC}/colour_log_formatter.cpp
    ${SM_TEST_SRC}/security-manager-tests.cpp
    ${SM_TEST_SRC}/test_file-lock.cpp
    ${SM_TEST_SRC}/privilege_db_fixture.cpp
    ${SM_TEST_SRC}/test_privilege_db_transactions.cpp
    ${SM_TEST_SRC}/test_privilege_db_app_pkg_getters.cpp
    ${SM_TEST_SRC}/test_privilege_db_add_app.cpp
    ${SM_TEST_SRC}/test_privilege_db_app_remove.cpp
    ${SM_TEST_SRC}/test_privilege_db_privilege.cpp
    ${SM_TEST_SRC}/test_privilege_db_sharing.cpp
    ${SM_TEST_SRC}/test_privilege_db_app_defined_privileges.cpp
    ${SM_TEST_SRC}/test_smack-labels.cpp
    ${SM_TEST_SRC}/test_smack-rules.cpp
    ${DPL_PATH}/core/src/assert.cpp
    ${DPL_PATH}/core/src/colors.cpp
    ${DPL_PATH}/core/src/errno_string.cpp
    ${DPL_PATH}/core/src/exception.cpp
    ${DPL_PATH}/core/src/noncopyable.cpp
    ${DPL_PATH}/db/src/sql_connection.cpp
    ${DPL_PATH}/db/src/naive_synchronization_object.cpp
    ${DPL_PATH}/log/src/abstract_log_provider.cpp
    ${DPL_PATH}/log/src/log.cpp
    ${DPL_PATH}/log/src/old_style_log_provider.cpp
    ${PROJECT_SOURCE_DIR}/src/common/file-lock.cpp
    ${PROJECT_SOURCE_DIR}/src/common/privilege_db.cpp
    ${PROJECT_SOURCE_DIR}/src/common/smack-check.cpp
    ${PROJECT_SOURCE_DIR}/src/common/smack-labels.cpp
    ${PROJECT_SOURCE_DIR}/src/common/smack-rules.cpp
    ${PROJECT_SOURCE_DIR}/src/common/filesystem.cpp
    ${PROJECT_SOURCE_DIR}/src/common/tzplatform-config.cpp
)

IF(DPL_WITH_DLOG)
    SET(SM_TESTS_SOURCES
        ${SM_TESTS_SOURCES}
        ${DPL_PATH}/log/src/dlog_log_provider.cpp)
ENDIF(DPL_WITH_DLOG)

IF(DPL_WITH_SYSTEMD_JOURNAL)
    SET(SM_TESTS_SOURCES
        ${SM_TESTS_SOURCES}
        ${DPL_PATH}/log/src/sd_journal_provider.cpp)
ENDIF(DPL_WITH_SYSTEMD_JOURNAL)

INCLUDE_DIRECTORIES(
    ${COMMON_DEP_INCLUDE_DIRS}
    ${DLOG_DEP_INCLUDE_DIRS}
    ${SM_TEST_SRC}
    ${PROJECT_SOURCE_DIR}/src/include
    ${PROJECT_SOURCE_DIR}/src/client/include
    ${PROJECT_SOURCE_DIR}/src/common/include
    ${PROJECT_SOURCE_DIR}/src/server/main/include
    ${PROJECT_SOURCE_DIR}/src/dpl/core/include
    ${PROJECT_SOURCE_DIR}/src/dpl/db/include
    ${PROJECT_SOURCE_DIR}/src/dpl/log/include
    ${PROJECT_SOURCE_DIR}/src/dpl/log/include/dpl/log
    ${PROJECT_SOURCE_DIR}/src/dpl/log
)

ADD_EXECUTABLE(${TARGET_SM_TESTS} ${SM_TESTS_SOURCES})

TARGET_LINK_LIBRARIES(${TARGET_SM_TESTS}
    ${COMMON_DEP_LIBRARIES}
    ${DLOG_DEP_LIBRARIES}
    boost_unit_test_framework
    -ldl
    -lcrypt
)

INSTALL(TARGETS ${TARGET_SM_TESTS} DESTINATION ${BIN_INSTALL_DIR})
