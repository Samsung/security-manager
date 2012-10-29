/*
 * Copyright (c) 2011 Samsung Electronics Co., Ltd All Rights Reserved
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */
/**
 * @file        Constants.h
 * @author      Piotr Fatyga (p.fatyga@samsung.com)
 * @version     0.1
 * @brief
 */

#ifndef _CONSTANTS_H
#define _CONSTANTS_H

#define ACE_MAIN_STORAGE "/usr/etc/ace"
#define ACE_WAC_POLICY_FILE_NAME "/WAC2.0Policy.xml"
#define ACE_TIZEN_POLICY_FILE_NAME "/TizenPolicy.xml"
#define ACE_DTD_LOCATION ACE_MAIN_STORAGE "/bondixml.dtd"

// !! DEPRECATED !!
#pragma message "ACE_CONFIGURATION_PATH, ACE_CONFIGURATION_DTD \
 macros are DEPRECATED"
#define ACE_CONFIGURATION_PATH ACE_MAIN_STORAGE "/config.xml"
#define ACE_CONFIGURATION_DTD ACE_MAIN_STORAGE "/config.dtd"

/////////////////FOR GUI//////////////////////

#define MYSTERIOUS_BITMAP "/usr/apps/org.tizen.policy/d.png"
#define MYSTERIOUS_BITMAP2 "/usr/apps/org.tizen.policy/file.png"

///////////////////FOR TESTS//////////////////////////

#define COMBINER_TEST "/usr/etc/ace/CMTest/com_general-test.xml"
#define CONFIGURATION_MGR_TEST_PATH "/usr/etc/ace/CMTest/"
#define CONFIGURATION_MGR_TEST_CONFIG ACE_MAIN_STORAGE "/CMTest/pms_config.xml"
#define CONFIGURATION_MGR_TEST_POLICY_STORAGE ACE_MAIN_STORAGE "/CMTest/active"
#define CONFIGURATION_MGR_TEST_POLICY_STORAGE_MOVED ACE_MAIN_STORAGE \
    "/CMTest/activeMoved"
#define CONFIGURATION_MGR_TEST_POLICY CONFIGURATION_MGR_TEST_POLICY_STORAGE \
    "/pms_general-test.xml"
#define POLICIES_TO_SIGN_DIR ACE_MAIN_STORAGE "/SignerTests/"

#define OUTPUT_DIR ACE_MAIN_STORAGE "/SignerTests/signedPolicies/"
#define PRIVATE_KEY_DIR ACE_MAIN_STORAGE "/SignerTests/PrvKey/"
#define X509_DATA_BASE_DIR ACE_MAIN_STORAGE "/SignerTests/X509Data/"

#endif    /* _CONSTANTS_H */

