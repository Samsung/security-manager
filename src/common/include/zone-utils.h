/*
 *  Copyright (c) 2000 - 2015 Samsung Electronics Co., Ltd All Rights Reserved
 *
 *  Contact: Rafal Krypa <r.krypa@samsung.com>
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License
 */
/*
 * @file        zone-utils.h
 * @author      Lukasz Kostyra (l.kostyra@samsung.com)
 * @version     1.0
 * @brief       Definition of Zone utilities
 */

#ifndef _SECURITY_MANAGER_ZONE_UTILS_H_
#define _SECURITY_MANAGER_ZONE_UTILS_H_

#include <string>

// FIXME This module is a replacement for Vasum functions.
//
//       When Vasum will be included into OBS, the module should be removed and vasum-client should
//       be used instead.

namespace SecurityManager
{

extern const std::string ZONE_HOST;

/**
 * Extracts Zone ID in which runs process having provided PID.
 *
 * This function parses /proc/<pid>/cpuset file and tries to acquire Zone ID name from it.
 *
 * @param[in]  pid    PID of process to get Zone ID from.
 * @param[out] zoneId Zone ID extracted from cpuset. If process runs in host, returns "host" string.
 * @return            True on success, false on failure.
 */
bool getZoneIdFromPid(int pid, std::string& zoneId);

/**
 * Generates zone-specific label from given @ref label and zone's name @ref zoneName
 *
 * @param[in]  label    Base label, used to generate new zone-specific label
 * @param[in]  zoneName Name of zone for which label will be generated
 * @return              Generated label
 */
std::string zoneSmackLabelGenerate(const std::string &label, const std::string &zoneName);

/**
 * Map @ref hostLabel to @ref zoneLabel using Smack namespaces.
 *
 * FIXME This is a placeholder for Vasum API - implement when Smack Namespaces are implemented
 *
 * @param[in]  hostLabel Smack label as seen from hosts perspective
 * @param[in]  zoneName  Zone ID to which label will be mapped
 * @param[in]  zoneLabel Smack label seen from zone's perspective
 * @return               True on success, false on failure
 */
bool zoneSmackLabelMap(const std::string &hostLabel, const std::string &zoneName,
                       const std::string &zoneLabel);

/**
 * Unmap label mapped by zoneSmackLabelMap.
 *
 * FIXME This is a placeholder for Vasum API - implement when Smack Namespaces are implemented
 *
 * @param[in]  hostLabel Label to unmap
 * @param[in]  zoneName  Zone ID for which unmapping should be done
 * @return               True on success, false on failure
 */
bool zoneSmackLabelUnmap(const std::string &hostLabel, const std::string &zoneName);

} //namespace SecurityManager

#endif //_SECURITY_MANAGER_ZONE_UTILS_H_
