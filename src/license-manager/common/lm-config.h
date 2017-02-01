/*
 *  Copyright (c) 2017 Samsung Electronics Co.
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
/**
 * @file        lm-config.h
 * @author      Bartlomiej Grzelewski <b.grzelewski@samsung.com>
 * @brief       Implementation of license manager plugin.
 */
#pragma once

#include <cynara-plugin.h>

namespace LicenseManager {
namespace Config {

const char * const AgentName = "LicenseManager";

const Cynara::PolicyType LM_ASK = 32; // 0x20

const Cynara::PolicyType LM_ALLOW = 33; // 0x21
const Cynara::PolicyType LM_DENY  = 34; // 0x22

} // namespace Config
} // namespace LicenseManager

