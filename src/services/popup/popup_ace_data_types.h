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
/*
 * @file    popup_ace_data_types.h
 * @author  Pawel Sikorski (p.sikorski@samsung.com)
 * @version 1.0
 * @brief
 */

#ifndef POPUP_ACE_DATA_TYPES_H_
#define POPUP_ACE_DATA_TYPES_H_

#include <vector>
#include <string>

// additional data needed by PolicyEvaluaor to recognize Popup Response
struct AceUserdata
{
    //TODO INVALID_WIDGET_HANDLE is defined in wrt_plugin_export.h.
    // I do not want to include that file here...
    AceUserdata(): handle(-1) {}

    int handle;
    std::string subject;
    std::string resource;
    std::vector<std::string> paramKeys;
    std::vector<std::string> paramValues;
    std::string sessionId;
};

typedef bool SecurityStatus;

#endif /* POPUP_ACE_DATA_TYPES_H_ */
