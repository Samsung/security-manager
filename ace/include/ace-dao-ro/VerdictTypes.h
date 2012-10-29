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
 *
 *
 * @file       VerdictTypes.h
 * @author     Grzegorz Krawczyk (g.krawczyk@samsung.com)
 * @version    0.1
 * @brief
 */

#ifndef ACCESS_CONTROL_DAO_VERDICTTYPES_H_
#define ACCESS_CONTROL_DAO_VERDICTTYPES_H_

namespace AceDB{

enum class VerdictTypes
{
    VERDICT_PERMIT,
    VERDICT_DENY,
    //Verdict is innapplicable if policy evaluate to INAPPLICABLE,
    //in this case WRT should decide what to do
    VERDICT_INAPPLICABLE,
    VERDICT_UNDETERMINED,
    VERDICT_UNKNOWN,  //Verdict is unknown if Verdicts manager cannot find it
    VERDICT_ASYNC,
    VERDICT_ERROR
};

}

#endif
