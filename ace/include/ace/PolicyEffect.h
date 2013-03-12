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
 * @file    PolicyEffect.h
 * @author  B.Grzelewski (b.grzelewski@samsung.com)
 * @version 1.0
 * @brief   This file contains the declaration of PolicyEffect type.
 */
#ifndef _SRC_ACCESS_CONTROL_COMMON_POLICY_EFFECT_H_
#define _SRC_ACCESS_CONTROL_COMMON_POLICY_EFFECT_H_

enum class PolicyEffect {
    DENY = 0,
    PERMIT,
    PROMPT_ONESHOT,
    PROMPT_SESSION,
    PROMPT_BLANKET
};

inline static std::ostream & operator<<(std::ostream& stream,
                                        PolicyEffect effect)
{
    switch (effect) {
        case PolicyEffect::DENY:           stream << "DENY"; break;
        case PolicyEffect::PERMIT:         stream << "PERMIT"; break;
        case PolicyEffect::PROMPT_ONESHOT: stream << "PROMPT_ONESHOT"; break;
        case PolicyEffect::PROMPT_SESSION: stream << "PROMPT_SESSION"; break;
        case PolicyEffect::PROMPT_BLANKET: stream << "PROMPT_BLANKET"; break;
        default: Assert(false && "Invalid PolicyEffect constant");
    }
    return stream;
}

#endif // _SRC_ACCESS_CONTROL_COMMON_POLICY_EFFECT_H_
