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

#ifndef _SRC_ACCESS_CONTROL_COMMON_PROMPT_DECISION_H_
#define _SRC_ACCESS_CONTROL_COMMON_PROMPT_DECISION_H_

#include <dpl/optional.h>
#include <dpl/optional_typedefs.h>

enum class PromptDecision {
    ALLOW_ALWAYS,
    DENY_ALWAYS,
    ALLOW_THIS_TIME,
    DENY_THIS_TIME,
    ALLOW_FOR_SESSION,
    DENY_FOR_SESSION
};

typedef DPL::Optional<PromptDecision> OptionalPromptDecision;

struct CachedPromptDecision {
    PromptDecision decision;
    DPL::OptionalString session;
};

typedef DPL::Optional<CachedPromptDecision> OptionalCachedPromptDecision;

#endif // _SRC_ACCESS_CONTROL_COMMON_PROMPT_DECISION_H_
