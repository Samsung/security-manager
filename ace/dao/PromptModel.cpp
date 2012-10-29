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
/* @file        PromptModel.cpp
 * @author      Justyna Mejzner (j.kwiatkowsk@samsung.com)
 * @author      Jaroslaw Osmanski (j.osmanski@samsung.com)
 * @version     1.0
 *
 */

#include <ace-dao-ro/PromptModel.h>

#include <algorithm>
#include <dpl/log/log.h>
#include <dpl/assert.h>

namespace {

const char INFO[] = "Widget requires access to:";
const char DENY[] = "Deny";
const char ALLOW[] = "Permit";

const char BLANKET_CHECKBOX_LABEL[] = "Keep setting as permanent";
const char SESSION_CHECKBOX_LABEL[] = "Remember for one run";

Prompt::ButtonLabels aceQuestionLabel = {DENY, ALLOW};

static Prompt::PromptLabels* getModel(
        Prompt::PromptModel::PromptType promptType,
        const std::string& resourceId)
{
    std::string strLabel;
    strLabel = INFO;
    strLabel += "<br>";
    strLabel += resourceId;

    return new Prompt::PromptLabels(promptType, aceQuestionLabel, strLabel);
}

Prompt::Validity fromPromptTypeToValidity(int aPromptType, bool checkClicked)
{
    using namespace Prompt;
    PromptModel::PromptType promptTypeEnum =
        static_cast<PromptModel::PromptType>(aPromptType);
    switch (promptTypeEnum) {
    case PromptModel::PROMPT_ONESHOT:
        return Validity::ONCE;
    case PromptModel::PROMPT_SESSION:
        if (checkClicked)
        {
            return Validity::SESSION;
        }
        else
        {
            return Validity::ONCE;
        }
    case PromptModel::PROMPT_BLANKET:
        if (checkClicked)
        {
            return Validity::ALWAYS;
        }
        else
        {
            return Validity::ONCE;
        }
    default:
        Assert(0);
        return Validity::ONCE;
    }
}
} // namespace anonymous

namespace Prompt {


PromptLabels::PromptLabels(int promptType,
                           const Prompt::ButtonLabels& questionLabel,
                           const std::string& mainLabel) :
               m_promptType(promptType),
               m_buttonLabels(questionLabel),
               m_mainLabel(mainLabel)
{

}

int PromptLabels::getPromptType() const
{
    return m_promptType;
}
const ButtonLabels& PromptLabels::getButtonLabels() const
{
    return m_buttonLabels;
}
const std::string& PromptLabels::getMainLabel() const
{
    return m_mainLabel;
}

DPL::OptionalString PromptLabels::getCheckLabel() const
{
    if (PromptModel::PROMPT_BLANKET == m_promptType)
    {
        return DPL::OptionalString(
                DPL::FromUTF8String(BLANKET_CHECKBOX_LABEL));
    }
    else if (PromptModel::PROMPT_SESSION == m_promptType)
    {
        return DPL::OptionalString(
                DPL::FromUTF8String(SESSION_CHECKBOX_LABEL));
    }

    return DPL::OptionalString::Null;
}

bool PromptLabels::isAllowed(const size_t buttonClicked) const
{
    Assert(buttonClicked < aceQuestionLabel.size() &&
            "Button Clicked number is not in range of questionLabel");

    return aceQuestionLabel[buttonClicked] == ALLOW;
}

PromptAnswer::PromptAnswer(bool isAccessAllowed, Validity validity) :
        m_isAccessAllowed(isAccessAllowed),
        m_validity(validity)
{

}

PromptAnswer::PromptAnswer(
        int aPromptType, unsigned int buttonAns, bool checkAns)
{
    Assert(buttonAns < aceQuestionLabel.size() &&
            "Button Clicked number is not in range of questionLabel");

    m_isAccessAllowed = aceQuestionLabel[buttonAns] == ALLOW;
    m_validity = fromPromptTypeToValidity(aPromptType, checkAns);
}

bool PromptAnswer::isAccessAllowed() const
{
    return m_isAccessAllowed;
}

Validity PromptAnswer::getValidity() const
{
    return m_validity;
}

PromptLabels* PromptModel::getOneShotModel(const std::string& resourceId)
{
    return getModel(PROMPT_ONESHOT, resourceId);
}

PromptLabels* PromptModel::getSessionModel(const std::string& resourceId)
{
    return getModel(PROMPT_SESSION, resourceId);
}

PromptLabels* PromptModel::getBlanketModel(const std::string& resourceId)
{
    return getModel(PROMPT_BLANKET, resourceId);
}


} // Prompt
