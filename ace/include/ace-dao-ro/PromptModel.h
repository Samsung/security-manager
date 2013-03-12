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
/* @file        PromptModel.h
 * @author      Justyna Mejzner (j.kwiatkowsk@samsung.com)
 * @author      Jaroslaw Osmanski (j.osmanski@samsung.com)
 * @version     1.0
 *
 */

#ifndef WRT_SRC_ACCESSCONTROL_ENGINE_PROMPT_MODEL_H_
#define WRT_SRC_ACCESSCONTROL_ENGINE_PROMPT_MODEL_H_

#include <memory>
#include <string>
#include <vector>

#include <dpl/optional_typedefs.h>

namespace Prompt {
typedef std::vector<std::string> ButtonLabels;

class PromptLabels
{
public:
    PromptLabels(int promptType,
                 const Prompt::ButtonLabels& questionLabel,
                 const std::string& mainLabel);
    DPL::OptionalString getCheckLabel() const;
    bool isAllowed(const size_t buttonNumber) const;
    int getPromptType() const;
    const ButtonLabels& getButtonLabels() const;
    const std::string& getMainLabel() const;

private:
    int m_promptType;
    ButtonLabels m_buttonLabels;
    std::string m_mainLabel;
};

typedef std::unique_ptr<PromptLabels> PromptLabelsPtr;

enum Validity
{
    ONCE,
    SESSION,
    ALWAYS
};

class PromptAnswer
{
public:
    PromptAnswer(bool isAccessAllowed, Validity validity);
    PromptAnswer(int aPromptType, unsigned int buttonAns, bool checkAns);
    bool isAccessAllowed() const;
    Validity getValidity() const;

private:
    bool m_isAccessAllowed;
    Validity m_validity;
};

class PromptModel
{
  public:
    static PromptLabels* getOneShotModel(const std::string& resourceId);
    static PromptLabels* getSessionModel(const std::string& resourceId);
    static PromptLabels* getBlanketModel(const std::string& resourceId);

    enum PromptType
    {
        PROMPT_ONESHOT,
        PROMPT_SESSION,
        PROMPT_BLANKET
    };
};

} // Prompt

#endif /* WRT_SRC_ACCESSCONTROL_ENGINE_PROMPT_MODEL_H_ */
