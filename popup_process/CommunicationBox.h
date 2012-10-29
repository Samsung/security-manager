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
/* @file        CommunicationBox.h
 * @author      Justyna Mejzner (j.kwiatkowsk@samsung.com)
 * @version     1.0
 *
 */

#ifndef _WRT_SRC_DOMAIN_EFL_COMMUNICATION_BOX_H
#define _WRT_SRC_DOMAIN_EFL_COMMUNICATION_BOX_H

#include <memory>
#include <iostream>
#include <dpl/string.h>
#include <dpl/fast_delegate.h>
#include <dpl/optional_typedefs.h>
#include <dpl/popup/popup_controller.h>
#include <dpl/popup/popup_manager.h>
#include <dpl/popup/popup_renderer.h>
#include <dpl/framework_efl.h>
#include <ace-dao-ro/PromptModel.h>

class CommunicationBox :
    public DPL::Popup::PopupControllerUser
{
  private:
    void AnswerCallback(const DPL::Popup::AnswerCallbackData &answer);

  public:
    typedef DPL::FastDelegate<void (int buttonAnswer,
                                    bool checkState,
                                    void* userdata)>
    ResponseDelegate;

    CommunicationBox() :
        m_promptType(Prompt::PromptModel::PROMPT_ONESHOT),
        m_callback(NULL),
        m_userdata(NULL)
    {
    }

    void showAsync(const Prompt::PromptModel::PromptType promptType,
            const std::string& mainLabel,
            const std::vector<std::string>& buttonLabels,
            const DPL::OptionalString& checkLabel,
            ResponseDelegate callback,
            void* userdata);

    Prompt::PromptModel::PromptType getPromptType() const;

  private:

    Prompt::PromptModel::PromptType m_promptType;
    ResponseDelegate m_callback;
    void* m_userdata;
};

#endif  //_WRT_SRC_DOMAIN_EFL_COMMUNICATION_BOX_H
