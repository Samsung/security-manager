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
/* @file        CommunicationBox.cpp
 * @author      Justyna Mejzner (j.kwiatkowsk@samsung.com)
 * @version     1.0
 *
 */
#include "CommunicationBox.h"
#include <stddef.h>
#include <dpl/log/log.h>

void CommunicationBox::showAsync(
        const Prompt::PromptModel::PromptType promptType,
        const std::string& mainLabel,
        const std::vector<std::string>& buttonLabels,
        const DPL::OptionalString& checkLabel,
        ResponseDelegate callback,
        void* userdata)
{
    m_callback = callback;
    m_userdata = userdata;
    m_promptType = promptType;
    using namespace DPL::Popup;

    CtrlPopupPtr popup = PopupControllerSingleton::Instance().CreatePopup();
    popup->Append(new PopupObject::Label(mainLabel));

    if (!!checkLabel)
    {
        popup->Append(new PopupObject::Check(DPL::ToUTF8String(*checkLabel)));
    }

    for (size_t questionIndex = 0; questionIndex < buttonLabels.size();
         ++questionIndex)
    {
        popup->Append(new PopupObject::Button(
                buttonLabels[questionIndex],questionIndex));
    }


    ListenForAnswer(popup);

     //nested loop is not used here
    ShowPopupEventShort event(popup,
                              MakeAnswerCallback(
                                     this,
                                     &CommunicationBox::AnswerCallback));

    CONTROLLER_POST_EVENT(PopupController,
                          event);
}

void CommunicationBox::AnswerCallback(const DPL::Popup::AnswerCallbackData &answer)
{
    m_callback(answer.buttonAnswer, answer.chackState, m_userdata);
}


Prompt::PromptModel::PromptType CommunicationBox::getPromptType() const
{
    return m_promptType;
}
