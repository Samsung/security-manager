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
 * @file        YesNoPopup.h
 * @author      Andrzej Surdej (a.surdej@samsung.com)
 * @version     1.0
 * @brief       Popup that contains 'Yes' and 'No' buttons
 */

#ifndef WRT_YES_NO_POPUP_H
#define WRT_YES_NO_POPUP_H

#include "wrt-popup.h"

namespace PopupProcess {

class YesNoPopup : public IPopup
{
public:
    virtual void show(DPL::BinaryQueueAutoPtr data, WrtPopup* parent);

private:

    void responseCallback(const DPL::Popup::AnswerCallbackData &answer);
    WrtPopup* m_parent;
};

} // PopupProcess

#endif /* WRT_YES_NO_POPUP_H */

