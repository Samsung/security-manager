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

#ifndef WRT_POPUP_H
#define WRT_POPUP_H

#include <memory>
#include <dpl/application.h>
#include <dpl/generic_event.h>
#include <dpl/event/controller.h>
#include <dpl/type_list.h>
#include <dpl/named_input_pipe.h>
#include <dpl/named_output_pipe.h>
#include <dpl/waitable_handle_watch_support.h>
#include <dpl/binary_queue.h>
#include <dpl/popup/popup_controller.h>

namespace PopupProcess {

DECLARE_GENERIC_EVENT_0(QuitEvent)
class WrtPopup;

class IPopup : public DPL::Popup::PopupControllerUser
{
public:
    virtual void show(DPL::BinaryQueueAutoPtr data, WrtPopup* parent) = 0;
};

typedef std::unique_ptr<IPopup> IPopupPtr;


class WrtPopup :
    public DPL::WaitableHandleWatchSupport::WaitableHandleListener,
    public DPL::Application,
    private DPL::Event::Controller<DPL::TypeListDecl<QuitEvent>::Type>
{
public:
    WrtPopup(int argc, char **argv);
    virtual ~WrtPopup();

    void response(DPL::BinaryQueue result);

protected:
    //DPL::Application functions
    virtual void OnStop();
    virtual void OnCreate();
    virtual void OnResume();
    virtual void OnPause();
    virtual void OnReset(bundle *b);
    virtual void OnTerminate();
    virtual void OnEventReceived(const QuitEvent &event);
    virtual void OnWaitableHandleEvent(DPL::WaitableHandle waitableHandle,
                                       DPL::WaitMode::Type mode);
private:

    void showAcePrompt(DPL::BinaryQueueAutoPtr data);
    void communicationBoxResponse(int buttonAnswer,
                                  bool checkState,
                                  void* userdata);
    bool m_pipesOpened;
    IPopupPtr m_popup;

    bool openPipes();
    void closePipes();
    void readInputData();

    DPL::NamedInputPipe m_input;
    DPL::NamedOutputPipe m_output;
};

} // PopupProcess

#endif // WRT_POPUP_H
