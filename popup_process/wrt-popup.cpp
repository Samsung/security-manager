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
#include "wrt-popup.h"
#include <limits>
#include <memory>

#include <aul.h>
#include <dpl/log/log.h>
#include <dpl/exception.h>
#include <dpl/assert.h>

#include "PopupEnum.h"
#include "PopupSerializer.h"
#include "YesNoPopup.h"

#include <CommunicationBox.h>
#include <ace-dao-ro/PromptModel.h>
#include <ace/PolicyEffect.h>

namespace {
struct PopupsUserdata
{
    PopupsUserdata(CommunicationBox* pCommunicationBox) :
        communicationBox(pCommunicationBox)
    {
    }
    std::unique_ptr<CommunicationBox> communicationBox;
    Prompt::PromptLabelsPtr promptLabels;
};

Prompt::PromptLabels* getPromptLabelsFromPolicyEffect(
        const PolicyEffect promptEffect, const std::string& resource)
{
    switch(promptEffect) {
    case PolicyEffect::PROMPT_ONESHOT: {
        return Prompt::PromptModel::getOneShotModel(resource);
    }
    case PolicyEffect::PROMPT_SESSION: {
        return Prompt::PromptModel::getSessionModel(resource);
    }
    case PolicyEffect::PROMPT_BLANKET: {
        return Prompt::PromptModel::getBlanketModel(resource);
    }
    default:
        LogError("Policy Effect not an prompt");
        Assert(0);
        return NULL;
    }
}

} // namespace anonymous

namespace PopupProcess {

bool WrtPopup::openPipes()
{
    Try
    {
        if (m_argc != 3) {
            LogError("Wrong arguments!");
            return false;
        }
        m_input.Open(m_argv[1]);
        //open output pipe
        m_output.Open(m_argv[2]);

        DPL::WaitableHandleWatchSupport::InheritedContext()->
            AddWaitableHandleWatch(this,
                                   m_input.WaitableReadHandle(),
                                   DPL::WaitMode::Read);
        m_pipesOpened = true;
        return true;
    }
    Catch(DPL::Exception)
    {
        LogError("cannot open pipes");
    }
    return false;
}

void WrtPopup::closePipes()
{
    Try
    {
        if (m_pipesOpened)
        {
            DPL::WaitableHandleWatchSupport::InheritedContext()->
                RemoveWaitableHandleWatch(this,
                                          m_input.WaitableReadHandle(),
                                          DPL::WaitMode::Read);
            m_input.Close();
            m_output.Close();
            m_pipesOpened = false;
        }
    }
    Catch(DPL::Exception)
    {
        LogError("cannot close pipes");
    }
}

void WrtPopup::OnEventReceived(const QuitEvent &/* event */)
{
    LogDebug("Quiting");
    closePipes();
    Quit();
}

void WrtPopup::OnWaitableHandleEvent(DPL::WaitableHandle waitableHandle,
                                     DPL::WaitMode::Type /*mode*/)
{
    if (waitableHandle == m_input.WaitableReadHandle())
    {
        readInputData();
    }
}

void WrtPopup::readInputData()
{
    DPL::BinaryQueueAutoPtr data =
        m_input.Read(std::numeric_limits<std::size_t>::max());
    int popupType = PopupSerializer::getIntArg(*data);
    LogDebug("popup type " << popupType);
    switch(popupType) {
    case ACE_PROMPT:
        // TODO: fix this to use IPopup interface
        showAcePrompt(data);
        break;
    case YES_NO_PROMPT: {
        m_popup.reset(new YesNoPopup());
        m_popup->show(data, this);
        break; }
    default:
        Assert(false);
    }
}

void WrtPopup::showAcePrompt(DPL::BinaryQueueAutoPtr data)
{
    int promptType = PopupSerializer::getIntArg(*data);
    std::string resource = PopupSerializer::getStringArg(*data);
    Assert(data->Empty());
    LogDebug("PopupType: " << promptType << " resource: " << resource);

    PopupsUserdata* popupsUserdata =
            new PopupsUserdata(new CommunicationBox());

    using namespace Prompt;
    popupsUserdata->promptLabels.reset(
            getPromptLabelsFromPolicyEffect(static_cast<PolicyEffect>(promptType),
                                            resource));
    popupsUserdata->communicationBox->showAsync(
            static_cast<PromptModel::PromptType>(
                    popupsUserdata->promptLabels->getPromptType()),
            popupsUserdata->promptLabels->getMainLabel(),
            popupsUserdata->promptLabels->getButtonLabels(),
            popupsUserdata->promptLabels->getCheckLabel(),
            CommunicationBox::ResponseDelegate(
                    this,
                    &WrtPopup::communicationBoxResponse),
            popupsUserdata);
}

void WrtPopup::communicationBoxResponse(int buttonAnswer,
                                        bool checkState,
                                        void* userdata)
{
    LogDebug("Communication box response");
    Assert(userdata);
    std::unique_ptr<PopupsUserdata> popupsUserdata(
            static_cast<PopupsUserdata*>(userdata));
    //following code can be moved to different place, but this is only a stub

    Prompt::PromptAnswer promptAnswer(
            popupsUserdata->promptLabels->getPromptType(),
            buttonAnswer, checkState);

    const bool allowed = promptAnswer.isAccessAllowed();
    const Prompt::Validity validity = promptAnswer.getValidity();

    DPL::BinaryQueue result;
    PopupSerializer::appendArg(allowed, result);
    PopupSerializer::appendArg(static_cast<int>(validity), result);
    m_output.Write(result, result.Size());
    PostEvent(QuitEvent());
}

void WrtPopup::response(DPL::BinaryQueue result)
{
    m_output.Write(result, result.Size());
    PostEvent(QuitEvent());
}

void WrtPopup::OnStop()
{
    LogInfo("On Stop");
}

void WrtPopup::OnCreate()
{
    if (!openPipes())
    {
        PostEvent(QuitEvent());
    }
    LogInfo("On Create");
}

void WrtPopup::OnResume()
{
    LogDebug("OnResume");
}

void WrtPopup::OnPause()
{
    LogDebug("OnPause");
}

void WrtPopup::OnReset(bundle */*b*/)
{
    LogDebug("OnReset");
}

void WrtPopup::OnTerminate()
{
    LogDebug("Wrt Shutdown now");
}

WrtPopup::WrtPopup(int argc, char **argv) :
    Application(argc, argv, "wrt-popup", false),
    m_pipesOpened(false),
    m_popup(NULL)
{
    Touch();
    DPL::Popup::PopupControllerSingleton::Instance().Touch();
    DPL::Popup::PopupManagerSingleton::Instance().Initialize(
        DPL::Popup::PopupRendererPtr(new DPL::Popup::PopupRenderer));
    LogDebug("App Created");
}

WrtPopup::~WrtPopup()
{
    DPL::Popup::PopupManagerSingleton::Instance().Deinitialize();
    LogDebug("App Finished");
}

} // PopupProcess

int main(int argc, char *argv[])
{
    // Output on stdout will be flushed after every newline character,
    // even if it is redirected to a pipe. This is useful for running
    // from a script and parsing output.
    // (Standard behavior of stdlib is to use full buffering when
    // redirected to a pipe, which means even after an end of line
    // the output may not be flushed).
    setlinebuf(stdout);

    DPL::Log::LogSystemSingleton::Instance().SetTag("WRT-POPUP");
    PopupProcess::WrtPopup app(argc, argv);
    int ret = app.Exec();
    LogDebug("App returned: " << ret);
    return ret;
}
