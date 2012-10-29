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

#include "PopupInvoker.h"
#include <sstream>
#include <unistd.h>
#include <stdio.h>
#include <dpl/log/log.h>
#include <dpl/waitable_handle.h>
#include <dpl/binary_queue.h>
#include <dpl/serialization.h>
#include <unistd.h>
#include <stdlib.h>
#include "PopupEnum.h"
#include "PopupSerializer.h"
#include "security_daemon_dbus_config.h"
#include "popup_response_server_api.h"

namespace {
const char *POPUP_EXEC = "/usr/bin/wrt-popup";
}

PopupInvoker::PopupInvoker() :
    m_inputName(tmpnam(NULL)),
    m_outputName(tmpnam(NULL))
{
    Try
    {
        m_input.Create(m_inputName);
        m_output.Create(m_outputName);
        LogDebug("Pipes created");
    }
    Catch (DPL::Exception)
    {
        LogError("Cannot create pipes");
    }
}

PopupInvoker::~PopupInvoker()
{
    Try
    {
        m_input.Destroy(m_inputName);
        m_output.Destroy(m_outputName);
        LogDebug("Pipes destroyed");
    }
    Catch (DPL::Exception)
    {
        LogError("Cannot destroy pipes");
    }
}

bool PopupInvoker::showSyncPopup(int popupType, const AceUserdata& aceData)
{
    Try
    {
        DPL::BinaryQueue data;
        PopupSerializer::appendArg(ACE_PROMPT, data);
        PopupSerializer::appendArg(popupType, data);
        PopupSerializer::appendArg(aceData.resource, data);
        DPL::NamedInputPipe tmp;
        tmp.Open(m_outputName);
        m_output.Open(m_outputName);
        m_input.Open(m_inputName);
        m_output.Write(data, data.Size());

        executePopup();

        //Result from popup application is available. Read it.
        DPL::BinaryQueueAutoPtr resultData =
            m_input.Read(std::numeric_limits<std::size_t>::max());
        const int result = PopupSerializer::getIntArg(*resultData);
        const int validity = PopupSerializer::getIntArg(*resultData);

        Assert(resultData->Empty());

        tmp.Close();
        m_input.Close();
        m_output.Close();

        Prompt::PromptAnswer answer(result,
                                    static_cast<Prompt::Validity>(validity));

        LogDebug("Answer: " << result << " Validity: " << validity);

        //ASK SECURITY DAEMON
        if (!result &&
            Prompt::Validity::ONCE == answer.getValidity())
        {
            LogInfo("User answer is DENY ONCE. Don't call security daemon");
        }
        else
        {
            LogInfo("calling security daemon");
            bool securityResponse =
                    securityDaemonCall(answer.isAccessAllowed(),
                                       answer.getValidity(),
                                       aceData);

            if(!securityResponse)
            {
                LogError("Security Daemon has responded with false!");
                return false;
            }
            LogInfo("Security Daemon has responded with true");
        }

        return answer.isAccessAllowed();
    }
    Catch(DPL::Exception)
    {
        LogError("error occured");
    }
    // if error then return deny once
    return false;
}

bool PopupInvoker::askYesNo(const std::string& title, const std::string& message)
{
    Try
    {
        DPL::BinaryQueue data;
        PopupSerializer::appendArg(YES_NO_PROMPT, data);
        PopupSerializer::appendArg(title, data);
        PopupSerializer::appendArg(message, data);
        DPL::NamedInputPipe tmp;
        tmp.Open(m_outputName);
        m_output.Open(m_outputName);
        m_input.Open(m_inputName);
        m_output.Write(data, data.Size());

        executePopup();

        //Result from popup application is available. Read it.
        DPL::BinaryQueueAutoPtr resultData =
            m_input.Read(std::numeric_limits<std::size_t>::max());
        const int result = PopupSerializer::getIntArg(*resultData);

        LogDebug("Popup result is: " << result);

        Assert(resultData->Empty());

        tmp.Close();
        m_input.Close();
        m_output.Close();

        return (!!result);
    }
    Catch(DPL::Exception)
    {
        LogError("error occured");
    }

    return false;
}

void PopupInvoker::executePopup()
{
    pid_t pid = fork();
    if (pid == -1)
    {
        //error occured
        LogError("Cannot display popup!");
        Assert(false);
    }
    if (pid == 0)
    {
        //child process
        int ret = execl(POPUP_EXEC,
                        POPUP_EXEC,
                        m_outputName.c_str(),
                        m_inputName.c_str(),
                        NULL);
        if (ret == -1) {
            //execl returns -1 on error
            LogError("Cannot display popup!");
            Assert(false);
        }
    }

    DPL::WaitableHandle handle = m_input.WaitableReadHandle();
    DPL::WaitForSingleHandle(handle);
}

bool PopupInvoker::securityDaemonCall(bool allowed,
                                           Prompt::Validity valid,
                                           const AceUserdata &data)
{
    if(!m_dbusPopupClient)
        m_dbusPopupClient.Reset(new DPL::DBus::Client(
                    WrtSecurity::SecurityDaemonConfig::OBJECT_PATH(),
                    WrtSecurity::SecurityDaemonConfig::SERVICE_NAME(),
                    WrtSecurity::PopupServerApi::INTERFACE_NAME()));

    bool response = false;
    Try {
        m_dbusPopupClient->call(
                WrtSecurity::PopupServerApi::VALIDATION_METHOD(),
                       allowed,
                       static_cast<int>(valid),
                       data.handle,
                       data.subject,
                       data.resource,
                       data.paramKeys,
                       data.paramValues,
                       data.sessionId,
                       &response);
    } Catch (DPL::DBus::Client::Exception::DBusClientException) {
        ReThrowMsg(PopupInvoker::Exception::PopupInvokerException,
                 "Failed to call security daemon");
    }

    return response;
}