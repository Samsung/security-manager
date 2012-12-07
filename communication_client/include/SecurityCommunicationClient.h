/*
 * Copyright (c) 2012 Samsung Electronics Co., Ltd All Rights Reserved
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
 * @file        SecurityCommunicationClient.h
 * @author      Zofia Abramowska (z.abramowska@samsung.com)
 * @version     1.0
 * @brief       This is header of class used by IPC client with implemented templates
 *
 */

/*
 * This class hides implementation of specific communication types
 * and enables switching between them by #defined macros.
 *
 * supported types : DBUS_CONNECTION
 *
 * IMPORTANT : Exactly ONE type MUST be defined.
 *
 */

#ifndef SECURITYCOMMUNICATIONCLIENT_H_
#define SECURITYCOMMUNICATIONCLIENT_H_

#include <dpl/dbus/dbus_client.h>
#include <dpl/log/log.h>
#include <dpl/scoped_ptr.h>
#include "SecuritySocketClient.h"
#include <string>
#include <memory>

#define DBUS_CONNECTION


namespace WrtSecurity {
namespace Communication {
class Client
{
public:
    class Exception
    {
    public:
        DECLARE_EXCEPTION_TYPE(DPL::Exception, Base)
        DECLARE_EXCEPTION_TYPE(Base, SecurityCommunicationClientException)
    };

    explicit Client(const std::string &intefaceName);



    template<typename ... Args>
    void call(const char* methodName, const Args& ... args)
    {

        connect();
        Try{
        #ifdef DBUS_CONNECTION
            m_dbusClient->call(methodName, args...);
        } Catch (DPL::DBus::Client::Exception::DBusClientException){
        #endif
        #ifdef SOCKET_CONNECTION
            m_socketClient->call(methodName, args...);
        } Catch (SecuritySocketClient::Exception::SecuritySocketClientException){
        #endif
            LogError("Error getting response");
            disconnect();
            ReThrowMsg(Exception::SecurityCommunicationClientException,
                       "Error getting response");
        }
        LogInfo("Call served");
        disconnect();
  }

    template<typename ...Args>
    void call(std::string methodName, const Args&... args)
    {
        call(methodName.c_str(), args...);
    }


private:

    void connect();
    void disconnect();

    std::string m_interfaceName;
    #ifdef DBUS_CONNECTION
    std::unique_ptr<DPL::DBus::Client> m_dbusClient;
    #endif

    #ifdef SOCKET_CONNECTION
    std::unique_ptr<SecuritySocketClient> m_socketClient;
    #endif
};
} // namespace Communication
} // namespace WrtSecurity

#endif /* SECURITYCOMMUNICATIONCLIENT_H_ */
