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
 * @brief       This is implementation of class used IPC client
 */


#include "SecurityCommunicationClient.h"

#ifdef DBUS_CONNECTION
#include "security_daemon_dbus_config.h"
#endif

namespace WrtSecurity{
namespace Communication{

  Client::Client(const std::string& interfaceName){
    #if DBUS_CONNECTION
      LogInfo("DBus create");
    Try {
      m_dbusClient.reset(new DPL::DBus::Client(WrtSecurity::SecurityDaemonConfig::OBJECT_PATH(),
                         WrtSecurity::SecurityDaemonConfig::SERVICE_NAME(),
                         interfaceName));
    } Catch (DPL::DBus::Client::Exception::DBusClientException) {
      LogError("Error getting connection");
      ReThrowMsg(Exception::SecurityCommunicationClientException,
               "Error getting connection");
    }
    if(NULL == m_dbusClient.get()){
      LogError("Couldn't get client");
      ThrowMsg(Exception::SecurityCommunicationClientException,
               "Error getting client");
    }
    #endif //DBUS_CONNECTION

    #ifdef SOCKET_CONNECTION
    m_socketClient.reset(new SecuritySocketClient(interfaceName));
    if(NULL == m_socketClient.get()){
        LogError("Couldn't get client");
        ThrowMsg(Exception::SecurityCommunicationClientException,
                 "Error getting client");
    }
    #endif //SOCKET_CONNECTION
    LogInfo("Created communication client");
  }

  void Client::connect(){
    #ifdef SOCKET_CONNECTION
      Try {
          m_socketClient->connect();
      } Catch(SecuritySocketClient::Exception::SecuritySocketClientException){
          LogError("Couldn't connect");
          ReThrowMsg(Exception::SecurityCommunicationClientException,
                     "Error connecting");
      }

    #endif //SOCKET_CONNECTION
      LogInfo("Connected");
  }

  void Client::disconnect(){

    #ifdef SOCKET_CONNECTION
      m_socketClient->disconnect();
    #endif //SOCKET_CONNECTION
    LogInfo("Disconnected");
  }


} // namespace Communication

} // namespace WrtSecurity

