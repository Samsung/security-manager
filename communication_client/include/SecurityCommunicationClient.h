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

#ifndef SECURITYCOMMUNICATIONCLIENT_H_
#define SECURITYCOMMUNICATIONCLIENT_H_

#include <dpl/dbus/dbus_client.h>
#include <dpl/log/log.h>
#include <dpl/scoped_ptr.h>
#include <string>
#include <memory>

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

  void connect();

  template<typename ... Args>
  void call(const char* methodName, const Args& ... args)
  {
    //#ifdef DBUS_CONNECTION
    Try{
      m_dbusClient->call(methodName, args...);
    } Catch (DPL::DBus::Client::Exception::DBusClientException){
      LogError("Error getting response");
      ReThrowMsg(Exception::SecurityCommunicationClientException,
               "Error getting response");
    }
    //#endif
    LogInfo("Call served");
  }

  template<typename ...Args>
  void call(std::string methodName, const Args&... args)
  {
      call(methodName.c_str(), args...);
  }

  void disconnect();
private:

  std::string m_interfaceName;
  //#ifdef DBUS_CONNECTION
  std::unique_ptr<DPL::DBus::Client> m_dbusClient;
  //#endif
};
} // namespace Communication
} // namespace WrtSecurity

#endif /* SECURITYCOMMUNICATIONCLIENT_H_ */
