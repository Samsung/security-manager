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
 * @file        ace_client.h
 * @author      Tomasz Swierczek (t.swierczek@samsung.com)
 * @version     1.0
 * @brief       This file contains definitions of AceThinClient API
 */
#ifndef WRT_ACE_CLIENT_H
#define WRT_ACE_CLIENT_H

#include <dpl/noncopyable.h>
#include <dpl/singleton.h>
#include <dpl/exception.h>
#include <ace-client/ace_client_types.h>

namespace AceClient {

class AceThinClientImpl;

class AceThinClient : private DPL::Noncopyable {
  public:
    class Exception
    {
      public:
        DECLARE_EXCEPTION_TYPE(DPL::Exception, Base)
        DECLARE_EXCEPTION_TYPE(Base, AceThinClientException)
    };

    bool checkFunctionCall(const AceRequest& ace_request) const;
    AcePreference getWidgetResourcePreference(
            const AceResource& resource,
            const AceWidgetHandle& handle) const;
    AceResourcesPreferences* getGlobalResourcesPreferences() const;
    bool isInitialized() const;

  private:
    AceThinClient();
    virtual ~AceThinClient();

    AceThinClientImpl* m_impl;
    friend class DPL::Singleton<AceThinClient>;
} __attribute__ ((deprecated));

typedef DPL::Singleton<AceThinClient> AceThinClientSingleton
        __attribute__ ((deprecated));

} // namespace AceClient


#endif // WRT_ACE_CLIENT_H
