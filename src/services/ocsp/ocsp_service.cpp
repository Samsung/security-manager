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
 * @file        ocsp_service.cpp
 * @author      Piotr Marcinkiewicz (p.marcinkiew@samsung.com)
 * @version     1.0
 * @brief       This is implementation file of Ocsp service
 */

#include "security_daemon.h"

namespace OcspService {

class OcspService : public SecurityDaemon::DaemonService
{
  private:
    virtual void initialize()
    {
    }

    virtual void start()
    {
    }

    virtual void stop()
    {
    }

    virtual void deinitialize()
    {
    }

};

DAEMON_REGISTER_SERVICE_MODULE(OcspService)

}//namespace OcspService

