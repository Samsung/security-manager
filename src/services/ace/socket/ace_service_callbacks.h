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
 * @file        ace_service_callbacks.h
 * @author      Zofia Abramowska (z.abramowska@samsung.com)
 * @version     1.0
 * @brief       Header of Ace Service callbacks
 */

#ifndef ACE_SERVICE_CALLBACKS_H_
#define ACE_SERVICE_CALLBACKS_H_

#include <memory>
#include <SocketConnection.h>
#include <dpl/log/log.h>

namespace RPC {

namespace AceServiceCallbacks {

    // IN string subject
    // IN string resource
    // IN vector<string> function param names
    // IN vector<string> function param values
    // OUT int allow, deny, popup type
    void checkAccess(SocketConnection * connector);

    // IN string subject
    // IN string resource
    // OUT int allow, deny, popup type
    void checkAccessInstall(SocketConnection * connector);

    // Policy update trigger
    void updatePolicy(SocketConnection * connector);

};

} //namespace RPC

#endif /* ACE_SERVICE_CALLBACKS_H_ */
