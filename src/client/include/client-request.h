/*
 *  Copyright (c) 2000 - 2016 Samsung Electronics Co., Ltd All Rights Reserved
 *
 *  Contact: Rafal Krypa <r.krypa@samsung.com>
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License
 */
/*
 * @file        client-request.h
 * @author      Rafal Krypa <r.krypa@samsung.com>
 * @version     1.0
 * @brief       Helper class wrapping client communication with the service
 */

#pragma once

#include <stdexcept>

#include <connection.h>
#include <dpl/log/log.h>
#include <message-buffer.h>
#include <protocols.h>
#include <security-manager-types.h>

namespace SecurityManager {

class ClientRequest {
public:
    ClientRequest(SecurityModuleCall action)
    {
        Serialization::Serialize(m_send, static_cast<int>(action));
    }

    int getStatus()
    {
        return m_status;
    }

    bool failed()
    {
        return m_status != SECURITY_MANAGER_SUCCESS;
    }

    ClientRequest &send()
    {
        if (m_sent)
            throw std::logic_error(
                "Only one call to ClientRequest::send() is allowed");

        m_sent = true;
        m_status = sendToServer(SERVICE_SOCKET, m_send.Pop(), m_recv);
        if (!failed())
            Deserialization::Deserialize(m_recv, m_status);
        else
            LogError("Error in sendToServer. Error code: " << m_status);

        return *this;
    }

    template <typename... T> ClientRequest &send(const T&... args)
    {
        Serialization::Serialize(m_send, args...);
        return send();
    }

    template <typename... T> ClientRequest &recv(T&... args)
    {
        if (!m_sent)
            throw std::logic_error(
                "Call to ClientRequest::send() must happen before call to ClientRequest::recv()");

        if (failed())
            throw std::logic_error(
                "ClientRequest::recv() not allowed if the request failed");

        Deserialization::Deserialize(m_recv, args...);

        return *this;
    }

private:
    bool m_sent = false;
    int m_status = SECURITY_MANAGER_SUCCESS;
    MessageBuffer m_send, m_recv;
};

} // namespace SecurityManager
