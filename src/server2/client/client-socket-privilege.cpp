/*
 *  Copyright (c) 2000 - 2013 Samsung Electronics Co., Ltd All Rights Reserved
 *
 *  Contact: Bumjin Im <bj.im@samsung.com>
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
 * @file        client-socket-privilege.cpp
 * @author      Zofia Abramowska (z.abramowska@samsung.com)
 * @version     1.0
 * @brief       This file constains implementation of socket privilege api.
 */
#include <memory>

#include <sys/socket.h>
#include <sys/smack.h>

#include <dpl/log/log.h>
#include <dpl/exception.h>

#include <message-buffer.h>
#include <client-common.h>
#include <protocols.h>
#include <smack-check.h>

#include <security-server.h>
#include <security-server-common.h>

//static int get_exec_path(pid_t pid, std::string &exe)
//{
//    using namespace SecurityServer;
//
//    try{
//        MessageBuffer send, recv;
//        Serialization::Serialize(send, pid);
//
//        int result = sendToServer(
//                SERVICE_SOCKET_EXEC_PATH,
//                send.Pop(),
//                recv);
//        if(result != SECURITY_SERVER_API_SUCCESS)
//            return result;
//
//        Deserialization::Deserialize(recv, result);
//        if(result != SECURITY_SERVER_API_SUCCESS)
//            return result;
//
//        Deserialization::Deserialize(recv, exe);
//        return result;
//    } catch (MessageBuffer::Exception::Base &e) {
//        LogDebug("SecurityServer::MessageBuffer::Exception " << e.DumpToString());
//    } catch (std::exception &e) {
//        LogDebug("STD exception " << e.what());
//    } catch (...) {
//        LogDebug("Unknown exception occured");
//    }
//    return SECURITY_SERVER_API_ERROR_UNKNOWN;
//}

SECURITY_SERVER_API
int security_server_check_privilege_by_sockfd(int sockfd,
                                              const char *object,
                                              const char *access_rights)
{
    char *subject = NULL;
    int ret;
    std::string path;
    std::unique_ptr<char, void (*)(void*)throw ()> subjectPtr(NULL, std::free);

    //for get socket options
    struct ucred cr;
    size_t len = sizeof(struct ucred);

    //SMACK runtime check
    if (!smack_runtime_check())
    {
        LogDebug("No SMACK support on device");
        return SECURITY_SERVER_API_SUCCESS;
    }

    if (sockfd < 0 || !object || !access_rights)
        return SECURITY_SERVER_API_ERROR_INPUT_PARAM;

    ret = smack_new_label_from_socket(sockfd, &subject);
    if (ret >= 0) {
        subjectPtr.reset(subject);
        subject = NULL;
    } else {
        LogError("Failed to get new label from socket. Object="
            << object << ", access=" << access_rights
            << ", error=" << strerror(errno));
        return SECURITY_SERVER_API_ERROR_SOCKET;
    }

    ret = getsockopt(sockfd, SOL_SOCKET, SO_PEERCRED, &cr, &len);
    if (ret < 0) {
        LogError("Error in getsockopt(). Errno: "
            << strerror(errno) <<  ", subject="
            << (subjectPtr.get() ? subjectPtr.get() : "NULL")
            << ", object=" << object << ", access=" << access_rights
            << ", error=" << strerror(errno));
        return SECURITY_SERVER_API_ERROR_SOCKET;
    }

    ret = security_server_check_privilege_by_pid(cr.pid, object, access_rights);

    //Getting path for logs
//    if (SECURITY_SERVER_API_SUCCESS != get_exec_path(cr.pid, path)) {
//        LogError("Failed to read executable path for process " << cr.pid);
//    }
//
//    if (ret == SECURITY_SERVER_API_SUCCESS)
//        LogSecureDebug("SS_SMACK: caller_pid=" << cr.pid << ", subject=" <<
//            (subjectPtr.get() ? subjectPtr.get() : "NULL") << ", object=" <<
//            object << ", access=" << access_rights << ", result=" <<
//            ret << ", caller_path=" << path.c_str());
//    else
//        LogSecureWarning("SS_SMACK: caller_pid=" << cr.pid << ", subject=" <<
//            (subjectPtr.get() ? subjectPtr.get() : "NULL") << ", object=" <<
//            object << ", access=" << access_rights << ", result=" <<
//            ret << ", caller_path=" << path.c_str());

    return ret;
}

SECURITY_SERVER_API
char *security_server_get_smacklabel_sockfd(int fd)
{
    char *label = NULL;

    if (!smack_check())
    {
        LogDebug("No SMACK support on device");
        label = (char*) malloc(1);
        if (label) label[0] = '\0';
        return label;
    }

    if (smack_new_label_from_socket(fd, &label) < 0)
    {
        LogError("Client ERROR: Unable to get socket SMACK label");
        return NULL;
    }

    return label;
}
