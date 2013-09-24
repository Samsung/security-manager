/*
 * security-server
 *
 *  Copyright (c) 2000 - 2011 Samsung Electronics Co., Ltd All Rights Reserved
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
 *
 */

#include <sys/poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/smack.h>
#include <fcntl.h>
#include <pwd.h>
#include <sys/un.h>
#include <errno.h>
#include <unistd.h>
#include <sys/stat.h>
#include <limits.h>
#include <ctype.h>

#include <systemd/sd-daemon.h>

#include "security-server-common.h"
#include "security-server-comm.h"
#include "smack-check.h"

void printhex(const unsigned char *data, int size)
{
    int i;
    for (i = 0; i < size; i++)
    {
        if (data[i] < 0xF)
            printf("0");

        printf("%X ", data[i]);
        if (((i + 1) % 16) == 0 && i != 0)
            printf("\n");
    }
    printf("\n");
}

/* Return code in packet is positive integer *
 * We need to convert them to error code which are negative integer */
int return_code_to_error_code(int ret_code)
{
    int ret;
    switch (ret_code)
    {
        case SECURITY_SERVER_RETURN_CODE_SUCCESS:
        case SECURITY_SERVER_RETURN_CODE_ACCESS_GRANTED:
            ret = SECURITY_SERVER_SUCCESS;
            break;
        case SECURITY_SERVER_RETURN_CODE_BAD_REQUEST:
            ret = SECURITY_SERVER_ERROR_BAD_REQUEST;
            break;
        case SECURITY_SERVER_RETURN_CODE_AUTHENTICATION_FAILED:
            ret = SECURITY_SERVER_ERROR_AUTHENTICATION_FAILED;
            break;
        case SECURITY_SERVER_RETURN_CODE_ACCESS_DENIED:
            ret = SECURITY_SERVER_ERROR_ACCESS_DENIED;
            break;
        case SECURITY_SERVER_RETURN_CODE_NO_SUCH_OBJECT:
            ret = SECURITY_SERVER_ERROR_NO_SUCH_OBJECT;
            break;
        case SECURITY_SERVER_RETURN_CODE_SERVER_ERROR:
            ret = SECURITY_SERVER_ERROR_SERVER_ERROR;
            break;
        case SECURITY_SERVER_RETURN_CODE_NO_SUCH_COOKIE:
            ret = SECURITY_SERVER_ERROR_NO_SUCH_COOKIE;
            break;
        default:
            ret = SECURITY_SERVER_ERROR_UNKNOWN;
            break;
    }
    return ret;
}

int check_socket_poll(int sockfd, int event, int timeout)
{
    struct pollfd poll_fd[1];
    int retval = SECURITY_SERVER_ERROR_POLL;

    poll_fd[0].fd = sockfd;
    poll_fd[0].events = event;
    retval = poll(poll_fd, 1, timeout);
    if (retval < 0)
    {
        SEC_SVR_ERR("poll() error. errno=%d", errno);
        if (errno != EINTR)
            return SECURITY_SERVER_ERROR_POLL;
        else
        {
            /* Chile process has been closed. Not poll() problem. Call it once again */
            return check_socket_poll(sockfd, event, timeout);
        }
    }

    /* Timed out */
    if (retval == 0)
    {
        return SECURITY_SERVER_ERROR_TIMEOUT;
    }

    if (poll_fd[0].revents != event)
    {
        SEC_SVR_ERR("Something wrong on the peer socket. event=0x%x", poll_fd[0].revents);
        return SECURITY_SERVER_ERROR_POLL;
    }
    return SECURITY_SERVER_SUCCESS;
}

int safe_server_sock_close(int client_sockfd)
{
    struct pollfd poll_fd[1];
    poll_fd[0].fd = client_sockfd;
    poll_fd[0].events = POLLRDHUP;
    if (0 > poll(poll_fd, 1, SECURITY_SERVER_SOCKET_TIMEOUT_MILISECOND)) {
        SECURE_SLOGE("%s", "Unable to poll from socket");
        return SECURITY_SERVER_ERROR_SOCKET;
    }
    SEC_SVR_DBG("%s", "Server: Closing server socket");
    close(client_sockfd);
    return SECURITY_SERVER_SUCCESS;
}

/* Get socket from systemd */
int get_socket_from_systemd(int *sockfd)
{
    int n = sd_listen_fds(0);
    int fd;

    for(fd = SD_LISTEN_FDS_START; fd < SD_LISTEN_FDS_START+n; ++fd) {
        if (0 < sd_is_socket_unix(fd, SOCK_STREAM, 1,
                                  SECURITY_SERVER_SOCK_PATH, 0))
        {
            *sockfd = fd;
            return SECURITY_SERVER_SUCCESS;
        }
    }
    return SECURITY_SERVER_ERROR_SOCKET;
}

/* Create a Unix domain socket and bind */
int create_new_socket(int *sockfd)
{
    int retval = 0, localsockfd = 0, flags;
    struct sockaddr_un serveraddr;
    mode_t sock_mode;

    /* Deleted garbage Unix domain socket file */
    retval = remove(SECURITY_SERVER_SOCK_PATH);

    if (retval == -1 && errno != ENOENT) {
        retval = SECURITY_SERVER_ERROR_UNKNOWN;
        localsockfd = -1;
        SECURE_SLOGE("%s", "Unable to remove /tmp/.security_server.sock");
        goto error;
    }

    /* Create Unix domain socket */
    if ((localsockfd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0)
    {
        retval = SECURITY_SERVER_ERROR_SOCKET;
        localsockfd = -1;
        SEC_SVR_ERR("%s", "Socket creation failed");
        goto error;
    }

    // If SMACK is present we have to label our sockets regardless of SMACK_ENABLED flag
    if (smack_runtime_check()) {
        if (smack_fsetlabel(localsockfd, "@", SMACK_LABEL_IPOUT) != 0)
        {
            SEC_SVR_ERR("%s", "SMACK labeling failed");
            if (errno != EOPNOTSUPP)
            {
                retval = SECURITY_SERVER_ERROR_SOCKET;
                close(localsockfd);
                localsockfd = -1;
                goto error;
            }
        }
        if (smack_fsetlabel(localsockfd, "*", SMACK_LABEL_IPIN) != 0)
        {   SEC_SVR_ERR("%s", "SMACK labeling failed");
            if (errno != EOPNOTSUPP)
            {
                retval = SECURITY_SERVER_ERROR_SOCKET;
                close(localsockfd);
                localsockfd = -1;
                goto error;
            }}
    }
    else {
        SEC_SVR_DBG("SMACK is not available. Sockets won't be labeled.");
    }

    /* Make socket as non blocking */
    if ((flags = fcntl(localsockfd, F_GETFL, 0)) < 0 ||
        fcntl(localsockfd, F_SETFL, flags | O_NONBLOCK) < 0)
    {
        retval = SECURITY_SERVER_ERROR_SOCKET;
        close(localsockfd);
        localsockfd = -1;
        SEC_SVR_ERR("%s", "Cannot go to nonblocking mode");
        goto error;
    }

    bzero (&serveraddr, sizeof(serveraddr));
    serveraddr.sun_family = AF_UNIX;
    strncpy(serveraddr.sun_path, SECURITY_SERVER_SOCK_PATH,
        strlen(SECURITY_SERVER_SOCK_PATH));
    serveraddr.sun_path[strlen(SECURITY_SERVER_SOCK_PATH)] = 0;

    /* Bind the socket */
    if ((bind(localsockfd, (struct sockaddr*)&serveraddr, sizeof(serveraddr))) < 0)
    {
        retval = SECURITY_SERVER_ERROR_SOCKET_BIND;
        SEC_SVR_ERR("%s", "Cannot bind");
        close(localsockfd);
        localsockfd = -1;
        goto error;
    }


    /* Change permission to accept all processes that has different uID/gID */
    sock_mode = (S_IRWXU | S_IRWXG | S_IRWXO);
    /* Flawfinder hits this chmod function as level 5 CRITICAL as race condition flaw *
     * Flawfinder recommends to user fchmod insted of chmod
     * But, fchmod doesn't work on socket file so there is no other choice at this point */
    if (chmod(SECURITY_SERVER_SOCK_PATH, sock_mode) < 0)     /* Flawfinder: ignore */
    {
        SEC_SVR_ERR("%s", "chmod() error");
        retval = SECURITY_SERVER_ERROR_SOCKET;
        close(localsockfd);
        localsockfd = -1;
        goto error;
    }

    retval = SECURITY_SERVER_SUCCESS;

error:
    *sockfd = localsockfd;
    return retval;
}

/* Authenticate peer that it's really security server.
 * Check UID that is root
 */
int authenticate_server(int sockfd)
{
    int retval;
    struct ucred cr;
    unsigned int cl = sizeof(cr);
/*	char *exe = NULL;*/

    /* get socket peer credential */
    if (getsockopt(sockfd, SOL_SOCKET, SO_PEERCRED, &cr, &cl) != 0)
    {
        retval = SECURITY_SERVER_ERROR_SOCKET;
        SEC_SVR_ERR("%s", "getsockopt() failed");
        goto error;
    }

    /* Security server must run as root */
    if (cr.uid != 0)
    {
        retval = SECURITY_SERVER_ERROR_AUTHENTICATION_FAILED;
        SEC_SVR_ERR("Peer is not root: uid=%d", cr.uid);
        goto error;
    }
    else
        retval = SECURITY_SERVER_SUCCESS;

    /* Read command line of the PID from proc fs */
    /* This is commented out because non root process cannot read link of /proc/pid/exe */
/*	exe = read_exe_path_from_proc(cr.pid);

    if(strcmp(exe, SECURITY_SERVER_DAEMON_PATH) != 0)
    {
        retval = SECURITY_SERVER_ERROR_AUTHENTICATION_FAILED;
        SEC_SVR_DBG("Executable path is different. auth failed. Exe path=%s", exe);
    }
    else
    {
        retval = SECURITY_SERVER_SUCCESS;
        SEC_SVR_DBG("Server authenticatd. %s, sockfd=%d", exe, sockfd);
    }
*/
error:
/*	if(exe != NULL)
        free(exe);
*/
    return retval;
}

/* Create a socket and connect to Security Server */
int connect_to_server(int *fd)
{
    struct sockaddr_un clientaddr;
    int client_len = 0, localsockfd, ret, flags;
    *fd = -1;

    /* Create a socket */
    localsockfd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (localsockfd < 0)
    {
        SEC_SVR_ERR("%s", "Error on socket()");
        return SECURITY_SERVER_ERROR_SOCKET;
    }

    /* Make socket as non blocking */
    if ((flags = fcntl(localsockfd, F_GETFL, 0)) < 0 ||
        fcntl(localsockfd, F_SETFL, flags | O_NONBLOCK) < 0)
    {
        close(localsockfd);
        SEC_SVR_ERR("%s", "Cannot go to nonblocking mode");
        return SECURITY_SERVER_ERROR_SOCKET;
    }

    bzero(&clientaddr, sizeof(clientaddr));
    clientaddr.sun_family = AF_UNIX;
    strncpy(clientaddr.sun_path, SECURITY_SERVER_SOCK_PATH, strlen(SECURITY_SERVER_SOCK_PATH));
    clientaddr.sun_path[strlen(SECURITY_SERVER_SOCK_PATH)] = 0;
    client_len = sizeof(clientaddr);

    ret = connect(localsockfd, (struct sockaddr*)&clientaddr, client_len);
    if (ret < 0)
    {
        if (errno == EINPROGRESS)
        {
            SEC_SVR_DBG("%s", "Connection is in progress");
            ret = check_socket_poll(localsockfd, POLLOUT, SECURITY_SERVER_SOCKET_TIMEOUT_MILISECOND);
            if (ret == SECURITY_SERVER_ERROR_POLL)
            {
                SEC_SVR_ERR("%s", "poll() error");
                close(localsockfd);
                return SECURITY_SERVER_ERROR_SOCKET;
            }
            if (ret == SECURITY_SERVER_ERROR_TIMEOUT)
            {
                SEC_SVR_ERR("%s", "poll() timeout");
                close(localsockfd);
                return SECURITY_SERVER_ERROR_SOCKET;
            }
            ret = connect(localsockfd, (struct sockaddr*)&clientaddr, client_len);
            if (ret < 0)
            {
                SEC_SVR_ERR("%s", "connection failed");
                close(localsockfd);
                return SECURITY_SERVER_ERROR_SOCKET;
            }
        }
        else
        {
            SEC_SVR_ERR("%s", "Connection failed");
            close(localsockfd);
            return SECURITY_SERVER_ERROR_SOCKET;
        }
    }

    /* Authenticate the peer is actually security server */
    ret = authenticate_server(localsockfd);
    if (ret != SECURITY_SERVER_SUCCESS)
    {
        close(localsockfd);
        SEC_SVR_ERR("Authentication failed. %d", ret);
        return ret;
    }
    *fd = localsockfd;
    return SECURITY_SERVER_SUCCESS;
}

/* Accept a new client connection */
int accept_client(int server_sockfd)
{
    /* Call poll() to wait for socket connection */
    int retval, localsockfd;
    struct sockaddr_un clientaddr;
    unsigned int client_len;

    client_len = sizeof(clientaddr);

    /* Check poll */
    retval = check_socket_poll(server_sockfd, POLLIN, SECURITY_SERVER_ACCEPT_TIMEOUT_MILISECOND);
    if (retval == SECURITY_SERVER_ERROR_POLL)
    {
        SEC_SVR_ERR("%s", "Error on polling");
        return SECURITY_SERVER_ERROR_SOCKET;
    }

    /* Timed out */
    if (retval == SECURITY_SERVER_ERROR_TIMEOUT)
    {
        /*SEC_SVR_DBG("%s", "accept() timeout");*/
        return SECURITY_SERVER_ERROR_TIMEOUT;
    }

    localsockfd = accept(server_sockfd,
        (struct sockaddr*)&clientaddr,
        &client_len);

    if (localsockfd < 0)
    {
        SEC_SVR_ERR("Cannot accept client. errno=%d", errno);
        return SECURITY_SERVER_ERROR_SOCKET;
    }
    return localsockfd;
}

/* Minimal check of request packet */
int validate_header(basic_header hdr)
{
    if (hdr.version != SECURITY_SERVER_MSG_VERSION)
        return SECURITY_SERVER_ERROR_BAD_REQUEST;

    return SECURITY_SERVER_SUCCESS;
}

/* Send generic response packet to client
 *
 * Generic Response Packet Format
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
|---------------------------------------------------------------|
| version=0x01  |  Message ID   |Message Length (without header)|
|---------------------------------------------------------------|
|  return code  |
-----------------
*/
int send_generic_response (int sockfd, unsigned char msgid, unsigned char return_code)
{
    response_header hdr;
    int size;

    /* Assemble header */
    hdr.basic_hdr.version = SECURITY_SERVER_MSG_VERSION;
    hdr.basic_hdr.msg_id = msgid;
    hdr.basic_hdr.msg_len = 0;
    hdr.return_code = return_code;

    /* Check poll */
    size = check_socket_poll(sockfd, POLLOUT, SECURITY_SERVER_SOCKET_TIMEOUT_MILISECOND);
    if (size == SECURITY_SERVER_ERROR_POLL)
    {
        SEC_SVR_ERR("%s", "poll() error");
        return SECURITY_SERVER_ERROR_SEND_FAILED;
    }
    if (size == SECURITY_SERVER_ERROR_TIMEOUT)
    {
        SEC_SVR_ERR("%s", "poll() timeout");
        return SECURITY_SERVER_ERROR_SEND_FAILED;
    }

    /* Send to client */
    size = TEMP_FAILURE_RETRY(write(sockfd, &hdr, sizeof(hdr)));

    if (size < (int)sizeof(hdr))
        return SECURITY_SERVER_ERROR_SEND_FAILED;
    return SECURITY_SERVER_SUCCESS;
}


/* Send Object name response *
 * Get Object name response packet format
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * |---------------------------------------------------------------|
 * | version=0x01  |MessageID=0x06 |       Message Length          |
 * |---------------------------------------------------------------|
 * |  return code  |                                               |
 * -----------------                                               |
 * |                 object name                                   |
 * |---------------------------------------------------------------|
*/
int send_object_name(int sockfd, char *obj)
{
    response_header hdr;
    unsigned char msg[strlen(obj) + sizeof(hdr)];
    int ret;

    hdr.basic_hdr.version = SECURITY_SERVER_MSG_VERSION;
    hdr.basic_hdr.msg_id = 0x06;
    hdr.basic_hdr.msg_len = strlen(obj);
    hdr.return_code = SECURITY_SERVER_RETURN_CODE_SUCCESS;

    memcpy(msg, &hdr, sizeof(hdr));
    memcpy(msg + sizeof(hdr), obj, strlen(obj));

    /* Check poll */
    ret = check_socket_poll(sockfd, POLLOUT, SECURITY_SERVER_SOCKET_TIMEOUT_MILISECOND);
    if (ret == SECURITY_SERVER_ERROR_POLL)
    {
        SEC_SVR_ERR("%s", "poll() error");
        return SECURITY_SERVER_ERROR_SEND_FAILED;
    }
    if (ret == SECURITY_SERVER_ERROR_TIMEOUT)
    {
        SEC_SVR_ERR("%s", "poll() timeout");
        return SECURITY_SERVER_ERROR_SEND_FAILED;
    }

    ret = TEMP_FAILURE_RETRY(write(sockfd, msg, sizeof(hdr) + strlen(obj)));
    if (ret < (int)(sizeof(hdr) + strlen(obj)))
    {
        /* Error on writing */
        SEC_SVR_ERR("Error on write: %d", ret);
        ret = SECURITY_SERVER_ERROR_SEND_FAILED;
        return ret;
    }
    return SECURITY_SERVER_SUCCESS;
}

/* Send GID response to client
 *
 * Get GID response packet format
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * |---------------------------------------------------------------|
 * | version=0x01  |MessageID=0x08 |       Message Length = 4      |
 * |---------------------------------------------------------------|
 * |  return code  |           gid (first 3 words)                 |
 * |---------------------------------------------------------------|
 * |gid(last word) |
 * |---------------|
*/
int send_gid(int sockfd, int gid)
{
    response_header hdr;
    unsigned char msg[sizeof(gid) + sizeof(hdr)];
    int ret;

    /* Assemble header */
    hdr.basic_hdr.version = SECURITY_SERVER_MSG_VERSION;
    hdr.basic_hdr.msg_id = SECURITY_SERVER_MSG_TYPE_GID_RESPONSE;
    hdr.basic_hdr.msg_len = sizeof(gid);
    hdr.return_code = SECURITY_SERVER_RETURN_CODE_SUCCESS;

    /* Perpare packet */
    memcpy(msg, &hdr, sizeof(hdr));
    memcpy(msg + sizeof(hdr), &gid, sizeof(gid));

    /* Check poll */
    ret = check_socket_poll(sockfd, POLLOUT, SECURITY_SERVER_SOCKET_TIMEOUT_MILISECOND);
    if (ret == SECURITY_SERVER_ERROR_POLL)
    {
        SEC_SVR_ERR("%s", "poll() error");
        return SECURITY_SERVER_ERROR_SEND_FAILED;
    }
    if (ret == SECURITY_SERVER_ERROR_TIMEOUT)
    {
        SEC_SVR_ERR("%s", "poll() timeout");
        return SECURITY_SERVER_ERROR_SEND_FAILED;
    }

    /* Send it */
    ret = TEMP_FAILURE_RETRY(write(sockfd, msg, sizeof(hdr) + sizeof(gid)));
    if (ret < (int)(sizeof(hdr) + sizeof(gid)))
    {
        /* Error on writing */
        SEC_SVR_ERR("Error on write(): %d", ret);
        ret = SECURITY_SERVER_ERROR_SEND_FAILED;
        return ret;
    }
    return SECURITY_SERVER_SUCCESS;
}


/* Send Check password response to client
 *
 * Check password response packet format
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * |---------------------------------------------------------------|
 * | version=0x01  |   MessageID   |       Message Length = 12     |
 * |---------------------------------------------------------------|
 * |  return code  |           attempts (first 3 words)            |
 * |---------------------------------------------------------------|
 * |attempts(rest) |          max_attempts (first 3 words)         |
 * |---------------|-----------------------------------------------|
 * | max_attempts  |          expire_in_days (first 3 words)       |
 * |---------------------------------------------------------------|
 * |expire_in_days |
 * |----------------
 */
int send_pwd_response(const int sockfd,
                      const unsigned char msg_id,
                      const unsigned char return_code,
                      const unsigned int current_attempts,
                      const unsigned int max_attempts,
                      const unsigned int expire_time)
{
    response_header hdr;
    unsigned int expire_secs;
    unsigned char msg[sizeof(hdr) + sizeof(current_attempts) + sizeof(max_attempts) + sizeof(expire_secs)];
    int ret, ptr = 0;


    /* Assemble header */
    hdr.basic_hdr.version = SECURITY_SERVER_MSG_VERSION;
    hdr.basic_hdr.msg_id = msg_id;
    hdr.basic_hdr.msg_len = sizeof(unsigned int) * 3;
    hdr.return_code = return_code;

    /* Perpare packet */
    memcpy(msg, &hdr, sizeof(hdr));
    ptr += sizeof(hdr);
    memcpy(msg + ptr, &current_attempts, sizeof(current_attempts));
    ptr += sizeof(current_attempts);
    memcpy(msg + ptr, &max_attempts, sizeof(max_attempts));
    ptr += sizeof(max_attempts);
    memcpy(msg + ptr, &expire_time, sizeof(expire_time));
    ptr += sizeof(expire_time);

    /* Check poll */
    ret = check_socket_poll(sockfd, POLLOUT, SECURITY_SERVER_SOCKET_TIMEOUT_MILISECOND);
    if (ret == SECURITY_SERVER_ERROR_POLL)
    {
        SEC_SVR_ERR("%s", "Server: poll() error");
        return SECURITY_SERVER_ERROR_SEND_FAILED;
    }
    if (ret == SECURITY_SERVER_ERROR_TIMEOUT)
    {
        SEC_SVR_ERR("%s", "Server: poll() timeout");
        return SECURITY_SERVER_ERROR_SEND_FAILED;
    }

    /* Send it */
    ret = TEMP_FAILURE_RETRY(write(sockfd, msg, ptr));
    if (ret < ptr)
    {
        /* Error on writing */
        SEC_SVR_ERR("Server: ERROR on write(): %d", ret);
        ret = SECURITY_SERVER_ERROR_SEND_FAILED;
        return ret;
    }
    return SECURITY_SERVER_SUCCESS;
}

/* Send GID request message to security server
 *
 * Message format
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * |---------------------------------------------------------------|
 * | version=0x01  |MessageID=0x07 |   Message Length = variable   |
 * |---------------------------------------------------------------|
 * |                                                               |
 * |                   Object name (variable)                      |
 * |                                                               |
 * |---------------------------------------------------------------|
 */
int send_gid_request(int sock_fd, const char *object)
{
    basic_header hdr;
    int retval = 0, send_len = 0;
    unsigned char *buf = NULL;

    if (strlen(object) > SECURITY_SERVER_MAX_OBJ_NAME)
    {
        /* Object name is too big*/
        SEC_SVR_ERR("Object name is too big %dbytes", strlen(object));
        return SECURITY_SERVER_ERROR_INPUT_PARAM;
    }

    hdr.version = SECURITY_SERVER_MSG_VERSION;
    hdr.msg_id = SECURITY_SERVER_MSG_TYPE_GID_REQUEST;
    hdr.msg_len = strlen(object);

    send_len = sizeof(hdr) + strlen(object);

    buf = malloc(send_len);
    if (buf == NULL)
    {
        SEC_SVR_ERR("%s", "out of memory");
        return SECURITY_SERVER_ERROR_OUT_OF_MEMORY;
    }

    memcpy(buf, &hdr, sizeof(hdr));
    memcpy(buf + sizeof(hdr), object, strlen(object));

    /* Check poll */
    retval = check_socket_poll(sock_fd, POLLOUT, SECURITY_SERVER_SOCKET_TIMEOUT_MILISECOND);
    if (retval == SECURITY_SERVER_ERROR_POLL)
    {
        SEC_SVR_ERR("%s", "poll() error");
        retval = SECURITY_SERVER_ERROR_SEND_FAILED;
        goto error;
    }
    if (retval == SECURITY_SERVER_ERROR_TIMEOUT)
    {
        SEC_SVR_ERR("%s", "poll() timeout");
        retval = SECURITY_SERVER_ERROR_SEND_FAILED;
        goto error;
    }

    retval = TEMP_FAILURE_RETRY(write(sock_fd, buf, send_len));
    if (retval < send_len)
    {
        /* Write error */
        SEC_SVR_ERR("Error on write(): %d. errno=%d, sockfd=%d", retval, errno, sock_fd);
        retval = SECURITY_SERVER_ERROR_SEND_FAILED;
    }
    else
        retval = SECURITY_SERVER_SUCCESS;

error:
    if (buf != NULL)
        free(buf);

    return retval;
}

/* Send object name request message to security server *
 *
 * Message format
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * |---------------------------------------------------------------|
 * | version=0x01  |MessageID=0x05 |       Message Length = 4      |
 * |---------------------------------------------------------------|
 * |                               gid                             |
 * |---------------------------------------------------------------|
 */
// int send_object_name_request(int sock_fd, int gid)
// {
//     basic_header hdr;
//     int retval;
//     unsigned char buf[sizeof(hdr) + sizeof(gid)];

//     /* Assemble header */
//     hdr.version = SECURITY_SERVER_MSG_VERSION;
//     hdr.msg_id = SECURITY_SERVER_MSG_TYPE_OBJECT_NAME_REQUEST;
//     hdr.msg_len = sizeof(gid);

//     memcpy(buf, &hdr, sizeof(hdr));
//     memcpy(buf + sizeof(hdr), &gid, sizeof(gid));

//     /* Check poll */
//     retval = check_socket_poll(sock_fd, POLLOUT, SECURITY_SERVER_SOCKET_TIMEOUT_MILISECOND);
//     if (retval == SECURITY_SERVER_ERROR_POLL)
//     {
//         SEC_SVR_ERR("%s", "poll() error");
//         return SECURITY_SERVER_ERROR_SEND_FAILED;
//     }
//     if (retval == SECURITY_SERVER_ERROR_TIMEOUT)
//     {
//         SEC_SVR_ERR("%s", "poll() timeout");
//         return SECURITY_SERVER_ERROR_SEND_FAILED;
//     }

//     /* Send to server */
//     retval = TEMP_FAILURE_RETRY(write(sock_fd, buf, sizeof(buf)));
//     if (retval < sizeof(buf))
//     {
//         /* Write error */
//         SEC_SVR_ERR("Error on write(): %d", retval);
//         return SECURITY_SERVER_ERROR_SEND_FAILED;
//     }
//     return SECURITY_SERVER_SUCCESS;
// }

/* Receive request header */
int recv_hdr(int client_sockfd, basic_header *basic_hdr)
{
    int retval;

    /* Check poll */
    retval = check_socket_poll(client_sockfd, POLLIN, SECURITY_SERVER_SOCKET_TIMEOUT_MILISECOND);
    if (retval == SECURITY_SERVER_ERROR_POLL)
    {
        SEC_SVR_ERR("%s", "poll() error");
        return SECURITY_SERVER_ERROR_SOCKET;
    }
    if (retval == SECURITY_SERVER_ERROR_TIMEOUT)
    {
        SEC_SVR_ERR("%s", "poll() timeout");
        return SECURITY_SERVER_ERROR_TIMEOUT;
    }

    /* Receive request header first */
    retval = TEMP_FAILURE_RETRY(read(client_sockfd, basic_hdr, sizeof(basic_header)));
    if (retval < (int)sizeof(basic_header))
    {
        SEC_SVR_ERR("read failed. closing socket %d", retval);
        return SECURITY_SERVER_ERROR_RECV_FAILED;
    }

    /* Validate header */
    retval = validate_header(*basic_hdr);
    return retval;
}

int recv_generic_response(int sockfd, response_header *hdr)
{
    int retval;

    /* Check poll */
    retval = check_socket_poll(sockfd, POLLIN, SECURITY_SERVER_SOCKET_TIMEOUT_MILISECOND);
    if (retval == SECURITY_SERVER_ERROR_POLL)
    {
        SEC_SVR_ERR("%s", "Client: poll() error");
        return SECURITY_SERVER_ERROR_RECV_FAILED;
    }
    if (retval == SECURITY_SERVER_ERROR_TIMEOUT)
    {
        SEC_SVR_ERR("%s", "Client: poll() timeout");
        return SECURITY_SERVER_ERROR_RECV_FAILED;
    }

    /* Receive response */
    retval = TEMP_FAILURE_RETRY(read(sockfd, hdr, sizeof(response_header)));
    if (retval < (int)sizeof(response_header))
    {
        /* Error on socket */
        SEC_SVR_ERR("Client: Receive failed %d", retval);
        return SECURITY_SERVER_ERROR_RECV_FAILED;
    }

    if (hdr->return_code != SECURITY_SERVER_RETURN_CODE_SUCCESS)
    {
        /* Return codes
         *   SECURITY_SERVER_MSG_TYPE_CHECK_PRIVILEGE_REQUEST
         *   SECURITY_SERVER_MSG_TYPE_CHECK_PRIVILEGE_RESPONSE
         * are not errors but warnings
         */
        SEC_SVR_WRN("Client: return code is not success: %d", hdr->return_code);
        return return_code_to_error_code(hdr->return_code);
    }
    return SECURITY_SERVER_SUCCESS;
}

int recv_get_gid_response(int sockfd, response_header *hdr, int *gid)
{
    int retval;

    retval = recv_generic_response(sockfd, hdr);
    if (retval != SECURITY_SERVER_SUCCESS)
        return return_code_to_error_code(hdr->return_code);

    retval = TEMP_FAILURE_RETRY(read(sockfd, gid, sizeof(int)));
    if (retval < (int)sizeof(int))
    {
        /* Error on socket */
        SEC_SVR_ERR("Receive failed %d", retval);
        return SECURITY_SERVER_ERROR_RECV_FAILED;
    }
    return SECURITY_SERVER_SUCCESS;
}

int recv_get_object_name(int sockfd, response_header *hdr, char *object, int max_object_size)
{
    int retval;
    char *local_obj_name = NULL;

    /* Check poll */
    retval = check_socket_poll(sockfd, POLLIN, SECURITY_SERVER_SOCKET_TIMEOUT_MILISECOND);
    if (retval == SECURITY_SERVER_ERROR_POLL)
    {
        SEC_SVR_ERR("%s", "poll() error");
        return SECURITY_SERVER_ERROR_RECV_FAILED;
    }
    if (retval == SECURITY_SERVER_ERROR_TIMEOUT)
    {
        SEC_SVR_ERR("%s", "poll() timeout");
        return SECURITY_SERVER_ERROR_RECV_FAILED;
    }

    /* Read response */
    retval = TEMP_FAILURE_RETRY(read(sockfd, hdr, sizeof(response_header)));
    if (retval < (int)sizeof(response_header))
    {
        /* Error on socket */
        SEC_SVR_ERR("cannot recv respons: %d", retval);
        return SECURITY_SERVER_ERROR_RECV_FAILED;
    }

    if (hdr->return_code == SECURITY_SERVER_RETURN_CODE_SUCCESS)
    {
        if (max_object_size < hdr->basic_hdr.msg_len)
        {
            SEC_SVR_ERR("Object name is too small need %d bytes, but %d bytes", hdr->basic_hdr.msg_len, max_object_size);
            return SECURITY_SERVER_ERROR_BUFFER_TOO_SMALL;
        }
        if (hdr->basic_hdr.msg_len > SECURITY_SERVER_MAX_OBJ_NAME)
        {
            SEC_SVR_ERR("Received object name is too big. %d", hdr->basic_hdr.msg_len);
            return SECURITY_SERVER_ERROR_BAD_RESPONSE;
        }

        local_obj_name = malloc(hdr->basic_hdr.msg_len + 1);
        if (local_obj_name == NULL)
        {
            SEC_SVR_ERR("%s", "Out of memory error");
            return SECURITY_SERVER_ERROR_OUT_OF_MEMORY;
        }

        retval = TEMP_FAILURE_RETRY(read(sockfd, local_obj_name, hdr->basic_hdr.msg_len));
        if (retval < (hdr->basic_hdr.msg_len))
        {
            /* Error on socket */
            SEC_SVR_ERR("read() failed: %d", retval);
            if (local_obj_name != NULL)
                free(local_obj_name);
            return SECURITY_SERVER_ERROR_RECV_FAILED;
        }
        memcpy(object, local_obj_name, hdr->basic_hdr.msg_len);
        object[hdr->basic_hdr.msg_len] = 0;
        retval = SECURITY_SERVER_SUCCESS;
    }
    else
    {
        SEC_SVR_ERR("Error received. return code: %d", hdr->return_code);
        retval = return_code_to_error_code(hdr->return_code);
        return retval;
    }

    if (local_obj_name != NULL)
        free(local_obj_name);
    return SECURITY_SERVER_SUCCESS;
}

/* Authenticate client application *
 * Currently it only gets peer's credential information only *
 * If we need, we can extend in the futer */
int authenticate_client_application(int sockfd, int *pid, int *uid)
{
    struct ucred cr;
    unsigned int cl = sizeof(cr);

    /* get PID of socket peer */
    if (getsockopt(sockfd, SOL_SOCKET, SO_PEERCRED, &cr, &cl) != 0)
    {
        SEC_SVR_ERR("%s", "getsockopt failed");
        return SECURITY_SERVER_ERROR_SOCKET;
    }
    *pid = cr.pid;
    *uid = cr.uid;
    return SECURITY_SERVER_SUCCESS;
}

/* Authenticate the application is middleware daemon
 * The middleware must run as root (or middleware user) and the cmd line must be
 * pre listed for authentication to succeed */
int authenticate_client_middleware(int sockfd, int *pid)
{
    int uid;
    return authenticate_client_application(sockfd, pid, &uid);
#if 0
    int retval = SECURITY_SERVER_SUCCESS;
    struct ucred cr;
    unsigned int cl = sizeof(cr);
    char *exe = NULL;
    struct passwd pw, *ppw;
    size_t buf_size;
    char *buf;
    static uid_t middleware_uid = 0;

    *pid = 0;

    /* get PID of socket peer */
    if (getsockopt(sockfd, SOL_SOCKET, SO_PEERCRED, &cr, &cl) != 0)
    {
        retval = SECURITY_SERVER_ERROR_SOCKET;
        SEC_SVR_ERR("%s", "Error on getsockopt");
        goto error;
    }

    if (!middleware_uid)
    {
        buf_size = sysconf(_SC_GETPW_R_SIZE_MAX);
        if (buf_size == -1)
            buf_size = 1024;

        buf = malloc(buf_size);

        /* This test isn't essential, skip it in case of error */
        if (buf) {
            if (getpwnam_r(SECURITY_SERVER_MIDDLEWARE_USER, &pw, buf, buf_size, &ppw) == 0 && ppw)
                middleware_uid = pw.pw_uid;

            free(buf);
        }
    }

    /* Middleware services need to run as root or middleware/app user */
    if (cr.uid != 0 && cr.uid != middleware_uid)
    {
        retval = SECURITY_SERVER_ERROR_AUTHENTICATION_FAILED;
        SEC_SVR_ERR("Non root process has called API: %d", cr.uid);
        goto error;
    }

    /* Read command line of the PID from proc fs */
    exe = read_exe_path_from_proc(cr.pid);
    if (exe == NULL)
    {
        /* It's weired. no file in proc file system, */
        retval = SECURITY_SERVER_ERROR_FILE_OPERATION;
        SEC_SVR_ERR("Error on opening /proc/%d/exe", cr.pid);
        goto error;
    }

    *pid = cr.pid;

error:
    if (exe != NULL)
        free(exe);

    return retval;
#endif
}

/* Get app PID from socked and read its privilege (GID) list
 * from /proc/<PID>/status.
 *
 * param 1: socket descriptor
 * param 2: pointer for hold returned array
 *
 * ret: size of array or -1 in case of error
 *
 * Notice that user must free space allocated in this function and
 * returned by second parameter (int * privileges)
 * */
int get_client_gid_list(int sockfd, int **privileges)
{
    int ret;
    //for read socket options
    struct ucred socopt;
    unsigned int socoptSize = sizeof(socopt);
    //buffer for store /proc/<PID>/status filepath
    const int PATHSIZE = 24;
    char path[PATHSIZE];
    //file pointer
    FILE *fp = NULL;
    //buffer for filelines
    const int LINESIZE = 256;
    char fileLine[LINESIZE];
    //for parsing file
    char delim[] = ": ";
    char *token = NULL;


    //clear pointer
    *privileges = NULL;

    //read socket options
    ret = getsockopt(sockfd, SOL_SOCKET, SO_PEERCRED, &socopt, &socoptSize);
    if (ret != 0)
    {
        SEC_SVR_ERR("%s", "Error on getsockopt");
        return -1;
    }

    //now we have PID in sockopt.pid
    bzero(path, PATHSIZE);
    snprintf(path, PATHSIZE, "/proc/%d/status", socopt.pid);

    fp = fopen(path, "r");
    if (fp == NULL)
    {
        SEC_SVR_ERR("%s", "Error on fopen");
        return -1;
    }

    bzero(fileLine, LINESIZE);

    //search for line beginning with "Groups:"
    while (strncmp(fileLine, "Groups:", 7) != 0)
    {
        if (NULL == fgets(fileLine, LINESIZE, fp))
        {
            SEC_SVR_ERR("%s", "Error on fgets");
            fclose(fp);
            return -1;
        }
    }

    fclose(fp);

    //now we have "Groups:" line in fileLine[]
    ret = 0;
    strtok(fileLine, delim);
    while ((token = strtok(NULL, delim)))
    {
        //add found GID
        if (*privileges == NULL)
        {
            //first GID on list
            *privileges = (int*)malloc(sizeof(int) * 1);
            if (*privileges == NULL)
            {
                SEC_SVR_ERR("%s", "Error on malloc");
                return -1;
            }
            (*privileges)[0] = atoi(token);
        }
        else
        {
            *privileges = realloc(*privileges, sizeof(int) * (ret + 1));
            (*privileges)[ret] = atoi(token);
        }

        ret++;
    }

    //check if we found any GIDs for process
    if (*privileges == NULL)
    {
        SEC_SVR_DBG("%s %d", "No GIDs found for PID:", socopt.pid);
    }
    else
    {
        SEC_SVR_DBG("%s %d", "Number of GIDs found:", ret);
    }

    return ret;
}

