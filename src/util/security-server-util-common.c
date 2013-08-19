/*
 *  security-server
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


#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/smack.h>
#include <fcntl.h>
#include <sys/un.h>
#include <errno.h>
#include <unistd.h>
#include <stdint.h>

#include <smack-check.h>

#include "security-server-common.h"
#include "security-server-cookie.h"
#include "security-server-comm.h"
#include "security-server-util.h"
#include "security-server.h"

/*
 * @buffer   output buffer
 * @position target position in output buffer
 * @source   source data
 * @len      source data length
 */
static void append_to_buffer(unsigned char *buffer, int *position, const void *source, size_t len)
{
    if (len <= 0) {
        SEC_SVR_DBG("Appending nothing.");
        return;
    }
    memcpy(buffer + *position, source, len);
    *position += len;
}

static void append_cookie(unsigned char *buffer, int *position, const cookie_list *cookie)
{
    int i;
    int path_len = cookie->path ? strlen(cookie->path) : 0;

    append_to_buffer(buffer, position, &path_len, sizeof(int));
    append_to_buffer(buffer, position, &cookie->permission_len, sizeof(int));
    append_to_buffer(buffer, position, &cookie->cookie, SECURITY_SERVER_COOKIE_LEN);
    append_to_buffer(buffer, position, &cookie->pid, sizeof(pid_t));
    append_to_buffer(buffer, position, &cookie->path, path_len);

    for (i = 0; i < cookie->permission_len; ++i)
        append_to_buffer(buffer, position, &cookie->permissions[i], sizeof(int));
}

/* Get all cookie info response *
 * packet format
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * |---------------------------------------------------------------|
 * | version=0x01  |MessageID=0x52 |       Message Length          |
 * |---------------------------------------------------------------|
 * |  return code  |             tot # of cooks (32bit)            |
 * |---------------------------------------------------------------|
 * |   cont'd...   |            1st cmdline_len (32bit)            |
 * |---------------------------------------------------------------|
 * |   cont'd...   |           1st permission_len (32bit)          |
 * ----------------------------------------------------------------|
 * |   cont'd...   |                                               |
 * |----------------                                               |
 * |                         1st cookie                            |
 * |                                                               |
 * |---------------------------------------------------------------|
 * |                         1st PID (32bit)                       |
 * |---------------------------------------------------------------|
 * |                     1st cmdline (string)                      |
 * |---------------------------------------------------------------|
 * |                           1st perm_1                          |
 * |---------------------------------------------------------------|
 * |                           1st perm_2                          |
 * |---------------------------------------------------------------|
 * |                              ...                              |
 * |---------------------------------------------------------------|
 * |                      2nd cmdline_len  (32bit)                 |
 * |---------------------------------------------------------------|
 * |                     2nd permission_len (32bit)                |
 * |---------------------------------------------------------------|
 * |                                                               |
 * |                        2nd cookie                             |
 * |                                                               |
 * |---------------------------------------------------------------|
 * |                         2nd PID (32 bit)                      |
 * |---------------------------------------------------------------|
 * |                     2nd cmdline (string)                      |
 * |---------------------------------------------------------------|
 * |                           2st perm_1                          |
 * |---------------------------------------------------------------|
 * |                           2st perm_2                          |
 * |---------------------------------------------------------------|
 * |                              ...                              |
 * |---------------------------------------------------------------|
 * |                                                               |
 * |                             ...                               |
 * |                                                               |
 * |                                                               |
 */
unsigned char *get_all_cookie_info(cookie_list *list, int *size)
{
    cookie_list *current = list;
    int ptr, total_num, total_size, path_len;
    unsigned char *buf = NULL, *tempptr = NULL;
    response_header hdr;

    total_size = sizeof(hdr) + sizeof(int);

    buf = malloc(total_size); /* header size */
    ptr = sizeof(hdr) + sizeof(int);
    total_num = 0;  /* Total # of cookies initial value */

    while (current != NULL)
    {
        current = garbage_collection(current);
        if (current == NULL)
            break;

        total_num++;
        path_len = current->path ? strlen(current->path) : 0;
        total_size += sizeof(int) + sizeof(int) + SECURITY_SERVER_COOKIE_LEN + sizeof(pid_t) + path_len + (current->permission_len * sizeof(int));
        tempptr = realloc(buf, total_size);
        if (tempptr == NULL)
        {
            SEC_SVR_ERR("%s", "Out of memory");
            return NULL;
        }
        buf = tempptr;

        append_cookie(buf, &ptr, current);
        current = current->next;
    }

    if (total_size > 65530)
    {
        SEC_SVR_ERR("Packet too big. message length overflow: %d", total_size);
        free(buf);
        return NULL;
    }

    hdr.basic_hdr.version = SECURITY_SERVER_MSG_VERSION;
    hdr.basic_hdr.msg_id = SECURITY_SERVER_MSG_TYPE_GET_ALL_COOKIES_RESPONSE;
    hdr.basic_hdr.msg_len = (unsigned short)(total_size - sizeof(hdr));
    hdr.return_code = SECURITY_SERVER_RETURN_CODE_SUCCESS;

    // reset buffer position to the beginning of buffer and insert header
    ptr = 0;
    append_to_buffer(buf, &ptr, &hdr, sizeof(hdr));
    append_to_buffer(buf, &ptr, &total_num, sizeof(total_num));
    *size = total_size;
    return buf;
}

int send_all_cookie_info(const unsigned char *buf, int size, int sockfd)
{
    int ret;
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

    /* Send to client */
    ret = TEMP_FAILURE_RETRY(write(sockfd, buf, size));

    if (ret < size)
        return SECURITY_SERVER_ERROR_SEND_FAILED;
    return SECURITY_SERVER_SUCCESS;
}

/* Get one cookie info response *
 * packet format
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * |---------------------------------------------------------------|
 * | version=0x01  |MessageID=0x54 |       Message Length          |
 * |---------------------------------------------------------------|
 * |  return code  |              cmdline_len (32bit)t)            |
 * |---------------------------------------------------------------|
 * |   cont'd...   |              permission_len (32bit)           |
 * ----------------------------------------------------------------|
 * |   cont'd...   |                                               |
 * |----------------                                               |
 * |                             cookie                            |
 * |                                                               |
 * |---------------------------------------------------------------|
 * |                           PID (32bit)                         |
 * |---------------------------------------------------------------|
 * |                         cmdline (string)                      |
 * |---------------------------------------------------------------|
 * |                             perm_1                            |
 * |---------------------------------------------------------------|
 * |                             perm_2                            |
 * |---------------------------------------------------------------|
 * |                              ...                              |
 * |---------------------------------------------------------------|
*/
int send_one_cookie_info(const cookie_list *list, int sockfd)
{
    unsigned char *buf = NULL;
    response_header hdr;
    int total_size, ptr = 0, ret, path_len;

    path_len = list->path ? strlen(list->path) : 0;

    total_size = sizeof(hdr) + sizeof(int) + sizeof(int) + SECURITY_SERVER_COOKIE_LEN + sizeof(pid_t) + path_len + (list->permission_len * sizeof(int));
    buf = malloc(total_size);
    if (buf == NULL)
    {
        SEC_SVR_ERR("%s", "Out of memory");
        return SECURITY_SERVER_ERROR_OUT_OF_MEMORY;
    }

    hdr.basic_hdr.version = SECURITY_SERVER_MSG_VERSION;
    hdr.basic_hdr.msg_id = SECURITY_SERVER_MSG_TYPE_GET_COOKIEINFO_RESPONSE;
    hdr.basic_hdr.msg_len = sizeof(int) + sizeof(int) + SECURITY_SERVER_COOKIE_LEN + sizeof(pid_t) + path_len + (list->permission_len * sizeof(int));
    hdr.return_code = SECURITY_SERVER_RETURN_CODE_SUCCESS;

    // header
    append_to_buffer(buf, &ptr, &hdr, sizeof(hdr));
    // cookie
    append_cookie(buf, &ptr, list);

    ret = check_socket_poll(sockfd, POLLOUT, SECURITY_SERVER_SOCKET_TIMEOUT_MILISECOND);
    if (ret == SECURITY_SERVER_ERROR_POLL)
    {
        SEC_SVR_ERR("%s", "poll() error");
        free(buf);
        return SECURITY_SERVER_ERROR_SEND_FAILED;
    }
    if (ret == SECURITY_SERVER_ERROR_TIMEOUT)
    {
        SEC_SVR_ERR("%s", "poll() timeout");
        free(buf);
        return SECURITY_SERVER_ERROR_SEND_FAILED;
    }

    /* Send to client */
    ret = TEMP_FAILURE_RETRY(write(sockfd, buf, total_size));
    free(buf);
    if (ret < total_size)
        return SECURITY_SERVER_ERROR_SEND_FAILED;
    return SECURITY_SERVER_SUCCESS;
}

int util_process_all_cookie(int sockfd, cookie_list *list)
{
    unsigned char *buf = NULL;
    int ret;
    buf = get_all_cookie_info(list, &ret);
    if (buf == NULL)
    {
        return SECURITY_SERVER_ERROR_OUT_OF_MEMORY;
    }

    ret = send_all_cookie_info(buf, ret, sockfd);

    if (buf != NULL)
        free(buf);
    return ret;
}
int util_process_cookie_from_pid(int sockfd, cookie_list *list)
{
    int pid, ret;
    cookie_list *result = NULL;

    ret = TEMP_FAILURE_RETRY(read(sockfd, &pid, sizeof(int)));
    if (ret < (int)sizeof(int))
    {
        SEC_SVR_ERR("Received cookie size is too small: %d", ret);
        return SECURITY_SERVER_ERROR_RECV_FAILED;
    }
    if (pid == 0)
    {
        SEC_SVR_ERR("%s", "ERROR: Default cookie is not allowed to be retrieved");
        ret = send_generic_response(sockfd, SECURITY_SERVER_MSG_TYPE_GET_COOKIEINFO_RESPONSE,
            SECURITY_SERVER_RETURN_CODE_BAD_REQUEST);
        if (ret != SECURITY_SERVER_SUCCESS)
        {
            SEC_SVR_ERR("ERROR: Cannot send generic response: %d", ret);
        }
    }
    result = search_cookie_from_pid(list, pid);
    if (result == NULL)
    {
        ret = send_generic_response(sockfd, SECURITY_SERVER_MSG_TYPE_GET_COOKIEINFO_RESPONSE,
            SECURITY_SERVER_RETURN_CODE_NO_SUCH_COOKIE);
        if (ret != SECURITY_SERVER_SUCCESS)
        {
            SEC_SVR_ERR("ERROR: Cannot send generic response: %d", ret);
        }
    }
    else
    {
        ret = send_one_cookie_info(result, sockfd);
        if (ret != SECURITY_SERVER_SUCCESS)
        {
            SEC_SVR_ERR("ERROR: Cannot send cookie info response: %d", ret);
        }
    }

    return ret;
}

int util_process_cookie_from_cookie(int sockfd, cookie_list *list)
{
    unsigned char cookie[SECURITY_SERVER_COOKIE_LEN];
    int ret;
    int privileges[] = { 0 };   //only one privilege to check - root
    cookie_list *result = NULL;

    ret = TEMP_FAILURE_RETRY(read(sockfd, cookie, SECURITY_SERVER_COOKIE_LEN));
    if (ret < SECURITY_SERVER_COOKIE_LEN)
    {
        SEC_SVR_ERR("Received cookie size is too small: %d", ret);
        return SECURITY_SERVER_ERROR_RECV_FAILED;
    }
    result = search_cookie(list, cookie, privileges, 1);
    if (result == NULL)
    {
        ret = send_generic_response(sockfd, SECURITY_SERVER_MSG_TYPE_GET_COOKIEINFO_RESPONSE,
            SECURITY_SERVER_RETURN_CODE_NO_SUCH_COOKIE);
        if (ret != SECURITY_SERVER_SUCCESS)
        {
            SEC_SVR_ERR("ERROR: Cannot send generic response: %d", ret);
        }
    }
    else
    {
        ret = send_one_cookie_info(result, sockfd);
        if (ret != SECURITY_SERVER_SUCCESS)
        {
            SEC_SVR_ERR("ERROR: Cannot send cookie info response: %d", ret);
        }
    }

    return ret;
}

int util_smack_label_is_valid(const char *smack_label)
{
    int i;

    if (!smack_label || smack_label[0] == '\0' || smack_label[0] == '-')
        goto err;

    for (i = 0; smack_label[i]; ++i) {
        if (i >= SMACK_LABEL_LEN)
            return 0;
        switch (smack_label[i]) {
            case '~':
            case ' ':
            case '/':
            case '"':
            case '\\':
            case '\'':
                goto err;
            default:
                break;
        }
    }

    return 1;
err:
    SEC_SVR_ERR("ERROR: Invalid Smack label: %s", smack_label);
    return 0;
}

char *read_exe_path_from_proc(pid_t pid)
{
    char link[32];
    char *exe = NULL;
    size_t size = 64;
    ssize_t cnt = 0;

    // get link to executable
    snprintf(link, sizeof(link), "/proc/%d/exe", pid);

    for (;;)
    {
        exe = malloc(size);
        if (exe == NULL)
        {
            SEC_SVR_ERR("Out of memory");
            return NULL;
        }

        // read link target
        cnt = readlink(link, exe, size);

        // error
        if (cnt < 0 || (size_t) cnt > size)
        {
            SEC_SVR_ERR("Can't locate process binary for pid[%d]", pid);
            free(exe);
            return NULL;
        }

        // read less than requested
        if ((size_t) cnt < size)
            break;

        // read exactly the number of bytes requested
        free(exe);
        if (size > (SIZE_MAX >> 1))
        {
            SEC_SVR_ERR("Exe path too long (more than %d characters)", size);
            return NULL;
        }
        size <<= 1;
    }
    // readlink does not append null byte to buffer.
    exe[cnt] = '\0';
    return exe;
}

/*
 * Function that checks if API caller have access to specified label.
 * In positive case (caller has access to the API) returns 1.
 * In case of no access returns 0, and -1 in case of error.
 */
int authorize_SS_API_caller_socket(int sockfd, char *required_API_label, char *required_rule)
{
    int retval;
    int checkval;
    char *label = NULL;
    char *path = NULL;
    //for getting socket options
    struct ucred cr;
    unsigned int len;

    SEC_SVR_DBG("Checking client SMACK access to SS API");

    if (!smack_check()) {
        SEC_SVR_ERR("No SMACK on device found, API PROTECTION DISABLED!!!");
        retval = 1;
        goto end;
    }

    retval = smack_new_label_from_socket(sockfd, &label);
    if (retval < 0) {
        SEC_SVR_ERR("%s", "Error in getting label from socket");
        retval = -1;
        goto end;
    }

    retval = smack_have_access(label, required_API_label, required_rule);

    len = sizeof(cr);
    checkval = getsockopt(sockfd, SOL_SOCKET, SO_PEERCRED, &cr, &len);

    if (checkval < 0) {
        SEC_SVR_ERR("Error in getsockopt(): client pid is unknown.");
        if (retval) {
            SEC_SVR_DBG("SS_SMACK: subject=%s, object=%s, access=%s, result=%d", label, required_API_label, required_rule, retval);
        } else {
            SEC_SVR_ERR("SS_SMACK: subject=%s, object=%s, access=%s, result=%d", label, required_API_label, required_rule, retval);
        }
    } else {
        path = read_exe_path_from_proc(cr.pid);

        if (retval == 0) {
            retval = smack_pid_have_access(cr.pid, required_API_label, required_rule);
        }

        const char *cap_info = "";
        if (retval == 0)
            cap_info = ", no CAP_MAC_OVERRIDE";

        if (retval > 0) {
            SEC_SVR_DBG("SS_SMACK: caller_pid=%d, subject=%s, object=%s, access=%s, result=%d, caller_path=%s",
                        cr.pid, label, required_API_label, required_rule, retval, path);
        } else {
            SEC_SVR_ERR("SS_SMACK: caller_pid=%d, subject=%s, object=%s, access=%s, result=%d, caller_path=%s%s",
                        cr.pid, label, required_API_label, required_rule, retval, path, cap_info);
        }
    }

end:
    if (path != NULL)
        free(path);
    if (label != NULL)
        free(label);

    return retval;
}
