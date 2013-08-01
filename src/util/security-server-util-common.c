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
#include "security-server-comm.h"
#include "security-server-util.h"
#include "security-server.h"


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
