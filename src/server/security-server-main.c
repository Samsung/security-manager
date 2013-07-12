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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/smack.h>
#include <errno.h>
#include <signal.h>
#include <pthread.h>
#include <limits.h>
#include <fcntl.h>
#include <sys/smack.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <poll.h>
#include <grp.h>
#include <stdint.h>

#include <server2-main.h>

#include <privilege-control.h>

#include "security-server-cookie.h"
#include "security-server-common.h"
#include "security-server-password.h"
#include "security-server-comm.h"
#include "smack-check.h"

//definitions of security-server API labels
#define API_PASSWD_SET   "security-server::api-password-set"
#define API_PASSWD_CHECK "security-server::api-password-check"
#define API_DATA_SHARE   "security-server::api-data-share"
#define API_MIDDLEWARE   "security-server::api-middleware"
#define API_FREE_ACCESS  "*"

//required rule type
#define API_RULE_REQUIRED "w"

/* Set cookie as a global variable */
cookie_list *c_list;
pthread_mutex_t cookie_mutex;
int thread_status[SECURITY_SERVER_NUM_THREADS];
struct security_server_thread_param {
    int client_sockfd;
    int server_sockfd;
    int thread_status;
};


/************************************************************************************************/
/* Just for test. This code must be removed on release */
#include "security-server-util.h"
/************************************************************************************************/

#if 0
void printhex(unsigned char *data, int size)
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

void print_cookie(cookie_list *list)
{
    int i;
    printf("%s", "cookie:\n");
    printhex(list->cookie, SECURITY_SERVER_COOKIE_LEN);
    printf("path_len: %d\n", list->path ? strlen(list->path) : 0);
    printf("permission_len: %d\n", list->permission_len);
    printf("PID: %d\n", list->pid);
    printf("path: %s\n", list->path);
    printf("%s", "permissions: ");
    for (i = 0; i < list->permission_len; i++)
    {
        printf("%d ", list->permissions[i]);
    }
    printf("%s", "\n");
    printf("prev: %p\n", list->prev);
    printf("next: %p\n", list->next);
}
#endif


/* Object name is actually name of a Group ID *
 * This function opens /etc/group file and search group ID and
 * returns the string */
int search_object_name(int gid, char *obj, int obj_size)
{
    FILE *fp = NULL;
    char *linebuf = NULL, *token = NULL, *token2, *tempstr = NULL;
    int ret = 0, tmp_gid, bufsize;
    fp = fopen("/etc/group", "r");
    if (fp == NULL)
    {
        /* cannot open /etc/group */
        SEC_SVR_ERR("%s", "Cannot open /etc/group");
        return SECURITY_SERVER_ERROR_FILE_OPERATION;
    }

    linebuf = malloc(128);
    bufsize = 128;
    if (linebuf == NULL)
    {
        ret = SECURITY_SERVER_ERROR_OUT_OF_MEMORY;
        SEC_SVR_ERR("%s", "cannot malloc()");
        goto error;
    }

    bzero(linebuf, bufsize);
    ret = SECURITY_SERVER_ERROR_NO_SUCH_OBJECT;
    while (fgets(linebuf, bufsize, fp) != NULL)
    {
        while (linebuf[bufsize - 2] != 0)
        {
            linebuf[bufsize - 1] = (char) fgetc(fp);
            tempstr = realloc(linebuf, bufsize + 128);
            if (tempstr == NULL)
            {
                ret = SECURITY_SERVER_ERROR_OUT_OF_MEMORY;
                goto error;
            }
            linebuf = tempstr;
            bzero(linebuf + bufsize, 128);
            fgets(linebuf + bufsize, 128, fp);
            bufsize += 128;
        }

        token = strtok(linebuf, ":");   /* group name */
        if (token == NULL)
        {
            SEC_SVR_ERR("/etc/group is not valid. cannot find gid: [%s]", linebuf);
            ret = SECURITY_SERVER_ERROR_SERVER_ERROR;
            goto error;
        }
        token2 = strtok(NULL, ":"); /* group password */
        if (token2 == NULL)
        {
            SEC_SVR_ERR("/etc/group is not valid. cannot find gid: [%s]", linebuf);
            ret = SECURITY_SERVER_ERROR_SERVER_ERROR;
            goto error;
        }
        token2 = strtok(NULL, ":"); /* gid */
        if (token2 == NULL)
        {
            SEC_SVR_ERR("/etc/group is not valid. cannot find gid: [%s]", linebuf);
            ret = SECURITY_SERVER_ERROR_SERVER_ERROR;
            goto error;
        }

        errno = 0;
        tmp_gid = strtoul(token2, 0, 10);
        if (errno != 0)
        {
            SEC_SVR_ERR("cannot change string to integer [%s]", token2);
            ret = SECURITY_SERVER_ERROR_SERVER_ERROR;
            goto error;
        }

        if (tmp_gid == gid)
        {
            /* We found it */
            if ((int)strlen(token) > obj_size)
            {
                ret = SECURITY_SERVER_ERROR_BUFFER_TOO_SMALL;
                SEC_SVR_ERR("buffer is too small. %d --> %d", obj_size, strlen(token));
                goto error;
            }
            strncpy(obj, token, strlen(token));
            obj[strlen(token)] = 0;
            ret = SECURITY_SERVER_SUCCESS;
            break;
        }
        bzero(linebuf, bufsize);
    }

error:
    if (linebuf != NULL)
        free(linebuf);
    if (fp != NULL)
        fclose(fp);
    return ret;
}

/*
 * Searches for group ID by given group name
 */

int search_gid(const char *obj)
{
    int ret = 0;
    struct group *grpbuf = NULL;
    struct group grp;
    char *buf = NULL;
    char *bigger_buf = NULL;
    long int max_buf_size = 0;

    /*
     * The maximum needed size for buf can be found using sysconf(3) with the argument _SC_GETGR_R_SIZE_MAX
 * If _SC_GETGR_R_SIZE_MAX is not returned we set max_buf_size to 1024 bytes. Enough to store few groups.
     */
    max_buf_size = sysconf(_SC_GETGR_R_SIZE_MAX);
    if (max_buf_size == -1)
        max_buf_size = 1024;

    buf = malloc((size_t)max_buf_size);
    if (buf == NULL)
    {
        ret = SECURITY_SERVER_ERROR_OUT_OF_MEMORY;
        SEC_SVR_ERR("Out Of Memory");
        goto error;
    }

    /*
     * There can be some corner cases when for example user is assigned to a lot of groups.
     * In that case if buffer is to small getgrnam_r will return ERANGE error.
     * Solution could be calling getgrnam_r with bigger buffer until it's enough big.
     */
    while ((ret = getgrnam_r(obj, &grp, buf, (size_t)max_buf_size, &grpbuf)) == ERANGE) {
        max_buf_size *= 2;

        bigger_buf = realloc(buf, (size_t)max_buf_size);
        if (bigger_buf == NULL) {
            ret = SECURITY_SERVER_ERROR_OUT_OF_MEMORY;
            SEC_SVR_ERR("Out Of Memory");
            goto error;
        }

        buf = bigger_buf;
    }

    if (ret != 0)
    {
        ret = SECURITY_SERVER_ERROR_SERVER_ERROR;
        SEC_SVR_ERR("getgrnam_r failed with error %s\n", strerror(errno));
        goto error;
    } else if (grpbuf == NULL) {
        ret = SECURITY_SERVER_ERROR_NO_SUCH_OBJECT;
        SEC_SVR_ERR("Cannot find gid for group %s\n", obj);
        goto error;
    }

    ret = grpbuf->gr_gid;

error:
    free(buf);
    return ret;
}

/* Signal handler for processes */
static void security_server_sig_child(int signo, siginfo_t *info, void *data)
{
    int status;
    pid_t child_pid;
    pid_t child_pgid;

    (void)signo;
    (void)data;

    child_pgid = getpgid(info->si_pid);
    SEC_SVR_DBG("Signal handler: dead_pid=%d, pgid=%d",info->si_pid,child_pgid);

    while ((child_pid = waitpid(-1, &status, WNOHANG)) > 0) {
        if (child_pid == child_pgid)
            killpg(child_pgid,SIGKILL);
    }

    return;
}

/* Execute a debugging tool by fork() and execve() */
int execute_debug_tool(int argc, char*const *argv, int server_sockfd, int client_sockfd)
{
    int ret, i;
    SEC_SVR_DBG("%s", "Executing tool");

    (void)argc;

    ret = fork();
    if (ret == 0)
    {
        close(client_sockfd);
        close(server_sockfd);
        setsid();

        for (i = 0; i < _NSIG; i++)
            signal(i, SIG_DFL);

        ret = execv(argv[0], argv);
        if (ret == -1)
        {
            SEC_SVR_ERR("Error:Failed to execute [%d]", errno);
            exit(-1);
        }
    }
    if (ret < 0)
    {
        SEC_SVR_ERR("Error: Failed to fork [%d]", errno);
        return SECURITY_SERVER_ERROR_SERVER_ERROR;
    }
    return SECURITY_SERVER_SUCCESS;
}

/* Authenticate the application is middleware daemon
 * The middleware must run as root and the cmd line must be pre listed */
int authenticate_developer_shell(int sockfd)
{
    int retval = SECURITY_SERVER_ERROR_AUTHENTICATION_FAILED;
    struct ucred cr;
    unsigned int cl = sizeof(cr);
    char *exe = NULL;

    /* get PID of socket peer */
    if (getsockopt(sockfd, SOL_SOCKET, SO_PEERCRED, &cr, &cl) != 0)
    {
        retval = SECURITY_SERVER_ERROR_SOCKET;
        SEC_SVR_ERR("%s", "Error on getsockopt");
        goto error;
    }

    /* All middlewares will run as root */
    if (cr.uid != SECURITY_SERVER_DEVELOPER_UID)
    {
        retval = SECURITY_SERVER_ERROR_AUTHENTICATION_FAILED;
        SEC_SVR_ERR("Non root process has called API: %d", cr.uid);
        goto error;
    }

    /* Read executable path of the PID from proc fs */
    exe = read_exe_path_from_proc(cr.pid);
    if (exe == NULL)
    {
        /* It's weired. no file in proc file system, */
        retval = SECURITY_SERVER_ERROR_FILE_OPERATION;
        SEC_SVR_ERR("Error on opening /proc/%d/exe", cr.pid);
        goto error;
    }

    /* Search exe of the peer that is really debug tool */
    if (strcmp(exe, SECURITY_SERVER_DEBUG_TOOL_PATH) != 0)
    {
        SEC_SVR_ERR("Error: Wrong exe path [%s]", exe);
        retval = SECURITY_SERVER_ERROR_AUTHENTICATION_FAILED;
        goto error;
    }
    retval = SECURITY_SERVER_SUCCESS;
    SEC_SVR_DBG("%s", "Client Authenticated");

error:
    if (exe != NULL)
        free(exe);

    return retval;
}

int process_cookie_request(int sockfd)
{
    int retval, client_pid, client_uid;
    cookie_list *created_cookie = NULL;
    unsigned char cookie[SECURITY_SERVER_COOKIE_LEN];
    pid_t cookie_pid;
    char *cookie_label = NULL;

    /* Authenticate client */
    retval = authenticate_client_application(sockfd, &client_pid, &client_uid);
    if (retval != SECURITY_SERVER_SUCCESS)
    {
        SEC_SVR_ERR("%s", "Client Authentication Failed");
        retval = send_generic_response(sockfd,
            SECURITY_SERVER_MSG_TYPE_GENERIC_RESPONSE,
            SECURITY_SERVER_RETURN_CODE_AUTHENTICATION_FAILED);
        if (retval != SECURITY_SERVER_SUCCESS)
        {
            SEC_SVR_ERR("ERROR: Cannot send generic response: %d", retval);
        }
        goto error;
    }
    /* If client application is root process, just respond default cookie */
    /*
    if( client_uid == 0)
    {
        SEC_SVR_DBG("%s", "Requested application is a root process");
        created_cookie = c_list;
        if(c_list == NULL)
        {
            SEC_SVR_DBG("%s", "Cannot read default cookie");
            goto error;
        }
    }
    else
    {
    */
    //TODO: Remove above code if there will be no crashes without it
    //All process should be treaded the same

    /* Create a new cookie. or find existing one */
    pthread_mutex_lock(&cookie_mutex);
    created_cookie = create_cookie_item(client_pid, sockfd, c_list);
    if (created_cookie == NULL)
    {
        pthread_mutex_unlock(&cookie_mutex);
        SEC_SVR_ERR("%s","Cannot create a cookie");
        goto error;
    }

    //let others know if this cookie belongs to root process
    if (client_uid == 0)
        created_cookie->is_roots_process = 1;
    else
        created_cookie->is_roots_process = 0;
    memcpy(cookie, created_cookie->cookie, SECURITY_SERVER_COOKIE_LEN);
    cookie_pid = created_cookie->pid;
    if (created_cookie->smack_label)
        cookie_label = strdup(created_cookie->smack_label);
    else
        cookie_label = strdup("NULL");
    pthread_mutex_unlock(&cookie_mutex);

    //}
    /* send cookie as response */
    retval = send_cookie(sockfd, cookie);
    if (retval != SECURITY_SERVER_SUCCESS)
    {
        SEC_SVR_ERR("ERROR: Cannot send generic response: %d", retval);
    }
    SECURE_SLOGD("Server: Cookie created for client PID %d LABEL >%s<",
        cookie_pid, cookie_label);

    SEC_SVR_DBG("%s", "Server: Cookie has been sent to client");
    free(cookie_label);

error:
    return retval;
}

int process_check_privilege_request(int sockfd)
{
    /* Authenticate client */
    int retval, client_pid, requested_privilege;
    int privileges[1];
    unsigned char requested_cookie[SECURITY_SERVER_COOKIE_LEN];
    cookie_list *search_result = NULL;

    retval = authenticate_client_middleware(sockfd, &client_pid);
    if (retval != SECURITY_SERVER_SUCCESS)
    {
        SEC_SVR_ERR("%s", "Client Authentication Failed");
        retval = send_generic_response(sockfd,
            SECURITY_SERVER_MSG_TYPE_CHECK_PRIVILEGE_RESPONSE,
            SECURITY_SERVER_RETURN_CODE_AUTHENTICATION_FAILED);
        if (retval != SECURITY_SERVER_SUCCESS)
        {
            SEC_SVR_ERR("ERROR: Cannot send generic response: %d", retval);
        }
        goto error;;
    }

    retval = recv_check_privilege_request(sockfd,
        requested_cookie, &requested_privilege);
    if (retval == SECURITY_SERVER_ERROR_RECV_FAILED)
    {
        SEC_SVR_ERR("%s", "Receiving request failed");
        retval = send_generic_response(sockfd,
            SECURITY_SERVER_MSG_TYPE_CHECK_PRIVILEGE_RESPONSE,
            SECURITY_SERVER_RETURN_CODE_BAD_REQUEST);
        if (retval != SECURITY_SERVER_SUCCESS)
        {
            SEC_SVR_ERR("ERROR: Cannot send generic response: %d", retval);
        }
        goto error;;
    }

    if (requested_privilege < 1)
    {
        SEC_SVR_ERR("Requiring bad privilege [%d]", requested_privilege);
        retval = send_generic_response(sockfd,
            SECURITY_SERVER_MSG_TYPE_CHECK_PRIVILEGE_RESPONSE,
            SECURITY_SERVER_RETURN_CODE_BAD_REQUEST);
        if (retval != SECURITY_SERVER_SUCCESS)
        {
            SEC_SVR_ERR("ERROR: Cannot send generic response: %d", retval);
        }
        goto error;
    }

    /* Search cookie list */
    pthread_mutex_lock(&cookie_mutex);
    privileges[0] = requested_privilege;
    search_result = search_cookie(c_list, requested_cookie, privileges, 1);
    pthread_mutex_unlock(&cookie_mutex);
    if (search_result != NULL)
    {
        /* We found */
        SEC_SVR_DBG("We found the cookie with %d privilege and pid:%d", requested_privilege, client_pid);
        SEC_SVR_DBG("%s", "Cookie comparison succeeded. Access granted.");
        retval = send_generic_response(sockfd,
            SECURITY_SERVER_MSG_TYPE_CHECK_PRIVILEGE_RESPONSE,
            SECURITY_SERVER_RETURN_CODE_ACCESS_GRANTED);
        if (retval != SECURITY_SERVER_SUCCESS)
        {
            SEC_SVR_ERR("ERROR: Cannot send generic response: %d", retval);
        }
    }
    else
    {
        /* It's not exist */
        SEC_SVR_WRN("Could not find the cookie with %d privilege", requested_privilege);
        retval = send_generic_response(sockfd,
            SECURITY_SERVER_MSG_TYPE_CHECK_PRIVILEGE_RESPONSE,
            SECURITY_SERVER_RETURN_CODE_ACCESS_DENIED);
        if (retval != SECURITY_SERVER_SUCCESS)
        {
            SEC_SVR_ERR("ERROR: Cannot send generic response: %d", retval);
        }
    }
error:
    return retval;
}

int process_check_privilege_new_request(int sockfd)
{
    /* Authenticate client */
    int retval, client_pid;
    unsigned char requested_cookie[SECURITY_SERVER_COOKIE_LEN];
    cookie_list *search_result = NULL;
    char object_label[MAX_OBJECT_LABEL_LEN + 1];
    char access_rights[MAX_MODE_STR_LEN + 1];

    retval = authenticate_client_middleware(sockfd, &client_pid);
    if (retval != SECURITY_SERVER_SUCCESS)
    {
        SEC_SVR_ERR("%s", "Client Authentication Failed");
        retval = send_generic_response(sockfd,
            SECURITY_SERVER_MSG_TYPE_CHECK_PRIVILEGE_NEW_RESPONSE,
            SECURITY_SERVER_RETURN_CODE_AUTHENTICATION_FAILED);
        if (retval != SECURITY_SERVER_SUCCESS)
        {
            SEC_SVR_ERR("ERROR: Cannot send generic response: %d", retval);
        }
        goto error;;
    }

    retval = recv_check_privilege_new_request(
        sockfd, requested_cookie, object_label, access_rights);
    if (retval == SECURITY_SERVER_ERROR_RECV_FAILED)
    {
        SEC_SVR_ERR("%s", "Receiving request failed");
        retval = send_generic_response(sockfd,
            SECURITY_SERVER_MSG_TYPE_CHECK_PRIVILEGE_NEW_RESPONSE,
            SECURITY_SERVER_RETURN_CODE_BAD_REQUEST);
        if (retval != SECURITY_SERVER_SUCCESS)
        {
            SEC_SVR_ERR("ERROR: Cannot send generic response: %d", retval);
        }
        goto error;;
    }

    /* Search cookie list */
    pthread_mutex_lock(&cookie_mutex);
    search_result = search_cookie_new(c_list, requested_cookie, object_label, access_rights);
    pthread_mutex_unlock(&cookie_mutex);

    if (search_result != NULL)
    {
        /* We found */
        SEC_SVR_DBG("We found the cookie with %s rights and pid:%d", access_rights, client_pid);
        SEC_SVR_DBG("%s", "Cookie comparison succeeded. Access granted.");
        retval = send_generic_response(sockfd,
            SECURITY_SERVER_MSG_TYPE_CHECK_PRIVILEGE_NEW_RESPONSE,
            SECURITY_SERVER_RETURN_CODE_ACCESS_GRANTED);
        if (retval != SECURITY_SERVER_SUCCESS)
        {
            SEC_SVR_ERR("ERROR: Cannot send generic response: %d", retval);
        }
    }
    else
    {
        /* It's not exist */
        SEC_SVR_WRN("Could not find the cookie with %s rights", access_rights);
        retval = send_generic_response(sockfd,
            SECURITY_SERVER_MSG_TYPE_CHECK_PRIVILEGE_NEW_RESPONSE,
            SECURITY_SERVER_RETURN_CODE_ACCESS_DENIED);
        if (retval != SECURITY_SERVER_SUCCESS)
        {
            SEC_SVR_ERR("ERROR: Cannot send generic response: %d", retval);
        }
    }
error:
    return retval;
}

int process_object_name_request(int sockfd)
{
    int retval, client_pid, requested_privilege;
    char object_name[SECURITY_SERVER_MAX_OBJ_NAME];

    /* Authenticate client */
    retval = authenticate_client_middleware(sockfd, &client_pid);
    if (retval != SECURITY_SERVER_SUCCESS)
    {
        SEC_SVR_ERR("%s", "Client Authentication Failed");
        retval = send_generic_response(sockfd,
            SECURITY_SERVER_MSG_TYPE_OBJECT_NAME_RESPONSE,
            SECURITY_SERVER_RETURN_CODE_AUTHENTICATION_FAILED);
        if (retval != SECURITY_SERVER_SUCCESS)
        {
            SEC_SVR_ERR("ERROR: Cannot send generic response: %d", retval);
        }
        goto error;
    }

    /* Receive GID */
    retval = TEMP_FAILURE_RETRY(read(sockfd, &requested_privilege, sizeof(requested_privilege)));
    if (retval < (int)sizeof(requested_privilege))
    {
        SEC_SVR_ERR("%s", "Receiving request failed");
        retval = send_generic_response(sockfd,
            SECURITY_SERVER_MSG_TYPE_OBJECT_NAME_RESPONSE,
            SECURITY_SERVER_RETURN_CODE_BAD_REQUEST);
        if (retval != SECURITY_SERVER_SUCCESS)
        {
            SEC_SVR_ERR("ERROR: Cannot send generic response: %d", retval);
        }
        goto error;
    }

    /* Search from /etc/group */
    retval = search_object_name(requested_privilege,
        object_name,
        SECURITY_SERVER_MAX_OBJ_NAME);
    if (retval == SECURITY_SERVER_ERROR_NO_SUCH_OBJECT)
    {
        /* It's not exist */
        SEC_SVR_ERR("There is no such object for gid [%d]", requested_privilege);
        retval = send_generic_response(sockfd,
            SECURITY_SERVER_MSG_TYPE_OBJECT_NAME_RESPONSE,
            SECURITY_SERVER_RETURN_CODE_NO_SUCH_OBJECT);
        if (retval != SECURITY_SERVER_SUCCESS)
        {
            SEC_SVR_ERR("ERROR: Cannot send generic response: %d", retval);
        }
        goto error;
    }
    if (retval != SECURITY_SERVER_SUCCESS)
    {
        /* Error occurred */
        SEC_SVR_ERR("Error on searching object name [%d]", retval);
        retval = send_generic_response(sockfd,
            SECURITY_SERVER_MSG_TYPE_OBJECT_NAME_RESPONSE,
            SECURITY_SERVER_RETURN_CODE_SERVER_ERROR);
        if (retval != SECURITY_SERVER_SUCCESS)
        {
            SEC_SVR_ERR("ERROR: Cannot send generic response: %d", retval);
        }
        goto error;
    }

    /* We found */
    SECURE_SLOGD("We found object: %s", object_name);
    retval = send_object_name(sockfd, object_name);
    if (retval != SECURITY_SERVER_SUCCESS)
    {
        SEC_SVR_ERR("ERROR: Cannot send generic response: %d", retval);
    }
error:
    return retval;
}

int process_gid_request(int sockfd, int msg_len)
{
    int retval, client_pid;
    char object_name[SECURITY_SERVER_MAX_OBJ_NAME];
    /* Authenticate client as middleware daemon */
    retval = authenticate_client_middleware(sockfd, &client_pid);
    if (retval != SECURITY_SERVER_SUCCESS)
    {
        SEC_SVR_ERR("%s", "Client authentication failed");
        retval = send_generic_response(sockfd,
            SECURITY_SERVER_MSG_TYPE_GID_RESPONSE,
            SECURITY_SERVER_RETURN_CODE_AUTHENTICATION_FAILED);
        if (retval != SECURITY_SERVER_SUCCESS)
        {
            SEC_SVR_ERR("ERROR: Cannot send generic response: %d", retval);
        }
        goto error;
    }
    if (msg_len >= SECURITY_SERVER_MAX_OBJ_NAME)
    {
        /* Too big ojbect name */
        SECURE_SLOGE("%s", "Object name is too big");
        retval = send_generic_response(sockfd,
            SECURITY_SERVER_MSG_TYPE_GID_RESPONSE,
            SECURITY_SERVER_RETURN_CODE_BAD_REQUEST);
        if (retval != SECURITY_SERVER_SUCCESS)
        {
            SEC_SVR_ERR("ERROR: Cannot send generic response: %d", retval);
        }
        goto error;
    }

    /* Receive group name */
    retval = TEMP_FAILURE_RETRY(read(sockfd, object_name, msg_len));
    if (retval < msg_len)
    {
        SECURE_SLOGE("%s", "Failed to read object name");
        retval = send_generic_response(sockfd,
            SECURITY_SERVER_MSG_TYPE_GID_RESPONSE,
            SECURITY_SERVER_RETURN_CODE_BAD_REQUEST);
        if (retval != SECURITY_SERVER_SUCCESS)
        {
            SEC_SVR_ERR("ERROR: Cannot send generic response: %d", retval);
        }
        goto error;
    }
    object_name[msg_len] = 0;

    /* Search /etc/group for the given group name */
    retval = search_gid(object_name);
    if (retval == SECURITY_SERVER_ERROR_NO_SUCH_OBJECT)
    {
        /* Not exist */
        SECURE_SLOGD("The object [%s] is not exist", object_name);
        retval = send_generic_response(sockfd,
            SECURITY_SERVER_MSG_TYPE_GID_RESPONSE,
            SECURITY_SERVER_RETURN_CODE_NO_SUCH_OBJECT);
        if (retval != SECURITY_SERVER_SUCCESS)
        {
            SEC_SVR_ERR("ERROR: Cannot send generic response: %d", retval);
        }
        goto error;
    }

    if (retval < 0)
    {
        /* Error occurred */
        SEC_SVR_ERR("Cannot send the response. %d", retval);
        retval = send_generic_response(sockfd,
            SECURITY_SERVER_MSG_TYPE_GID_RESPONSE,
            SECURITY_SERVER_RETURN_CODE_SERVER_ERROR);
        if (retval != SECURITY_SERVER_SUCCESS)
        {
            SEC_SVR_ERR("ERROR: Cannot send generic response: %d", retval);
        }

        goto error;
    }
    /* We found */
    retval = send_gid(sockfd, retval);
    if (retval != SECURITY_SERVER_SUCCESS)
    {
        SEC_SVR_ERR("ERROR: Cannot gid response: %d", retval);
    }
error:
    return retval;
}

int process_pid_request(int sockfd)
{
    int retval, client_pid;
    unsigned char requested_cookie[SECURITY_SERVER_COOKIE_LEN];
    int *privileges = NULL;
    cookie_list *search_result = NULL;
    pid_t cookie_pid = 0;

    /* Authenticate client */
    retval = authenticate_client_middleware(sockfd, &client_pid);
    if (retval != SECURITY_SERVER_SUCCESS)
    {
        SEC_SVR_ERR("%s", "Client Authentication Failed");
        retval = send_generic_response(sockfd,
            SECURITY_SERVER_MSG_TYPE_PID_RESPONSE,
            SECURITY_SERVER_RETURN_CODE_AUTHENTICATION_FAILED);
        if (retval != SECURITY_SERVER_SUCCESS)
        {
            SEC_SVR_ERR("ERROR: Cannot send generic response: %d", retval);
        }
        goto error;
    }

    retval = recv_pid_request(sockfd, requested_cookie);
    if (retval == SECURITY_SERVER_ERROR_RECV_FAILED)
    {
        SEC_SVR_ERR("%s", "Receiving request failed");
        retval = send_generic_response(sockfd,
            SECURITY_SERVER_MSG_TYPE_PID_RESPONSE,
            SECURITY_SERVER_RETURN_CODE_BAD_REQUEST);
        if (retval != SECURITY_SERVER_SUCCESS)
        {
            SEC_SVR_ERR("ERROR: Cannot send generic response: %d", retval);
        }
        goto error;
    }

    retval = get_client_gid_list(sockfd, &privileges);
    if (retval < 0)
    {
        SEC_SVR_ERR("ERROR: Cannot get GID list");
        goto error;
    }

    /* Search cookie list */
    pthread_mutex_lock(&cookie_mutex);
    search_result = search_cookie(c_list, requested_cookie, privileges, retval);
    if (search_result)
        cookie_pid = search_result->pid;
    pthread_mutex_unlock(&cookie_mutex);

    free(privileges);

    if (search_result != NULL)
    {
        /* We found */
        SEC_SVR_DBG("We found the cookie and pid:%d", cookie_pid);
        SEC_SVR_DBG("%s", "Cookie comparison succeeded. Access granted.");
        retval = send_pid(sockfd, cookie_pid);

        if (retval != SECURITY_SERVER_SUCCESS)
        {
            SEC_SVR_ERR("ERROR: Cannot send generic response: %d", retval);
        }
    }
    else
    {
        /* It's not exist */
        SEC_SVR_ERR("%s", "Could not find the cookie");
        retval = send_generic_response(sockfd,
            SECURITY_SERVER_MSG_TYPE_PID_RESPONSE,
            SECURITY_SERVER_RETURN_CODE_NO_SUCH_COOKIE);
        if (retval != SECURITY_SERVER_SUCCESS)
        {
            SEC_SVR_ERR("ERROR: Cannot send pid response: %d", retval);
        }
    }
error:
    return retval;
}

int process_smack_request(int sockfd)
{
    int retval, client_pid;
    int *privileges = NULL;
    unsigned char requested_cookie[SECURITY_SERVER_COOKIE_LEN];
    cookie_list *search_result = NULL;
    //handler for SMACK label
    char *label = NULL;

    /* Authenticate client */
    retval = authenticate_client_middleware(sockfd, &client_pid);
    if (retval != SECURITY_SERVER_SUCCESS)
    {
        SEC_SVR_ERR("%s", "Client Authentication Failed");
        retval = send_generic_response(sockfd,
            SECURITY_SERVER_MSG_TYPE_SMACK_RESPONSE,
            SECURITY_SERVER_RETURN_CODE_AUTHENTICATION_FAILED);
        if (retval != SECURITY_SERVER_SUCCESS)
        {
            SEC_SVR_ERR("ERROR: Cannot send generic response: %d", retval);
        }
        goto error;
    }

    retval = recv_smack_request(sockfd, requested_cookie);
    if (retval == SECURITY_SERVER_ERROR_RECV_FAILED)
    {
        SEC_SVR_ERR("%s", "Receiving request failed");
        retval = send_generic_response(sockfd,
            SECURITY_SERVER_MSG_TYPE_SMACK_RESPONSE,
            SECURITY_SERVER_RETURN_CODE_BAD_REQUEST);
        if (retval != SECURITY_SERVER_SUCCESS)
        {
            SEC_SVR_ERR("ERROR: Cannot send generic response: %d", retval);
        }
        goto error;
    }

    retval = get_client_gid_list(sockfd, &privileges);
    if (retval < 0)
    {
        SEC_SVR_ERR("ERROR: Cannot get GID list");
        goto error;
    }

    /* Search cookie list */
    pthread_mutex_lock(&cookie_mutex);
    search_result = search_cookie(c_list, requested_cookie, privileges, retval);
    if (search_result) {
        if (search_result->smack_label)
            label = strdup(search_result->smack_label);
        else {
            SEC_SVR_DBG("%s", "No SMACK support on device - returning empty label");
            label = strdup("");
        }
    }
    pthread_mutex_unlock(&cookie_mutex);

    free(privileges);

    if (search_result != NULL)
    {
        /* We found */
        SEC_SVR_DBG("We found the cookie and pid:%d", search_result->pid);
        SEC_SVR_DBG("%s", "Cookie comparison succeeded. Access granted.");
        SECURE_SLOGD("Read label is: %s\n", label);

        retval = send_smack(sockfd, label);

        if (retval != SECURITY_SERVER_SUCCESS)
        {
            SEC_SVR_ERR("ERROR: Cannot send generic response: %d", retval);
        }
    }
    else
    {
        /* It's not exist */
        SEC_SVR_ERR("%s", "Could not find the cookie");
        retval = send_generic_response(sockfd,
            SECURITY_SERVER_MSG_TYPE_SMACK_RESPONSE,
            SECURITY_SERVER_RETURN_CODE_NO_SUCH_COOKIE);
        if (retval != SECURITY_SERVER_SUCCESS)
        {
            SEC_SVR_ERR("ERROR: Cannot send SMACK label response: %d", retval);
        }
    }
    free(label);
error:
    return retval;
}
#ifdef USE_SEC_SRV1_FOR_CHECK_PRIVILEGE_BY_PID
int process_pid_privilege_check(int sockfd, int datasize)
{
    //In this function we parsing received PID privilege check request
    int retval;
    int client_pid;
    int pid;
    char *object = NULL;
    char *access_rights = NULL;
    unsigned char return_code;
    char *path = NULL;
    char subject[SMACK_LABEL_LEN + 1];
    subject[0] = '\0';

    //authenticate client
    retval = authenticate_client_middleware(sockfd, &client_pid);

    if (retval != SECURITY_SERVER_SUCCESS) {
        SEC_SVR_ERR("%s", "Client Authentication Failed");
        retval = send_generic_response(sockfd,
            SECURITY_SERVER_MSG_TYPE_CHECK_PID_PRIVILEGE_RESPONSE,
            SECURITY_SERVER_RETURN_CODE_AUTHENTICATION_FAILED);

        if (retval != SECURITY_SERVER_SUCCESS)
            SEC_SVR_ERR("ERROR: Cannot send generic response: %d", retval);

        goto error;
    }

    //receive request
    retval = recv_pid_privilege_request(sockfd, datasize, &pid, &object, &access_rights);

    if (retval == SECURITY_SERVER_ERROR_RECV_FAILED) {
        SEC_SVR_ERR("%s", "Receiving request failed");
        retval = send_generic_response(sockfd,
            SECURITY_SERVER_MSG_TYPE_CHECK_PID_PRIVILEGE_RESPONSE,
            SECURITY_SERVER_RETURN_CODE_BAD_REQUEST);

        if (retval != SECURITY_SERVER_SUCCESS)
            SEC_SVR_ERR("ERROR: Cannot send generic response: %d", retval);

        goto error;
    }

    if (smack_check()) {
        retval = smack_pid_have_access(pid, object, access_rights);
        SEC_SVR_DBG("smack_pid_have_access returned %d", retval);

        if (get_smack_label_from_process(pid, subject) != PC_OPERATION_SUCCESS) {
            // subject label is set to empty string
            SEC_SVR_ERR("get_smack_label_from_process failed. Subject label has not been read.");
        } else {
            SECURE_SLOGD("Subject label of client PID %d is: %s", pid, subject);
        }
    } else {
        SEC_SVR_DBG("SMACK is not available. Subject label has not been read.");
        retval = 1;
    }

    path = read_exe_path_from_proc(pid);

    if (retval > 0)
        SECURE_SLOGD("SS_SMACK: caller_pid=%d, subject=%s, object=%s, access=%s, result=%d, caller_path=%s", pid, subject, object, access_rights, retval, path);
    else
        SECURE_SLOGW("SS_SMACK: caller_pid=%d, subject=%s, object=%s, access=%s, result=%d, caller_path=%s", pid, subject, object, access_rights, retval, path);

    if (path != NULL)
        free(path);

    if (retval == 1)   //there is permission
        return_code = SECURITY_SERVER_RETURN_CODE_SUCCESS;
    else                //there is no permission
        return_code = SECURITY_SERVER_RETURN_CODE_ACCESS_DENIED;

    //send response
    retval = send_generic_response(sockfd,
        SECURITY_SERVER_MSG_TYPE_CHECK_PID_PRIVILEGE_RESPONSE,
        return_code);

    if (retval != SECURITY_SERVER_SUCCESS)
        SEC_SVR_ERR("ERROR: Cannot send generic response: %d", retval);

error:

    if (object != NULL)
        free(object);
    if (access_rights != NULL)
        free(access_rights);

    return retval;
}
#endif

int process_tool_request(int client_sockfd, int server_sockfd)
{
    int retval, argcnum = 0;
    char **recved_argv = NULL;

    /* Authenticate client */
    retval = authenticate_developer_shell(client_sockfd);
    if (retval != SECURITY_SERVER_SUCCESS)
    {
        SEC_SVR_ERR("%s", "Client Authentication Failed");
        retval = send_generic_response(client_sockfd,
            SECURITY_SERVER_MSG_TYPE_TOOL_RESPONSE,
            SECURITY_SERVER_RETURN_CODE_AUTHENTICATION_FAILED);
        if (retval != SECURITY_SERVER_SUCCESS)
        {
            SEC_SVR_ERR("ERROR: Cannot send generic response: %d", retval);
        }
        goto error;
    }

    /* Receive Total number of argv */
    retval = TEMP_FAILURE_RETRY(read(client_sockfd, &argcnum, sizeof(int)));
    if ((retval < (int)sizeof(int)) || argcnum > (UINT_MAX / sizeof(char*)) - 2 || argcnum < 0)
    {
        SEC_SVR_ERR("Error: argc recieve failed: %d", retval);
        retval = send_generic_response(client_sockfd,
            SECURITY_SERVER_MSG_TYPE_TOOL_RESPONSE,
            SECURITY_SERVER_RETURN_CODE_BAD_REQUEST);
        if (retval != SECURITY_SERVER_SUCCESS)
        {
            SEC_SVR_ERR("ERROR: Cannot send generic response: %d", retval);
        }
        goto error;
    }
    argcnum += 2;
    recved_argv = (char**)malloc(sizeof(char*) * argcnum);
    if (recved_argv == NULL)
    {
        SEC_SVR_ERR("Error: malloc() failed: %d", retval);
        retval = send_generic_response(client_sockfd,
            SECURITY_SERVER_MSG_TYPE_TOOL_RESPONSE,
            SECURITY_SERVER_RETURN_CODE_SERVER_ERROR);
        if (retval != SECURITY_SERVER_SUCCESS)
        {
            SEC_SVR_ERR("ERROR: Cannot send generic response: %d", retval);
        }
        goto error;
    }
    memset(recved_argv, 0, sizeof(char*) * argcnum);

    retval = recv_launch_tool_request(client_sockfd, argcnum - 1, recved_argv);
    if (retval == SECURITY_SERVER_ERROR_RECV_FAILED || retval == SECURITY_SERVER_ERROR_OUT_OF_MEMORY)
    {
        SEC_SVR_ERR("%s", "Receiving request failed");
        retval = send_generic_response(client_sockfd,
            SECURITY_SERVER_MSG_TYPE_TOOL_RESPONSE,
            SECURITY_SERVER_RETURN_CODE_BAD_REQUEST);
        if (retval != SECURITY_SERVER_SUCCESS)
        {
            SEC_SVR_ERR("ERROR: Cannot send generic response: %d", retval);
        }
        goto error;
    }
    if (argcnum < 2)
    {
        SEC_SVR_ERR("Error: Too small number of argv [%d]", argcnum);
        retval = send_generic_response(client_sockfd,
            SECURITY_SERVER_MSG_TYPE_TOOL_RESPONSE,
            SECURITY_SERVER_RETURN_CODE_BAD_REQUEST);
        if (retval != SECURITY_SERVER_SUCCESS)
        {
            SEC_SVR_ERR("ERROR: Cannot send generic response: %d", retval);
        }
        goto error;
    }
    /* Execute the command */
    retval = execute_debug_tool(argcnum, recved_argv, server_sockfd, client_sockfd);
    if (retval != SECURITY_SERVER_SUCCESS)
    {
        SEC_SVR_ERR("Error: Cannot execute debug tool [%d]", retval);
        retval = send_generic_response(client_sockfd,
            SECURITY_SERVER_MSG_TYPE_TOOL_RESPONSE,
            SECURITY_SERVER_RETURN_CODE_SERVER_ERROR);
        if (retval != SECURITY_SERVER_SUCCESS)
        {
            SEC_SVR_ERR("ERROR: Cannot send generic response: %d", retval);
        }
    }
    else
    {
        SEC_SVR_DBG("%s", "Tool has been executed");
        retval = send_generic_response(client_sockfd,
            SECURITY_SERVER_MSG_TYPE_TOOL_RESPONSE,
            SECURITY_SERVER_RETURN_CODE_SUCCESS);
        if (retval != SECURITY_SERVER_SUCCESS)
        {
            SEC_SVR_ERR("ERROR: Cannot send generic response: %d", retval);
        }
    }
error:
    free_argv(recved_argv, argcnum);
    return retval;
}


/* Send exe path response to client
 *
 * Get exe path response packet format
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * |---------------------------------------------------------------|
 * | version=0x01  |MessageID=0x24 |Message Length = 4+path length |
 * |---------------------------------------------------------------|
 * |  return code  |  Path length  |             Path              |
 * |---------------------------------------------------------------|

*/
int send_exe_path_response(int sockfd, const char *path)
{
    response_header hdr;
    unsigned char *msg = NULL;
    unsigned char *ptr = NULL;
    int ret;
    size_t path_len = 0;
    unsigned short msg_len = 0;

    if (!path) {
        SEC_SVR_ERR("Path is NULL");
        return SECURITY_SERVER_ERROR_INPUT_PARAM;
    }

    path_len = strlen(path);
    msg_len = sizeof(hdr) + sizeof(size_t) + path_len;
    msg = (unsigned char*)malloc(msg_len * sizeof(unsigned char));
    if (!msg) {
        SEC_SVR_ERR("malloc failed");
        return SECURITY_SERVER_ERROR_OUT_OF_MEMORY;
    }

    /* Assemble header */
    hdr.basic_hdr.version = SECURITY_SERVER_MSG_VERSION;
    hdr.basic_hdr.msg_id = SECURITY_SERVER_MSG_TYPE_EXE_PATH_RESPONSE;
    hdr.basic_hdr.msg_len = sizeof(size_t) + path_len;
    hdr.return_code = SECURITY_SERVER_RETURN_CODE_SUCCESS;

    /* Prepare packet */
    ptr = msg;
    memcpy(ptr, &hdr, sizeof(hdr));
    ptr += sizeof(hdr);
    memcpy(ptr, &path_len, sizeof(size_t));
    ptr += sizeof(size_t);
    memcpy(ptr, path, path_len);

    /* Check poll */
    ret = check_socket_poll(sockfd, POLLOUT, SECURITY_SERVER_SOCKET_TIMEOUT_MILISECOND);
    if (ret == SECURITY_SERVER_ERROR_POLL)
    {
        SEC_SVR_ERR("%s", "poll() error");
        ret = SECURITY_SERVER_ERROR_SEND_FAILED;
        goto out;
    }
    if (ret == SECURITY_SERVER_ERROR_TIMEOUT)
    {
        SEC_SVR_ERR("%s", "poll() timeout");
        ret = SECURITY_SERVER_ERROR_SEND_FAILED;
        goto out;
    }

    /* Send it */
    ret = TEMP_FAILURE_RETRY(write(sockfd, msg, msg_len));
    if (ret < msg_len)
    {
        SEC_SVR_ERR("Error on write(): %d", ret);
        ret = SECURITY_SERVER_ERROR_SEND_FAILED;
        goto out;
    }
    ret = SECURITY_SERVER_SUCCESS;

out:
    free(msg);
    return ret;
}


int process_exe_path_request(int sockfd)
{
    pid_t pid;
    int retval;
    char *exe = NULL;

    // read pid
    retval = TEMP_FAILURE_RETRY(read(sockfd, &pid, sizeof(pid_t)));
    if (retval < (ssize_t) sizeof(pid_t))
    {
        SEC_SVR_ERR("Server Error: recieve failed: %d", retval);
        retval = send_generic_response(
            sockfd,
            SECURITY_SERVER_MSG_TYPE_EXE_PATH_RESPONSE,
            SECURITY_SERVER_RETURN_CODE_BAD_REQUEST);

        if (retval != SECURITY_SERVER_SUCCESS)
            SEC_SVR_ERR("Server ERROR: Cannot send generic response: %d", retval);
        goto error;
    }

    SEC_SVR_DBG("Server: Get exe path request for pid %d", pid);

    // get executable path
    exe = read_exe_path_from_proc(pid);
    if (!exe)
    {
        SEC_SVR_ERR("Server: Failed to read executable path for pid %d", pid);
        retval = send_generic_response(
            sockfd,
            SECURITY_SERVER_MSG_TYPE_EXE_PATH_RESPONSE,
            SECURITY_SERVER_RETURN_CODE_SERVER_ERROR);

        if (retval != SECURITY_SERVER_SUCCESS)
            SEC_SVR_ERR("Server ERROR: Cannot send generic response: %d", retval);
        goto error;
    }

    // send response
    retval = send_exe_path_response(sockfd, exe);
    if (retval != SECURITY_SERVER_SUCCESS)
        SEC_SVR_ERR("ERROR: Cannot send exe path response: %d", retval);

error:
    free(exe);
    return retval;
}

int client_has_access(int sockfd, const char *object)
{
    char *label = NULL;
    int ret = 0;
    int pid = -1;
    int uid = -1;
    int retval;
    struct ucred socopt;
    unsigned int socoptSize = sizeof(socopt);

    if (smack_check())
    {
        retval = getsockopt(sockfd, SOL_SOCKET, SO_PEERCRED, &socopt, &socoptSize);
        if (retval != 0) {
            SEC_SVR_DBG("%s", "Error on getsockopt");
            return 0;
        }
        //now we have PID in sockopt.pid

        if (smack_new_label_from_socket(sockfd, &label)) {
            SEC_SVR_ERR("%s", "Error on smack_new_label_from_socket");
            label = NULL;
        }

        if (0 >= (ret = smack_pid_have_access(socopt.pid, object, "rw"))) {
            ret = 0;
        }
    }

    if (SECURITY_SERVER_SUCCESS == authenticate_client_application(sockfd, &pid, &uid))
        SECURE_SLOGD("SS_SMACK: caller_pid=%d, subject=%s, object=%s, access=rw, result=%d",
            pid, label, object, ret);

    free(label);
    return ret;
}

void *security_server_thread(void *param)
{
    int client_sockfd = -1, client_uid, client_pid;
    int server_sockfd, retval;
    basic_header basic_hdr;
    struct security_server_thread_param *my_param;

    my_param = (struct security_server_thread_param*) param;
    client_sockfd = my_param->client_sockfd;
    server_sockfd = my_param->server_sockfd;

    /* Receive request header */
    retval = recv_hdr(client_sockfd, &basic_hdr);
    if (retval == SECURITY_SERVER_ERROR_TIMEOUT || retval == SECURITY_SERVER_ERROR_RECV_FAILED
        || retval == SECURITY_SERVER_ERROR_SOCKET)
    {
        SEC_SVR_ERR("Receiving header error [%d]",retval);
        close(client_sockfd);
        client_sockfd = -1;
        goto error;;
    }

    if (retval != SECURITY_SERVER_SUCCESS)
    {
        /* Response */
        SEC_SVR_ERR("Receiving header error [%d]",retval);
        retval = send_generic_response(client_sockfd,
            SECURITY_SERVER_MSG_TYPE_GENERIC_RESPONSE,
            SECURITY_SERVER_RETURN_CODE_BAD_REQUEST);
        if (retval != SECURITY_SERVER_SUCCESS)
        {
            SEC_SVR_ERR("ERROR: Cannot send generic response: %d", retval);
            goto error;
        }
        safe_server_sock_close(client_sockfd);
        client_sockfd = -1;
        goto error;
    }

    //TODO: Below authorize_SS_API_caller_socket() is used for authorize API caller by SMACK,
    //      at the moment return value is not checked and each access is allowed.
    //      If we realy want to restrict access it must be changed in future.

    /* Act different for request message ID */
    switch (basic_hdr.msg_id)
    {
        case SECURITY_SERVER_MSG_TYPE_COOKIE_REQUEST:
            SEC_SVR_DBG("%s", "Cookie request received");
            authorize_SS_API_caller_socket(client_sockfd, API_FREE_ACCESS, API_RULE_REQUIRED);
            process_cookie_request(client_sockfd);
            break;

        case SECURITY_SERVER_MSG_TYPE_CHECK_PRIVILEGE_REQUEST:
            SEC_SVR_DBG("%s", "Privilege check received");
            authorize_SS_API_caller_socket(client_sockfd, API_MIDDLEWARE, API_RULE_REQUIRED);
            process_check_privilege_request(client_sockfd);
            break;

        case SECURITY_SERVER_MSG_TYPE_CHECK_PRIVILEGE_NEW_REQUEST:
            SEC_SVR_DBG("%s", "Privilege check (new mode) received");
            authorize_SS_API_caller_socket(client_sockfd, API_MIDDLEWARE, API_RULE_REQUIRED);
            process_check_privilege_new_request(client_sockfd);
            break;

        case SECURITY_SERVER_MSG_TYPE_OBJECT_NAME_REQUEST:
            SECURE_SLOGD("%s", "Get object name request received");
            authorize_SS_API_caller_socket(client_sockfd, API_MIDDLEWARE, API_RULE_REQUIRED);
            process_object_name_request(client_sockfd);
            break;

        case SECURITY_SERVER_MSG_TYPE_GID_REQUEST:
            SEC_SVR_DBG("%s", "Get GID received");
            authorize_SS_API_caller_socket(client_sockfd, API_MIDDLEWARE, API_RULE_REQUIRED);
            process_gid_request(client_sockfd, (int)basic_hdr.msg_len);
            break;

        case SECURITY_SERVER_MSG_TYPE_PID_REQUEST:
            SEC_SVR_DBG("%s", "pid request received");
            authorize_SS_API_caller_socket(client_sockfd, API_MIDDLEWARE, API_RULE_REQUIRED);
            process_pid_request(client_sockfd);
            break;

        case SECURITY_SERVER_MSG_TYPE_SMACK_REQUEST:
            SEC_SVR_DBG("%s", "SMACK label request received");
            authorize_SS_API_caller_socket(client_sockfd, API_MIDDLEWARE, API_RULE_REQUIRED);
            process_smack_request(client_sockfd);
            break;

#ifdef USE_SEC_SRV1_FOR_CHECK_PRIVILEGE_BY_PID
        case SECURITY_SERVER_MSG_TYPE_CHECK_PID_PRIVILEGE_REQUEST:
            SEC_SVR_DBG("%s", "PID privilege check request received");
            authorize_SS_API_caller_socket(client_sockfd, API_MIDDLEWARE, API_RULE_REQUIRED);
            //pass data size to function
            process_pid_privilege_check(client_sockfd, basic_hdr.msg_len);
            break;
#endif

        case SECURITY_SERVER_MSG_TYPE_TOOL_REQUEST:
            SEC_SVR_DBG("%s", "launch tool request received");
            authorize_SS_API_caller_socket(client_sockfd, API_MIDDLEWARE, API_RULE_REQUIRED);
            process_tool_request(client_sockfd, server_sockfd);
            break;

        case SECURITY_SERVER_MSG_TYPE_VALID_PWD_REQUEST:
            SECURE_SLOGD("%s", "Server: validate password request received");
            authorize_SS_API_caller_socket(client_sockfd, API_PASSWD_CHECK, API_RULE_REQUIRED);
            process_valid_pwd_request(client_sockfd);
            break;

        case SECURITY_SERVER_MSG_TYPE_SET_PWD_REQUEST:
            SECURE_SLOGD("%s", "Server: set password request received");
            authorize_SS_API_caller_socket(client_sockfd, API_PASSWD_SET, API_RULE_REQUIRED);
            process_set_pwd_request(client_sockfd);
            break;

        case SECURITY_SERVER_MSG_TYPE_RESET_PWD_REQUEST:
            SECURE_SLOGD("%s", "Server: reset password request received");
            authorize_SS_API_caller_socket(client_sockfd, API_PASSWD_SET, API_RULE_REQUIRED);
            process_reset_pwd_request(client_sockfd);
            break;

        case SECURITY_SERVER_MSG_TYPE_CHK_PWD_REQUEST:
            SECURE_SLOGD("%s", "Server: check password request received");
            authorize_SS_API_caller_socket(client_sockfd, API_PASSWD_CHECK, API_RULE_REQUIRED);
            process_chk_pwd_request(client_sockfd);
            break;

        case SECURITY_SERVER_MSG_TYPE_SET_PWD_HISTORY_REQUEST:
            SECURE_SLOGD("%s", "Server: set password histroy request received");
            authorize_SS_API_caller_socket(client_sockfd, API_PASSWD_SET, API_RULE_REQUIRED);
            process_set_pwd_history_request(client_sockfd);
            break;

        case SECURITY_SERVER_MSG_TYPE_SET_PWD_MAX_CHALLENGE_REQUEST:
            SECURE_SLOGD("%s", "Server: set password max challenge request received");
            authorize_SS_API_caller_socket(client_sockfd, API_PASSWD_SET, API_RULE_REQUIRED);
            process_set_pwd_max_challenge_request(client_sockfd);
            break;

        case SECURITY_SERVER_MSG_TYPE_SET_PWD_VALIDITY_REQUEST:
            SECURE_SLOGD("%s", "Server: set password validity request received");
            authorize_SS_API_caller_socket(client_sockfd, API_PASSWD_SET, API_RULE_REQUIRED);
            process_set_pwd_validity_request(client_sockfd);
            break;

        case SECURITY_SERVER_MSG_TYPE_EXE_PATH_REQUEST:
            SEC_SVR_DBG("Server: get executable path by pid request received");
            process_exe_path_request(client_sockfd);
            break;

        /************************************************************************************************/
        /* Just for test. This code must be removed on release */
        case SECURITY_SERVER_MSG_TYPE_GET_ALL_COOKIES_REQUEST:
            SEC_SVR_DBG("%s", "all cookie info request received -- NEED TO BE DELETED ON RELEASE");
            retval = authenticate_client_application(client_sockfd, &client_pid, &client_uid);
            if (retval != SECURITY_SERVER_SUCCESS)
            {
                SEC_SVR_ERR("%s", "Client Authentication Failed");
                retval = send_generic_response(client_sockfd,
                    SECURITY_SERVER_MSG_TYPE_GENERIC_RESPONSE,
                    SECURITY_SERVER_RETURN_CODE_AUTHENTICATION_FAILED);
                if (retval != SECURITY_SERVER_SUCCESS)
                {
                    SEC_SVR_ERR("ERROR: Cannot send generic response: %d", retval);
                }
                break;
            }
            retval = util_process_all_cookie(client_sockfd, c_list);
            if (retval != SECURITY_SERVER_SUCCESS)
            {
                SEC_SVR_ERR("ERROR: Cannot send all cookie info: %d", retval);
            }
            break;

        case SECURITY_SERVER_MSG_TYPE_GET_COOKIEINFO_FROM_PID_REQUEST:
            SEC_SVR_DBG("%s", "cookie info from pid request received -- NEED TO BE DELETED ON RELEASE");
            if (retval != SECURITY_SERVER_SUCCESS)
            {
                SEC_SVR_ERR("%s", "Client Authentication Failed");
                retval = send_generic_response(client_sockfd,
                    SECURITY_SERVER_MSG_TYPE_GENERIC_RESPONSE,
                    SECURITY_SERVER_RETURN_CODE_AUTHENTICATION_FAILED);
                if (retval != SECURITY_SERVER_SUCCESS)
                {
                    SEC_SVR_ERR("ERROR: Cannot send generic response: %d", retval);
                }
                break;
            }
            util_process_cookie_from_pid(client_sockfd, c_list);
            break;

        case SECURITY_SERVER_MSG_TYPE_GET_COOKIEINFO_FROM_COOKIE_REQUEST:
            SEC_SVR_DBG("%s", "cookie info from cookie request received -- NEED TO BE DELETED ON RELEASE");
            if (retval != SECURITY_SERVER_SUCCESS)
            {
                SEC_SVR_ERR("%s", "Client Authentication Failed");
                retval = send_generic_response(client_sockfd,
                    SECURITY_SERVER_MSG_TYPE_GENERIC_RESPONSE,
                    SECURITY_SERVER_RETURN_CODE_AUTHENTICATION_FAILED);
                if (retval != SECURITY_SERVER_SUCCESS)
                {
                    SEC_SVR_ERR("ERROR: Cannot send generic response: %d", retval);
                }
                break;
            }
            util_process_cookie_from_cookie(client_sockfd, c_list);
            break;
        /************************************************************************************************/


        default:
            SEC_SVR_ERR("Unknown msg ID :%d", basic_hdr.msg_id);
            /* Unknown message ID */
            retval = send_generic_response(client_sockfd,
            SECURITY_SERVER_MSG_TYPE_GENERIC_RESPONSE,
            SECURITY_SERVER_RETURN_CODE_BAD_REQUEST);
            if (retval != SECURITY_SERVER_SUCCESS)
            {
                SEC_SVR_ERR("ERROR: Cannot send generic response: %d", retval);
            }
            break;
    }

    if (client_sockfd > 0)
    {
        safe_server_sock_close(client_sockfd);
        client_sockfd = -1;
    }

error:
    if (client_sockfd > 0)
        close(client_sockfd);
    thread_status[my_param->thread_status] = 0;
    pthread_detach(pthread_self());
    pthread_exit(NULL);
}

void *security_server_main_thread(void *data)
{
    int server_sockfd = 0, retval, client_sockfd = -1, rc;
    struct sigaction act, dummy;
    pthread_t threads[SECURITY_SERVER_NUM_THREADS];
    struct security_server_thread_param param[SECURITY_SERVER_NUM_THREADS];

    (void)data;

    SECURE_SLOGD("%s", "Starting Security Server main thread");

    /* security server must be executed by root */
    if (getuid() != 0)
    {
        fprintf(stderr, "%s\n", "You are not root. exiting...");
        goto error;
    }

    for (retval = 0; retval < SECURITY_SERVER_NUM_THREADS; retval++)
        thread_status[retval] = 0;
    initiate_try();

    /* Create and bind a Unix domain socket */
    if(SECURITY_SERVER_SUCCESS != get_socket_from_systemd(&server_sockfd))
    {
        SEC_SVR_ERR("%s", "Error in get_socket_from_systemd");
        retval = create_new_socket(&server_sockfd);
        if (retval != SECURITY_SERVER_SUCCESS)
        {
            SEC_SVR_ERR("%s", "cannot create socket. exiting...");
            goto error;
        }

        if (listen(server_sockfd, 5) < 0)
        {
            SEC_SVR_ERR("%s", "listen() failed. exiting...");
            goto error;
        }
    } else {
        SEC_SVR_ERR("%s", "Socket was passed by systemd");
    }

    /* Create a default cookie --> Cookie for root process */
    c_list = create_default_cookie();
    if (c_list == NULL)
    {
        SEC_SVR_ERR("%s", "cannot make a default cookie. exiting...");
        goto error;
    }

    /* Init signal handler */
    act.sa_handler = NULL;
    act.sa_sigaction = security_server_sig_child;
    sigemptyset(&act.sa_mask);
    act.sa_flags = SA_NOCLDSTOP | SA_SIGINFO;

    if (sigaction(SIGCHLD, &act, &dummy) < 0)
    {
        SEC_SVR_ERR("%s", "cannot change session");
    }

    pthread_mutex_init(&cookie_mutex, NULL);

    while (1)
    {
        /* Accept a new client */
        if (client_sockfd < 0)
            client_sockfd = accept_client(server_sockfd);

        if (client_sockfd == SECURITY_SERVER_ERROR_TIMEOUT)
            continue;
        if (client_sockfd < 0)
            goto error;
        SEC_SVR_DBG("Server: new connection has been accepted: %d", client_sockfd);
        retval = 0;
        while (1)
        {
            if (thread_status[retval] == 0)
            {
                thread_status[retval] = 1;
                param[retval].client_sockfd = client_sockfd;
                param[retval].server_sockfd = server_sockfd;
                param[retval].thread_status = retval;
                SEC_SVR_DBG("Server: Creating a new thread: %d", retval);
                rc = pthread_create(&threads[retval], NULL, security_server_thread, (void*)&param[retval]);
                if (rc)
                {
                    SEC_SVR_ERR("Error: Server: Cannot create thread:%d", rc);
                    goto error;
                }
                break;
            }
            retval++;
            if (retval >= SECURITY_SERVER_NUM_THREADS)
                retval = 0;
        }
        client_sockfd = -1;
    }
error:
    if (server_sockfd > 0)
        close(server_sockfd);

    pthread_detach(pthread_self());
    pthread_exit(NULL);
}

ssize_t read_wrapper(int sockfd, void *buffer, size_t len)
{
    unsigned char *buff = (unsigned char*)buffer;
    ssize_t done = 0;
    while (done < (int)len) {
        struct pollfd fds = { sockfd, POLLIN, 0};
        if (0 >= poll(&fds, 1, 1000))
            break;
        ssize_t ret = read(sockfd, buff + done, len - done);
        if (0 < ret) {
            done += ret;
            continue;
        }
        if (0 == ret)
            break;
        if (-1 == ret && EAGAIN != errno && EINTR != errno)
            break;
    }
    return done;
}

int main(int argc, char *argv[])
{
    int res;
    pthread_t main_thread;

    (void)argc;
    (void)argv;

    if (0 != (res = pthread_create(&main_thread, NULL, security_server_main_thread, NULL))) {
        SEC_SVR_ERR("Error: Server: Cannot create main security server thread: %s", strerror(res));
        return -1;
    }

    server2();

    pthread_exit(NULL);
    return 0;
}

