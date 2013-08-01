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

#include "security-server-common.h"
#include "security-server-password.h"
#include "security-server-comm.h"
#include "security-server-util.h"
#include "smack-check.h"

//definitions of security-server API labels
#define API_PASSWD_SET   "security-server::api-password-set"
#define API_PASSWD_CHECK "security-server::api-password-check"
#define API_DATA_SHARE   "security-server::api-data-share"
#define API_MIDDLEWARE   "security-server::api-middleware"
#define API_FREE_ACCESS  "*"

//required rule type
#define API_RULE_REQUIRED "w"

int thread_status[SECURITY_SERVER_NUM_THREADS];
struct security_server_thread_param {
    int client_sockfd;
    int server_sockfd;
    int thread_status;
};


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

// int process_object_name_request(int sockfd)
// {
//     int retval, client_pid, requested_privilege;
//     char object_name[SECURITY_SERVER_MAX_OBJ_NAME];

//     /* Authenticate client */
//     retval = authenticate_client_middleware(sockfd, &client_pid);
//     if (retval != SECURITY_SERVER_SUCCESS)
//     {
//         SEC_SVR_ERR("%s", "Client Authentication Failed");
//         retval = send_generic_response(sockfd,
//             SECURITY_SERVER_MSG_TYPE_OBJECT_NAME_RESPONSE,
//             SECURITY_SERVER_RETURN_CODE_AUTHENTICATION_FAILED);
//         if (retval != SECURITY_SERVER_SUCCESS)
//         {
//             SEC_SVR_ERR("ERROR: Cannot send generic response: %d", retval);
//         }
//         goto error;
//     }

//     /* Receive GID */
//     retval = TEMP_FAILURE_RETRY(read(sockfd, &requested_privilege, sizeof(requested_privilege)));
//     if (retval < (int)sizeof(requested_privilege))
//     {
//         SEC_SVR_ERR("%s", "Receiving request failed");
//         retval = send_generic_response(sockfd,
//             SECURITY_SERVER_MSG_TYPE_OBJECT_NAME_RESPONSE,
//             SECURITY_SERVER_RETURN_CODE_BAD_REQUEST);
//         if (retval != SECURITY_SERVER_SUCCESS)
//         {
//             SEC_SVR_ERR("ERROR: Cannot send generic response: %d", retval);
//         }
//         goto error;
//     }

//     /* Search from /etc/group */
//     retval = search_object_name(requested_privilege,
//         object_name,
//         SECURITY_SERVER_MAX_OBJ_NAME);
//     if (retval == SECURITY_SERVER_ERROR_NO_SUCH_OBJECT)
//     {
//         /* It's not exist */
//         SEC_SVR_ERR("There is no such object for gid [%d]", requested_privilege);
//         retval = send_generic_response(sockfd,
//             SECURITY_SERVER_MSG_TYPE_OBJECT_NAME_RESPONSE,
//             SECURITY_SERVER_RETURN_CODE_NO_SUCH_OBJECT);
//         if (retval != SECURITY_SERVER_SUCCESS)
//         {
//             SEC_SVR_ERR("ERROR: Cannot send generic response: %d", retval);
//         }
//         goto error;
//     }
//     if (retval != SECURITY_SERVER_SUCCESS)
//     {
//         /* Error occurred */
//         SEC_SVR_ERR("Error on searching object name [%d]", retval);
//         retval = send_generic_response(sockfd,
//             SECURITY_SERVER_MSG_TYPE_OBJECT_NAME_RESPONSE,
//             SECURITY_SERVER_RETURN_CODE_SERVER_ERROR);
//         if (retval != SECURITY_SERVER_SUCCESS)
//         {
//             SEC_SVR_ERR("ERROR: Cannot send generic response: %d", retval);
//         }
//         goto error;
//     }

//     /* We found */
//     SECURE_SLOGD("We found object: %s", object_name);
//     retval = send_object_name(sockfd, object_name);
//     if (retval != SECURITY_SERVER_SUCCESS)
//     {
//         SEC_SVR_ERR("ERROR: Cannot send generic response: %d", retval);
//     }
// error:
//     return retval;
// }

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

        if (smack_new_label_from_socket(sockfd, &label) < 0) {
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
    int client_sockfd = -1;
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
        // case SECURITY_SERVER_MSG_TYPE_OBJECT_NAME_REQUEST:
        //     SECURE_SLOGD("%s", "Get object name request received");
        //     authorize_SS_API_caller_socket(client_sockfd, API_MIDDLEWARE, API_RULE_REQUIRED);
        //     process_object_name_request(client_sockfd);
        //     break;

        case SECURITY_SERVER_MSG_TYPE_GID_REQUEST:
            SEC_SVR_DBG("%s", "Get GID received");
            authorize_SS_API_caller_socket(client_sockfd, API_MIDDLEWARE, API_RULE_REQUIRED);
            process_gid_request(client_sockfd, (int)basic_hdr.msg_len);
            break;

#ifdef USE_SEC_SRV1_FOR_CHECK_PRIVILEGE_BY_PID
        case SECURITY_SERVER_MSG_TYPE_CHECK_PID_PRIVILEGE_REQUEST:
            SEC_SVR_DBG("%s", "PID privilege check request received");
            authorize_SS_API_caller_socket(client_sockfd, API_MIDDLEWARE, API_RULE_REQUIRED);
            //pass data size to function
            process_pid_privilege_check(client_sockfd, basic_hdr.msg_len);
            break;
#endif

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

    /* Init signal handler */
    act.sa_handler = NULL;
    act.sa_sigaction = security_server_sig_child;
    sigemptyset(&act.sa_mask);
    act.sa_flags = SA_NOCLDSTOP | SA_SIGINFO;

    if (sigaction(SIGCHLD, &act, &dummy) < 0)
    {
        SEC_SVR_ERR("%s", "cannot change session");
    }

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

    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGTERM);
    sigaddset(&mask, SIGPIPE);
    if (-1 == pthread_sigmask(SIG_BLOCK, &mask, NULL)) {
        SEC_SVR_ERR("Error in pthread_sigmask");
    }

    if (0 != (res = pthread_create(&main_thread, NULL, security_server_main_thread, NULL))) {
        SEC_SVR_ERR("Error: Server: Cannot create main security server thread: %s", strerror(res));
        return -1;
    }

    server2();
    exit(0);
    return 0;
}

