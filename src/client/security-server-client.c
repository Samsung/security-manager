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
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <sys/smack.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/poll.h>

#include "smack-check.h"
#include "security-server.h"
#include "security-server-common.h"
#include "security-server-comm.h"

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


char *read_cmdline_from_proc(pid_t pid)
{
    int memsize = 32;
    char path[32];
    char *cmdline = NULL;

    snprintf(path, sizeof(path), "/proc/%d/exe", pid);

    cmdline = malloc(32);
    if (cmdline == NULL)
    {
        SEC_SVR_DBG("%s", "Out of memory");
        goto error;
    }

    while (1)
    {
        bzero(cmdline, memsize);
        /* readlink() may have security hole in normal symbolic link. *
         * But this link is located at proc fs that only kernel can change */
        readlink(path, cmdline, memsize);   /* FlawFinder: ignore */
        SEC_SVR_DBG("pid: %d, cmdline: %s", pid, cmdline);

        /* Check it's truncated */
        if (cmdline[memsize - 1] != 0)
        {
            cmdline = (char*)realloc(cmdline, sizeof(char) * (memsize + 32));
            memsize += 32;
            if (cmdline == NULL)
            {
                SEC_SVR_DBG("%s", "Out of memory");
                goto error;
            }
        }
        else
            break;
    }

error:
    return cmdline;
}
#endif


/* We may need to filter error code */
int convert_to_public_error_code(int err_code)
{
    /* Do we need this? */
    return err_code;
}

// SECURITY_SERVER_API
// int security_server_get_gid(const char *object)
// {
//     int sockfd = -1, retval, gid;
//     response_header hdr;

//     if (object == NULL)
//     {
//         SEC_SVR_ERR("%s", "Client: object is null or object is too big");
//         retval = SECURITY_SERVER_API_ERROR_INPUT_PARAM;
//         goto error;
//     }
//     if (strlen(object) > SECURITY_SERVER_MAX_OBJ_NAME)
//     {
//         SEC_SVR_ERR("%s", "object is null or object is too big");
//         retval = SECURITY_SERVER_API_ERROR_INPUT_PARAM;
//         goto error;
//     }

//     if (strlen(object) == 0)
//     {
//         SEC_SVR_ERR("Client: object is is empty");
//         retval = SECURITY_SERVER_API_ERROR_INPUT_PARAM;
//         goto error;
//     }

//     SECURE_SLOGD("%s", "Client: security_server_get_gid() is called");
//     retval = connect_to_server(&sockfd);
//     if (retval != SECURITY_SERVER_SUCCESS)
//     {
//         /* Error on socket */
//         SEC_SVR_ERR("Connection failed: %d", retval);
//         goto error;
//     }
//     SECURE_SLOGD("%s", "Client: Security server has been connected");

//     /* make request packet and send to server*/
//     retval = send_gid_request(sockfd, object);
//     SEC_SVR_DBG("%s", "Client: gid request has been sent");
//     if (retval != SECURITY_SERVER_SUCCESS)
//     {
//         /* Error on socket */
//         SEC_SVR_ERR("Send gid request failed: %d", retval);
//         goto error;
//     }

//     /* Receive response */
//     retval = recv_get_gid_response(sockfd, &hdr, &gid);
//     if (retval != SECURITY_SERVER_SUCCESS)
//     {
//         SEC_SVR_ERR("Client: Receive response failed: %d", retval);
//         goto error;
//     }
//     SEC_SVR_DBG("%s", "Client: get gid response has been received");

//     if (hdr.basic_hdr.msg_id != SECURITY_SERVER_MSG_TYPE_GID_RESPONSE)   /* Wrong response */
//     {
//         if (hdr.basic_hdr.msg_id == SECURITY_SERVER_MSG_TYPE_GENERIC_RESPONSE)
//         {
//             /* There must be some error */
//             SEC_SVR_ERR("Client: It'll be an error. return code:%d", hdr.return_code);
//             retval = return_code_to_error_code(hdr.return_code);
//             goto error;
//         }
//         else
//         {
//             /* Something wrong with response */
//             SEC_SVR_ERR("Client: Something wrong with response:%d", hdr.basic_hdr.msg_id);
//             retval = SECURITY_SERVER_ERROR_BAD_RESPONSE;
//             goto error;
//         }
//     }

//     SEC_SVR_DBG("received gid is %d", gid);
//     retval = gid;

// error:
//     if (sockfd > 0)
//         close(sockfd);
//     /* If error happened */
//     if (retval < 0)
//         retval = convert_to_public_error_code(retval);

//     return retval;
// }



// SECURITY_SERVER_API
// int security_server_get_object_name(gid_t gid, char *object, size_t max_object_size)
// {
//     int sockfd = -1, retval;
//     response_header hdr;

//     if (object == NULL)
//     {
//         retval = SECURITY_SERVER_ERROR_INPUT_PARAM;
//         goto error;
//     }

//     retval = connect_to_server(&sockfd);
//     if (retval != SECURITY_SERVER_SUCCESS)
//     {
//         /* Error on socket */
//         SEC_SVR_ERR("Client: connect to server failed: %d", retval);
//         goto error;
//     }

//     /* make request packet */
//     retval = send_object_name_request(sockfd, gid);
//     if (retval != SECURITY_SERVER_SUCCESS)
//     {
//         /* Error on socket */
//         SEC_SVR_ERR("Client: cannot send request: %d", retval);
//         goto error;
//     }

//     retval = recv_get_object_name(sockfd, &hdr, object, max_object_size);
//     if (retval != SECURITY_SERVER_SUCCESS)
//     {
//         SEC_SVR_ERR("Client: Receive response failed: %d", retval);
//         goto error;
//     }

//     if (hdr.basic_hdr.msg_id != SECURITY_SERVER_MSG_TYPE_OBJECT_NAME_RESPONSE)   /* Wrong response */
//     {
//         if (hdr.basic_hdr.msg_id == SECURITY_SERVER_MSG_TYPE_GENERIC_RESPONSE)
//         {
//             /* There must be some error */
//             SEC_SVR_ERR("Client: There is error on response: return code:%d", hdr.basic_hdr.msg_id);
//             retval = return_code_to_error_code(hdr.return_code);
//         }
//         else
//         {
//             /* Something wrong with response */
//             SEC_SVR_ERR("Client: Some unexpected error happene: return code:%d", hdr.basic_hdr.msg_id);
//             retval = SECURITY_SERVER_ERROR_BAD_RESPONSE;
//         }
//         goto error;
//     }

// error:
//     if (sockfd > 0)
//         close(sockfd);

//     retval = convert_to_public_error_code(retval);
//     return retval;
// }


SECURITY_SERVER_API
int security_server_is_pwd_valid(unsigned int *current_attempts,
                                 unsigned int *max_attempts,
                                 unsigned int *valid_secs)
{
    int sockfd = -1, retval = SECURITY_SERVER_ERROR_UNKNOWN;
    response_header hdr;

    if (current_attempts == NULL || max_attempts == NULL || valid_secs == NULL)
    {
        retval = SECURITY_SERVER_ERROR_INPUT_PARAM;
        goto error;
    }

    /* Authenticate self that is setting app  goes here */
    /* 1st, check cmdline which is setting app */
    /* 2nd, check /proc/self/attr/current for the SMACK label */

    retval = connect_to_server(&sockfd);
    if (retval != SECURITY_SERVER_SUCCESS)
    {
        /* Error on socket */
        goto error;
    }

    /* make request packet */
    retval = send_valid_pwd_request(sockfd);
    if (retval != SECURITY_SERVER_SUCCESS)
    {
        /* Error on socket */
        SEC_SVR_ERR("Client: Send failed: %d", retval);
        goto error;
    }

    retval = recv_pwd_response(sockfd, &hdr, current_attempts, max_attempts, valid_secs);

    retval = return_code_to_error_code(hdr.return_code);
    if (hdr.basic_hdr.msg_id != SECURITY_SERVER_MSG_TYPE_VALID_PWD_RESPONSE) /* Wrong response */
    {
        if (hdr.basic_hdr.msg_id == SECURITY_SERVER_MSG_TYPE_VALID_PWD_RESPONSE)
        {
            /* There must be some error */
            SEC_SVR_ERR("Client: Error has been received. return code:%d", hdr.return_code);
        }
        else
        {
            /* Something wrong with response */
            SEC_SVR_ERR("Client ERROR: Unexpected error occurred:%d", retval);
            retval = SECURITY_SERVER_ERROR_BAD_RESPONSE;
        }
        goto error;
    }
error:
    if (sockfd > 0)
        close(sockfd);

    retval = convert_to_public_error_code(retval);
    return retval;
}



SECURITY_SERVER_API
int security_server_set_pwd(const char *cur_pwd,
                            const char *new_pwd,
                            const unsigned int max_challenge,
                            const unsigned int valid_period_in_days)
{
    int sockfd = -1, retval;
    response_header hdr;

    if (new_pwd == NULL || strlen(new_pwd) > SECURITY_SERVER_MAX_PASSWORD_LEN || strlen(new_pwd) == 0)
    {
        retval = SECURITY_SERVER_ERROR_INPUT_PARAM;
        goto error;
    }

    /* Authenticate self that is setting app  goes here */
    /* 1st, check cmdline which is setting app */
    /* 2nd, check /proc/self/attr/current for the SMACK label */

    retval = connect_to_server(&sockfd);
    if (retval != SECURITY_SERVER_SUCCESS)
    {
        /* Error on socket */
        goto error;
    }

    /* make request packet */
    retval = send_set_pwd_request(sockfd, cur_pwd, new_pwd, max_challenge, valid_period_in_days);
    if (retval != SECURITY_SERVER_SUCCESS)
    {
        /* Error on socket */
        SEC_SVR_ERR("Client: Send failed: %d", retval);
        goto error;
    }

    retval = recv_generic_response(sockfd, &hdr);

    retval = return_code_to_error_code(hdr.return_code);
    if (hdr.basic_hdr.msg_id != SECURITY_SERVER_MSG_TYPE_SET_PWD_RESPONSE)   /* Wrong response */
    {
        if (hdr.basic_hdr.msg_id == SECURITY_SERVER_MSG_TYPE_GENERIC_RESPONSE)
        {
            /* There must be some error */
            SEC_SVR_ERR("Client: Error has been received. return code:%d", hdr.return_code);
        }
        else
        {
            /* Something wrong with response */
            SEC_SVR_ERR("Client ERROR: Unexpected error occurred:%d", retval);
            retval = SECURITY_SERVER_ERROR_BAD_RESPONSE;
        }
        goto error;
    }
error:
    if (sockfd > 0)
        close(sockfd);

    retval = convert_to_public_error_code(retval);
    return retval;
}


SECURITY_SERVER_API
int security_server_set_pwd_validity(const unsigned int valid_period_in_days)
{
    int sockfd = -1, retval;
    response_header hdr;

    retval = connect_to_server(&sockfd);
    if (retval != SECURITY_SERVER_SUCCESS)
    {
        /* Error on socket */
        goto error;
    }

    /* make request packet */
    retval = send_set_pwd_validity_request(sockfd, valid_period_in_days);
    if (retval != SECURITY_SERVER_SUCCESS)
    {
        /* Error on socket */
        SEC_SVR_ERR("Client: Send failed: %d", retval);
        goto error;
    }

    retval = recv_generic_response(sockfd, &hdr);

    retval = return_code_to_error_code(hdr.return_code);
    if (hdr.basic_hdr.msg_id != SECURITY_SERVER_MSG_TYPE_SET_PWD_VALIDITY_RESPONSE)   /* Wrong response */
    {
        if (hdr.basic_hdr.msg_id == SECURITY_SERVER_MSG_TYPE_GENERIC_RESPONSE)
        {
            /* There must be some error */
            SEC_SVR_ERR("Client: Error has been received. return code:%d", hdr.return_code);
        }
        else
        {
            /* Something wrong with response */
            SEC_SVR_ERR("Client ERROR: Unexpected error occurred:%d", retval);
            retval = SECURITY_SERVER_ERROR_BAD_RESPONSE;
        }
        goto error;
    }
error:
    if (sockfd > 0)
        close(sockfd);

    retval = convert_to_public_error_code(retval);
    return retval;
}

SECURITY_SERVER_API
int security_server_set_pwd_max_challenge(const unsigned int max_challenge)
{
    int sockfd = -1, retval;
    response_header hdr;

    retval = connect_to_server(&sockfd);
    if (retval != SECURITY_SERVER_SUCCESS)
    {
        /* Error on socket */
        goto error;
    }

    /* make request packet */
    retval = send_set_pwd_max_challenge_request(sockfd, max_challenge);
    if (retval != SECURITY_SERVER_SUCCESS)
    {
        /* Error on socket */
        SEC_SVR_ERR("Client: Send failed: %d", retval);
        goto error;
    }

    retval = recv_generic_response(sockfd, &hdr);

    retval = return_code_to_error_code(hdr.return_code);
    if (hdr.basic_hdr.msg_id != SECURITY_SERVER_MSG_TYPE_SET_PWD_MAX_CHALLENGE_RESPONSE)   /* Wrong response */
    {
        if (hdr.basic_hdr.msg_id == SECURITY_SERVER_MSG_TYPE_GENERIC_RESPONSE)
        {
            /* There must be some error */
            SEC_SVR_ERR("Client: Error has been received. return code:%d", hdr.return_code);
        }
        else
        {
            /* Something wrong with response */
            SEC_SVR_ERR("Client ERROR: Unexpected error occurred:%d", retval);
            retval = SECURITY_SERVER_ERROR_BAD_RESPONSE;
        }
        goto error;
    }
error:
    if (sockfd > 0)
        close(sockfd);

    retval = convert_to_public_error_code(retval);
    return retval;
}



SECURITY_SERVER_API
int security_server_reset_pwd(const char *new_pwd,
                              const unsigned int max_challenge,
                              const unsigned int valid_period_in_days)
{
    int sockfd = -1, retval;
    response_header hdr;

    if (new_pwd == NULL || strlen(new_pwd) > SECURITY_SERVER_MAX_PASSWORD_LEN || strlen(new_pwd) == 0)
    {
        retval = SECURITY_SERVER_ERROR_INPUT_PARAM;
        goto error;
    }

    /* Authenticate self that is setting app  goes here */
    /* 1st, check cmdline which is setting app */
    /* 2nd, check /proc/self/attr/current for the SMACK label */

    retval = connect_to_server(&sockfd);
    if (retval != SECURITY_SERVER_SUCCESS)
    {
        /* Error on socket */
        goto error;
    }

    /* make request packet */
    retval = send_reset_pwd_request(sockfd, new_pwd, max_challenge, valid_period_in_days);
    if (retval != SECURITY_SERVER_SUCCESS)
    {
        /* Error on socket */
        SEC_SVR_ERR("Client: Send failed: %d", retval);
        goto error;
    }

    retval = recv_generic_response(sockfd, &hdr);

    retval = return_code_to_error_code(hdr.return_code);
    if (hdr.basic_hdr.msg_id != SECURITY_SERVER_MSG_TYPE_RESET_PWD_RESPONSE) /* Wrong response */
    {
        if (hdr.basic_hdr.msg_id == SECURITY_SERVER_MSG_TYPE_GENERIC_RESPONSE)
        {
            /* There must be some error */
            SEC_SVR_ERR("Client: Error has been received. return code:%d", hdr.return_code);
        }
        else
        {
            /* Something wrong with response */
            SEC_SVR_ERR("Client ERROR: Unexpected error occurred:%d", retval);
            retval = SECURITY_SERVER_ERROR_BAD_RESPONSE;
        }
        goto error;
    }
error:
    if (sockfd > 0)
        close(sockfd);

    retval = convert_to_public_error_code(retval);
    return retval;
}



SECURITY_SERVER_API
int security_server_chk_pwd(const char *challenge,
                            unsigned int *current_attempt,
                            unsigned int *max_attempts,
                            unsigned int *valid_secs)
{
    int sockfd = -1, retval;
    response_header hdr;

    if (challenge == NULL || strlen(challenge) > SECURITY_SERVER_MAX_PASSWORD_LEN
        || strlen(challenge) == 0  || current_attempt == NULL
        || max_attempts == NULL || valid_secs == NULL)
    {
        retval = SECURITY_SERVER_ERROR_INPUT_PARAM;
        goto error;
    }

    /* Authenticate self goes here */

    retval = connect_to_server(&sockfd);
    if (retval != SECURITY_SERVER_SUCCESS)
    {
        /* Error on socket */
        goto error;
    }

    /* make request packet */
    retval = send_chk_pwd_request(sockfd, challenge);
    if (retval != SECURITY_SERVER_SUCCESS)
    {
        /* Error on socket */
        SEC_SVR_ERR("Client: Send failed: %d", retval);
        goto error;
    }

    retval = recv_pwd_response(sockfd, &hdr, current_attempt, max_attempts, valid_secs);

    retval = return_code_to_error_code(hdr.return_code);
    if (hdr.basic_hdr.msg_id != SECURITY_SERVER_MSG_TYPE_CHK_PWD_RESPONSE)   /* Wrong response */
    {
        if (hdr.basic_hdr.msg_id == SECURITY_SERVER_MSG_TYPE_GENERIC_RESPONSE)
        {
            /* There must be some error */
            SEC_SVR_ERR("Client: Error has been received. return code:%d", hdr.return_code);
        }
        else
        {
            /* Something wrong with response */
            SEC_SVR_ERR("Client ERROR: Unexpected error occurred:%d", retval);
            retval = SECURITY_SERVER_ERROR_BAD_RESPONSE;
        }
        goto error;
    }
error:
    if (sockfd > 0)
        close(sockfd);

    retval = convert_to_public_error_code(retval);
    return retval;
}

SECURITY_SERVER_API
int security_server_set_pwd_history(int number_of_history)
{
    int sockfd = -1, retval;
    response_header hdr;

    if (number_of_history > SECURITY_SERVER_MAX_PASSWORD_HISTORY || number_of_history < 0)
        return SECURITY_SERVER_API_ERROR_INPUT_PARAM;

    /* Authenticate self that is setting app  goes here */
    /* 1st, check cmdline which is setting app */
    /* 2nd, check /proc/self/attr/current for the SMACK label */

    retval = connect_to_server(&sockfd);
    if (retval != SECURITY_SERVER_SUCCESS)
    {
        /* Error on socket */
        goto error;
    }

    /* make request packet */
    retval = send_set_pwd_history_request(sockfd, number_of_history);
    if (retval != SECURITY_SERVER_SUCCESS)
    {
        /* Error on socket */
        SEC_SVR_ERR("Client: Send failed: %d", retval);
        goto error;
    }
    retval = recv_generic_response(sockfd, &hdr);

    retval = return_code_to_error_code(hdr.return_code);
    if (hdr.basic_hdr.msg_id != SECURITY_SERVER_MSG_TYPE_SET_PWD_HISTORY_RESPONSE)   /* Wrong response */
    {
        if (hdr.basic_hdr.msg_id == SECURITY_SERVER_MSG_TYPE_GENERIC_RESPONSE)
        {
            /* There must be some error */
            SEC_SVR_ERR("Client: Error has been received. return code:%d", hdr.return_code);
        }
        else
        {
            /* Something wrong with response */
            SEC_SVR_ERR("Client ERROR: Unexpected error occurred:%d", retval);
            retval = SECURITY_SERVER_ERROR_BAD_RESPONSE;
        }
        goto error;
    }
error:
    if (sockfd > 0)
        close(sockfd);

    retval = convert_to_public_error_code(retval);
    return retval;
}


#ifdef USE_SEC_SRV1_FOR_CHECK_PRIVILEGE_BY_PID
SECURITY_SERVER_API
int security_server_check_privilege_by_pid(int pid, const char *object, const char *access_rights)
{
    //This function check SMACK privilege betwen subject and object.
    //Subject is identified by PID number, object is function parameter.

    int sockfd = -1;
    int retval;
    response_header hdr;

    //check for input PID param
    if (pid < 0) {
        retval = SECURITY_SERVER_ERROR_INPUT_PARAM;
        goto error;
    }

    SEC_SVR_DBG("%s","Check privilige by PID called");
    SEC_SVR_DBG("%s %d","PID", pid);
    SEC_SVR_DBG("%s %s", "OBJECT:", object);
    SEC_SVR_DBG("%s %s", "ACCESS_RIGHTS", access_rights);

    //check if able to connect
    retval = connect_to_server(&sockfd);
    if (retval != SECURITY_SERVER_SUCCESS)
        goto error;

    //send request
    retval = send_pid_privilege_request(sockfd, pid, object, access_rights);
    if (retval != SECURITY_SERVER_SUCCESS) {
        /* Error on socket */
        SEC_SVR_ERR("Client: Send failed: %d", retval);
        goto error;
    }

    //get response
    retval = recv_pid_privilege_response(sockfd, &hdr);

    //convert error code
    retval = return_code_to_error_code(hdr.return_code);

    //check if frame has correct MSG_ID
    if (hdr.basic_hdr.msg_id != SECURITY_SERVER_MSG_TYPE_CHECK_PID_PRIVILEGE_RESPONSE) {
        if (hdr.basic_hdr.msg_id == SECURITY_SERVER_MSG_TYPE_GENERIC_RESPONSE) {
            /* There must be some error */
            SEC_SVR_ERR("Client: Error has been received. return code:%d", hdr.return_code);
        }
        else {
            /* Something wrong with response */
            SEC_SVR_ERR("Client ERROR: Unexpected error occurred:%d", retval);
            retval = SECURITY_SERVER_ERROR_BAD_RESPONSE;
        }
        goto error;
    }

    //debug info about checking result

    if (hdr.return_code == SECURITY_SERVER_RETURN_CODE_SUCCESS) {
        SEC_SVR_DBG("%s","Client: There is privilege match");
        retval = SECURITY_SERVER_SUCCESS;
    } else {
        SEC_SVR_WRN("%s","Client: There is no privilege match");
        retval = SECURITY_SERVER_ERROR_ACCESS_DENIED;
    }

error:
    if (sockfd > 0)
        close(sockfd);

    retval = convert_to_public_error_code(retval);
    return retval;
}
#endif
