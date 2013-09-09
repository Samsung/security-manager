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

#ifndef SECURITY_SERVER_COMMON_H
#define SECURITY_SERVER_COMMON_H

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <dlog.h>

/* Definitions *********************************************************/
/* Return value. Continuing from return value of the client header file */
#define SECURITY_SERVER_SUCCESS                              0
#define SECURITY_SERVER_ERROR_SOCKET                         -1
#define SECURITY_SERVER_ERROR_BAD_REQUEST                    -2
#define SECURITY_SERVER_ERROR_BAD_RESPONSE                   -3
#define SECURITY_SERVER_ERROR_SEND_FAILED                    -4
#define SECURITY_SERVER_ERROR_RECV_FAILED                    -5
#define SECURITY_SERVER_ERROR_NO_SUCH_OBJECT                 -6
#define SECURITY_SERVER_ERROR_AUTHENTICATION_FAILED          -7
#define SECURITY_SERVER_ERROR_INPUT_PARAM                    -8
#define SECURITY_SERVER_ERROR_BUFFER_TOO_SMALL               -9
#define SECURITY_SERVER_ERROR_OUT_OF_MEMORY                  -10
#define SECURITY_SERVER_ERROR_ACCESS_DENIED                  -11
#define SECURITY_SERVER_ERROR_SERVER_ERROR                   -12
#define SECURITY_SERVER_ERROR_NO_SUCH_COOKIE                 -13
#define SECURITY_SERVER_ERROR_NO_PASSWORD                    -14
#define SECURITY_SERVER_ERROR_PASSWORD_EXIST                 -15
#define SECURITY_SERVER_ERROR_PASSWORD_MISMATCH              -16
#define SECURITY_SERVER_ERROR_PASSWORD_RETRY_TIMER           -17
#define SECURITY_SERVER_ERROR_PASSWORD_MAX_ATTEMPTS_EXCEEDED -18
#define SECURITY_SERVER_ERROR_PASSWORD_EXPIRED               -19
#define SECURITY_SERVER_ERROR_PASSWORD_REUSED                -20
#define SECURITY_SERVER_ERROR_SOCKET_BIND                    -21
#define SECURITY_SERVER_ERROR_FILE_OPERATION                 -22
#define SECURITY_SERVER_ERROR_TIMEOUT                        -23
#define SECURITY_SERVER_ERROR_POLL                           -24
#define SECURITY_SERVER_ERROR_UNKNOWN                        -255

/* Miscellaneous Definitions */
#define SECURITY_SERVER_SOCK_PATH                          "/tmp/.security_server.sock"
#define SECURITY_SERVER_DEFAULT_COOKIE_PATH                "/tmp/.security_server.coo"
#define SECURITY_SERVER_DAEMON_PATH                        "/usr/bin/security-server"
#define SECURITY_SERVER_COOKIE_LEN                         20
#define MAX_OBJECT_LABEL_LEN                               32
#define MAX_MODE_STR_LEN                                   16
#define SECURITY_SERVER_MAX_OBJ_NAME                       30
#define SECURITY_SERVER_MSG_VERSION                        0x01
#define SECURITY_SERVER_ACCEPT_TIMEOUT_MILISECOND          10000
#define SECURITY_SERVER_SOCKET_TIMEOUT_MILISECOND          3000
#define SECURITY_SERVER_DEVELOPER_UID                      5100
#define SECURITY_SERVER_DATA_DIRECTORY_PATH                "/opt/data/security-server"
#define SECURITY_SERVER_ATTEMPT_FILE_NAME                  "attempts"
#define SECURITY_SERVER_HISTORY_FILE_NAME                  "history"
#define SECURITY_SERVER_MAX_PASSWORD_LEN                   32
#define SECURITY_SERVER_HASHED_PWD_LEN                     32 /* SHA256 */
#define SECURITY_SERVER_PASSWORD_RETRY_TIMEOUT_SECOND      1         /* Deprecated. Will be removed. */
#define SECURITY_SERVER_PASSWORD_RETRY_TIMEOUT_MICROSECOND 500000    /* = 500 milliseconds */
#define SECURITY_SERVER_MAX_PASSWORD_HISTORY               50
#define SECURITY_SERVER_NUM_THREADS                        10
#define MESSAGE_MAX_LEN                                    1048576

/* API prefix */
#ifndef SECURITY_SERVER_API
#define SECURITY_SERVER_API __attribute__((visibility("default")))
#endif



/* Data types *****************************************************************/


/* Cookie List data type */
typedef struct _cookie_list
{
    unsigned char cookie[SECURITY_SERVER_COOKIE_LEN];   /* 20 bytes random Cookie */
    int permission_len;                 /* Client process permissions (aka group IDs) */
    pid_t pid;                          /* Client process's PID */
    char *path;                         /* Client process's executable path */
    int *permissions;                   /* Array of GID that the client process has */
    char *smack_label;                                      /* SMACK label of the client process */
    char is_roots_process;              /* Is cookie belongs to roots process */
    struct _cookie_list *prev;              /* Next cookie list */
    struct _cookie_list *next;              /* Previous cookie list */
} cookie_list;


/* Function prototypes ******************************************************/
/* IPC */

void printhex(const unsigned char *data, int size);

/* for SECURE_LOG* purpose */
#undef _SECURE_
#ifndef _SECURE_LOG
#define _SECURE_ (0)
#else
#define _SECURE_ (1)
#endif
#undef LOG_
#define LOG_(id, prio, tag, fmt, arg ...) \
    (__dlog_print(id, prio, tag, "%s: %s(%d) > " fmt, __MODULE__, __func__, __LINE__, ##arg))
#undef SECURE_LOG_
#define SECURE_LOG_(id, prio, tag, fmt, arg ...) \
    (_SECURE_ ? (__dlog_print(id, prio, tag, "%s: %s(%d) > [SECURE_LOG] " fmt, __MODULE__, __func__, __LINE__, ##arg)) : (0))

#ifdef LOG_TAG
    #undef LOG_TAG
#endif
#define LOG_TAG "SECURITY_SERVER"

#define SECURE_LOGD(format, arg ...) SECURE_LOG_(LOG_ID_MAIN, DLOG_DEBUG, LOG_TAG, format, ##arg)
#define SECURE_LOGI(format, arg ...) SECURE_LOG_(LOG_ID_MAIN, DLOG_INFO, LOG_TAG, format, ##arg)
#define SECURE_LOGW(format, arg ...) SECURE_LOG_(LOG_ID_MAIN, DLOG_WARN, LOG_TAG, format, ##arg)
#define SECURE_LOGE(format, arg ...) SECURE_LOG_(LOG_ID_MAIN, DLOG_ERROR, LOG_TAG, format, ##arg)

#ifndef SECURE_SLOGE
    #define SECURE_SLOGE(format, arg ...) SECURE_LOG_(LOG_ID_MAIN, DLOG_ERROR, LOG_TAG, format, ##arg)
#endif // SECURE_SLOGE
/****************************/

/* Debug */
#ifdef SECURITY_SERVER_DEBUG_TO_CONSOLE /* debug msg will be printed in console */
#define SEC_SVR_DBG(FMT, ARG ...) fprintf(stderr, "[DBG:%s:%d] " FMT "\n", \
                __FILE__, __LINE__, ##ARG)
#define SEC_SVR_WRN(FMT, ARG ...) fprintf(stderr, "[WRN:%s:%d] " FMT "\n", \
                __FILE__, __LINE__, ##ARG)
#define SEC_SVR_ERR(FMT, ARG ...) fprintf(stderr, "[ERR:%s:%d] " FMT "\n", \
                __FILE__, __LINE__, ##ARG)

#else
#ifdef LOG_TAG
    #undef LOG_TAG
#endif
#define LOG_TAG "SECURITY_SERVER"
#define SEC_SVR_ERR SLOGE
#if SECURITY_SERVER_DEBUG_DLOG        /* debug msg will be printed by dlog daemon */
#define SEC_SVR_DBG SLOGD
#define SEC_SVR_WRN SLOGW
#else /* No debug output */

#define SEC_SVR_DBG(FMT, ARG ...) do { } while(0)
#define SEC_SVR_WRN(FMT, ARG ...) do { } while(0)
#ifdef SECURE_SLOGD
    #undef SECURE_SLOGD
#endif
#define SECURE_SLOGD(FMT, ARG ...) do { } while(0)
#ifdef SECURE_SLOGW
   #undef SECURE_SLOGW
#endif
#define SECURE_SLOGW(FMT, ARG ...) do { } while(0)

#endif // SECURITY_SERVER_DEBUG_DLOG
#endif // SECURITY_SERVER_DEBUG_TO_CONSOLE

#ifdef __cplusplus
}
#endif

#endif
