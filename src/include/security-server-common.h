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

#include <sys/types.h>

/* Definitions *********************************************************/
/* Return value. Continuing from return value of the client header file */
#define SECURITY_SERVER_SUCCESS				0
#define SECURITY_SERVER_ERROR_SOCKET			-1
#define SECURITY_SERVER_ERROR_BAD_REQUEST		-2
#define SECURITY_SERVER_ERROR_BAD_RESPONSE		-3
#define SECURITY_SERVER_ERROR_SEND_FAILED		-4
#define SECURITY_SERVER_ERROR_RECV_FAILED		-5
#define SECURITY_SERVER_ERROR_NO_SUCH_OBJECT		-6
#define SECURITY_SERVER_ERROR_AUTHENTICATION_FAILED	-7
#define SECURITY_SERVER_ERROR_INPUT_PARAM		-8
#define SECURITY_SERVER_ERROR_BUFFER_TOO_SMALL		-9
#define SECURITY_SERVER_ERROR_OUT_OF_MEMORY		-10
#define SECURITY_SERVER_ERROR_ACCESS_DENIED		-11
#define SECURITY_SERVER_ERROR_SERVER_ERROR		-12
#define SECURITY_SERVER_ERROR_NO_SUCH_COOKIE		-13
#define SECURITY_SERVER_ERROR_NO_PASSWORD		-14
#define SECURITY_SERVER_ERROR_PASSWORD_EXIST		-15
#define SECURITY_SERVER_ERROR_PASSWORD_MISMATCH		-16
#define SECURITY_SERVER_ERROR_PASSWORD_RETRY_TIMER	-17
#define SECURITY_SERVER_ERROR_PASSWORD_MAX_ATTEMPTS_EXCEEDED	-18
#define SECURITY_SERVER_ERROR_PASSWORD_EXPIRED	-19
#define SECURITY_SERVER_ERROR_PASSWORD_REUSED	-20
#define SECURITY_SERVER_ERROR_SOCKET_BIND		-21
#define SECURITY_SERVER_ERROR_FILE_OPERATION		-22
#define SECURITY_SERVER_ERROR_TIMEOUT			-23
#define SECURITY_SERVER_ERROR_POLL			-24
#define SECURITY_SERVER_ERROR_UNKNOWN			-255

/* Miscellaneous Definitions */
#define SECURITY_SERVER_SOCK_PATH			"/tmp/.security_server.sock"
#define SECURITY_SERVER_DEFAULT_COOKIE_PATH		"/tmp/.security_server.coo"
#define SECURITY_SERVER_DAEMON_PATH			"/usr/bin/security-server"
#define SECURITY_SERVER_COOKIE_LEN			20
#define MAX_OBJECT_LABEL_LEN                            32
#define MAX_MODE_STR_LEN                                16
#define SECURITY_SERVER_MAX_OBJ_NAME			30
#define SECURITY_SERVER_MSG_VERSION			0x01
#define SECURITY_SERVER_ACCEPT_TIMEOUT_MILISECOND	10000
#define SECURITY_SERVER_SOCKET_TIMEOUT_MILISECOND	3000
#define SECURITY_SERVER_DEVELOPER_UID			5100
#define SECURITY_SERVER_DEBUG_TOOL_PATH			"/usr/bin/debug-util"
#define SECURITY_SERVER_KILL_APP_PATH			"/usr/bin/kill_app"
#define SECURITY_SERVER_DATA_DIRECTORY_PATH		"/opt/data/security-server"
#define SECURITY_SERVER_ATTEMPT_FILE_NAME	"attempts"
#define SECURITY_SERVER_HISTORY_FILE_NAME	"history"
#define SECURITY_SERVER_MAX_PASSWORD_LEN		32
#define SECURITY_SERVER_HASHED_PWD_LEN			32  /* SHA256 */
#define SECURITY_SERVER_PASSWORD_RETRY_TIMEOUT_SECOND		1        /* Deprecated. Will be removed. */
#define SECURITY_SERVER_PASSWORD_RETRY_TIMEOUT_MICROSECOND  500000   /* = 500 milliseconds */
#define SECURITY_SERVER_MAX_PASSWORD_HISTORY	50
#define SECURITY_SERVER_NUM_THREADS			10

/* API prefix */
#ifndef SECURITY_SERVER_API
#define SECURITY_SERVER_API	__attribute__((visibility("default")))
#endif



/* Data types *****************************************************************/
/* Cookie List data type */
typedef struct _cookie_list
{
	unsigned char	cookie[SECURITY_SERVER_COOKIE_LEN];	/* 20 bytes random Cookie */
	int		permission_len;				/* Client process permissions (aka group IDs) */
	pid_t		pid;					/* Client process's PID */
	char		*path;					/* Client process's executable path */
	int		*permissions;				/* Array of GID that the client process has */
    char            *smack_label;                           /* SMACK label of the client process */
    char    is_roots_process;           /* Is cookie belongs to roots process */
	struct _cookie_list	*prev;				/* Next cookie list */
	struct _cookie_list	*next;				/* Previous cookie list */
} cookie_list;


/* Function prototypes ******************************************************/
/* IPC */

void printhex(const unsigned char *data, int size);

/* Debug */
#ifdef SECURITY_SERVER_DEBUG_TO_CONSOLE /* debug msg will be printed in console */
#define SEC_SVR_DBG(FMT, ARG ...) fprintf(stderr, "[%s:%d] "FMT"\n", \
	       	__FILE__, __LINE__, ##ARG)

#elif SECURITY_SERVER_DEBUG_DLOG	/* debug msg will be printed by dlog daemon */
#define LOG_TAG "SECURITY_SERVER"
#include <dlog.h>
#define SEC_SVR_DBG	SLOGD
#else /* No debug output */
#define SEC_SVR_DBG(FMT, ARG ...) {}
#endif

#endif
