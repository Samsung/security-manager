/*
 *  security-server
 *
 *  Copyright (c) 2012 Samsung Electronics Co., Ltd All Rights Reserved
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
#include <sys/xattr.h>
#include <fcntl.h>
#include <sys/un.h>
#include <errno.h>
#include <unistd.h>

#include "security-server-common.h"
#include "security-server-comm.h"

void printhex(const unsigned char *data, int size)
{
	int i;
	for(i=0;i<size;i++)
	{
		if(data[i] < 0xF)
			printf("0");

		printf("%X ", data[i]);
		if(((i+1) % 16) == 0 && i != 0)
			printf("\n");
	}
	printf("\n");
}

char *read_cmdline_from_proc(pid_t pid)
{
	int memsize = 32;
	char path[32];
	char *cmdline = NULL, *tempptr = NULL;
	FILE *fp = NULL;

	snprintf(path, sizeof(path), "/proc/%d/cmdline", pid);

	fp = fopen(path, "r");
	if(fp == NULL)
	{
		SEC_SVR_DBG("Cannot open cmdline on pid[%d]", pid);
		return NULL;
	}

	cmdline = malloc(32);
	if(cmdline == NULL)
	{
		SEC_SVR_DBG("%s", "Out of memory");
		fclose(fp);
		return NULL;
	}

	bzero(cmdline, memsize);
	if(fgets(cmdline, 32, fp) == NULL)
	{
		SEC_SVR_DBG("%s", "Cannot read cmdline");
		free(cmdline);
		fclose(fp);
		return NULL;
	}

	while(cmdline[memsize -2] != 0)
	{
		cmdline[memsize -1] = (char) fgetc(fp);
		tempptr = realloc(cmdline, memsize + 32);
		if(tempptr == NULL)
		{
			fclose(fp);
			SEC_SVR_DBG("%s", "Out of memory");
			return NULL;
		}
		cmdline = tempptr;
		bzero(cmdline + memsize, 32);
		fgets(cmdline + memsize, 32, fp);
		memsize += 32;
	}

	if(fp != NULL)
		fclose(fp);
	return cmdline;
}

/* Return code in packet is positive integer *
 * We need to convert them to error code which are negative integer */
int return_code_to_error_code(int ret_code)
{
	int ret;
	switch(ret_code)
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
		case SECURITY_SERVER_RETURN_CODE_NO_PASSWORD:
			ret = SECURITY_SERVER_ERROR_NO_PASSWORD;
			break;
		case SECURITY_SERVER_RETURN_CODE_PASSWORD_EXIST:
			ret = SECURITY_SERVER_ERROR_PASSWORD_EXIST;
			break;
		case SECURITY_SERVER_RETURN_CODE_PASSWORD_MISMATCH:
			ret = SECURITY_SERVER_ERROR_PASSWORD_MISMATCH;
			break;
		case SECURITY_SERVER_RETURN_CODE_PASSWORD_RETRY_TIMER:
			ret = SECURITY_SERVER_ERROR_PASSWORD_RETRY_TIMER;
			break;
		case SECURITY_SERVER_RETURN_CODE_PASSWORD_EXPIRED:
			ret = SECURITY_SERVER_ERROR_PASSWORD_EXPIRED;
			break;
		case SECURITY_SERVER_RETURN_CODE_PASSWORD_MAX_ATTEMPTS_EXCEEDED:
			ret = SECURITY_SERVER_ERROR_PASSWORD_MAX_ATTEMPTS_EXCEEDED;
			break;
		case SECURITY_SERVER_RETURN_CODE_PASSWORD_REUSED:
			ret = SECURITY_SERVER_ERROR_PASSWORD_REUSED;
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
	if(retval < 0)
	{
		SEC_SVR_DBG("poll() error. errno=%d", errno);
		if(errno != EINTR)
			return SECURITY_SERVER_ERROR_POLL;
		else
		{
			/* Chile process has been closed. Not poll() problem. Call it once again */ 
			return check_socket_poll(sockfd, event, timeout);
		}
	}

	/* Timed out */
	if(retval == 0)
	{
		return SECURITY_SERVER_ERROR_TIMEOUT;
	}

	if(poll_fd[0].revents != event)
	{
		SEC_SVR_DBG("Something wrong on the peer socket. event=0x%x", poll_fd[0].revents);
		return SECURITY_SERVER_ERROR_POLL;
	}
	return SECURITY_SERVER_SUCCESS;
}

int safe_server_sock_close(int client_sockfd)
{
	struct pollfd poll_fd[1];
	int retval;
	retval = SECURITY_SERVER_ERROR_POLL;
	poll_fd[0].fd = client_sockfd;
	poll_fd[0].events = POLLRDHUP;
	retval = poll(poll_fd, 1, SECURITY_SERVER_SOCKET_TIMEOUT_MILISECOND);
	SEC_SVR_DBG("%s", "Server: Closing server socket");
	close(client_sockfd);
	return SECURITY_SERVER_SUCCESS;
}

/* Create a Unix domain socket and bind */
int create_new_socket(int *sockfd)
{
	int retval = 0, localsockfd = 0, flags;
	struct sockaddr_un serveraddr;
	mode_t sock_mode;

	/* Deleted garbage Unix domain socket file */
	remove(SECURITY_SERVER_SOCK_PATH);

	/* Create Unix domain socket */
	if((localsockfd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0 )
	{
		retval = SECURITY_SERVER_ERROR_SOCKET;
		localsockfd = -1;
		SEC_SVR_DBG("%s", "Socket creation failed");
		goto error;
	}

	if((fsetxattr(localsockfd, "security.SMACK64IPOUT", "@", 2, 0)) < 0)
	{
		SEC_SVR_DBG("%s", "SMACK labeling failed");
		if(errno != EOPNOTSUPP)
		{
			retval = SECURITY_SERVER_ERROR_SOCKET;
			localsockfd = -1;
			goto error;
		}
	}
	if((fsetxattr(localsockfd, "security.SMACK64IPIN", "*", 2, 0)) < 0)
	{	SEC_SVR_DBG("%s", "SMACK labeling failed");
		if(errno != EOPNOTSUPP)
		{
			retval = SECURITY_SERVER_ERROR_SOCKET;
			localsockfd = -1;
			goto error;
		}
	}

	/* Make socket as non blocking */
	if((flags = fcntl(localsockfd, F_GETFL, 0)) < 0 || 
			fcntl(localsockfd, F_SETFL, flags | O_NONBLOCK) < 0)
	{
		retval = SECURITY_SERVER_ERROR_SOCKET;
		close(localsockfd);
		localsockfd = -1;
		SEC_SVR_DBG("%s", "Cannot go to nonblocking mode");
		goto error;
	}

	bzero (&serveraddr, sizeof(serveraddr));
	serveraddr.sun_family = AF_UNIX;
	strncpy(serveraddr.sun_path, SECURITY_SERVER_SOCK_PATH, 
			strlen(SECURITY_SERVER_SOCK_PATH));
	serveraddr.sun_path[strlen(SECURITY_SERVER_SOCK_PATH)] = 0;

	/* Bind the socket */
	if((bind(localsockfd, (struct sockaddr *)&serveraddr, sizeof(serveraddr))) < 0)
	{
		retval = SECURITY_SERVER_ERROR_SOCKET_BIND;
		SEC_SVR_DBG("%s", "Cannot bind");
		close(localsockfd);
		localsockfd = -1;
		goto error;
	}
	

	/* Change permission to accept all processes that has different uID/gID */
	sock_mode = (S_IRWXU | S_IRWXG | S_IRWXO);
	/* Flawfinder hits this chmod function as level 5 CRITICAL as race condition flaw *
	 * Flawfinder recommends to user fchmod insted of chmod
	 * But, fchmod doesn't work on socket file so there is no other choice at this point */
	if(chmod(SECURITY_SERVER_SOCK_PATH, sock_mode) < 0)		/* Flawfinder: ignore */
	{
		SEC_SVR_DBG("%s", "chmod() error");
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
/*	char *cmdline = NULL;*/

	/* get socket peer credential */
	if(getsockopt(sockfd, SOL_SOCKET, SO_PEERCRED, &cr, &cl) != 0)
	{
		retval = SECURITY_SERVER_ERROR_SOCKET;
		SEC_SVR_DBG("%s", "getsockopt() failed");
		goto error;
	}

	/* Security server must run as root */
	if(cr.uid != 0)
	{
		retval = SECURITY_SERVER_ERROR_AUTHENTICATION_FAILED;
		SEC_SVR_DBG("Peer is not root: uid=%d", cr.uid);
		goto error;
	}
	else
		retval = SECURITY_SERVER_SUCCESS;

	/* Read command line of the PID from proc fs */
	/* This is commented out because non root process cannot read link of /proc/pid/exe */
/*	cmdline = read_cmdline_from_proc(cr.pid);

	if(strcmp(cmdline, SECURITY_SERVER_DAEMON_PATH) != 0)
	{
		retval = SECURITY_SERVER_ERROR_AUTHENTICATION_FAILED;
		SEC_SVR_DBG("Cmdline is different. auth failed. cmdline=%s", cmdline);
	}
	else
	{
		retval = SECURITY_SERVER_SUCCESS;
		SEC_SVR_DBG("Server authenticatd. %s, sockfd=%d", cmdline, sockfd);
	}
*/
error:
/*	if(cmdline != NULL)
		free(cmdline);
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
	if(localsockfd < 0)
	{
		SEC_SVR_DBG("%s", "Error on socket()");
		return SECURITY_SERVER_ERROR_SOCKET;
	}

	/* Make socket as non blocking */
	if((flags = fcntl(localsockfd, F_GETFL, 0)) < 0 || 
			fcntl(localsockfd, F_SETFL, flags | O_NONBLOCK) < 0)
	{
		close(localsockfd);
		SEC_SVR_DBG("%s", "Cannot go to nonblocking mode");
		return SECURITY_SERVER_ERROR_SOCKET;
	}

	bzero(&clientaddr, sizeof(clientaddr));
	clientaddr.sun_family = AF_UNIX;
	strncpy(clientaddr.sun_path, SECURITY_SERVER_SOCK_PATH, strlen(SECURITY_SERVER_SOCK_PATH));
	clientaddr.sun_path[strlen(SECURITY_SERVER_SOCK_PATH)] = 0;
	client_len = sizeof(clientaddr);

	ret = connect(localsockfd, (struct sockaddr*)&clientaddr, client_len);
	if( ret < 0)
	{
		if(errno == EINPROGRESS)
		{
			SEC_SVR_DBG("%s", "Connection is in progress");
			ret = check_socket_poll(localsockfd, POLLOUT, SECURITY_SERVER_SOCKET_TIMEOUT_MILISECOND);
			if(ret == SECURITY_SERVER_ERROR_POLL)
			{
				SEC_SVR_DBG("%s", "poll() error");
				close(localsockfd);
				return SECURITY_SERVER_ERROR_SOCKET;
			}
			if(ret == SECURITY_SERVER_ERROR_TIMEOUT)
			{
				SEC_SVR_DBG("%s", "poll() timeout");
				close(localsockfd);
				return SECURITY_SERVER_ERROR_SOCKET;
			}
			ret = connect(localsockfd, (struct sockaddr*)&clientaddr, client_len);
			if(ret < 0)
			{
				SEC_SVR_DBG("%s", "connection failed");
				close(localsockfd);
				return SECURITY_SERVER_ERROR_SOCKET;
			}
		}
		else
		{
			SEC_SVR_DBG("%s", "Connection failed");
			close(localsockfd);
			return SECURITY_SERVER_ERROR_SOCKET;
		}
	}

	/* Authenticate the peer is actually security server */
	ret = authenticate_server(localsockfd);
	if(ret  != SECURITY_SERVER_SUCCESS)
	{
		close(localsockfd);
		SEC_SVR_DBG("Authentication failed. %d", ret);
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
	if(retval == SECURITY_SERVER_ERROR_POLL)
	{
		SEC_SVR_DBG("%s", "Error on polling");
		return SECURITY_SERVER_ERROR_SOCKET;
	}

	/* Timed out */
	if(retval == SECURITY_SERVER_ERROR_TIMEOUT)
	{
		/*SEC_SVR_DBG("%s", "accept() timeout");*/
		return SECURITY_SERVER_ERROR_TIMEOUT;
	}

	localsockfd = accept(server_sockfd, 
			(struct sockaddr *)&clientaddr, 
			&client_len);

	if(localsockfd < 0)
	{
		SEC_SVR_DBG("Cannot accept client. errno=%d", errno);
		return SECURITY_SERVER_ERROR_SOCKET;
	}
	return localsockfd;
}

/* Minimal check of request packet */
int validate_header(basic_header hdr)
{
	if(hdr.version != SECURITY_SERVER_MSG_VERSION)
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
	if(size == SECURITY_SERVER_ERROR_POLL)
	{
		SEC_SVR_DBG("%s", "poll() error");
		return SECURITY_SERVER_ERROR_SEND_FAILED;
	}
	if(size == SECURITY_SERVER_ERROR_TIMEOUT)
	{
		SEC_SVR_DBG("%s", "poll() timeout");
		return SECURITY_SERVER_ERROR_SEND_FAILED;
	}

	/* Send to client */
	size = write(sockfd, &hdr, sizeof(hdr));

	if(size < sizeof(hdr))
		return SECURITY_SERVER_ERROR_SEND_FAILED;
	return SECURITY_SERVER_SUCCESS;
}

/* Send cookie response to client
 * 
 * Get Cookie response packet format
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 
 *  |---------------------------------------------------------------|
 *  | version=0x01  |MessageID=0x02 |       Message Length =20      |
 *  |---------------------------------------------------------------|
 *  |  return code  |                                               |
 *  -----------------                                               |
 *  |                 cookie (20 bytes)                             |
 *  |---------------------------------------------------------------|
*/
int send_cookie(int sockfd, unsigned char *cookie)
{
	response_header hdr;
	unsigned char msg[SECURITY_SERVER_COOKIE_LEN + sizeof(hdr)];
	int ret;

	/* Assemble header */
	hdr.basic_hdr.version = SECURITY_SERVER_MSG_VERSION;
	hdr.basic_hdr.msg_id = SECURITY_SERVER_MSG_TYPE_COOKIE_RESPONSE;
	hdr.basic_hdr.msg_len = SECURITY_SERVER_COOKIE_LEN;
	hdr.return_code = SECURITY_SERVER_RETURN_CODE_SUCCESS;

	memcpy(msg, &hdr, sizeof(hdr));
	memcpy(msg + sizeof(hdr), cookie, SECURITY_SERVER_COOKIE_LEN);

	/* Check poll */
	ret = check_socket_poll(sockfd, POLLOUT, SECURITY_SERVER_SOCKET_TIMEOUT_MILISECOND);
	if(ret == SECURITY_SERVER_ERROR_POLL)
	{
		SEC_SVR_DBG("%s", "poll() error");
		return SECURITY_SERVER_ERROR_SEND_FAILED;
	}
	if(ret == SECURITY_SERVER_ERROR_TIMEOUT)
	{
		SEC_SVR_DBG("%s", "poll() timeout");
		return SECURITY_SERVER_ERROR_SEND_FAILED;
	}

	ret = write(sockfd, msg, sizeof(hdr) + SECURITY_SERVER_COOKIE_LEN);
	if(ret <  sizeof(hdr) + SECURITY_SERVER_COOKIE_LEN)
	{
		/* Error on writing */
		SEC_SVR_DBG("Error on write: %d", ret);
		ret = SECURITY_SERVER_ERROR_SEND_FAILED;
		return ret;
	}
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
	if(ret == SECURITY_SERVER_ERROR_POLL)
	{
		SEC_SVR_DBG("%s", "poll() error");
		return SECURITY_SERVER_ERROR_SEND_FAILED;
	}
	if(ret == SECURITY_SERVER_ERROR_TIMEOUT)
	{
		SEC_SVR_DBG("%s", "poll() timeout");
		return SECURITY_SERVER_ERROR_SEND_FAILED;
	}

	ret = write(sockfd, msg, sizeof(hdr) + strlen(obj));
	if(ret <  sizeof(hdr) + strlen(obj))
	{
		/* Error on writing */
		SEC_SVR_DBG("Error on write: %d", ret);
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
	if(ret == SECURITY_SERVER_ERROR_POLL)
	{
		SEC_SVR_DBG("%s", "poll() error");
		return SECURITY_SERVER_ERROR_SEND_FAILED;
	}
	if(ret == SECURITY_SERVER_ERROR_TIMEOUT)
	{
		SEC_SVR_DBG("%s", "poll() timeout");
		return SECURITY_SERVER_ERROR_SEND_FAILED;
	}

	/* Send it */
	ret = write(sockfd, msg, sizeof(hdr) + sizeof(gid));
	if(ret <  sizeof(hdr) + sizeof(gid))
	{
		/* Error on writing */
		SEC_SVR_DBG("Error on write(): %d", ret);
		ret = SECURITY_SERVER_ERROR_SEND_FAILED;
		return ret;
	}
	return SECURITY_SERVER_SUCCESS;
}

/* Send PID response to client
 * 
 * Get PID response packet format
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 
 * |---------------------------------------------------------------|
 * | version=0x01  |MessageID=0x0a |       Message Length = 4      |
 * |---------------------------------------------------------------|
 * |  return code  |           pid (first 3 words)                 |
 * |---------------------------------------------------------------|
 * |pid(last word) |
 * |---------------|
*/
int send_pid(int sockfd, int pid)
{
	response_header hdr;
	unsigned char msg[sizeof(pid) + sizeof(hdr)];
	int ret;

	/* Assemble header */
	hdr.basic_hdr.version = SECURITY_SERVER_MSG_VERSION;
	hdr.basic_hdr.msg_id = SECURITY_SERVER_MSG_TYPE_PID_RESPONSE;
	hdr.basic_hdr.msg_len = sizeof(pid);
	hdr.return_code = SECURITY_SERVER_RETURN_CODE_SUCCESS;

	/* Perpare packet */
	memcpy(msg, &hdr, sizeof(hdr));
	memcpy(msg + sizeof(hdr), &pid, sizeof(pid));

	/* Check poll */
	ret = check_socket_poll(sockfd, POLLOUT, SECURITY_SERVER_SOCKET_TIMEOUT_MILISECOND);
	if(ret == SECURITY_SERVER_ERROR_POLL)
	{
		SEC_SVR_DBG("%s", "poll() error");
		return SECURITY_SERVER_ERROR_SEND_FAILED;
	}
	if(ret == SECURITY_SERVER_ERROR_TIMEOUT)
	{
		SEC_SVR_DBG("%s", "poll() timeout");
		return SECURITY_SERVER_ERROR_SEND_FAILED;
	}

	/* Send it */
	ret = write(sockfd, msg, sizeof(hdr) + sizeof(pid));
	if(ret <  sizeof(hdr) + sizeof(pid))
	{
		/* Error on writing */
		SEC_SVR_DBG("Error on write(): %d", ret);
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
	if(ret == SECURITY_SERVER_ERROR_POLL)
	{
		SEC_SVR_DBG("%s", "Server: poll() error");
		return SECURITY_SERVER_ERROR_SEND_FAILED;
	}
	if(ret == SECURITY_SERVER_ERROR_TIMEOUT)
	{
		SEC_SVR_DBG("%s", "Server: poll() timeout");
		return SECURITY_SERVER_ERROR_SEND_FAILED;
	}

	/* Send it */
	ret = write(sockfd, msg, ptr);
	if(ret <  ptr)
	{
		/* Error on writing */
		SEC_SVR_DBG("Server: ERROR on write(): %d", ret);
		ret = SECURITY_SERVER_ERROR_SEND_FAILED;
		return ret;
	}
	return SECURITY_SERVER_SUCCESS;
}

/* Send cookie request packet to security server *
 * 
 * Message format
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * |---------------------------------------------------------------|
 * | version=0x01  |MessageID=0x01 |       Message Length = 0      |
 * |---------------------------------------------------------------|
 */
int send_cookie_request(int sock_fd)
{
	basic_header hdr;
	int retval;

	/* Assemble header */
	hdr.version = SECURITY_SERVER_MSG_VERSION;
	hdr.msg_id = SECURITY_SERVER_MSG_TYPE_COOKIE_REQUEST;
	hdr.msg_len = 0;

	/* Check poll */
	retval = check_socket_poll(sock_fd, POLLOUT, SECURITY_SERVER_SOCKET_TIMEOUT_MILISECOND);
	if(retval == SECURITY_SERVER_ERROR_POLL)
	{
		SEC_SVR_DBG("%s", "poll() error");
		return SECURITY_SERVER_ERROR_SEND_FAILED;
	}
	if(retval == SECURITY_SERVER_ERROR_TIMEOUT)
	{
		SEC_SVR_DBG("%s", "poll() timeout");
		return SECURITY_SERVER_ERROR_SEND_FAILED;
	}

	/* Send to server */
	retval = write(sock_fd, &hdr, sizeof(hdr));
	if(retval < sizeof(hdr))
	{
		/* Write error */
		SEC_SVR_DBG("Error on write(): %d", retval);
		return SECURITY_SERVER_ERROR_SEND_FAILED;
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
int send_gid_request(int sock_fd, const char* object)
{
	basic_header hdr;
	int retval = 0, send_len = 0;
	unsigned char *buf = NULL;

	if(strlen(object) > SECURITY_SERVER_MAX_OBJ_NAME)
	{
		/* Object name is too big*/
		SEC_SVR_DBG("Object name is too big %dbytes", strlen(object));
		return SECURITY_SERVER_ERROR_INPUT_PARAM;
	}

	hdr.version = SECURITY_SERVER_MSG_VERSION;
	hdr.msg_id = SECURITY_SERVER_MSG_TYPE_GID_REQUEST;
	hdr.msg_len = strlen(object);

	send_len = sizeof(hdr) + strlen(object);

	buf = malloc(send_len);
	if(buf == NULL)
	{
		SEC_SVR_DBG("%s", "out of memory");
		return SECURITY_SERVER_ERROR_OUT_OF_MEMORY;
	}

	memcpy(buf, &hdr, sizeof(hdr));
	memcpy(buf + sizeof(hdr), object, strlen(object));

	/* Check poll */
	retval = check_socket_poll(sock_fd, POLLOUT, SECURITY_SERVER_SOCKET_TIMEOUT_MILISECOND);
	if(retval == SECURITY_SERVER_ERROR_POLL)
	{
		SEC_SVR_DBG("%s", "poll() error");
		retval = SECURITY_SERVER_ERROR_SEND_FAILED;
		goto error;
	}
	if(retval == SECURITY_SERVER_ERROR_TIMEOUT)
	{
		SEC_SVR_DBG("%s", "poll() timeout");
		retval =  SECURITY_SERVER_ERROR_SEND_FAILED;
		goto error;
	}

	retval = write(sock_fd, buf, send_len);
	if(retval < send_len)
	{
		/* Write error */
		SEC_SVR_DBG("Error on write(): %d. errno=%d, sockfd=%d", retval, errno, sock_fd);
		retval = SECURITY_SERVER_ERROR_SEND_FAILED;
	}
	else
		retval = SECURITY_SERVER_SUCCESS;

error:
	if(buf != NULL)
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
int send_object_name_request(int sock_fd, int gid)
{
	basic_header hdr;
	int retval;
	unsigned char buf[sizeof(hdr) + sizeof(gid)];

	/* Assemble header */
	hdr.version = SECURITY_SERVER_MSG_VERSION;
	hdr.msg_id = SECURITY_SERVER_MSG_TYPE_OBJECT_NAME_REQUEST;
	hdr.msg_len = sizeof(gid);

	memcpy(buf, &hdr, sizeof(hdr));
	memcpy(buf + sizeof(hdr), &gid, sizeof(gid));

	/* Check poll */
	retval = check_socket_poll(sock_fd, POLLOUT, SECURITY_SERVER_SOCKET_TIMEOUT_MILISECOND);
	if(retval == SECURITY_SERVER_ERROR_POLL)
	{
		SEC_SVR_DBG("%s", "poll() error");
		return SECURITY_SERVER_ERROR_SEND_FAILED;
	}
	if(retval == SECURITY_SERVER_ERROR_TIMEOUT)
	{
		SEC_SVR_DBG("%s", "poll() timeout");
		return SECURITY_SERVER_ERROR_SEND_FAILED;
	}

	/* Send to server */
	retval = write(sock_fd, buf, sizeof(buf));
	if(retval < sizeof(buf))
	{
		/* Write error */
		SEC_SVR_DBG("Error on write(): %d", retval);
		return SECURITY_SERVER_ERROR_SEND_FAILED;
	}
	return SECURITY_SERVER_SUCCESS;	
}

/* Send privilege check request message to security server *
 *
 * Message format
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 
 * |---------------------------------------------------------------|
 * | version=0x01  |MessageID=0x03 |      Message Length = 24      |
 * |---------------------------------------------------------------|
 * |                                                               |
 * |                                                               |
 * |                      Cookie (20bytes)                         |
 * |                                                               |
 * |                                                               |
 * |---------------------------------------------------------------|
 * |                            GID                                |
 * |---------------------------------------------------------------|
 */
int send_privilege_check_request(int sock_fd, const char*cookie, int gid)
{
	basic_header hdr;
	int retval;
	unsigned char buf[sizeof(hdr) + sizeof(gid) + SECURITY_SERVER_COOKIE_LEN];

	/* Assemble header */
	hdr.version = SECURITY_SERVER_MSG_VERSION;
	hdr.msg_id = SECURITY_SERVER_MSG_TYPE_CHECK_PRIVILEGE_REQUEST;
	hdr.msg_len = sizeof(gid) + SECURITY_SERVER_COOKIE_LEN;

	memcpy(buf, &hdr, sizeof(hdr));
	memcpy(buf + sizeof(hdr), cookie, SECURITY_SERVER_COOKIE_LEN);
	memcpy(buf + sizeof(hdr) + SECURITY_SERVER_COOKIE_LEN, &gid, sizeof(gid));

	/* Check poll */
	retval = check_socket_poll(sock_fd, POLLOUT, SECURITY_SERVER_SOCKET_TIMEOUT_MILISECOND);
	if(retval == SECURITY_SERVER_ERROR_POLL)
	{
		SEC_SVR_DBG("%s", "poll() error");
		return SECURITY_SERVER_ERROR_SEND_FAILED;
	}
	if(retval == SECURITY_SERVER_ERROR_TIMEOUT)
	{
		SEC_SVR_DBG("%s", "poll() timeout");
		return SECURITY_SERVER_ERROR_SEND_FAILED;
	}

	/* Send to server */
	retval = write(sock_fd, buf, sizeof(buf));
	if(retval < sizeof(buf))
	{
		/* Write error */
		SEC_SVR_DBG("Error on write(): %d", retval);
		return SECURITY_SERVER_ERROR_SEND_FAILED;
	}
	return SECURITY_SERVER_SUCCESS;
}

/* Send PID check request message to security server *
 *
 * Message format
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 
 * |---------------------------------------------------------------|
 * | version=0x01  |MessageID=0x09 |      Message Length = 20      |
 * |---------------------------------------------------------------|
 * |                                                               |
 * |                                                               |
 * |                      Cookie (20bytes)                         |
 * |                                                               |
 * |                                                               |
 * |---------------------------------------------------------------|
 */
int send_pid_request(int sock_fd, const char*cookie)
{
	basic_header hdr;
	int retval;
	unsigned char buf[sizeof(hdr) + SECURITY_SERVER_COOKIE_LEN];

	/* Assemble header */
	hdr.version = SECURITY_SERVER_MSG_VERSION;
	hdr.msg_id = SECURITY_SERVER_MSG_TYPE_PID_REQUEST;
	hdr.msg_len = SECURITY_SERVER_COOKIE_LEN;

	memcpy(buf, &hdr, sizeof(hdr));
	memcpy(buf + sizeof(hdr), cookie, SECURITY_SERVER_COOKIE_LEN);

	/* Check poll */
	retval = check_socket_poll(sock_fd, POLLOUT, SECURITY_SERVER_SOCKET_TIMEOUT_MILISECOND);
	if(retval == SECURITY_SERVER_ERROR_POLL)
	{
		SEC_SVR_DBG("%s", "poll() error");
		return SECURITY_SERVER_ERROR_SEND_FAILED;
	}
	if(retval == SECURITY_SERVER_ERROR_TIMEOUT)
	{
		SEC_SVR_DBG("%s", "poll() timeout");
		return SECURITY_SERVER_ERROR_SEND_FAILED;
	}

	/* Send to server */
	retval = write(sock_fd, buf, sizeof(buf));
	if(retval < sizeof(buf))
	{
		/* Write error */
		SEC_SVR_DBG("Error on write(): %d", retval);
		return SECURITY_SERVER_ERROR_SEND_FAILED;
	}
	return SECURITY_SERVER_SUCCESS;
}


/* Send debug tool launch request message to security server *
 *
 * Message format
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 
 * |---------------------------------------------------------------|
 * | version=0x01  |MessageID=0x0b |       Message Length          |
 * |---------------------------------------------------------------|
 * |                        total # of args                        |
 * |---------------------------------------------------------------|
 * |                        1st argv length                        |
 * |---------------------------------------------------------------|
 * |                                                               |
 * |                            1st argv                           |
 * |                                                               |
 * |---------------------------------------------------------------|
 * |                        2nd argv length                        |
 * |---------------------------------------------------------------|
 * |                                                               |
 * |                            2nd argv                           |
 * |                                                               |
 * |---------------------------------------------------------------|
 * |                                ...                            |
 * |---------------------------------------------------------------|
 * |                        nth argv length                        |
 * |---------------------------------------------------------------|
 * |                                                               |
 * |                            nth argv                           |
 * |                                                               |
 * |---------------------------------------------------------------|
 */
int send_launch_tool_request(int sock_fd, int argc, const char **argv)
{
	basic_header hdr;
	int retval, total_length = 0, ptr, i, tempnum;
	unsigned char *buf = NULL;

	for (i=0;i<argc;i++)
	{
		if(argv[i] == NULL)
		{
			SEC_SVR_DBG("Error: %dth argv is NULL", i);
			return SECURITY_SERVER_ERROR_INPUT_PARAM;
		}
		total_length += strlen(argv[i]);
	}

	if(total_length < 1)
	{
		SEC_SVR_DBG("Error: There is a problem in argv. [%d]", total_length);
		return SECURITY_SERVER_ERROR_INPUT_PARAM;
	}
	total_length += sizeof(hdr) + sizeof(int) +(argc * sizeof(int));

	if(total_length > 0xffff)
	{
		SEC_SVR_DBG("Buffer overflow. too big payload. [%d]", total_length);
		return SECURITY_SERVER_ERROR_INPUT_PARAM;
	}

	buf = malloc(total_length);
	if(buf == NULL)
	{
		SEC_SVR_DBG("%s", "Error: failed to malloc()");
		return SECURITY_SERVER_ERROR_OUT_OF_MEMORY;
	}

	/* Assemble header */
	hdr.version = SECURITY_SERVER_MSG_VERSION;
	hdr.msg_id = SECURITY_SERVER_MSG_TYPE_TOOL_REQUEST;
	hdr.msg_len = (unsigned short)total_length;
	memcpy(buf, &hdr, sizeof(hdr));
	ptr = sizeof(hdr);
	memcpy(buf + ptr, &argc, sizeof(int));
	ptr += sizeof(hdr);

	/* Assemple each argv length and value */
	for(i=0;i<argc;i++)
	{
		tempnum = strlen(argv[i]);
		memcpy(buf + ptr, &tempnum, sizeof(int));
		ptr += sizeof(int);
		memcpy(buf + ptr, argv[i], tempnum);
		ptr += tempnum;
	}

	/* Check poll */
	retval = check_socket_poll(sock_fd, POLLOUT, SECURITY_SERVER_SOCKET_TIMEOUT_MILISECOND);
	if(retval == SECURITY_SERVER_ERROR_POLL)
	{
		SEC_SVR_DBG("%s", "poll() error");
		retval =  SECURITY_SERVER_ERROR_SEND_FAILED;
		goto error;
		
	}
	if(retval == SECURITY_SERVER_ERROR_TIMEOUT)
	{
		SEC_SVR_DBG("%s", "poll() timeout");
		retval =  SECURITY_SERVER_ERROR_SEND_FAILED;
		goto error;
	}

	/* Send to server */
	retval = write(sock_fd, buf, total_length);
	if(retval < sizeof(buf))
	{
		/* Write error */
		SEC_SVR_DBG("Error on write(): %d", retval);
		retval =  SECURITY_SERVER_ERROR_SEND_FAILED;
		goto error;
	}
	retval = SECURITY_SERVER_SUCCESS;

error:
	if(buf != NULL)
		free(buf);
	return retval;
}

/* Send validate password request message to security server *
 *
 * Message format
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 
 * |---------------------------------------------------------------|
 * | version=0x01  |MessageID=0x0d |       Message Length          |
 * |---------------------------------------------------------------|
 */
int send_valid_pwd_request(int sock_fd)
{
	basic_header hdr;
	int retval;

	hdr.version = SECURITY_SERVER_MSG_VERSION;
	hdr.msg_id = SECURITY_SERVER_MSG_TYPE_VALID_PWD_REQUEST;
	hdr.msg_len = 0;

	/* Check poll */
	retval = check_socket_poll(sock_fd, POLLOUT, SECURITY_SERVER_SOCKET_TIMEOUT_MILISECOND);
	if(retval == SECURITY_SERVER_ERROR_POLL)
	{
		SEC_SVR_DBG("%s", "poll() error");
		retval =  SECURITY_SERVER_ERROR_SEND_FAILED;
		goto error;
		
	}
	if(retval == SECURITY_SERVER_ERROR_TIMEOUT)
	{
		SEC_SVR_DBG("%s", "poll() timeout");
		retval =  SECURITY_SERVER_ERROR_SEND_FAILED;
		goto error;
	}

	/* Send to server */
	retval = write(sock_fd, &hdr, sizeof(hdr));
	if(retval < sizeof(hdr))
	{
		/* Write error */
		SEC_SVR_DBG("Error on write(): %d", retval);
		retval =  SECURITY_SERVER_ERROR_SEND_FAILED;
		goto error;
	}
	retval = SECURITY_SERVER_SUCCESS;

error:
	return retval;
}

/* Send password set request message to security server *
 *
 * Message format
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 
 * |---------------------------------------------------------------|
 * | version=0x01  |MessageID=0x0f |       Message Length          |
 * |---------------------------------------------------------------|
 * |  cur_pwd_len  |  new_pwd_len  |                               |
 * |--------------------------------                               |
 * |                            cur pwd                            |
 * |---------------------------------------------------------------|
 * |                                                               |
 * |                            new pwd                            |
 * |                                                               |
 * |---------------------------------------------------------------|
 * |                         max attempts                          |
 * |---------------------------------------------------------------|
 * |                         valid days                            |
 * |---------------------------------------------------------------|
 */
int send_set_pwd_request(int sock_fd, 
			const char*cur_pwd, 
			const char*new_pwd,
			const unsigned int max_challenge,
			const unsigned int valid_period_in_days)
{
	basic_header hdr;
	int retval, total_length = 0, ptr;
	unsigned char *buf = NULL, cur_pwd_len, new_pwd_len;

	if(cur_pwd == NULL)
		cur_pwd_len = 0;
	else
		cur_pwd_len = strlen(cur_pwd);
	new_pwd_len = strlen(new_pwd);

	total_length += sizeof(hdr) + sizeof(char) + sizeof(char) + cur_pwd_len
		+ new_pwd_len + sizeof(unsigned int) + sizeof(unsigned int);

	buf = malloc(total_length);
	if(buf == NULL)
	{
		SEC_SVR_DBG("%s", "Error: failed to malloc()");
		return SECURITY_SERVER_ERROR_OUT_OF_MEMORY;
	}

	/* Assemble header */
	hdr.version = SECURITY_SERVER_MSG_VERSION;
	hdr.msg_id = SECURITY_SERVER_MSG_TYPE_SET_PWD_REQUEST;
	hdr.msg_len = (unsigned short)total_length;
	memcpy(buf, &hdr, sizeof(hdr));
	ptr = sizeof(hdr);
	memcpy(buf + ptr, &cur_pwd_len, sizeof(char));
	ptr += sizeof(char);
	memcpy(buf + ptr, &new_pwd_len, sizeof(char));
	ptr += sizeof(char);
	if(cur_pwd != NULL)
	{
		memcpy(buf + ptr, cur_pwd, cur_pwd_len);
		ptr += cur_pwd_len;
	}
	memcpy(buf + ptr, new_pwd, new_pwd_len);
	ptr += new_pwd_len;
	memcpy(buf + ptr, &max_challenge, sizeof(unsigned int));
	ptr += sizeof(unsigned int);
	memcpy(buf + ptr, &valid_period_in_days, sizeof(unsigned int));

	/* Check poll */
	retval = check_socket_poll(sock_fd, POLLOUT, SECURITY_SERVER_SOCKET_TIMEOUT_MILISECOND);
	if(retval == SECURITY_SERVER_ERROR_POLL)
	{
		SEC_SVR_DBG("%s", "poll() error");
		retval =  SECURITY_SERVER_ERROR_SEND_FAILED;
		goto error;
		
	}
	if(retval == SECURITY_SERVER_ERROR_TIMEOUT)
	{
		SEC_SVR_DBG("%s", "poll() timeout");
		retval =  SECURITY_SERVER_ERROR_SEND_FAILED;
		goto error;
	}

	/* Send to server */
	retval = write(sock_fd, buf, total_length);
	if(retval < sizeof(buf))
	{
		/* Write error */
		SEC_SVR_DBG("Error on write(): %d", retval);
		retval =  SECURITY_SERVER_ERROR_SEND_FAILED;
		goto error;
	}
	retval = SECURITY_SERVER_SUCCESS;

error:
	if(buf != NULL)
		free(buf);
	return retval;
}

/* Send password reset request message to security server *
 *
 * Message format
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 
 * |---------------------------------------------------------------|
 * | version=0x01  |MessageID=0x11 |       Message Length          |
 * |---------------------------------------------------------------|
 * |  new_pwd_len  |                                               |
 * |---------------------------------------------------------------|
 * |                                                               |
 * |                            new pwd                            |
 * |                                                               |
 * |---------------------------------------------------------------|
 * |                         max attempts                          |
 * |---------------------------------------------------------------|
 * |                         valid days                            |
 * |---------------------------------------------------------------|
 */
int send_reset_pwd_request(int sock_fd, 
			const char*new_pwd,
			const unsigned int max_challenge,
			const unsigned int valid_period_in_days)
{
	basic_header hdr;
	int retval, total_length = 0, ptr;
	unsigned char *buf = NULL, new_pwd_len;

	new_pwd_len = strlen(new_pwd);

	total_length += sizeof(hdr) + sizeof(char) + new_pwd_len + sizeof(unsigned int) + 
		sizeof(unsigned int);

	buf = malloc(total_length);
	if(buf == NULL)
	{
		SEC_SVR_DBG("%s", "Error: failed to malloc()");
		return SECURITY_SERVER_ERROR_OUT_OF_MEMORY;
	}

	/* Assemble header */
	hdr.version = SECURITY_SERVER_MSG_VERSION;
	hdr.msg_id = SECURITY_SERVER_MSG_TYPE_RESET_PWD_REQUEST;
	hdr.msg_len = (unsigned short)total_length;
	memcpy(buf, &hdr, sizeof(hdr));
	ptr = sizeof(hdr);
	memcpy(buf + ptr, &new_pwd_len, sizeof(char));
	ptr += sizeof(char);
	memcpy(buf + ptr, new_pwd, new_pwd_len);
	ptr += new_pwd_len;
	memcpy(buf + ptr, &max_challenge, sizeof(unsigned int));
	ptr += sizeof(unsigned int);
	memcpy(buf + ptr, &valid_period_in_days, sizeof(unsigned int));

	/* Check poll */
	retval = check_socket_poll(sock_fd, POLLOUT, SECURITY_SERVER_SOCKET_TIMEOUT_MILISECOND);
	if(retval == SECURITY_SERVER_ERROR_POLL)
	{
		SEC_SVR_DBG("%s", "poll() error");
		retval =  SECURITY_SERVER_ERROR_SEND_FAILED;
		goto error;
		
	}
	if(retval == SECURITY_SERVER_ERROR_TIMEOUT)
	{
		SEC_SVR_DBG("%s", "poll() timeout");
		retval =  SECURITY_SERVER_ERROR_SEND_FAILED;
		goto error;
	}

	/* Send to server */
	retval = write(sock_fd, buf, total_length);
	if(retval < sizeof(buf))
	{
		/* Write error */
		SEC_SVR_DBG("Error on write(): %d", retval);
		retval =  SECURITY_SERVER_ERROR_SEND_FAILED;
		goto error;
	}
	retval = SECURITY_SERVER_SUCCESS;

error:
	if(buf != NULL)
		free(buf);
	return retval;
}

/* Send password check request message to security server *
 *
 * Message format
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 
 * |---------------------------------------------------------------|
 * | version=0x01  |MessageID=0x13 |       Message Length          |
 * |---------------------------------------------------------------|
 * | challenge_len |                                               |
 * |---------------                                                |
 * |                          challenge                            |
 * |---------------------------------------------------------------|
 */
int send_chk_pwd_request(int sock_fd, const char*challenge)
{
	basic_header hdr;
	int retval, total_length = 0, ptr;
	unsigned char *buf = NULL, challenge_len;

	challenge_len = strlen(challenge);

	total_length += sizeof(hdr) + sizeof(char) + challenge_len;

	buf = malloc(total_length);
	if(buf == NULL)
	{
		SEC_SVR_DBG("%s", "Error: failed to malloc()");
		return SECURITY_SERVER_ERROR_OUT_OF_MEMORY;
	}

	/* Assemble header */
	hdr.version = SECURITY_SERVER_MSG_VERSION;
	hdr.msg_id = SECURITY_SERVER_MSG_TYPE_CHK_PWD_REQUEST;
	hdr.msg_len = (unsigned short)total_length;
	memcpy(buf, &hdr, sizeof(hdr));
	ptr = sizeof(hdr);
	memcpy(buf + ptr, &challenge_len, sizeof(char));
	ptr += sizeof(char);
	memcpy(buf + ptr, challenge, challenge_len);
	ptr += sizeof(char);

	/* Check poll */
	retval = check_socket_poll(sock_fd, POLLOUT, SECURITY_SERVER_SOCKET_TIMEOUT_MILISECOND);
	if(retval == SECURITY_SERVER_ERROR_POLL)
	{
		SEC_SVR_DBG("%s", "poll() error");
		retval =  SECURITY_SERVER_ERROR_SEND_FAILED;
		goto error;
		
	}
	if(retval == SECURITY_SERVER_ERROR_TIMEOUT)
	{
		SEC_SVR_DBG("%s", "poll() timeout");
		retval =  SECURITY_SERVER_ERROR_SEND_FAILED;
		goto error;
	}

	/* Send to server */
	retval = write(sock_fd, buf, total_length);
	if(retval < sizeof(buf))
	{
		/* Write error */
		SEC_SVR_DBG("Error on write(): %d", retval);
		retval =  SECURITY_SERVER_ERROR_SEND_FAILED;
		goto error;
	}
	retval = SECURITY_SERVER_SUCCESS;

error:
	if(buf != NULL)
		free(buf);
	return retval;
}

/* Send password history set request message to security server *
 *
 * Message format
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 
 * |---------------------------------------------------------------|
 * | version=0x01  |MessageID=0x15 |       Message Length          |
 * |---------------------------------------------------------------|
 * | challenge_len |
 * |----------------
 */
int send_set_pwd_history_request(int sock_fd, int num)
{
	basic_header hdr;
	int retval, total_length = 0, ptr;
	unsigned char history;
	unsigned char buf[sizeof(hdr) + sizeof(history)];

	total_length = sizeof(hdr) + sizeof(char);
	history = (unsigned char) num;

	/* Assemble header */
	hdr.version = SECURITY_SERVER_MSG_VERSION;
	hdr.msg_id = SECURITY_SERVER_MSG_TYPE_SET_PWD_HISTORY_REQUEST;
	hdr.msg_len = (unsigned short)total_length;
	memcpy(buf, &hdr, sizeof(hdr));
	ptr = sizeof(hdr);
	memcpy(buf + ptr, &history, sizeof(char));
	ptr += sizeof(char);

	/* Check poll */
	retval = check_socket_poll(sock_fd, POLLOUT, SECURITY_SERVER_SOCKET_TIMEOUT_MILISECOND);
	if(retval == SECURITY_SERVER_ERROR_POLL)
	{
		SEC_SVR_DBG("%s", "poll() error");
		retval =  SECURITY_SERVER_ERROR_SEND_FAILED;
		goto error;
		
	}
	if(retval == SECURITY_SERVER_ERROR_TIMEOUT)
	{
		SEC_SVR_DBG("%s", "poll() timeout");
		retval =  SECURITY_SERVER_ERROR_SEND_FAILED;
		goto error;
	}

	/* Send to server */
	retval = write(sock_fd, buf, ptr);
	if(retval < sizeof(buf))
	{
		/* Write error */
		SEC_SVR_DBG("Error on write(): %d", retval);
		retval =  SECURITY_SERVER_ERROR_SEND_FAILED;
		goto error;
	}
	retval = SECURITY_SERVER_SUCCESS;

error:
	return retval;
}

/* Receive request header */
int recv_hdr(int client_sockfd, basic_header *basic_hdr)
{
	int retval;

	/* Check poll */
	retval = check_socket_poll(client_sockfd, POLLIN, SECURITY_SERVER_SOCKET_TIMEOUT_MILISECOND);
	if(retval == SECURITY_SERVER_ERROR_POLL)
	{
		SEC_SVR_DBG("%s", "poll() error");
		return SECURITY_SERVER_ERROR_SOCKET;
	}
	if(retval == SECURITY_SERVER_ERROR_TIMEOUT)
	{
		SEC_SVR_DBG("%s", "poll() timeout");
		return SECURITY_SERVER_ERROR_TIMEOUT;
	}

	/* Receive request header first */
	retval = read(client_sockfd, basic_hdr, sizeof(basic_header));
	if(retval < sizeof(basic_header))
	{
		SEC_SVR_DBG("read failed. closing socket %d", retval);
		return SECURITY_SERVER_ERROR_RECV_FAILED;
	}

	/* Validate header */
	retval = validate_header(*basic_hdr);
	return retval;
}


/* Receive check privilege request packet body */
int recv_check_privilege_request(int sockfd, unsigned char *requested_cookie, int *requested_privilege)
{
	int retval;
	retval = read(sockfd, requested_cookie, SECURITY_SERVER_COOKIE_LEN);
	if(retval < SECURITY_SERVER_COOKIE_LEN)
	{
		SEC_SVR_DBG("Received cookie size is too small: %d", retval);
		return SECURITY_SERVER_ERROR_RECV_FAILED;
	}

	retval = read(sockfd, requested_privilege, sizeof(int));
	if(retval < sizeof(int))
	{
		SEC_SVR_DBG("privilege size is too small: %d", retval);
		return SECURITY_SERVER_ERROR_RECV_FAILED;
	}
	return SECURITY_SERVER_SUCCESS;
}

/* Receive pid request packet body */
int recv_pid_request(int sockfd, unsigned char *requested_cookie)
{
	int retval;
	retval = read(sockfd, requested_cookie, SECURITY_SERVER_COOKIE_LEN);
	if(retval < SECURITY_SERVER_COOKIE_LEN)
	{
		SEC_SVR_DBG("Received cookie size is too small: %d", retval);
		return SECURITY_SERVER_ERROR_RECV_FAILED;
	}
	return SECURITY_SERVER_SUCCESS;
}

/* Receive pid request packet body */
int recv_launch_tool_request(int sockfd, int argc, char *argv[])
{
	int retval, i, argv_len;

	argv[0] = malloc(strlen(SECURITY_SERVER_DEBUG_TOOL_PATH) + 1);
	strncpy(argv[0], SECURITY_SERVER_DEBUG_TOOL_PATH, (strlen(SECURITY_SERVER_DEBUG_TOOL_PATH) + 1));

	for(i=1;i<argc;i++)
	{
		retval = read(sockfd, &argv_len, sizeof(int));
		if(retval < sizeof(int))
		{
			SEC_SVR_DBG("Error: argv length recieve failed: %d", retval);
			free_argv(argv, argc);
			return SECURITY_SERVER_ERROR_RECV_FAILED;
		}

		argv[i] = malloc(argv_len + 1);
		if(argv[i] == NULL)
		{
			SEC_SVR_DBG("Error: malloc() failed: %d", retval);
			free_argv(argv, argc);
			return SECURITY_SERVER_ERROR_OUT_OF_MEMORY;
		}

		memset(argv[i], 0x00, argv_len + 1);
		retval = read(sockfd, argv[i], argv_len);
		if(retval < argv_len)
		{
			SEC_SVR_DBG("Error: argv recieve failed: %d", retval);
			free_argv(argv, argc);
			return SECURITY_SERVER_ERROR_RECV_FAILED;
		}
	}

	return SECURITY_SERVER_SUCCESS;
}

int recv_generic_response(int sockfd, response_header *hdr)
{
	int retval;

	/* Check poll */
	retval = check_socket_poll(sockfd, POLLIN, SECURITY_SERVER_SOCKET_TIMEOUT_MILISECOND);
	if(retval == SECURITY_SERVER_ERROR_POLL)
	{
		SEC_SVR_DBG("%s", "Client: poll() error");
		return SECURITY_SERVER_ERROR_RECV_FAILED;
	}
	if(retval == SECURITY_SERVER_ERROR_TIMEOUT)
	{
		SEC_SVR_DBG("%s", "Client: poll() timeout");
		return SECURITY_SERVER_ERROR_RECV_FAILED;
	}

	/* Receive response */
	retval = read(sockfd, hdr, sizeof(response_header));
	if(retval < sizeof(hdr) )
	{
		/* Error on socket */
		SEC_SVR_DBG("Client: Receive failed %d", retval);
		return  SECURITY_SERVER_ERROR_RECV_FAILED;
	}

	if(hdr->return_code != SECURITY_SERVER_RETURN_CODE_SUCCESS)
	{
		SEC_SVR_DBG("Client: return code is not success: %d", hdr->return_code);
		return return_code_to_error_code(hdr->return_code);
	}
	return SECURITY_SERVER_SUCCESS;
}

int recv_get_gid_response(int sockfd, response_header *hdr, int *gid)
{
	int retval;

	retval = recv_generic_response(sockfd, hdr);
	if(retval != SECURITY_SERVER_SUCCESS)
		return return_code_to_error_code(hdr->return_code);

	retval = read(sockfd, gid, sizeof(int));
	if(retval < sizeof(int))
	{
		/* Error on socket */
		SEC_SVR_DBG("Receive failed %d", retval);
		return  SECURITY_SERVER_ERROR_RECV_FAILED;
	}
	return SECURITY_SERVER_SUCCESS;
}

int recv_get_object_name(int sockfd, response_header *hdr, char *object, int max_object_size)
{
	int retval;
	char *local_obj_name = NULL;

	/* Check poll */
	retval = check_socket_poll(sockfd, POLLIN, SECURITY_SERVER_SOCKET_TIMEOUT_MILISECOND);
	if(retval == SECURITY_SERVER_ERROR_POLL)
	{
		SEC_SVR_DBG("%s", "poll() error");
		return SECURITY_SERVER_ERROR_RECV_FAILED;
	}
	if(retval == SECURITY_SERVER_ERROR_TIMEOUT)
	{
		SEC_SVR_DBG("%s", "poll() timeout");
		return SECURITY_SERVER_ERROR_RECV_FAILED;
	}

	/* Read response */
	retval = read(sockfd, hdr, sizeof(response_header));
	if(retval < sizeof(hdr) )
	{
		/* Error on socket */
		SEC_SVR_DBG("cannot recv respons: %d", retval);
		return SECURITY_SERVER_ERROR_RECV_FAILED;
	}

	if(hdr->return_code == SECURITY_SERVER_RETURN_CODE_SUCCESS)
	{
		if(max_object_size < hdr->basic_hdr.msg_len)
		{
			SEC_SVR_DBG("Object name is too small need %d bytes, but %d bytes", hdr->basic_hdr.msg_len, max_object_size);
			return SECURITY_SERVER_ERROR_BUFFER_TOO_SMALL;
		}
		if(hdr->basic_hdr.msg_len > SECURITY_SERVER_MAX_OBJ_NAME)
		{
			SEC_SVR_DBG("Received object name is too big. %d", hdr->basic_hdr.msg_len);
			return SECURITY_SERVER_ERROR_BAD_RESPONSE;
		}

		local_obj_name = malloc(hdr->basic_hdr.msg_len + 1);
		if(local_obj_name == NULL)
		{
			SEC_SVR_DBG("%s", "Out of memory error");
			return SECURITY_SERVER_ERROR_OUT_OF_MEMORY;
		}
		
		retval = read(sockfd, local_obj_name, hdr->basic_hdr.msg_len);
		if(retval < (hdr->basic_hdr.msg_len))
		{
			/* Error on socket */
			SEC_SVR_DBG("read() failed: %d", retval);
			if(local_obj_name != NULL)
				free(local_obj_name);
			return SECURITY_SERVER_ERROR_RECV_FAILED;
		}
		memcpy(object, local_obj_name, hdr->basic_hdr.msg_len);
		object[hdr->basic_hdr.msg_len] = 0;
		retval = SECURITY_SERVER_SUCCESS;
	}
	else
	{
		SEC_SVR_DBG("Error received. return code: %d", hdr->return_code);
		retval = return_code_to_error_code(hdr->return_code);
		return retval;
	}

	if(local_obj_name != NULL)
		free(local_obj_name);
	return SECURITY_SERVER_SUCCESS;
}

int recv_cookie(int sockfd, response_header *hdr, char *cookie)
{
	int retval;

	retval = recv_generic_response(sockfd, hdr);
	if(retval != SECURITY_SERVER_SUCCESS)
		return return_code_to_error_code(hdr->return_code);

	retval = read(sockfd, cookie, SECURITY_SERVER_COOKIE_LEN);
	if(retval < SECURITY_SERVER_COOKIE_LEN)
	{
		/* Error on socket */
		SEC_SVR_DBG("read() failed: %d", retval);
		return SECURITY_SERVER_ERROR_RECV_FAILED;
	}
	return SECURITY_SERVER_SUCCESS;
}

int recv_privilege_check_response(int sockfd, response_header *hdr)
{
	int retval;

	retval = recv_generic_response(sockfd, hdr);
	if(hdr->return_code != SECURITY_SERVER_RETURN_CODE_ACCESS_GRANTED &&
			hdr->return_code != SECURITY_SERVER_RETURN_CODE_ACCESS_DENIED) 
	{
		SEC_SVR_DBG("response error: %d", hdr->return_code);
		return return_code_to_error_code(hdr->return_code);
	}
	return SECURITY_SERVER_SUCCESS;
}

int recv_pid_response(int sockfd, response_header *hdr, int *pid)
{
	int retval;

	retval = recv_generic_response(sockfd, hdr);
	if(retval != SECURITY_SERVER_SUCCESS)
		return return_code_to_error_code(hdr->return_code);

	retval = read(sockfd, pid, sizeof(int));
	if(retval < sizeof(int))
	{
		/* Error on socket */
		SEC_SVR_DBG("Client: Receive failed %d", retval);
		return  SECURITY_SERVER_ERROR_RECV_FAILED;
	}
	return SECURITY_SERVER_SUCCESS;
}

int recv_pwd_response(int sockfd, response_header *hdr, 
	unsigned int *current_attempts, 
	unsigned int *max_attempts, 
	unsigned int *valid_secs)
{
	int retval;
	*current_attempts = 0;
	*max_attempts = 0;
	*valid_secs = 0;

	retval = recv_generic_response(sockfd, hdr);

	switch(retval)
	{
		case SECURITY_SERVER_ERROR_PASSWORD_EXIST:
		case SECURITY_SERVER_ERROR_NO_PASSWORD:
		case SECURITY_SERVER_ERROR_PASSWORD_MISMATCH:
		case SECURITY_SERVER_ERROR_PASSWORD_RETRY_TIMER:
		case SECURITY_SERVER_ERROR_PASSWORD_MAX_ATTEMPTS_EXCEEDED:
		case SECURITY_SERVER_ERROR_PASSWORD_EXPIRED:
		case SECURITY_SERVER_ERROR_PASSWORD_REUSED:
		case SECURITY_SERVER_SUCCESS:
			break;
		default:
			return return_code_to_error_code(hdr->return_code);
	}

	retval = read(sockfd, current_attempts, sizeof(unsigned int));
	if(retval < sizeof(unsigned int))
	{
		/* Error on socket */
		SEC_SVR_DBG("Client: Receive failed %d", retval);
		return  SECURITY_SERVER_ERROR_RECV_FAILED;
	}
	retval = read(sockfd, max_attempts, sizeof(unsigned int));
	if(retval < sizeof(unsigned int))
	{
		/* Error on socket */
		SEC_SVR_DBG("Client: Receive failed %d", retval);
		return  SECURITY_SERVER_ERROR_RECV_FAILED;
	}
	retval = read(sockfd, valid_secs, sizeof(unsigned int));
	if(retval < sizeof(unsigned int))
	{
		/* Error on socket */
		SEC_SVR_DBG("Client: Receive failed %d", retval);
		return  SECURITY_SERVER_ERROR_RECV_FAILED;
	}
}

/* Authenticate client application *
 * Currently it only gets peer's credential information only *
 * If we need, we can extend in the futer */
int authenticate_client_application(int sockfd, int *pid, int *uid)
{
	int retval = 0;
	struct ucred cr;
	unsigned int cl = sizeof(cr);

	/* get PID of socket peer */
	if(getsockopt(sockfd, SOL_SOCKET, SO_PEERCRED, &cr, &cl) != 0)
	{
		retval = SECURITY_SERVER_ERROR_SOCKET;
		SEC_SVR_DBG("%s", "getsockopt failed");
		*pid = 0;
		goto error;
	}
	*pid = cr.pid;
	*uid = cr.uid;

	/* Authenticate client that it's real client application */
	/* TBA */
	
error:
	return retval;
}

/* Checking client is pre-defined middleware daemons *
 * Check privilege API is only allowed to middleware daemons *
 * cmd line list of middleware daemons are listed in
 * /usr/share/security-server/mw-list */
int search_middleware_cmdline(char *cmdline)
{
	FILE *fp = NULL;
	int ret;
	char middleware[SECURITY_SERVER_MAX_PATH_LEN];

	/* Open the list file */
	fp = fopen(SECURITY_SERVER_MIDDLEWARE_LIST_PATH, "r");
	if(fp == NULL)
	{
		/* error on file */
		SEC_SVR_DBG("%s", "Error oening mw-list file");
		return SECURITY_SERVER_ERROR_FILE_OPERATION; 
	}

	/* Search each line */
	ret = SECURITY_SERVER_ERROR_AUTHENTICATION_FAILED;
	while(fgets(middleware, SECURITY_SERVER_MAX_PATH_LEN, fp) != NULL)
	{
		if(strncmp(middleware, cmdline, strlen(middleware)-1) == 0)
		{
			/* found */
			SEC_SVR_DBG("%s", "found matching cmd line");
			ret = SECURITY_SERVER_SUCCESS;
			break;
		}

	}
	if(fp != NULL)
		fclose(fp);
	return ret;
}

/* Authenticate the application is middleware daemon
 * The middleware must run as root and the cmd line must be pre listed */
int authenticate_client_middleware(int sockfd, int *pid)
{
	int retval = SECURITY_SERVER_ERROR_AUTHENTICATION_FAILED;
	struct ucred cr;
	unsigned int cl = sizeof(cr);
	char *cmdline = NULL;

	*pid = 0;

	/* get PID of socket peer */
	if(getsockopt(sockfd, SOL_SOCKET, SO_PEERCRED, &cr, &cl) != 0)
	{
		retval = SECURITY_SERVER_ERROR_SOCKET;
		SEC_SVR_DBG("%s", "Error on getsockopt");
		goto error;
	}
	
	/* All middlewares will run as root */
	if(cr.uid != 0)
	{
		retval = SECURITY_SERVER_ERROR_AUTHENTICATION_FAILED;
		SEC_SVR_DBG("Non root process has called API: %d", cr.uid);
		goto error;
	}

	/* Read command line of the PID from proc fs */
	cmdline = read_cmdline_from_proc(cr.pid);
	if(cmdline  == NULL)
	{
		/* It's weired. no file in proc file system, */
		retval = SECURITY_SERVER_ERROR_FILE_OPERATION;
		SEC_SVR_DBG("Error on opening /proc/%d/cmdline", cr.pid);
		goto error;
	}

	/* Search cmdline of the peer that is really middleware executable */
	retval = search_middleware_cmdline(cmdline);
	*pid = cr.pid;

error:
	if(cmdline != NULL)
		free(cmdline);

	return retval;
}

/* Authenticate the application is middleware daemon
 * The middleware must run as root and the cmd line must be pre listed */
int authenticate_developer_shell(int sockfd)
{
	int retval = SECURITY_SERVER_ERROR_AUTHENTICATION_FAILED;
	struct ucred cr;
	unsigned int cl = sizeof(cr);
	char *cmdline = NULL;

	/* get PID of socket peer */
	if(getsockopt(sockfd, SOL_SOCKET, SO_PEERCRED, &cr, &cl) != 0)
	{
		retval = SECURITY_SERVER_ERROR_SOCKET;
		SEC_SVR_DBG("%s", "Error on getsockopt");
		goto error;
	}
	
	/* All middlewares will run as root */
	if(cr.uid != SECURITY_SERVER_DEVELOPER_UID)
	{
		retval = SECURITY_SERVER_ERROR_AUTHENTICATION_FAILED;
		SEC_SVR_DBG("Non root process has called API: %d", cr.uid);
		goto error;
	}

	/* Read command line of the PID from proc fs */
	cmdline = read_cmdline_from_proc(cr.pid);
	if(cmdline  == NULL)
	{
		/* It's weired. no file in proc file system, */
		retval = SECURITY_SERVER_ERROR_FILE_OPERATION;
		SEC_SVR_DBG("Error on opening /proc/%d/cmdline", cr.pid);
		goto error;
	}

	/* Search cmdline of the peer that is really debug tool */
	if(strncmp(cmdline, SECURITY_SERVER_DEBUG_TOOL_PATH, strlen(SECURITY_SERVER_DEBUG_TOOL_PATH)) != 0)
	{
		SEC_SVR_DBG("Error: Wrong cmdline [%s]", cmdline);
		retval = SECURITY_SERVER_ERROR_AUTHENTICATION_FAILED;
		goto error;
	}
	retval = SECURITY_SERVER_SUCCESS;
	SEC_SVR_DBG("%s", "Client Authenticated");

error:
	if(cmdline != NULL)
		free(cmdline);

	return retval;
}

int free_argv(char **argv, int argc)
{
	int i;
	if(argv == NULL)
	{
		SEC_SVR_DBG("%s", "Cannot free NULL pointer");
		return SECURITY_SERVER_ERROR_INPUT_PARAM;
	}
	for (i=0;i<argc;i++)
	{
		if(argv[i] != NULL)
			free(argv[i]);
	}
	free(argv);
	return SECURITY_SERVER_SUCCESS;
}

