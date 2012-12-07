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
#include <fcntl.h>
#include <sys/un.h>
#include <errno.h>
#include <unistd.h>

#include "security-server-common.h"
#include "security-server-cookie.h"
#include "security-server-comm.h"
#include "security-server-util.h"
#include "security-server.h"


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
 unsigned char * get_all_cookie_info(cookie_list *list, int *size)
{
	cookie_list *current = list;
	int ptr, total_num, total_size, tempnum, i;
	unsigned char *buf = NULL, *tempptr = NULL;
	response_header hdr;

	total_size = sizeof(hdr) + sizeof(int);

	buf = malloc(total_size); /* header size */
	ptr = sizeof(hdr) + sizeof(int);
	total_num = 0;  /* Total # of cookies initial value */

	while(current != NULL)
	{
		current = garbage_collection(current);
		if(current == NULL)
			break;

		total_num++;
		total_size += sizeof(int) + sizeof(int) + SECURITY_SERVER_COOKIE_LEN + sizeof(int) + current->path_len + (current->permission_len * sizeof(int));
		tempptr = realloc(buf, total_size);
		if(tempptr == NULL)
		{
			SEC_SVR_DBG("%s", "Out of memory");
			return NULL;
		}
		buf = tempptr;

		tempnum = current->path_len;
		memcpy(buf+ptr, &tempnum, sizeof(int));
		ptr += sizeof(int);
		tempnum = current->permission_len;
		memcpy(buf+ptr, &tempnum, sizeof(int));
		ptr += sizeof(int);
		memcpy(buf+ptr, current->cookie, SECURITY_SERVER_COOKIE_LEN);
		ptr += SECURITY_SERVER_COOKIE_LEN;
		tempnum = current->pid;
		memcpy(buf+ptr, &tempnum, sizeof(int));
		ptr += sizeof(int);
		memcpy(buf+ptr, current->path, current->path_len);
		ptr += current->path_len;

		for(i=0;i<current->permission_len;i++)
		{
			tempnum = current->permissions[i];
			memcpy(buf+ptr, &tempnum, sizeof(int));
			ptr += sizeof(int);
		}
		current = current->next;
	}

	if(total_size > 65530)
	{
		SEC_SVR_DBG("Packet too big. message length overflow: %d", total_size);
		free(buf);
		return  NULL;
	}

	hdr.basic_hdr.version = SECURITY_SERVER_MSG_VERSION;
	hdr.basic_hdr.msg_id = SECURITY_SERVER_MSG_TYPE_GET_ALL_COOKIES_RESPONSE;
	hdr.basic_hdr.msg_len =(unsigned short)( total_size - sizeof(hdr));
	hdr.return_code = SECURITY_SERVER_RETURN_CODE_SUCCESS;
	memcpy(buf, &hdr, sizeof(hdr));
	tempnum = total_num;
	memcpy(buf + sizeof(hdr), &tempnum, sizeof(int));
	*size = total_size;
	return buf;
}

int send_all_cookie_info(const unsigned char *buf, int size, int sockfd)
{
	int ret;
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

	/* Send to client */
	ret = write(sockfd, buf, size);

	if(ret < size)
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
	int total_size, ptr = 0, tempnum, ret, i;

	total_size = sizeof(hdr) + sizeof(int) + sizeof(int) + SECURITY_SERVER_COOKIE_LEN + sizeof(int) + list->path_len + (list->permission_len * sizeof(int));
	buf = malloc(total_size);
	if(buf == NULL)
	{
		SEC_SVR_DBG("%s", "Out of memory");
		return SECURITY_SERVER_ERROR_OUT_OF_MEMORY;
	}

	hdr.basic_hdr.version = SECURITY_SERVER_MSG_VERSION;
	hdr.basic_hdr.msg_id = SECURITY_SERVER_MSG_TYPE_GET_COOKIEINFO_RESPONSE;
	hdr.basic_hdr.msg_len =sizeof(int) + sizeof(int) + SECURITY_SERVER_COOKIE_LEN + sizeof(int) + list->path_len + (list->permission_len * sizeof(int));
	hdr.return_code = SECURITY_SERVER_RETURN_CODE_SUCCESS;
	memcpy(buf, &hdr, sizeof(hdr));
	ptr += sizeof(hdr);

	tempnum = list->path_len;
	memcpy(buf+ptr, &tempnum, sizeof(int));
	ptr += sizeof(int);
	tempnum = list->permission_len;
	memcpy(buf+ptr, &tempnum, sizeof(int));
	ptr += sizeof(int);
	memcpy(buf+ptr, list->cookie, SECURITY_SERVER_COOKIE_LEN);
	ptr += SECURITY_SERVER_COOKIE_LEN;
	tempnum = list->pid;
	memcpy(buf+ptr, &tempnum, sizeof(int));
	ptr += sizeof(int);
	memcpy(buf+ptr, list->path, list->path_len);
	ptr += list->path_len;

	for(i=0;i<list->permission_len;i++)
	{
		tempnum = list->permissions[i];
		memcpy(buf+ptr, &tempnum, sizeof(int));
		ptr += sizeof(int);
	}

	ret = check_socket_poll(sockfd, POLLOUT, SECURITY_SERVER_SOCKET_TIMEOUT_MILISECOND);
	if(ret == SECURITY_SERVER_ERROR_POLL)
	{
		SEC_SVR_DBG("%s", "poll() error");
		free(buf);
		return SECURITY_SERVER_ERROR_SEND_FAILED;
	}
	if(ret == SECURITY_SERVER_ERROR_TIMEOUT)
	{
		SEC_SVR_DBG("%s", "poll() timeout");
		free(buf);
		return SECURITY_SERVER_ERROR_SEND_FAILED;
	}

	/* Send to client */
	ret = write(sockfd, buf, total_size);
	free(buf);
	if(ret < total_size)
	    return SECURITY_SERVER_ERROR_SEND_FAILED;
	return SECURITY_SERVER_SUCCESS;
}

int util_process_all_cookie(int sockfd, cookie_list* list)
{
	unsigned char *buf = NULL;
	int ret;
	buf = get_all_cookie_info(list, &ret);
	if(buf == NULL)
	{
		return SECURITY_SERVER_ERROR_OUT_OF_MEMORY;
	}

	ret = send_all_cookie_info(buf, ret, sockfd);

	if(buf != NULL)
		free(buf);
	return ret;
}
int util_process_cookie_from_pid(int sockfd, cookie_list* list)
{
	int pid, ret;
	cookie_list *result = NULL;

	ret = read(sockfd, &pid, sizeof(int));
	if(ret < sizeof(int))
	{
		SEC_SVR_DBG("Received cookie size is too small: %d", ret);
		return SECURITY_SERVER_ERROR_RECV_FAILED;
	}
	if(pid == 0)
	{
		SEC_SVR_DBG("%s", "ERROR: Default cookie is not allowed to be retrieved");
		ret = send_generic_response(sockfd, SECURITY_SERVER_MSG_TYPE_GET_COOKIEINFO_RESPONSE,
			SECURITY_SERVER_RETURN_CODE_BAD_REQUEST);
		if(ret != SECURITY_SERVER_SUCCESS)
		{
			SEC_SVR_DBG("ERROR: Cannot send generic response: %d", ret);
		}
	}
	result = search_cookie_from_pid(list, pid);
	if(result == NULL)
	{
		ret = send_generic_response(sockfd, SECURITY_SERVER_MSG_TYPE_GET_COOKIEINFO_RESPONSE,
			SECURITY_SERVER_RETURN_CODE_NO_SUCH_COOKIE);
		if(ret != SECURITY_SERVER_SUCCESS)
		{
			SEC_SVR_DBG("ERROR: Cannot send generic response: %d", ret);
		}
	}
	else
	{
		ret = send_one_cookie_info(result, sockfd);
		if(ret != SECURITY_SERVER_SUCCESS)
		{
			SEC_SVR_DBG("ERROR: Cannot send cookie info response: %d", ret);
		}
	}
	
	return ret;
}

int util_process_cookie_from_cookie(int sockfd, cookie_list* list)
{
	unsigned char cookie[SECURITY_SERVER_COOKIE_LEN];
	int ret;
	cookie_list *result = NULL;

	ret = read(sockfd, cookie, SECURITY_SERVER_COOKIE_LEN);
	if(ret < SECURITY_SERVER_COOKIE_LEN)
	{
		SEC_SVR_DBG("Received cookie size is too small: %d", ret);
		return SECURITY_SERVER_ERROR_RECV_FAILED;
	}
	result = search_cookie(list, cookie, 0);
	if(result == NULL)
	{
		ret = send_generic_response(sockfd, SECURITY_SERVER_MSG_TYPE_GET_COOKIEINFO_RESPONSE,
			SECURITY_SERVER_RETURN_CODE_NO_SUCH_COOKIE);
		if(ret != SECURITY_SERVER_SUCCESS)
		{
			SEC_SVR_DBG("ERROR: Cannot send generic response: %d", ret);
		}
	}
	else
	{
		ret = send_one_cookie_info(result, sockfd);
		if(ret != SECURITY_SERVER_SUCCESS)
		{
			SEC_SVR_DBG("ERROR: Cannot send cookie info response: %d", ret);
		}
	}
	
	return ret;
}
