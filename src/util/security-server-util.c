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

#include "security-server.h"
#include "security-server-common.h"
#include "security-server-util.h"
#include "security-server-comm.h"

#define TOTAL_PATH_MAX 256

#define mszBase64Table  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
#define BASE64_PAD      '='



 void printusage(char *cmdline)
{
	printf("%s\n", "Usage: ");
	printf("%s [Options]\n", cmdline);
	printf("%s\n", "[Options]");
	printf("%s\n", "-a:\tList all active cookies ");
	printf("%s\n", "-f [filename]:\tList a specific cookie information from file");
	printf("%s\n", "\tThe file must contain binary form of cookie");
	printf("%s\n", "-p [pid]:\tList a specific cookie information for a process by PID");
	printf("%s\n", "-s [base64 encoded cookie]:\tList a specific cookie information for a process by given base64 encoded cookie value");
	printf("%s\n", "Example:");
	printf("%s -a\n", cmdline);
	printf("%s -f /tmp/mycookie.bin\n", cmdline);
	printf("%s -p 2115\n", cmdline);
	printf("%s -s asC34fddaxd6NDVDA43GFD345TfCADF==\n", cmdline);
}

void printstr(const unsigned char *data, int size)
{
	int i;
	for(i=0;i<size;i++)
	{
		printf("%c", data[i]);
	}
	printf("\n");
}

void printperm(const unsigned char *data, int num)
{
	int i, ptr, tempnum;
	for(i=0, ptr=0;i<num;i++)
	{
		memcpy(&tempnum, data+ptr, sizeof(int));
		printf("%d, ", tempnum);
		ptr+= sizeof(int);
		if(i % 6 == 0 && i != 0)
			printf("\n");
	}
	printf("\n");
}

/* Send all cookie information request packet to security server *
 * 
 * Message format
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * |---------------------------------------------------------------|
 * | version=0x01  |MessageID=0x51 |       Message Length = 0      |
 * |---------------------------------------------------------------|
 */
int send_all_cookie_info_request(int sockfd)
{

	basic_header hdr;
	int retval;

	/* Assemble header */
	hdr.version = SECURITY_SERVER_MSG_VERSION;
	hdr.msg_id = SECURITY_SERVER_MSG_TYPE_GET_ALL_COOKIES_REQUEST;
	hdr.msg_len = 0;

	/* Check poll */
	retval = check_socket_poll(sockfd, POLLOUT, SECURITY_SERVER_SOCKET_TIMEOUT_MILISECOND);
	if(retval == SECURITY_SERVER_ERROR_POLL)
	{
		printf("Error: %s\n", "poll() error");
		return SECURITY_SERVER_ERROR_SEND_FAILED;
	}
	if(retval == SECURITY_SERVER_ERROR_TIMEOUT)
	{
		printf("Error: %s\n", "poll() timeout");
		return SECURITY_SERVER_ERROR_SEND_FAILED;
	}

	/* Send to server */
	retval = TEMP_FAILURE_RETRY(write(sockfd, &hdr, sizeof(hdr)));
	if(retval < sizeof(hdr))
	{
		/* Write error */
		printf("Error on write(): %d\n", retval);
		return SECURITY_SERVER_ERROR_SEND_FAILED;
	}
	return SECURITY_SERVER_SUCCESS;	
}

int recv_all_cookie_info(int sockfd)
{
	int retval, total_cookie, ptr = 0, i, cmdline_len, perm_len, recved_pid;
	response_header hdr;
	unsigned char *buf = NULL;

	/* Check poll */
	retval = check_socket_poll(sockfd, POLLIN, SECURITY_SERVER_SOCKET_TIMEOUT_MILISECOND);
	if(retval == SECURITY_SERVER_ERROR_POLL)
	{
		printf("Error: %s\n", "poll() error");
		return SECURITY_SERVER_ERROR_RECV_FAILED;
	}
	if(retval == SECURITY_SERVER_ERROR_TIMEOUT)
	{
		printf("Error: %s\n", "poll() timeout");
		return SECURITY_SERVER_ERROR_RECV_FAILED;
	}

	/* Receive response */
	retval = TEMP_FAILURE_RETRY(read(sockfd, &hdr, sizeof(response_header)));
	if(retval < sizeof(hdr) )
	{
		/* Error on socket */
		printf("Error: Receive failed %d\n", retval);
		return  SECURITY_SERVER_ERROR_RECV_FAILED;
	}

	if(hdr.return_code != SECURITY_SERVER_RETURN_CODE_SUCCESS)
	{
		printf("Error: response error: %d\n", hdr.return_code);
		return return_code_to_error_code(hdr.return_code);
	}

	if(hdr.basic_hdr.msg_id != SECURITY_SERVER_MSG_TYPE_GET_ALL_COOKIES_RESPONSE)
	{
		printf("Error: response error: different msg type %d\n", hdr.basic_hdr.msg_id );
		return SECURITY_SERVER_ERROR_BAD_RESPONSE;
	}

	buf = malloc(hdr.basic_hdr.msg_len);
	if(buf == NULL)
	{
		printf("Error: Out of memory\n");
		return SECURITY_SERVER_ERROR_OUT_OF_MEMORY;
	}

	retval = TEMP_FAILURE_RETRY(read(sockfd, buf, hdr.basic_hdr.msg_len));
	if(retval < hdr.basic_hdr.msg_len)
	{
		printf("Error: receiving too small amount. %d, %d\n", retval,  hdr.basic_hdr.msg_len);
		printhex(buf, retval);
		if(buf != NULL)
			free(buf);
		return SECURITY_SERVER_ERROR_BAD_RESPONSE;
	}

	memcpy(&total_cookie, buf, sizeof(int));
	if(total_cookie == 0)
	{
		printf("There is no cookie available\n");
		if(buf != NULL)
			free(buf);
		return SECURITY_SERVER_SUCCESS;
	}
	ptr = sizeof(int);
	printf("--------------------------------\n");
	for(i=0;i<total_cookie;i++)
	{
		printf("%dth cookie:\n", i+1);
		memcpy(&cmdline_len, buf+ptr, sizeof(int));
		ptr += sizeof(int);
		memcpy(&perm_len, buf+ptr, sizeof(int));
		ptr+= sizeof(int);

		printf("%s\n", "Cookie:");
		printhex(buf + ptr, SECURITY_SERVER_COOKIE_LEN);
		ptr += SECURITY_SERVER_COOKIE_LEN;
		memcpy(&recved_pid, buf+ptr, sizeof(int));
		ptr+= sizeof(int);
		if(recved_pid == 0)
		{
			printf("PID: %d (default cookie - for all root processes)\n", recved_pid);
			printf("%s\n", "cmdline: N/A");
			printf("%s\n", "Permissions (gids): N/A");
		}
		else
		{
			printf("PID: %d\n", recved_pid);

			printf("%s\n", "cmdline:");
			printstr(buf + ptr, cmdline_len);
			ptr += cmdline_len;

			printf("%s\n", "Permissions (gids):");
			printperm(buf + ptr, perm_len);
			ptr += (perm_len * sizeof(int));
		}
		printf("--------------------------------\n");
	}
	if(buf != NULL)
		free(buf);
	return SECURITY_SERVER_SUCCESS;
}

/* Send cookie information request from cookie packet to security server *
 * 
 * Message format
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * |---------------------------------------------------------------|
 * | version=0x01  |MessageID=0x55 |       Message Length = 20     |
 * |---------------------------------------------------------------|
 * |                                                               |
 * |                         cookie                                |
 * |                                                               |
 * |---------------------------------------------------------------|
 */
int send_cookie_info_request_from_cookie(int sockfd, const unsigned char *cookie)
{

	basic_header hdr;
	int retval;
	int size = sizeof(hdr) + SECURITY_SERVER_COOKIE_LEN;
	unsigned char buf[size];

	/* Assemble header */
	hdr.version = SECURITY_SERVER_MSG_VERSION;
	hdr.msg_id = SECURITY_SERVER_MSG_TYPE_GET_COOKIEINFO_FROM_COOKIE_REQUEST;
	hdr.msg_len = SECURITY_SERVER_COOKIE_LEN;

	memcpy(buf, &hdr, sizeof(hdr));
	memcpy(buf + sizeof(hdr), cookie, SECURITY_SERVER_COOKIE_LEN);

	/* Check poll */
	retval = check_socket_poll(sockfd, POLLOUT, SECURITY_SERVER_SOCKET_TIMEOUT_MILISECOND);
	if(retval == SECURITY_SERVER_ERROR_POLL)
	{
		printf("Error: %s\n", "poll() error");
		return SECURITY_SERVER_ERROR_SEND_FAILED;
	}
	if(retval == SECURITY_SERVER_ERROR_TIMEOUT)
	{
		printf("Error: %s\n", "poll() timeout");
		return SECURITY_SERVER_ERROR_SEND_FAILED;
	}

	/* Send to server */
	retval = TEMP_FAILURE_RETRY(write(sockfd, buf, size));
	if(retval < size)
	{
		/* Write error */
		printf("Error on write(): %d\n", retval);
		return SECURITY_SERVER_ERROR_SEND_FAILED;
	}
	return SECURITY_SERVER_SUCCESS;	
}

/* Send cookie information request from pid packet to security server *
 * 
 * Message format
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * |---------------------------------------------------------------|
 * | version=0x01  |MessageID=0x53 |       Message Length = 20     |
 * |---------------------------------------------------------------|
 * |                            pid                                |
 * |---------------------------------------------------------------|
 */
int send_cookie_info_request_from_pid(int sockfd, int pid)
{
	basic_header hdr;
	int retval;
	int size = sizeof(hdr) + sizeof(int);
	unsigned char buf[size];

	/* Assemble header */
	hdr.version = SECURITY_SERVER_MSG_VERSION;
	hdr.msg_id = SECURITY_SERVER_MSG_TYPE_GET_COOKIEINFO_FROM_PID_REQUEST;
	hdr.msg_len = SECURITY_SERVER_COOKIE_LEN;
	memcpy(buf, &hdr, sizeof(hdr));
	memcpy(buf+sizeof(hdr), &pid, sizeof(int));

	/* Check poll */
	retval = check_socket_poll(sockfd, POLLOUT, SECURITY_SERVER_SOCKET_TIMEOUT_MILISECOND);
	if(retval == SECURITY_SERVER_ERROR_POLL)
	{
		printf("Error: %s\n", "poll() error");
		return SECURITY_SERVER_ERROR_SEND_FAILED;
	}
	if(retval == SECURITY_SERVER_ERROR_TIMEOUT)
	{
		printf("Error: %s\n", "poll() timeout");
		return SECURITY_SERVER_ERROR_SEND_FAILED;
	}

	/* Send to server */
	retval = TEMP_FAILURE_RETRY(write(sockfd, buf, size));
	if(retval < size)
	{
		/* Write error */
		printf("Error on write(): %d\n", retval);
		return SECURITY_SERVER_ERROR_SEND_FAILED;
	}
	return SECURITY_SERVER_SUCCESS;	
}

int recv_cookie_info_response(sockfd)
{
	unsigned char *buf = NULL;
	int retval, cmdline_len, perm_len, recved_pid, ptr = 0;
	response_header hdr;

	/* Check poll */
	retval = check_socket_poll(sockfd, POLLIN, SECURITY_SERVER_SOCKET_TIMEOUT_MILISECOND);
	if(retval == SECURITY_SERVER_ERROR_POLL)
	{
		printf("Error: %s\n", "poll() error");
		return SECURITY_SERVER_ERROR_RECV_FAILED;
	}
	if(retval == SECURITY_SERVER_ERROR_TIMEOUT)
	{
		printf("Error: %s\n", "poll() timeout");
		return SECURITY_SERVER_ERROR_RECV_FAILED;
	}

	/* Receive response */
	retval = TEMP_FAILURE_RETRY(read(sockfd, &hdr, sizeof(response_header)));
	if(retval < sizeof(hdr) )
	{
		/* Error on socket */
		printf("Error: Receive failed %d\n", retval);
		return  SECURITY_SERVER_ERROR_RECV_FAILED;
	}

	if(hdr.return_code != SECURITY_SERVER_RETURN_CODE_SUCCESS)
	{
		printf("Error: response error: %d\n", hdr.return_code);
		return return_code_to_error_code(hdr.return_code);
	}

	if(hdr.basic_hdr.msg_id != SECURITY_SERVER_MSG_TYPE_GET_COOKIEINFO_RESPONSE)
	{
		printf("Error: response error: different msg type %d\n" ,hdr.basic_hdr.msg_id);
		return SECURITY_SERVER_ERROR_BAD_RESPONSE;
	}

	buf = malloc(hdr.basic_hdr.msg_len);
	if(buf == NULL)
	{
		printf("Error: Out of memory\n");
		return SECURITY_SERVER_ERROR_OUT_OF_MEMORY;
	}

	retval = TEMP_FAILURE_RETRY(read(sockfd, buf, hdr.basic_hdr.msg_len));
	if(retval < hdr.basic_hdr.msg_len)
	{
		printf("Error: receiving too small amount. %d, %d\n", retval,  hdr.basic_hdr.msg_len);
		printhex(buf, retval);
		if(buf != NULL)
			free(buf);
		return SECURITY_SERVER_ERROR_BAD_RESPONSE;
	}

	memcpy(&cmdline_len, buf+ptr, sizeof(int));
	ptr += sizeof(int);
	memcpy(&perm_len, buf+ptr, sizeof(int));
	ptr+= sizeof(int);

	printf("%s\n", "Cookie:");
	printhex(buf + ptr, SECURITY_SERVER_COOKIE_LEN);
	ptr += SECURITY_SERVER_COOKIE_LEN;
	memcpy(&recved_pid, buf+ptr, sizeof(int));
	ptr+= sizeof(int);
	if(recved_pid == 0)
	{
		printf("PID: %d (default cookie - for all root processes)\n", recved_pid);
		printf("%s\n", "cmdline: N/A");
		printf("%s\n", "Permissions (gids): N/A");
	}
	else
	{
		printf("PID: %d\n", recved_pid);

		printf("%s\n", "cmdline:");
		printstr(buf + ptr, cmdline_len);
		ptr += cmdline_len;

		printf("%s\n", "Permissions (gids):");
		printperm(buf + ptr, perm_len);
	}

	free(buf);

	return SECURITY_SERVER_SUCCESS;
}

void util_send_all_cookie_info_request(void)
{
	int sockfd = -1, retval;

	retval = connect_to_server(&sockfd);
	if(retval != SECURITY_SERVER_SUCCESS)
	{
		/* Error on socket */
		printf("Error: %s\n", "connection failed");
		goto error;
	}

	/* make request packet */
	retval = send_all_cookie_info_request(sockfd);
	if(retval != SECURITY_SERVER_SUCCESS)
	{
		/* Error on socket */
		SEC_SVR_DBG("Error: send request failed: %d", retval);
		goto error;
	}
	retval = recv_all_cookie_info(sockfd);
	if(retval <0)
	{
		printf("Error: Error receiving cookie list: %d\n", retval);
		goto error;
	}

error:
	if(sockfd > 0)
	{
		close(sockfd);
	}
	return;
}

void util_read_cookie_from_bin_file(unsigned char *cookie, const char *path)
{
	char total_path[TOTAL_PATH_MAX] = {0, };
	FILE *fp = NULL;
	int ret;

	if(path[0] == '/' || (path[0] == '.' && path[1] == '/'))
	{
		/* Using absolute path */
		strncpy(total_path, path, TOTAL_PATH_MAX);
	}
	else
	{
		if (getcwd(total_path, TOTAL_PATH_MAX) == NULL)
		{
			printf("Cannot open cookie file\n");
			exit(1);
		}
		snprintf(total_path, TOTAL_PATH_MAX, "%s/%s", total_path, path);
	}

	fp = fopen(total_path, "rb");
	if(fp == NULL)
	{
		printf("Cannot open cookie file\n");
		exit(1);
	}

	ret = fread(cookie, 1, SECURITY_SERVER_COOKIE_LEN, fp);
	if(ret < SECURITY_SERVER_COOKIE_LEN)
	{
		printf("Cannot read cookie file: %d\n", ret);
		fclose(fp);
		exit(1);
	}

	fclose(fp);
	return;
}

void util_send_cookie_info_request_from_cookie(unsigned char *cookie)
{
	int sockfd = -1, retval;

	retval = connect_to_server(&sockfd);
	if(retval != SECURITY_SERVER_SUCCESS)
	{
		/* Error on socket */
		printf("Error: %s\n", "connection failed");
		goto error;
	}

	/* make request packet */
	retval = send_cookie_info_request_from_cookie(sockfd, cookie);
	if(retval != SECURITY_SERVER_SUCCESS)
	{
		/* Error on socket */
		SEC_SVR_DBG("Error: send request failed: %d", retval);
		goto error;
	}
	retval = recv_cookie_info_response(sockfd);
	if(retval == SECURITY_SERVER_ERROR_NO_SUCH_COOKIE)
	{
		printf("There is no such cookie available\n");
		goto error;
	}
	if(retval <0)
	{
		printf("Error: Error receiving cookie info: %d\n", retval);
		goto error;
	}

error:
	if(sockfd > 0)
	{
		close(sockfd);
	}
	return;
}

unsigned char* util_base64_decode(unsigned char* input, long inputLength, long* outputLength)
{
	unsigned char* pCurIn = input;
	unsigned char* pCurOut;
	long iOutCharNum = 0;
	long lInputLength = inputLength;
	char buf[4];
	unsigned char* inCode;
	unsigned char* output;
	(*outputLength) = 0;
	if((input == NULL) || (inputLength <= 0))
	return NULL;

	 /* calculate length of output data */
	for(; lInputLength > 0; lInputLength--)
	{
		if ((*pCurIn) == BASE64_PAD)
		{
			(*outputLength) += ((iOutCharNum + 1) >> 1);
			if ((iOutCharNum == 2) &&
			((lInputLength == 1) ||
			(*(pCurIn + 1) != BASE64_PAD)))
			{
				(*outputLength)++;
			}
			iOutCharNum = 0;
			break;
		}
		inCode = (unsigned char*)strchr(mszBase64Table, *(pCurIn++));
		if (!inCode)
			continue;
		iOutCharNum++;
		if (iOutCharNum == 4)
		{
			(*outputLength) += 3;
			iOutCharNum=0;
		}
	}
	(*outputLength) += ((iOutCharNum + 1)/2);

	/* allocate memory for output data*/
	output = malloc( *outputLength + 1 );
	if(NULL == output)
	{
		return NULL;
	}
	memset( output, 0, (*outputLength + 1) );
	pCurOut = output;
	iOutCharNum = buf[0] = buf[1] = buf[2] = buf[3] = 0;

	/* decode data*/
	pCurIn = input;

	for(; inputLength>0; inputLength--)
	{
		if ((*pCurIn) == BASE64_PAD)
		{
			/*end-padding processing*/
			if (iOutCharNum == 0)
			{
				return output;
			}
			(*(pCurOut++)) = ((buf[0] & 0x3F) << 2) + ((buf[1] & 0x30) >> 4);
			if ((iOutCharNum == 3)||((iOutCharNum == 2) && ((lInputLength == 0) ||
			((*(pCurIn + 1)) != BASE64_PAD))))
			{
				(*(pCurOut++)) = ((buf[1] & 0x0F) << 4) + ((buf[2] & 0x3C) >> 2);
			}
			return output;
		}
		inCode = (unsigned char*)strchr(mszBase64Table, *(pCurIn++));
		if (!inCode)
		{
			continue;
		}
		buf[iOutCharNum++] = (char)((unsigned long)inCode - (unsigned long)mszBase64Table);
		if (iOutCharNum == 4)
		{
			*(pCurOut++) = ((buf[0] & 0x3F) << 2) + ((buf[1] & 0x30) >> 4);
			*(pCurOut++) = ((buf[1] & 0x0F) << 4) + ((buf[2] & 0x3C) >> 2);
			*(pCurOut++) = ((buf[2] & 0x03) << 6) + (buf[3] & 0x3F);
			iOutCharNum = buf[0] = buf[1] = buf[2] = buf[3] = 0;
		}
	}
	if (iOutCharNum == 0)
	{
		return output;
	}
	(*(pCurOut++)) = ((buf[0] & 0x3F) << 2) + ((buf[1] & 0x30) >> 4);
	if (iOutCharNum == 3)
	{
		(*(pCurOut++)) = ((buf[1] & 0x0F) << 4) + ((buf[2] & 0x3C) >> 2);
	}
	return output;
}

void util_read_cookie_from_base64_string(unsigned char *cookie, const char *encoded_cookie)
{
	unsigned char *decoded_cookie = NULL;
	int encoded_len, decoded_len;
	encoded_len = strlen(encoded_cookie);

	decoded_cookie = util_base64_decode((unsigned char *)encoded_cookie, encoded_len, (long *)&decoded_len);
	if(decoded_len != SECURITY_SERVER_COOKIE_LEN)
	{
		printf("Base64 decode failed: %d\n", decoded_len);
		exit(1);
	}

	if(decoded_cookie == NULL)
	{
		printf("%s", "BASE64 decode failed:\n");
		exit(1);
	}

	memcpy(cookie, decoded_cookie, SECURITY_SERVER_COOKIE_LEN);
	if(decoded_cookie != NULL)
		free(decoded_cookie);

	return;
}

void util_send_cookie_info_request_from_pid(const char *str_pid)
{
	int retval, sockfd, pid;

	if(str_pid == NULL)
	{
		printf("Wrong PID\n");
		return;
	}

	errno = 0;
	pid = strtoul(str_pid, 0, 10);
	if (errno != 0)
	{
		SEC_SVR_DBG("cannot change string to integer [%s]", str_pid);
		return;
	}

	retval = connect_to_server(&sockfd);
	if(retval != SECURITY_SERVER_SUCCESS)
	{
		/* Error on socket */
		printf("Error: %s\n", "connection failed");
		goto error;
	}

	/* make request packet */
	retval = send_cookie_info_request_from_pid(sockfd, pid);
	if(retval != SECURITY_SERVER_SUCCESS)
	{
		/* Error on socket */
		SEC_SVR_DBG("Error: send request failed: %d", retval);
		goto error;
	}
	retval = recv_cookie_info_response(sockfd);
	if(retval == SECURITY_SERVER_ERROR_NO_SUCH_COOKIE)
	{
		printf("There is no such cookie available\n");
		goto error;
	}
	if(retval <0)
	{
		printf("Error: Error receiving cookie info: %d\n", retval);
		goto error;
	}

error:
	if(sockfd > 0)
	{
		close(sockfd);
	}
	return;
}

int main(int argc, char *argv[])
{
	int ret;
	unsigned char cookie[20];
	ret = getuid();
	if(ret != 0)
	{
		printf("You must be root to test. Current UID: %d\nExiting...\n", ret);
		exit(1);
	}
	if(argc < 2 || argc > 4)
	{
		printf("Wrong usage: %d\n", argc);
		printusage(argv[0]);
		exit(1);
	}
	if(strcmp(argv[1], "-a") == 0)
	{
		if(argc != 2)
		{
			printf("Wrong usage: %d\n", argc);
			printusage(argv[0]);
			exit(1);
		}
			
		util_send_all_cookie_info_request();
		exit(0);
	}

	if(argc < 3)
	{
		printf("Wrong usage: %d\n", argc);
		printusage(argv[0]);
		exit(1);
	}

	if(strcmp(argv[1], "-f") == 0)
	{
		util_read_cookie_from_bin_file(cookie, argv[2]);
		util_send_cookie_info_request_from_cookie(cookie);
		exit(0);
	}

	if(strcmp(argv[1], "-p") == 0)
	{
		util_send_cookie_info_request_from_pid(argv[2]);
		exit(0);
	}

	if(strcmp(argv[1], "-s") == 0)
	{
		util_read_cookie_from_base64_string(cookie, argv[2]);
		util_send_cookie_info_request_from_cookie(cookie);
		exit(0);
	}

	printf("%s", "Wrong usage\n");
	printusage(argv[0]);
	exit(1);
}
