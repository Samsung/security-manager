/*
 * security server
 *
 * Copyright (c) 2000 - 2010 Samsung Electronics Co., Ltd.
 * Contact: Bumjin Im <bj.im@samsung.com>
 *
 */

#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/param.h>
#include <fcntl.h>
#include <sys/un.h>
#include <unistd.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include "security-server.h"
#include "test.h"


#define SECURITY_SERVER_SOCK_PATH	"/tmp/.security_server.sock"

/* Message */
typedef struct
{
	unsigned char version;
	unsigned char msg_id;
	unsigned short msg_len;
} basic_header;

typedef struct
{
	basic_header basic_hdr;
	unsigned char return_code;
} response_header;


/* Create a Unix domain socket and bind */
int create_new_socket()
{
	int localsockfd = 0, flags;
	struct sockaddr_un serveraddr;
	mode_t sock_mode;

	remove(SECURITY_SERVER_TEST_SOCK_PATH);

	/* Create Unix domain socket */
	if((localsockfd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0 )
	{
		localsockfd = -1;
		printf("%s\n", "Socket creation failed");
		goto error;
	}

	/* Make socket as non blocking */
	if((flags = fcntl(localsockfd, F_GETFL, 0)) < 0 ||
			fcntl(localsockfd, F_SETFL, flags | O_NONBLOCK) < 0)
	{
		close(localsockfd);
		localsockfd = -1;
		printf("%s\n", "Cannot go to nonblocking mode");
		goto error;
	}

	bzero (&serveraddr, sizeof(serveraddr));
	serveraddr.sun_family = AF_UNIX;
	strncpy(serveraddr.sun_path, SECURITY_SERVER_TEST_SOCK_PATH,
			strlen(SECURITY_SERVER_TEST_SOCK_PATH) + 1);

	/* Bind the socket */
	if((bind(localsockfd, (struct sockaddr *)&serveraddr, sizeof(serveraddr))) < 0)
	{
		printf("%s\n", "Cannot bind");
		close(localsockfd);
		localsockfd = -1;
		goto error;
	}

	/* Change permission to accept all processes that has different uID/gID */
	sock_mode = (S_IRWXU | S_IRWXG | S_IRWXO);
	/* Flawfinder hits this chmod function as level 5 CRITICAL as race condition flaw *
	 * Flawfinder recommends to user fchmod insted of chmod
	 * But, fchmod doesn't work on socket file so there is no other choice at this point */
	if(chmod(SECURITY_SERVER_TEST_SOCK_PATH, sock_mode) < 0)		/* Flawfinder: ignore */
	{
		printf("%s\n", "chmod() error");
		close(localsockfd);
		localsockfd = -1;
		goto error;
	}
error:
	return localsockfd;
}

void printhex(unsigned char *data, int size)
{
	int i;
	for(i=0;i<size;i++)
	{
		if(data[i] < 0x10)
			printf("0");

		printf("%X ", data[i]);
		if(((i+1) % 16) == 0 && i != 0)
			printf("\n");
	}
	printf("\n");
}

int check_socket_poll(int sockfd, int event, int timeout)
{
	struct pollfd poll_fd[1];
	int retval;

	poll_fd[0].fd = sockfd;
	poll_fd[0].events = event;
	retval = poll(poll_fd, 1, timeout);
	if(retval < 0)
	{
		printf("%s", "poll() error");
		return -1;
	}

	/* Timed out */
	if(retval == 0)
	{
		/*SEC_SVR_DBG("%s", "poll() timeout");*/
		return 0;
	}
	return 1;
}

int send_gid_request(int sock_fd, const char* object)
{
	basic_header hdr;
	int retval, send_len = 0;
	unsigned char *buf = NULL;

	hdr.version = 0x01; /* SECURITY_SERVER_MSG_VERSION; */
	hdr.msg_id = 0x07; /* SECURITY_SERVER_MSG_TYPE_GID_REQUEST; */
	hdr.msg_len = strlen(object);

	send_len = sizeof(hdr) + strlen(object);

	buf = malloc(send_len);
	if(buf == NULL)
	{
		printf("%s", "out of memory");
		return -1;
	}

	memcpy(buf, &hdr, sizeof(hdr));
	memcpy(buf + sizeof(hdr), object, strlen(object));

	/* Check poll */
	retval = check_socket_poll(sock_fd, POLLOUT, 1000);
	if(retval == -1)
	{
		printf("%s", "poll() error");
		if(buf != NULL)
			free(buf);
		return -1;
	}
	if(retval == 0)
	{
		printf("%s", "poll() timeout");
		if(buf != NULL)
			free(buf);		
		return -1;
	}

	retval = write(sock_fd, buf, send_len);
	if(retval < send_len)
	{
		/* Write error */
		printf("Error on write(): %d. errno=%d, sockfd=%d", retval, errno, sock_fd);
		if(buf != NULL)
			free(buf);
		return -1;
	}
	if(buf != NULL)
		free(buf);

	return 0;	
}

int connect_to_server(int *fd)
{
	struct sockaddr_un clientaddr;
	int client_len = 0, localsockfd, ret, flags;
	*fd = -1;

	/* Create a socket */
	localsockfd = socket(AF_UNIX, SOCK_STREAM, 0);
	if(localsockfd < 0)
	{
		printf("%s", "Error on socket()");
		return -1;
	}

	/* Make socket as non blocking */
	if((flags = fcntl(localsockfd, F_GETFL, 0)) < 0 || 
			fcntl(localsockfd, F_SETFL, flags | O_NONBLOCK) < 0)
	{
		close(localsockfd);
		printf("%s", "Cannot go to nonblocking mode");
		return -1;
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
			printf("%s", "Connection is in progress");
			check_socket_poll(localsockfd, POLLOUT, 1000);
			if(ret == -1)
			{
				printf("%s", "poll() error");
				close(localsockfd);
				return -1;
			}
			if(ret == 0)
			{
				printf("%s", "poll() timeout");
				close(localsockfd);
				return -1;
			}
			ret = connect(localsockfd, (struct sockaddr*)&clientaddr, client_len);
			if(ret < 0)
			{
				printf("%s", "connection failed");
				close(localsockfd);
				return -1;
			}
		}
		else
		{
			printf("%s", "Connection failed");
			close(localsockfd);
			return -1;
		}
	}

	*fd = localsockfd;
	return 0;
}


int fake_get_gid(const char *object)
{
	 int sockfd = -1, retval, gid;
     response_header hdr;
 
     retval = connect_to_server(&sockfd);
     if(retval != 0)
     {
         /* Error on socket */
         printf("Connection failed: %d", retval);
         goto error;
     }
 
    /* make request packet and send to server*/
     retval = send_gid_request(sockfd, object);
     if(retval != 0)
     {
         /* Error on socket */
         printf("Send request failed: %d", retval);
         goto error;
     }
	 printf("%s", "Just closing the socket and exit\n");

error:
	 if(sockfd > 0)
		 close(sockfd);

	 return 0;
}


int main(int argc, char *argv[])
{
	int server_sockfd, client_sockfd, ret, recved_gid, client_len, i;
	unsigned char cookie[20], recved_cookie[20], recvbuf[33], wrong_cookie[20];
	char obj_name[30];
	struct pollfd accept_poll[1], client_poll[1];
	struct sockaddr_un clientaddr;
        int olen, alen;
        char olabel[1024];
        char arights[32];

	ret = getuid();
	if(ret != 0)
	{
		printf("TC must be executed by root\n");
		exit(1);
	}

	printf("TC S1: Getting default cookie\n");
	ret = security_server_request_cookie(cookie, 20);
	if(ret != SECURITY_SERVER_API_SUCCESS)
	{
		printf("TC S1 failed to get cookie. %d\n", ret);
		exit(1);
	}
	printhex(cookie, 20);
	printf("TC S1: PASSED\n\n");
	sleep(1);

	printf("TC S2: security_server_get_gid(): normal case. trying to get GID of \"tel_gprs\" \n");
	ret = security_server_get_gid("tel_gprs");
	if(ret < 0)
	{
		printf("Test failed: %d\n", ret);
		exit(-1);
	}
	printf("TC S2: PASSED with gid %d\n\n", ret);
	sleep(1);

	printf("TC S3: security_server_get_gid(): empty object name\n");
	ret = security_server_get_gid("");
	if(ret != SECURITY_SERVER_API_ERROR_INPUT_PARAM)
	{
		printf("Test failed: %d\n", ret);
		exit(-1);
	}
	printf("TC S3: PASSED\n\n");
	sleep(1);

	printf("TC S4: security_server_get_gid(): wrong object name. \"teltel\"\n");
	ret = security_server_get_gid("teltel");
	if(ret != SECURITY_SERVER_API_ERROR_NO_SUCH_OBJECT)
	{
		printf("Test failed: %d\n", ret);
		exit(-1);
	}
	printf("TC S4: PASSED\n\n");
	sleep(1);

	printf("TC S5: security_server_get_object_name(): normal case. trying 6001\n");
	ret = security_server_get_object_name(6001, obj_name, sizeof(obj_name));
	if(ret != SECURITY_SERVER_API_SUCCESS)
	{
		printf("Test failed: %d\n", ret);
		exit(-1);
	}
	printf("Result: %s\n", obj_name);
	printf("TC S5: PASSED\n\n");
	sleep(1);

	printf("TC S6: security_server_get_object_name(): Too small buffer size\n");
	ret = security_server_get_object_name(6001, obj_name, 5);
	if(ret != SECURITY_SERVER_API_ERROR_BUFFER_TOO_SMALL)
	{
		printf("Test failed: %d\n", ret);
		exit(-1);
	}
	printf("TC S6: PASSED\n\n");
	sleep(1);

	printf("TC S7: security_server_get_object_name(): Invalid gid\n");
	ret = security_server_get_object_name(9876, obj_name, sizeof(obj_name));
	if(ret != SECURITY_SERVER_API_ERROR_NO_SUCH_OBJECT)
	{
		printf("Test failed: %d\n", ret);
		exit(-1);
	}
	printf("TC S7: PASSED\n\n");
	sleep(1);

	printf("TC S8: Ask for priviege with default cookie. Normal case to check \"audio\" privilege \n");
	ret = security_server_get_gid("audio");
	ret = security_server_check_privilege(cookie, ret);
	if(ret != SECURITY_SERVER_API_SUCCESS)
	{
		printf("Test failed: %d\n", ret);
		exit(-1);
	}
	printf("TC S8: PASSED\n\n");
	sleep(1);

	printf("TC S9: Ask for priviege with default cookie. with wrong cookie \n");
	ret = security_server_get_gid("audio");
	srand(time(NULL));
	for(i=0;i<20;i++)
		wrong_cookie[i] = rand() % 255;

	ret = security_server_check_privilege(wrong_cookie, ret);
	if(ret != SECURITY_SERVER_API_ERROR_ACCESS_DENIED)
	{
		printf("Test failed: %d\n", ret);
		exit(-1);
	}
	printf("TC S9: PASSED\n\n");
	sleep(1);

	printf("TC S10: Close socket just after sending request msg. This is done not by library call with simulating security_server_get_gid() API \n");
	ret = fake_get_gid("audio");
	printf("TC S10: Watch whether security server has crhashed or not.\n\n");
	sleep(1);

	printf("TC S11: get PID of a given cookie --> default cookie case \n");
	ret = security_server_get_cookie_pid(cookie);
	if(ret != 0)
	{
		printf("Test failed: %d\n", ret);
		exit(-1);
	}
	printf("TC S11: PASSED\n\n");
	sleep(1);

	printf("TC S12: get PID of a given cookie --> non existing cookie \n");
	ret = security_server_get_cookie_pid(wrong_cookie);
	if(ret != SECURITY_SERVER_API_ERROR_NO_SUCH_COOKIE)
	{
		printf("Test failed: %d\n", ret);
		exit(-1);
	}
	printf("TC S12: PASSED\n\n");
	sleep(1);

	printf("TC S13: get PID of a given cookie --> NULL cookie \n");
	ret = security_server_get_cookie_pid(NULL);
	if(ret != SECURITY_SERVER_API_ERROR_INPUT_PARAM)
	{
		printf("Test failed: %d\n", ret);
		exit(-1);
	}
	printf("TC S13: PASSED\n\n");
	sleep(1);

	printf("TC S14: Communicating with client and test cookie and privilege control \n");
	printf("\tWaiting for client...\n");
	server_sockfd = create_new_socket();
	if(server_sockfd < 1)
	{
		printf("Error on creating a new socket\n");
		printf("Test failed: %d\n", ret);
		exit(1);
	}

	if(listen(server_sockfd, 5) < 0)
	{
		printf("%s\n", "listen() failed. exiting...");
		printf("Test failed: %d\n", ret);
		goto error;
	}

	while(1)
	{	
		accept_poll[0].fd = server_sockfd;
		accept_poll[0].events = POLLIN;
		ret = poll(accept_poll, 1, 5000);

		/* Call poll() to wait for socket connection */
		ret = poll(accept_poll, 1, 5000);
		if(ret < 0)
		{
			printf("%s\n", "poll() error");
			printf("Test failed: %d\n", ret);
			goto error;
		}
		if(ret == 0)
		{
			continue;
		}

		errno = 0;
		client_len = sizeof(clientaddr);
		client_sockfd = accept(server_sockfd,
				(struct sockaddr *)&clientaddr,
				&client_len);
		if(client_sockfd < 0)
		{
			printf("Cannot accept client. errno=%d\n", errno);
			printf("Test failed: %d\n", ret);
			goto error;
		}

		printf("New session accepted\n");

		/* Wait until packet received */
		client_poll[0].fd = client_sockfd;
		client_poll[0].events = POLLIN;

		/* Poll here */
		ret = poll(client_poll, 1, 500);
		if(ret < 0)
		{
			printf("%s\n", "poll() error");
			printf("Test failed: %d\n", ret);
			goto error;
		}
		if(ret == 0)
		{
			close(client_sockfd);
			client_sockfd = 0;
			printf("%s\n", "No request from client. closing socket");
			continue;
		}

		ret = read(client_sockfd, recvbuf, 4);
		if(recvbuf[0] == 0 && recvbuf[1] == 0 && recvbuf[2] == 0 && recvbuf[3] == 0)
		{
			ret = read(client_sockfd, recvbuf, 24);
			if(ret < 24)
			{
				close(client_sockfd);
				printf("cannot read request:%d\n", ret);
				close(client_sockfd);
				continue;
			}

			memcpy(recved_cookie, recvbuf, 20);
			memcpy(&recved_gid, recvbuf+20, sizeof(int));

			printf("requested cookie: \n");
			printhex(recved_cookie, 20);
			printf("requested gid: %d\n", recved_gid);

			ret = security_server_check_privilege(recved_cookie, recved_gid);
			if(ret != SECURITY_SERVER_API_SUCCESS && ret != SECURITY_SERVER_API_ERROR_ACCESS_DENIED)
			{
				printf("Unexpected error occurred: %d\n");
				printf("Test failed: %d\n", ret);
				goto error;
			}

			printf("Privilege for the request: %d\n", ret);

			ret = write(client_sockfd, &ret, sizeof(int));
			if(ret < sizeof(int))
			{
				printf("Send error: %d\n", ret);
				printf("Test failed: %d\n", ret);
				goto error;
			}

			ret = security_server_get_cookie_pid(recved_cookie);
			{
				if(ret < 0)
				{
					printf("Unexpected error occurred: %d\n", ret);
					printf("Test failed: %d\n", ret);
					goto error;
				}
				if(ret == 0)
				{
					printf("client is root process\n");
				}
				else
				{
					printf("Peer PID is %d\n", ret);
				}
			}
		}
		else if(recvbuf[0] == 255 && recvbuf[1] == 255 && recvbuf[2] == 255 && recvbuf[3] == 255)
			{
				char *myargv[5] = {NULL};
				int i, cnt;
				ret = read(client_sockfd, recvbuf, 28);
				if(ret < 28)
				{
					close(client_sockfd);
					printf("cannot read request:%d\n", ret);
					close(client_sockfd);
					continue;
				}

				memcpy(recved_cookie, recvbuf, 20);
				memcpy(&recved_gid, recvbuf + 20, sizeof(int));
				memcpy(&cnt, recvbuf + 24, sizeof(int));

				if(fork() == 0)
				{
					myargv[0] = malloc(strlen("/opt/home/root/security_server_tc_pid_reuser") + 1);
					sprintf(myargv[0], "/opt/home/root/security_server_tc_pid_reuser");
					myargv[1] = malloc(6);
					sprintf(myargv[1], "%d", cnt);
					myargv[2] = malloc(6);
					sprintf(myargv[2], "%d", recved_gid);
					myargv[3] = malloc(40);
					myargv[4] = NULL;
					for(i=0, cnt=0;i<20;i++)
					{
						if(recved_cookie[i] < 0x10)
							sprintf(myargv[3] + cnt, "0%x", recved_cookie[i]);
						else
							sprintf(myargv[3] + cnt, "%x", recved_cookie[i]);
						cnt += 2;
					}
					printf("argv[0]=%s, argv[1]=%s, argv[2]=%s, argv[3]=%s\n", myargv[0], myargv[1], myargv[2], myargv[3]);
					ret = execve("/opt/home/root/security_server_tc_pid_reuser", myargv, NULL);
					printf("execve failed. errno=%d\n", errno);

					if(myargv[0] != NULL)
						free(myargv[0]);
					if(myargv[1] != NULL)
						free(myargv[1]);
					if(myargv[2] != NULL)
						free(myargv[2]);
					if(myargv[3] != NULL)
						free(myargv[3]);
				}
			}
		else if(recvbuf[0] == 17 )
                {
                    if (recvbuf[3] == 0)
                    {
			ret = read(client_sockfd, recvbuf, 20);
			if(ret < 20)
			{
				close(client_sockfd);
				printf("cannot read request:%d\n", ret);
				close(client_sockfd);
				continue;
			}
			memcpy(recved_cookie, recvbuf, 20);
                        ret = read(client_sockfd, &olen, 4);
			if(ret < 4)
			{
				close(client_sockfd);
				printf("cannot read request:%d\n", ret);
				close(client_sockfd);
				continue;
			}
                        ret = read(client_sockfd, &alen, 4);
			if(ret < 4)
			{
				close(client_sockfd);
				printf("cannot read request:%d\n", ret);
				close(client_sockfd);
				continue;
			}
                        ret = read(client_sockfd, olabel, olen);
			if(ret < olen)
			{
				close(client_sockfd);
				printf("cannot read request:%d\n", ret);
				close(client_sockfd);
				continue;
			}
                        olabel[olen] = '\0';
                        ret = read(client_sockfd, arights, alen);
			if(ret < alen)
			{
				close(client_sockfd);
				printf("cannot read request:%d\n", ret);
				close(client_sockfd);
				continue;
			}
                        arights[alen] = '\0';
			printf("Check by cookie requested.\n");
			printf("requested cookie: \n");
			printhex(recved_cookie, 20);
                        printf("olen: %d\n", olen);
                        printf("object label: >%s<\n", olabel);
                        printf("alen: %d\n", alen);
                        printf("access rights: >%s<\n", arights);

                        ret = security_server_check_privilege_by_cookie(
                                  recved_cookie, olabel, arights);

                        printf("return: %d\n", ret);

			ret = write(client_sockfd, &ret, sizeof(int));
			if(ret < sizeof(int))
			{
				printf("Send error: %d\n", ret);
				printf("Test failed: %d\n", ret);
				goto error;
			}
                    }
                    else if (recvbuf[3] == 1)
                    {
                        ret = read(client_sockfd, &olen, 4);
			if(ret < 4)
			{
				close(client_sockfd);
				printf("cannot read request:%d\n", ret);
				close(client_sockfd);
				continue;
			}
                        ret = read(client_sockfd, &alen, 4);
			if(ret < 4)
			{
				close(client_sockfd);
				printf("cannot read request:%d\n", ret);
				close(client_sockfd);
				continue;
			}
                        ret = read(client_sockfd, olabel, olen);
			if(ret < olen)
			{
				close(client_sockfd);
				printf("cannot read request:%d\n", ret);
				close(client_sockfd);
				continue;
			}
                        olabel[olen] = '\0';
                        ret = read(client_sockfd, arights, alen);
			if(ret < alen)
			{
				close(client_sockfd);
				printf("cannot read request:%d\n", ret);
				close(client_sockfd);
				continue;
			}
                        arights[alen] = '\0';
			printf("Check by sockfd requested.\n");
                        printf("olen: %d\n", olen);
                        printf("object label: >%s<\n", olabel);
                        printf("alen: %d\n", alen);
                        printf("access rights: >%s<\n", arights);

                        ret = security_server_check_privilege_by_sockfd(
                                  client_sockfd, olabel, arights);

			ret = write(client_sockfd, &ret, sizeof(int));
			if(ret < sizeof(int))
			{
				printf("Send error: %d\n", ret);
				printf("Test failed: %d\n", ret);
				goto error;
			}
                    } else {
			printf("malformed request. %d, %d, %d, %d\n", recvbuf[0], recvbuf[1], recvbuf[2], recvbuf[3]);
			printf("Test failed: %d\n", ret);
			goto error;
                    }
                }
		else
		{
			printf("malformed request. %d, %d, %d, %d\n", recvbuf[0], recvbuf[1], recvbuf[2], recvbuf[3]);
			printf("Test failed: %d\n", ret);
			goto error;
		}
		if(client_sockfd > 0)
		{
			close(client_sockfd);
		}
	}
error:
	if(server_sockfd > 0)
		close(server_sockfd);
	if(client_sockfd > 0)
		close(client_sockfd);
}
