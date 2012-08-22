/*
 * security server
 *
 * Copyright (c) 2000 - 2010 Samsung Electronics Co., Ltd.
 *
 * Contact: Bumjin Im <bj.im@samsung.com>
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include "security-server.h"
#include "test.h"

void printusage(const char *cmdline)
{
	printf("%s\n", "Usage: ");
	printf("%s [uid] [pid] [hexa decimal cookie]\n", cmdline);
	printf("%s\n", "[pid]: PID want to be reused");
	printf("%s\n", "[hexa decimal cookie]: Cookie value which is issued to the previous process with the [pid] for comparison\nThe cookie must be hexa decimal, with lower case and without whitespace and new line characters\n");
	printf("%s\n", "* This test program must be executed as root process");
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

void convert_prev_cookie(const char *cmdline, const char *prev, unsigned char *now)
{
	int i, cnt;
	char tmphexnum[3] = {0};
	cnt = security_server_get_cookie_size();
	cnt = cnt * 2;
	if(strlen(prev) != cnt)
	{
		printf("%s\n", "Cookie lenth is wrong");
		printusage(cmdline);
		exit(1);
	}

	for(i=0, cnt=0 ; i<strlen(prev) ; i=i+2)
	{
		strncpy(tmphexnum, prev+i, 2);
		tmphexnum[2] = 0;
		errno = 0;
		now[cnt] = strtoul(tmphexnum, 0, 16);
		if(errno != 0)
		{
			printf("%s\n", "cannot convert hex cookie to binary");
			printusage(cmdline);
			exit(1);
		}
		cnt++;
	}
}

void check_status()
{
	struct stat statbuf;
	int ret;
	ret = stat("/opt/home/root/pid_cycle", &statbuf);
	if(ret != 0)
	{
		printf("Interrupt encountered. exiting...\n");
		exit(0);
	}
	
}

void cycle_pid(int pid)
{
	int cur_pid = getpid();
	int dotval;
	
	while(cur_pid != pid)
	{
		if(fork() != 0)
		{
			dotval = cur_pid % 1000;
			if(dotval == 0)
				printf(".");
			exit(0);
		}
		cur_pid = getpid();
		check_status();
	}
}

int main(int argc, char *argv[])
{
	int ret, sock_fd, cookie_size, target_pid, target_uid;

	target_uid = getuid();
	if(target_uid != 0)
	{
		printusage(argv[0]);
		exit(1);
	}

	cookie_size = security_server_get_cookie_size();
	unsigned char prev_cookie[cookie_size], new_cookie[cookie_size];

	if(argc < 3)
	{
		printusage(argv[0]);
		exit(1);
	}

	errno = 0;
	target_uid = strtoul(argv[1], 0, 10);
	if(errno != 0)
	{
		printf("%s\n", "cannot convert string uid to integer");
		printusage(argv[0]);
		exit(1);
	}
	printf("Target UID is %d. change user...\n", target_uid);
	setuid(target_uid);

	errno = 0;
	target_pid = strtoul(argv[2], 0, 10);
	if(errno != 0)
	{
		printf("%s\n", "cannot convert string pid to integer");
		printusage(argv[0]);
		exit(1);
	}
	convert_prev_cookie(argv[0], argv[3], prev_cookie);
	check_status();

	printf("Cycling PID to %d\n", target_pid);

	cycle_pid(target_pid);
	unlink("/opt/home/root/pid_cycle");

	ret = security_server_request_cookie(new_cookie, 20);
	if(ret != SECURITY_SERVER_API_SUCCESS)
	{
		printf("get cookie failed. %d\n", ret);
		exit(1);
	}
	printf("\nTarget PID: %d, Target UID: %d\n", target_pid, target_uid);
	printf("Previous cookie:\n");
	printhex(prev_cookie, 20);
	printf("Newly issued cookie:\n");
	printhex(new_cookie, 20);
	
	if(memcmp(prev_cookie, new_cookie, cookie_size) == 0)
	{
		printf("TC failed. same cookie\n");
		exit(1);
	}
	
	printf("TC C8: PASSED\n");
	return 0;
}

