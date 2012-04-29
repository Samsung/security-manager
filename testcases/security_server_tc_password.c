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

#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/param.h>
#include <fcntl.h>
#include <sys/un.h>
#include <unistd.h>
#include <sys/socket.h>
#include <dirent.h>
#include "security-server.h"
#include "test.h"

void printusage(char *cmdline)
{
	printf("%s\n", "Usage: ");
	printf("%s password1, password2\n", cmdline);
	printf("%s\n", "Example:");
	printf("%s 123456 abcdef\n", cmdline);
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

int dir_filter(const struct dirent *entry)
{
	if ((strcmp(entry->d_name, ".") == 0) || 
		(strcmp(entry->d_name, "..") == 0) ||
		(strcmp(entry->d_name, "attempts") ==0) ||
		(strcmp(entry->d_name, "history") ==0) )
		return (0);
	else
		return (1);
}

int main(int argc, char *argv[])
{
	int ret;
	unsigned long i=1;
	unsigned int attempt, max_attempt, expire_sec, temp_sec;
	struct timeval cur_time;
	char buf1[33], buf2[33];
	struct dirent **mydirent;

	if(argc < 2)
	{
		printf("%s\n", "Error: No password identified");
		printusage(argv[0]);
		exit(1);
	}

	if(getuid() == 0)
	{
		system("rm /opt/data/security-server/*");
		sync();

		printf("TC P1: security_server_is_pwd_empty(). no pwd case.\n");
		ret = security_server_is_pwd_valid(&attempt, &max_attempt, &expire_sec);
		if(ret != SECURITY_SERVER_API_ERROR_NO_PASSWORD || attempt != 0 || max_attempt != 0 || expire_sec != 0)
		{
			printf("TC P1 failed. return = %d, current_attempt=%d, max_attempt=%d, expire_day=%d\n", ret, attempt, max_attempt, expire_sec);
			exit(1);
		}
		printf("TC P1: PASSED\n\n");
		sleep(1);
	}
	else
	{
		printf("To run the TC as non root user, please remove password files (/opt/data/security-server/*) in root shell\n");
		printf("If not, you will see some TC failures\n");
	}

	printf("TC P2: security_server_chk_pwd(): Too long password case\n");
	ret = security_server_chk_pwd("abcdefghijklmnopqrstuvwxyz0123456", &attempt, &max_attempt, &expire_sec); /* 33 chars */
	if(ret != SECURITY_SERVER_API_ERROR_INPUT_PARAM)
	{
		printf("TC P2 failed. %d\n", ret);
		exit(1);
	}
	printf("TC P2: PASSED\n\n");
	sleep(1);

	printf("TC P3: security_server_chk_pwd(): NULL input case\n");
	ret = security_server_chk_pwd(NULL, &attempt, &max_attempt, &expire_sec);
	if(ret != SECURITY_SERVER_API_ERROR_INPUT_PARAM)
	{
		printf("TC P3.1 failed. %d\n", ret);
		exit(1);
	}
	ret = security_server_chk_pwd("password", NULL, &max_attempt, &expire_sec);
	if(ret != SECURITY_SERVER_API_ERROR_INPUT_PARAM)
	{
		printf("TC P3.2 failed. %d\n", ret);
		exit(1);
	}
	ret = security_server_chk_pwd("password", &attempt, NULL, &expire_sec);
	if(ret != SECURITY_SERVER_API_ERROR_INPUT_PARAM)
	{
		printf("TC P3.3 failed. %d\n", ret);
		exit(1);
	}
	ret = security_server_chk_pwd("password", &attempt, &max_attempt, NULL);
	if(ret != SECURITY_SERVER_API_ERROR_INPUT_PARAM)
	{
		printf("TC P3.4 failed. %d\n", ret);
		exit(1);
	}
	printf("TC P3: PASSED\n\n");
	sleep(1);

	printf("TC P4: security_server_chk_pwd(): no password case\n");
	ret = security_server_chk_pwd("isthisempty", &attempt, &max_attempt, &expire_sec);
	if(ret != SECURITY_SERVER_API_ERROR_NO_PASSWORD || max_attempt != 0 || expire_sec != 0)
	{
		printf("TC P4 failed. %d\n", ret);
		exit(1);
	}
	printf("TC P4: PASSED\n\n");
	sleep(1);

	printf("TC P5: security_server_set_pwd(): NULL input case\n");
	ret = security_server_set_pwd(NULL, NULL, 0, 0);
	if(ret != SECURITY_SERVER_API_ERROR_INPUT_PARAM)
	{
		printf("TC P5 failed. %d\n", ret);
		exit(1);
	}
	printf("TC P5: PASSED\n\n");
	sleep(1);

	printf("TC P6: security_server_set_pwd(): Too long input param\n");
	ret = security_server_set_pwd("abcdefghijklmnopqrstuvwxyz0123456", "abcdefghijklmnopqrstuvwxyz0123456", 0, 0);
	if(ret != SECURITY_SERVER_API_ERROR_INPUT_PARAM)
	{
		printf("TC P6 failed. %d\n", ret);
		exit(1);
	}
	printf("TC P6: PASSED\n\n");
	sleep(1);

	printf("TC P7: security_server_set_pwd(): Normal case when current pwd is empty\n");
	ret = security_server_set_pwd(NULL, argv[1], 0, 0);
	if(ret != SECURITY_SERVER_API_SUCCESS)
	{
		printf("TC P7 failed. %d\n", ret);
		exit(1);
	}
	printf("TC P7: PASSED\n\n");
	sleep(1);

	printf("TC P8: security_server_chk_pwd(): normal(correct pwd) case\n");
	ret = security_server_chk_pwd(argv[1], &attempt, &max_attempt, &expire_sec);
	if(ret != SECURITY_SERVER_API_SUCCESS)
	{
		printf("TC P8 failed. %d\n", ret);
		exit(1);
	}
	printf("TC P8: PASSED\n\n");
	sleep(1);

	printf("TC P9: security_server_is_pwd_empty(). password exists.\n");
	ret = security_server_is_pwd_valid(&attempt, &max_attempt, &expire_sec);
	if(ret != SECURITY_SERVER_API_ERROR_PASSWORD_EXIST)
	{
		printf("TC P9 failed. %d\n", ret);
		exit(1);
	}
	printf("TC P9: PASSED\n\n");
	sleep(1);
	
	printf("TC P10: security_server_chk_pwd(): incorrect pwd case\n");
	(argv[1])[0]++;
	ret = security_server_chk_pwd(argv[1], &attempt, &max_attempt, &expire_sec);
	if(ret != SECURITY_SERVER_API_ERROR_PASSWORD_MISMATCH)
	{
		printf("TC P10 failed. %d\n", ret);
		exit(1);
	}
	printf("TC P10: PASSED\n\n");
	sleep(1);

	printf("TC P11: security_server_set_pwd(): Incorrect current password\n");
	ret = security_server_set_pwd(argv[1], argv[2], 0, 0);
	if(ret != SECURITY_SERVER_API_ERROR_PASSWORD_MISMATCH)
	{
		printf("TC P11 failed. %d\n", ret);
		exit(1);
	}
	printf("TC P11: PASSED\n\n");
	(argv[1])[0]--;
	sleep(1);

	printf("TC P12: security_server_set_pwd(): correct password\n");
	ret = security_server_set_pwd(argv[1], argv[2], 0, 0);
	if(ret != SECURITY_SERVER_API_SUCCESS)
	{
		printf("TC P12 failed. %d\n", ret);
		exit(1);
	}
	printf("TC P12: PASSED\n\n");
	sleep(1);

	printf("TC P13: security_server_chk_pwd(): Check increasing attempts, with reset when correct password has been checked\n");
	ret = security_server_set_pwd(argv[2], argv[1], 10, 0);
	if(ret != SECURITY_SERVER_API_SUCCESS)
	{
		printf("TC P13.1 failed. %d\n", ret);
		exit(1);
	}
	sleep(1);
	for(i=0;i<5;i++)
	{
		printf("%d\n", i+1);
		ret = security_server_chk_pwd(argv[2],  &attempt, &max_attempt, &expire_sec);
		if(ret != SECURITY_SERVER_API_ERROR_PASSWORD_MISMATCH)
		{
			printf("\nTC P13.%da failed. %d\n", i+2, ret);
			exit(1);
		}
		if(attempt != (i+1))
		{
			printf("\nTC P13.%db failed. %d\n", i+2, ret);
			exit(1);
		}
		sleep(1);
	}
	printf("%d\n", i+1);
	ret = security_server_chk_pwd(argv[1],  &attempt, &max_attempt, &expire_sec);
	if(ret != SECURITY_SERVER_API_SUCCESS)
	{
		printf("TC P13.%d failed. %d\n", i+2, ret);
		exit(1);
	}
	sleep(1);
	printf("%d\n", i+2);
	ret = security_server_is_pwd_valid(&attempt, &max_attempt, &expire_sec);
	if(ret != SECURITY_SERVER_API_ERROR_PASSWORD_EXIST)
	{
		printf("TC P13.%d failed. %d\n", i+3, ret);
		exit(1);
	}
	if(attempt != 0 || max_attempt != 10)
	{
		printf("TC P13.%d failed. %d\n", i+3, ret);
		exit(1);
	}
	printf("TC P13: PASSED\n\n");
	sleep(1);	

	printf("TC P14: security_server_chk_pwd(): attempt exceeding case\n");
	for(i=0;i<10;i++)
	{
		printf("%d\n", i+1);
		ret = security_server_chk_pwd(argv[2],  &attempt, &max_attempt, &expire_sec);
		if(ret != SECURITY_SERVER_API_ERROR_PASSWORD_MISMATCH)
		{
			printf("\nTC P14.%da failed. %d\n", i+1, ret);
			exit(1);
		}
		if(attempt != (i+1))
		{
			printf("\nTC P14.%db failed. %d\n", i+1, ret);
			exit(1);
		}
		sleep(1);
	}
	printf("%d\n", i+1);
	ret = security_server_chk_pwd(argv[1],  &attempt, &max_attempt, &expire_sec);
	if(ret != SECURITY_SERVER_API_ERROR_PASSWORD_MAX_ATTEMPTS_EXCEEDED)
	{
		printf("TC P14.%d failed. %d\n", i+1, ret);
		exit(1);
	}
	printf("TC P14: PASSED\n\n");
	sleep(1);	

	printf("TC P15: security_server_reset_pwd(): Reset current password\n");
	ret = security_server_reset_pwd(argv[1],0, 0);
	if(ret != SECURITY_SERVER_API_SUCCESS)
	{
		printf("TC P15 failed. %d\n", ret);
		exit(1);
	}
	printf("TC P15: PASSED\n\n");
	sleep(1);	

	printf("TC P16: security_server_set_pwd(): Check expiration \n");
	ret = security_server_set_pwd(argv[1], argv[2], 10, 1);
	if(ret != SECURITY_SERVER_API_SUCCESS)
	{
		printf("TC P16.1 failed. %d\n", ret);
		exit(1);
	}
	sleep(1);
	ret = security_server_is_pwd_valid(&attempt, &max_attempt, &expire_sec);
	if(ret != SECURITY_SERVER_API_ERROR_PASSWORD_EXIST)
	{
		printf("TC P16.2 failed. %d\n", ret);
		exit(1);
	}
	if(expire_sec > 86400 || expire_sec < 86398)
	{
		printf("TC P16.3 failed. %d, %d\n", ret, expire_sec);
		exit(1);
	}
	printf("TC P16: PASSED\n\n");
	sleep(1);	

	printf("TC P17: security_server_chk_pwd(): Check expiration sec decreasing\n");
	ret = security_server_is_pwd_valid(&attempt, &max_attempt, &expire_sec);
	if(ret != SECURITY_SERVER_API_ERROR_PASSWORD_EXIST)
	{
		printf("TC P17.1 failed. %d\n", ret);
		exit(1);
	}
	sleep(1);
	temp_sec = 0;
	for(i=0;i<5;i++)
	{
		expire_sec = 0;
		ret = security_server_chk_pwd(argv[2],  &attempt, &max_attempt, &expire_sec);
		if(ret != SECURITY_SERVER_API_SUCCESS)
		{
			printf("\nTC P17.%da failed. %d\n", i+4, ret);
			exit(1);
		}
		if(temp_sec != 0 && ((temp_sec -expire_sec) > 2) && ((temp_sec -expire_sec) < 1))
		{
			printf("\nTC P17.%db failed. %d, %d, %d\n", i+4, ret, temp_sec, expire_sec);
			exit(1);
		}
		temp_sec = expire_sec;
		printf("%d\n", expire_sec);
		sleep(1);
	}
	printf("\nTC P17: PASSED\n\n");
	
	printf("TC P18: security_server_chk_pwd(): Check expiration with system time change\n");
	ret = gettimeofday(&cur_time, NULL);
	if(ret < 0)
	{
		printf("TC P18.1 failed. %d\n", ret);
		exit(1);
	}
	cur_time.tv_sec += (expire_sec -4);
	ret = settimeofday(&cur_time, NULL);
	if(ret < 0)
	{
		printf("TC P18.2 failed. %d\n", ret);
		exit(1);
	}
	temp_sec = 0;
	for(i=0;i<5;i++)
	{
		expire_sec = 0;
		ret = security_server_chk_pwd(argv[2],  &attempt, &max_attempt, &expire_sec);
		if(ret != SECURITY_SERVER_API_SUCCESS && ret != SECURITY_SERVER_API_ERROR_PASSWORD_EXPIRED)
		{
			printf("\nTC P18.%da failed. %d\n", i+1, ret);
			exit(1);
		}
		if(ret == SECURITY_SERVER_API_ERROR_PASSWORD_EXPIRED)
			break;

		if(temp_sec != 0 && ((temp_sec -expire_sec) > 2) && ((temp_sec -expire_sec) < 1))
		{
			printf("\nTC P18.%db failed. %d, %d, %d\n", i+1, ret, temp_sec, expire_sec);
			exit(1);
		}
		temp_sec = expire_sec;
		printf("%d\n", expire_sec);
		sleep(1);
	}
	if(ret != SECURITY_SERVER_API_ERROR_PASSWORD_EXPIRED)
	{
		printf("\nTC P18.%i failed. %d\n", i+1, ret);
		exit(1);
	}
	printf("\nTC P18: PASSED\n\n");
	sleep(1);

	printf("TC P19: security_server_set_pwd_history(): Too big & small number\n");
	ret = security_server_set_pwd_history(100);
	if(ret != SECURITY_SERVER_API_ERROR_INPUT_PARAM)
	{
		printf("\nTC P19.1 failed. %d\n", ret);
		exit(1);
	}
	ret = security_server_set_pwd_history(-5);
	if(ret != SECURITY_SERVER_API_ERROR_INPUT_PARAM)
	{
		printf("\nTC P19.2 failed. %d\n", ret);
		exit(1);
	}
	printf("\nTC P19: PASSED\n\n");
	sleep(1);

	printf("TC P20: security_server_set_pwd_history(): normal case\n");
	ret = security_server_set_pwd_history(10);
	if(ret != SECURITY_SERVER_API_SUCCESS)
	{
		printf("\nTC P20 failed. %d\n", ret);
		exit(1);
	}
	printf("\nTC P20: PASSED\n\n");
	sleep(1);

	printf("TC P21: security_server_set_pwd_history(): Check history is working\n");
	ret = security_server_reset_pwd("history1",0, 0);
	if(ret != SECURITY_SERVER_API_SUCCESS)
	{
		printf("TC P21.1 failed. %d\n", ret);
		exit(1);
	}
	printf("1\n");
	sleep(1);
	for(i=1;i<11;i++)
	{
		sprintf(buf1, "history%d", i);
		sprintf(buf2, "history%d", i+1);
		ret = security_server_set_pwd(buf1, buf2, 0, 0);
		if(ret != SECURITY_SERVER_API_SUCCESS)
		{
			printf("\nTC P21.%d failed. %d\n", i+1, ret);
			exit(1);
		}
		printf("%d\n", i+1);
		sleep(1);
	}
	ret = security_server_set_pwd("history11", "history1", 0, 0);
	if(ret != SECURITY_SERVER_API_SUCCESS)
	{
		printf("\nTC P21.%d failed. %d\n", i+1, ret);
		exit(1);
	}
	sleep(1);
	ret = security_server_set_pwd("history1", "history8", 0, 0);
	if(ret != SECURITY_SERVER_API_ERROR_PASSWORD_REUSED)
	{
		printf("\nTC P21.%d failed. %d\n", i+2, ret);
		exit(1);
	}
	printf("\nTC P21: PASSED\n\n");
	sleep(1);

	printf("TC P22: security_server_set_pwd(): Check Garbage collection\n");
	ret = security_server_set_pwd("history1", "history12", 0, 0);
	sprintf(buf1, "history12");
	if(ret != SECURITY_SERVER_API_SUCCESS)
	{
		printf("\nTC P22.1 failed. %d\n", i+1, ret);
		exit(1);
	}
	printf("12\n");
	sleep(1);
	for(i=12;i<60;i++)
	{
		sprintf(buf1, "history%d", i);
		sprintf(buf2, "history%d", i+1);
		ret = security_server_set_pwd(buf1, buf2, 0, 0);
		if(ret != SECURITY_SERVER_API_SUCCESS)
		{
			printf("\nTC P22.%d failed. %d\n", i+1, ret);
			exit(1);
		}
		printf("%d\n", i+1);
		sleep(1);
	}
	ret = scandir("/opt/data/security-server", &mydirent, &dir_filter, alphasort);
	i = ret;
	while((i--))
	{
		free(mydirent[i]);
	}
	free(mydirent);
	if( ret == 50 || ret == 51)
	{
		printf("\nTC P22: PASSED\n\n");
		sleep(1);
	}
	else
	{
		printf("\nTC P22 failed. %d", ret);
		exit(1);
	}
	printf("TC P23: security_server_chk_pwd(): incorrect with replay attack\n");
	ret = security_server_chk_pwd("quickquickquick", &attempt, &max_attempt, &expire_sec);
	do 
	{
		i =  i + 100000;
		ret = security_server_chk_pwd("quickquickquick", &attempt, &max_attempt, &expire_sec);
		usleep(i);
	}
	while(ret == SECURITY_SERVER_API_ERROR_PASSWORD_RETRY_TIMER);

	if(ret != SECURITY_SERVER_API_ERROR_PASSWORD_MISMATCH )
	{
		printf("TC P23 failed[1]. %d\n", ret);
		exit(1);
	}
	i = i - 100000;
	printf("Last interval was %d.%06d sec.\n", (i /1000000), (i % 1000000) );
	printf("TC P23: PASSED\n\n");

	return 0;
}

