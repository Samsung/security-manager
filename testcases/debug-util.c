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
#include "security-server.h"
#define DEVELOPER_UID 5100

int main(int argc, char *argv[])
{
	int uid, ret, i;

	uid = getuid();
	if(uid == DEVELOPER_UID)
	{
		printf("Sending request to security server...\n");
		ret = security_server_launch_debug_tool(argc -1, (const char **) argv + 1);
		if(ret != SECURITY_SERVER_API_SUCCESS)
		{
			printf("Failed to launch tool[%d]\n", ret);
			exit(-1);
		}
		exit(0);
	}
	if(uid == 0)
	{
		printf("%s", "This is executed as root privilege\n");
		printf("argc = %d\n");
		for(i=0;i<argc;i++)
		{
			printf("argv[%d]: [%s]\n", i, argv[i]);
		}
		exit(0);
	}
	printf("Wrong uid: %d\n", uid);
	printf("You must run %s under root user or developer(%d) user\n", argv[0], DEVELOPER_UID);
	exit(-1);
	
}
