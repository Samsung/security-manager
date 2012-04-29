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
