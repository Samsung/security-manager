/*
 *  security-server
 *
 *  Copyright (c) 2000 - 2012 Samsung Electronics Co., Ltd All Rights Reserved
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
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>
#include <fcntl.h>
#include <openssl/sha.h>

#include "security-server-password.h"

struct timeval prev_try;

void initiate_try()
{
	gettimeofday(&prev_try, NULL);
}

int validate_pwd_file(char *filename)
{
	int i;

	if((strncmp(filename + (strlen(filename) -4), ".pwd" , 4)) != 0)
	{
		SEC_SVR_DBG("The passwor filename [%s] is invalid", filename);
		return SECURITY_SERVER_ERROR_NO_PASSWORD;
	}

	for(i=0;i<((int)strlen(filename) -4);i++)
	{
		if(filename[i] > '9' || filename[i] < '0')
		{
			SEC_SVR_DBG("The passwor filename [%s] is invalid", filename);
			return SECURITY_SERVER_ERROR_NO_PASSWORD;
		}
	}
	return SECURITY_SERVER_SUCCESS;
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

int get_pwd_path(char *path)
{
	int retval;
	struct dirent **mydirent;
	int num;
	num = scandir(SECURITY_SERVER_DATA_DIRECTORY_PATH, &mydirent, &dir_filter, alphasort);
	if(num < 0)
	{
		SEC_SVR_DBG("Server: [Error] Cannot scan password directory. errno: %d", errno);
		return SECURITY_SERVER_ERROR_FILE_OPERATION;
	}
	if(num == 0)
	{
		SEC_SVR_DBG("%s", "Server: There is no password file");
		return SECURITY_SERVER_ERROR_NO_PASSWORD;
	}

	snprintf(path, 255, "%s/%s", SECURITY_SERVER_DATA_DIRECTORY_PATH, mydirent[num-1]->d_name);
	retval = validate_pwd_file(mydirent[num-1]->d_name);
	if(retval != SECURITY_SERVER_SUCCESS)
	{
		SEC_SVR_DBG("Removing invalid password file: %s", path);
		unlink(path);
		get_pwd_path(path);
	}
	SEC_SVR_DBG("Password file path: %s", path);
	while (num--)
		free(mydirent[num]);
	free(mydirent);
	return SECURITY_SERVER_SUCCESS;
}

int load_password(unsigned char *cur_pwd, unsigned int *max_attempt, unsigned int *expire_time)
{
	int retval, fd;
	char pwd_path[255];

	/* Create directory */
	retval = mkdir(SECURITY_SERVER_DATA_DIRECTORY_PATH, 0700);
	if(retval != 0)
	{
		if(errno != EEXIST)
		{
			SEC_SVR_DBG("Cannot create directory. errno: %d", errno);
			return SECURITY_SERVER_ERROR_FILE_OPERATION;
		}
	}

	/* Check password files */
	while(1)
	{
		/* Get password file path */
		retval = get_pwd_path(pwd_path);
		if(retval == SECURITY_SERVER_ERROR_NO_PASSWORD)
		{
			SEC_SVR_DBG("%s", "Current password doesn't exist");
			return SECURITY_SERVER_ERROR_NO_PASSWORD;
		}

		/* Load password file */
		fd = open(pwd_path, O_RDONLY | O_NONBLOCK );
		if(fd < 0)
		{
			if(errno == ENOENT)
			{
				SEC_SVR_DBG("%s", "Server: Current password doesn't exist");
				return SECURITY_SERVER_ERROR_NO_PASSWORD;
			}
			SEC_SVR_DBG("Server: Current password cannot be opened. errno: %d", errno);
			return SECURITY_SERVER_ERROR_FILE_OPERATION;
		}

		/* Read and store into memory */
		retval = TEMP_FAILURE_RETRY(read(fd, cur_pwd, SECURITY_SERVER_HASHED_PWD_LEN));
		if(retval < SECURITY_SERVER_HASHED_PWD_LEN)
		{
			SEC_SVR_DBG("%s", "Server: Current password corrupted. resetting to previous one. 0");
			close(fd);
			fd = 0;
			unlink(pwd_path);
			continue;
		}

		retval = TEMP_FAILURE_RETRY(read(fd, max_attempt, sizeof(unsigned int)));
		if(retval < sizeof(unsigned int))
		{
			SEC_SVR_DBG("%s", "Server: Current password corrupted. resetting to previous one. 1");
			close(fd);
			fd = 0;
			unlink(pwd_path);
			continue;
		}

		retval = TEMP_FAILURE_RETRY(read(fd, expire_time, sizeof(unsigned int)));
		if(retval < sizeof(unsigned int))
		{
			SEC_SVR_DBG("%s", "Server: Current password corrupted. resetting to previous one. 2");
			close(fd);
			fd = 0;
			unlink(pwd_path);
			continue;
		}
		close(fd);

		/* Check expiration time. */
		if(*expire_time == 0)  /* No valid period */
			*expire_time = 0xffffffff;
		else if(*expire_time <= time(NULL)) /* expired */
			*expire_time =0;
		else		/* valid yet */
			*expire_time -= time(NULL);
		break;
	}
	SEC_SVR_DBG("%s", "Server: Current password file successfully loaded");
	return SECURITY_SERVER_SUCCESS;
}

int get_current_attempt(int increase)
{
	int retval, fd, attempt;
	char path[255];

	snprintf(path, 255, "%s/%s", SECURITY_SERVER_DATA_DIRECTORY_PATH,
		SECURITY_SERVER_ATTEMPT_FILE_NAME);

	/* Open current attempt file as read mode */
	fd = open(path, O_RDONLY | O_NONBLOCK );
	if(fd < 0)
	{
		if(errno == ENOENT)
		{
			SEC_SVR_DBG("%s", "Server: attempt doesn't exist. Creating one:");
			/* Create one if it doesn't exist */
			fd = open(path, O_WRONLY | O_NONBLOCK | O_CREAT, 0600);
			if(fd < 0)
			{
				SEC_SVR_DBG("Server ERROR: Cannot open attempt file. errno: %d", errno);
				return SECURITY_SERVER_ERROR_FILE_OPERATION;
			}
			retval = fchmod(fd, 0600);
			if(retval != 0)
			{
				SEC_SVR_DBG("Server ERROR: Cannot chmod attempt file. errno: %d", errno);
				close(fd);
				return SECURITY_SERVER_ERROR_FILE_OPERATION;
			}
			attempt = increase;
			retval = TEMP_FAILURE_RETRY(write(fd, &attempt, sizeof(int)));
			close(fd);
			if(retval < sizeof(int))
			{
				SEC_SVR_DBG("%s", "Server ERROR: Cannot write attempt");
				return SECURITY_SERVER_ERROR_FILE_OPERATION;
			}
			return attempt;
		}
		SEC_SVR_DBG("Current password cannot be opened. errno: %d", errno);
		return SECURITY_SERVER_ERROR_FILE_OPERATION;
	}
	retval = TEMP_FAILURE_RETRY(read(fd, &attempt, sizeof(int)));
	close(fd);
	if(retval < sizeof(int))
	{
		SEC_SVR_DBG("%s", "Server ERROR: Cannot read attempt");
		return SECURITY_SERVER_ERROR_FILE_OPERATION;
	}

	if(increase > 0)
	{
		/* Open the file again with write mode */
		fd = open(path, O_WRONLY | O_NONBLOCK, 0600);
		if(fd < 0)
		{
			SEC_SVR_DBG("Server ERROR: Cannot open attempt file. errno: %d", errno);
			return SECURITY_SERVER_ERROR_FILE_OPERATION;
		}
		retval = fchmod(fd, 0600);
		if(retval != 0)
		{
			SEC_SVR_DBG("Server ERROR: Cannot chmod attempt file. errno: %d", errno);
			close(fd);
			return SECURITY_SERVER_ERROR_FILE_OPERATION;
		}
		attempt += increase;
		retval = TEMP_FAILURE_RETRY(write(fd, &attempt, sizeof(int)));
		close(fd);
		if(retval < sizeof(int))
		{
			SEC_SVR_DBG("%s", "Server ERROR: Cannot write attempt");
			return SECURITY_SERVER_ERROR_FILE_OPERATION;
		}
	}
	return attempt;
}

int reset_attempt(void)
{
	int fd, retval;
	char path[255];
	unsigned int attempt = 0;

	snprintf(path, 255, "%s/%s", SECURITY_SERVER_DATA_DIRECTORY_PATH,
		SECURITY_SERVER_ATTEMPT_FILE_NAME);

	/* Open the file again with write mode */
	fd = open(path, O_WRONLY | O_NONBLOCK, 0600);
	if(fd < 0)
	{
		SEC_SVR_DBG("Server ERROR: Cannot open attempt file. errno: %d", errno);
		return SECURITY_SERVER_ERROR_FILE_OPERATION;
	}
	retval = fchmod(fd, 0600);
	if(retval != 0)
	{
		SEC_SVR_DBG("Server ERROR: Cannot chmod attempt file. errno: %d", errno);
		close(fd);
		return SECURITY_SERVER_ERROR_FILE_OPERATION;
	}
	retval = TEMP_FAILURE_RETRY(write(fd, &attempt, sizeof(int)));
	close(fd);
	if(retval < sizeof(int))
	{
		SEC_SVR_DBG("%s", "Server ERROR: Cannot write attempt");
		return SECURITY_SERVER_ERROR_FILE_OPERATION;
	}
	SEC_SVR_DBG("%s", "Server: Attempt reset");
	return SECURITY_SERVER_SUCCESS;
}

/* Compare current password Stored password is hashed by SHA-256 Algorithm */
int check_password(const unsigned char *cur_pwd, const unsigned char *requested_pwd,
			const unsigned int max_attempts, const unsigned int expire_time,
			int *current_attempt)
{
	unsigned int current_time = time(NULL);

	if(max_attempts != 0)
	{
		*current_attempt = get_current_attempt(1);

		if(*current_attempt > max_attempts)
		{
			SEC_SVR_DBG("Server: Max attempt exceeded: %d, %d", *current_attempt, max_attempts);
			return SECURITY_SERVER_ERROR_PASSWORD_MAX_ATTEMPTS_EXCEEDED;
		}
		if(*current_attempt < 0)
		{
			SEC_SVR_DBG("Server: Attempt file operation failed. Ignoring... : %d", *current_attempt);
		}
	}

	/* Compare */
	if(memcmp(cur_pwd, requested_pwd, SECURITY_SERVER_HASHED_PWD_LEN) != 0)
	{
	    SEC_SVR_DBG("%s", "Password mismatched");
	    return SECURITY_SERVER_ERROR_PASSWORD_MISMATCH;
	}

    if(expire_time == 0)
    {
        SEC_SVR_DBG("Server: Password has been expired: %d, %d", current_time, expire_time);
        return SECURITY_SERVER_ERROR_PASSWORD_EXPIRED;
    }

    SEC_SVR_DBG("%s", "Password matched");
    return SECURITY_SERVER_SUCCESS;
}

int set_history(int num)
{
	int fd, retval;
	char path[255];

	snprintf(path, 255, "%s/%s", SECURITY_SERVER_DATA_DIRECTORY_PATH,
		SECURITY_SERVER_HISTORY_FILE_NAME);

	/* Open the file again with write mode */
	fd = open(path, O_WRONLY | O_NONBLOCK, 0600);
	if(fd < 0)
	{
		if (errno == ENOENT)
		{
			fd = open(path, O_WRONLY | O_NONBLOCK | O_CREAT, 0600);
			if(fd < 0)
			{
				SEC_SVR_DBG("Server ERROR: Cannot create history file. errno: %d", errno);
				return SECURITY_SERVER_ERROR_FILE_OPERATION;
			}
		}
		else
		{
			SEC_SVR_DBG("Server ERROR: Cannot open history file. errno: %d", errno);
			return SECURITY_SERVER_ERROR_FILE_OPERATION;
		}
	}
	retval = fchmod(fd, 0600);
	if(retval != 0)
	{
		SEC_SVR_DBG("Server ERROR: Cannot chmod history file. errno: %d", errno);
		close(fd);
		return SECURITY_SERVER_ERROR_FILE_OPERATION;
	}
	retval = TEMP_FAILURE_RETRY(write(fd, &num, sizeof(int)));
	close(fd);
	if(retval < sizeof(int))
	{
		SEC_SVR_DBG("%s", "Server ERROR: Cannot write history");
		return SECURITY_SERVER_ERROR_FILE_OPERATION;
	}
	SEC_SVR_DBG("%s", "Server: history set finished");
	return SECURITY_SERVER_SUCCESS;
}


int get_history_num(void)
{
	/* Placeholder for password history check count getting function */
	int fd, retval, history;
	char path[255];

	snprintf(path, 255, "%s/%s", SECURITY_SERVER_DATA_DIRECTORY_PATH,
		SECURITY_SERVER_HISTORY_FILE_NAME);

	/* Load password file */
	fd = open(path, O_RDONLY | O_NONBLOCK );
	if(fd < 0)
	{
		if(errno == ENOENT)
		{
			SEC_SVR_DBG("%s", "Server: history file doesn't exist");
			retval = set_history(0);
			return retval;
		}
		SEC_SVR_DBG("Server ERROR: history file cannot be opened. errno: %d", errno);
		return SECURITY_SERVER_ERROR_FILE_OPERATION;
	}
	retval = TEMP_FAILURE_RETRY(read(fd, &history, sizeof(history)));
	close(fd);
	if(retval < sizeof(history))
	{
		SEC_SVR_DBG("%s", "History file corrupted. Creating new one");
		unlink(path);
		retval = set_history(0);
		return retval;
	}
	SEC_SVR_DBG("History file read: %d", history);
	return history;
}



int check_history(const unsigned char *requested_pwd)
{
	unsigned char history_pwd[SECURITY_SERVER_HASHED_PWD_LEN];
	char path[255];
	int num, history_count, fd, file_count, retval;
	int retval2 = SECURITY_SERVER_SUCCESS;
	struct dirent **mydirent;

	history_count = get_history_num();
	if(history_count <= 0)
		return SECURITY_SERVER_SUCCESS;

	num = scandir(SECURITY_SERVER_DATA_DIRECTORY_PATH, &mydirent, &dir_filter, alphasort);
	if(num < 0)
	{
		SEC_SVR_DBG("Server: [Error] Cannot scan password directory. errno: %d", errno);
		return SECURITY_SERVER_ERROR_FILE_OPERATION;
	}

	if(num == 0)
	{
		SEC_SVR_DBG("%s", "Server: There is no password file");
		return SECURITY_SERVER_ERROR_NO_PASSWORD;
	}

	file_count = 2;
	while((num--))
	{
		snprintf(path, 255, "%s/%s", SECURITY_SERVER_DATA_DIRECTORY_PATH, mydirent[num]->d_name);
		SEC_SVR_DBG("Password file path: %s", path);
		if(history_count > 0)
		{
			/* Load password file */
			fd = open(path, O_RDONLY | O_NONBLOCK );
			if(fd < 0)
			{
				if(errno == ENOENT)
				{
					SEC_SVR_DBG("%s", "Current password doesn't exist");
					return SECURITY_SERVER_SUCCESS;
				}
				SEC_SVR_DBG("Current password cannot be opened. errno: %d", errno);
				return SECURITY_SERVER_ERROR_FILE_OPERATION;
			}
			/* Read and store into memory */
			retval = TEMP_FAILURE_RETRY(read(fd, history_pwd, SECURITY_SERVER_HASHED_PWD_LEN));
			if(retval < SECURITY_SERVER_HASHED_PWD_LEN)
			{
				SEC_SVR_DBG("%s", "Current password corrupted. resetting to previous one. 0");
				close(fd);
				fd = 0;
				unlink(path);
				continue;
			}
			close(fd);
			/* Compare */
			if(memcmp(history_pwd, requested_pwd, SECURITY_SERVER_HASHED_PWD_LEN) == 0)
			{
				SEC_SVR_DBG("%s", "Server: Password has been reused");
				retval2 =  SECURITY_SERVER_ERROR_PASSWORD_REUSED;
			}
			history_count--;

		}

		/* Remove too old or invalid password history */
		retval = validate_pwd_file(mydirent[num]->d_name);
		if(retval != SECURITY_SERVER_SUCCESS || file_count > (SECURITY_SERVER_MAX_PASSWORD_HISTORY))
		{
			SEC_SVR_DBG("Removing too old password. %s", path);
			unlink(path);
		}
		file_count++;
		free(mydirent[num]);
	}
	free(mydirent);
	if(retval2 == SECURITY_SERVER_ERROR_PASSWORD_REUSED)
		retval = retval2;
	return retval;
}

/* Password file format */
/*  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * |---------------------------------------------------------------|
 * |                                                               |
 * |                                                               |
 * |                       Hashed PWD (32 bytes)                   |
 * |                                                               |
 * |---------------------------------------------------------------|
 * |                       Max attempts (4 bytes)                  |
 * |---------------------------------------------------------------|
 * |              Expiration time in seconds (4 bytes)             |
 * |---------------------------------------------------------------|
 */
int set_password(const unsigned char *requested_new_pwd, const unsigned int attempts,
			const unsigned int expire_time)
{
	int retval, fd;
	char pwd_path[255];

	/* New file created */
	retval = time(NULL);
	snprintf(pwd_path, 255, "%s/%d.pwd", SECURITY_SERVER_DATA_DIRECTORY_PATH, retval);

	/* Save new password as current password */
	fd = open(pwd_path, O_WRONLY | O_NONBLOCK | O_CREAT, 0600);
	if(fd < 0)
	{
		SEC_SVR_DBG("Cannot open current password file. errno: %d", errno);
		return SECURITY_SERVER_ERROR_FILE_OPERATION;
	}
	retval = fchmod(fd, 0600);
	if(retval != 0)
	{
		SEC_SVR_DBG("Cannot chmod current password file. errno: %d", errno);
		close(fd);
		return SECURITY_SERVER_ERROR_FILE_OPERATION;
	}
	retval = TEMP_FAILURE_RETRY(write(fd, requested_new_pwd, SECURITY_SERVER_HASHED_PWD_LEN));
	if(retval < SECURITY_SERVER_HASHED_PWD_LEN)
	{
		SEC_SVR_DBG("%s", "Cannot write password");
		close(fd);
		return SECURITY_SERVER_ERROR_FILE_OPERATION;
	}
	retval = TEMP_FAILURE_RETRY(write(fd, &attempts, sizeof(unsigned int)));
	if(retval < sizeof(unsigned int))
	{
		SEC_SVR_DBG("%s", "Cannot write password");
		close(fd);
		return SECURITY_SERVER_ERROR_FILE_OPERATION;
	}
	retval = TEMP_FAILURE_RETRY(write(fd, &expire_time, sizeof(unsigned int)));
	if(retval < sizeof(unsigned int))
	{
		SEC_SVR_DBG("%s", "Cannot write password");
		close(fd);
		return SECURITY_SERVER_ERROR_FILE_OPERATION;
	}
	fsync(fd);
	close(fd);
	SEC_SVR_DBG("%s", "Password file created");
	return SECURITY_SERVER_SUCCESS;
}

int check_retry(const struct timeval cur_try)
{
	int interval_sec, interval_usec;
	interval_sec = cur_try.tv_sec - prev_try.tv_sec;
	interval_usec = cur_try.tv_usec - prev_try.tv_usec;
	prev_try = cur_try;
	if(interval_sec == 0
	        && interval_usec > SECURITY_SERVER_PASSWORD_RETRY_TIMEOUT_MICROSECOND)
		return SECURITY_SERVER_SUCCESS;

	if(interval_sec > 0)
		return SECURITY_SERVER_SUCCESS;

	SEC_SVR_DBG("%s", "retry timer hit");
	return SECURITY_SERVER_ERROR_PASSWORD_RETRY_TIMER;
}

int process_valid_pwd_request(int sockfd)
{
	struct timeval cur_try;
	int retval, current_attempts, password_set;
	unsigned char cur_pwd[SECURITY_SERVER_HASHED_PWD_LEN];
	unsigned int max_attempt, expire_time;

/*
	if(retval != SECURITY_SERVER_SUCCESS)
	{
		SEC_SVR_DBG("%s", "Client Authentication Failed");
		retval = send_generic_response(client_sockfd,
				SECURITY_SERVER_MSG_TYPE_TOOL_RESPONSE,
				SECURITY_SERVER_RETURN_CODE_AUTHENTICATION_FAILED);
		if(retval != SECURITY_SERVER_SUCCESS)
		{
			SEC_SVR_DBG("ERROR: Cannot send generic response: %d", retval);
		}
		goto error;
	}
*/

	/* Check retry timer */
	gettimeofday(&cur_try, NULL);
	retval = check_retry(cur_try);
	if(retval != SECURITY_SERVER_SUCCESS)
	{
		SEC_SVR_DBG("%s", "Server: Retry timeout occurred");
		retval = send_generic_response(sockfd,
				SECURITY_SERVER_MSG_TYPE_GENERIC_RESPONSE,
				SECURITY_SERVER_RETURN_CODE_PASSWORD_RETRY_TIMER);
		if(retval != SECURITY_SERVER_SUCCESS)
		{
			SEC_SVR_DBG("Server ERROR: Cannot send generic response: %d", retval);
		}
		goto error;
	}
	password_set = load_password(cur_pwd, &max_attempt, &expire_time);
	if(password_set == SECURITY_SERVER_ERROR_SERVER_ERROR)
	{
		SEC_SVR_DBG("%s", "Server: Responding error because we cannot provide password service");
		retval = send_generic_response(sockfd,
				SECURITY_SERVER_MSG_TYPE_GENERIC_RESPONSE,
				SECURITY_SERVER_RETURN_CODE_SERVER_ERROR);
		if(retval != SECURITY_SERVER_SUCCESS)
		{
			SEC_SVR_DBG("Server ERROR: Cannot send generic response: %d", retval);
		}
		goto error;
	}

	current_attempts = get_current_attempt(0);
	if(current_attempts < 0)
	{
		SEC_SVR_DBG("Server ERROR: Cannot get attempts: %d", current_attempts);
		retval = send_generic_response(sockfd,
				SECURITY_SERVER_MSG_TYPE_GENERIC_RESPONSE,
				SECURITY_SERVER_RETURN_CODE_SERVER_ERROR);
		if(retval != SECURITY_SERVER_SUCCESS)
		{
			SEC_SVR_DBG("Server ERROR: Cannot send generic response: %d", retval);
		}
	}

	/* There is no password */
	if(password_set == SECURITY_SERVER_ERROR_NO_PASSWORD)
	{
		retval = send_pwd_response(sockfd,
				SECURITY_SERVER_MSG_TYPE_VALID_PWD_RESPONSE,
				SECURITY_SERVER_RETURN_CODE_NO_PASSWORD,
				0, 0, 0);
		if(retval != SECURITY_SERVER_SUCCESS)
		{
			SEC_SVR_DBG("Server ERROR: Cannot send password response: %d", retval);
		}
		goto error;
	}
	if(password_set == SECURITY_SERVER_SUCCESS)
	{
		retval = send_pwd_response(sockfd,
				SECURITY_SERVER_MSG_TYPE_VALID_PWD_RESPONSE,
				SECURITY_SERVER_RETURN_CODE_PASSWORD_EXIST,
				current_attempts, max_attempt, expire_time);
		if(retval != SECURITY_SERVER_SUCCESS)
		{
			SEC_SVR_DBG("Server ERROR: Cannot send password response: %d", retval);
		}
		goto error;
	}
	SEC_SVR_DBG("Server ERROR: Unknown error: %d", retval);
	retval = send_generic_response(sockfd,
			SECURITY_SERVER_MSG_TYPE_GENERIC_RESPONSE,
			SECURITY_SERVER_RETURN_CODE_SERVER_ERROR);
	if(retval != SECURITY_SERVER_SUCCESS)
	{
		SEC_SVR_DBG("Server ERROR: Cannot send generic response: %d", retval);
	}
error:
	return retval;
}

int process_set_pwd_request(int sockfd)
{
	struct timeval cur_try;
	int retval, password_set, current_attempt;
	unsigned int max_attempt, expire_time, valid_days, received_attempts;
	char  new_pwd_len = 0, cur_pwd_len = 0;
	char requested_cur_pwd[SECURITY_SERVER_MAX_PASSWORD_LEN+1];
	char requested_new_pwd[SECURITY_SERVER_MAX_PASSWORD_LEN+1];
	unsigned char cur_pwd[SECURITY_SERVER_HASHED_PWD_LEN];
	unsigned char hashed_challenge[SECURITY_SERVER_HASHED_PWD_LEN];
	unsigned char hashed_new_pw[SECURITY_SERVER_HASHED_PWD_LEN];

	SHA256_CTX context;

	/* Authenticate client that peer is setting app goes here*/
	/* Check SMACK 'rw' rule for the set password */
	retval = SECURITY_SERVER_SUCCESS;
/*
	if(retval != SECURITY_SERVER_SUCCESS)
	{
		SEC_SVR_DBG("%s", "Client Authentication Failed");
		retval = send_generic_response(client_sockfd,
				SECURITY_SERVER_MSG_TYPE_TOOL_RESPONSE,
				SECURITY_SERVER_RETURN_CODE_AUTHENTICATION_FAILED);
		if(retval != SECURITY_SERVER_SUCCESS)
		{
			SEC_SVR_DBG("ERROR: Cannot send generic response: %d", retval);
		}
		goto error;
	}
*/

	/* Check retry timer */
	gettimeofday(&cur_try, NULL);
	retval = check_retry(cur_try);
	if(retval != SECURITY_SERVER_SUCCESS)
	{
		SEC_SVR_DBG("%s", "Server: Retry timeout occurred");
		retval = send_generic_response(sockfd,
				SECURITY_SERVER_MSG_TYPE_SET_PWD_RESPONSE,
				SECURITY_SERVER_RETURN_CODE_PASSWORD_RETRY_TIMER);
		if(retval != SECURITY_SERVER_SUCCESS)
		{
			SEC_SVR_DBG("Server ERROR: Cannot send generic response: %d", retval);
		}
		goto error;
	}
	password_set = load_password(cur_pwd, &max_attempt, &expire_time);
	/* If we cannot load password file */
	if(password_set == SECURITY_SERVER_ERROR_SERVER_ERROR)
	{
		SEC_SVR_DBG("%s", "Server: Responding error because we cannot provide password service");
		retval = send_generic_response(sockfd,
				SECURITY_SERVER_MSG_TYPE_SET_PWD_RESPONSE,
				SECURITY_SERVER_RETURN_CODE_SERVER_ERROR);
		if(retval != SECURITY_SERVER_SUCCESS)
		{
			SEC_SVR_DBG("Server ERROR: Cannot send generic response: %d", retval);
		}
		goto error;
	}

	/* Receive size of pwds */
	retval = TEMP_FAILURE_RETRY(read(sockfd, &cur_pwd_len, sizeof(char)));
	if(retval < sizeof(char) || cur_pwd_len > SECURITY_SERVER_MAX_PASSWORD_LEN)
	{
		SEC_SVR_DBG("Server Error: current password length recieve failed: %d, %d", retval, cur_pwd_len);
		retval = send_generic_response(sockfd,
				SECURITY_SERVER_MSG_TYPE_SET_PWD_RESPONSE,
				SECURITY_SERVER_RETURN_CODE_BAD_REQUEST);
		if(retval != SECURITY_SERVER_SUCCESS)
		{
			SEC_SVR_DBG("Server ERROR: Cannot send generic response: %d", retval);
		}
		goto error;
	}
	retval = TEMP_FAILURE_RETRY(read(sockfd, &new_pwd_len, sizeof(char)));
	if(retval < sizeof(char)  || new_pwd_len > SECURITY_SERVER_MAX_PASSWORD_LEN || new_pwd_len < 0)
	{
		SEC_SVR_DBG("Server Error: new password length recieve failed: %d, %d", retval, new_pwd_len);
		retval = send_generic_response(sockfd,
				SECURITY_SERVER_MSG_TYPE_SET_PWD_RESPONSE,
				SECURITY_SERVER_RETURN_CODE_BAD_REQUEST);
		if(retval != SECURITY_SERVER_SUCCESS)
		{
			SEC_SVR_DBG("Server ERROR: Cannot send generic response: %d", retval);
		}
		goto error;
	}

	/* Receive current password */
	if(cur_pwd_len > 0)
	{
		/* Check wheter current password is exist */
		if(password_set == SECURITY_SERVER_SUCCESS)
		retval = TEMP_FAILURE_RETRY(read(sockfd, requested_cur_pwd, cur_pwd_len));
		if(retval < cur_pwd_len)
		{
			SEC_SVR_DBG("Server Error: current password recieve failed: %d", retval);
			retval = send_generic_response(sockfd,
					SECURITY_SERVER_MSG_TYPE_SET_PWD_RESPONSE,
					SECURITY_SERVER_RETURN_CODE_BAD_REQUEST);
			if(retval != SECURITY_SERVER_SUCCESS)
			{
				SEC_SVR_DBG("Server ERROR: Cannot send generic response: %d", retval);
			}
			goto error;
		}
		requested_cur_pwd[cur_pwd_len] = 0;
	}
	else /* Check first password set attempt but password is already set */
	{
		if(password_set == SECURITY_SERVER_SUCCESS)
		{
			SEC_SVR_DBG("Server Error: password is already set: %d", retval);
			retval = send_generic_response(sockfd,
					SECURITY_SERVER_MSG_TYPE_SET_PWD_RESPONSE,
					SECURITY_SERVER_RETURN_CODE_PASSWORD_EXIST);
			if(retval != SECURITY_SERVER_SUCCESS)
			{
				SEC_SVR_DBG("Server ERROR: Cannot send generic response: %d", retval);
			}
			goto error;
		}
	}

	/* Receive new password */
	retval = TEMP_FAILURE_RETRY(read(sockfd, requested_new_pwd, new_pwd_len));
	if(retval < new_pwd_len)
	{
		SEC_SVR_DBG("Server Error:  new password recieve failed: %d", retval);
		retval = send_generic_response(sockfd,
				SECURITY_SERVER_MSG_TYPE_SET_PWD_RESPONSE,
				SECURITY_SERVER_RETURN_CODE_BAD_REQUEST);
		if(retval != SECURITY_SERVER_SUCCESS)
		{
			SEC_SVR_DBG("Server ERROR: Cannot send generic response: %d", retval);
		}
		goto error;
	}
	requested_new_pwd[new_pwd_len] = 0;

	/* Receive max attempt */
	retval = TEMP_FAILURE_RETRY(read(sockfd, &received_attempts, sizeof(unsigned int)));
	if(retval < sizeof(unsigned int))
	{
		SEC_SVR_DBG("Sever Error:  Max attempt receive failed: %d", retval);
		retval = send_generic_response(sockfd,
				SECURITY_SERVER_MSG_TYPE_SET_PWD_RESPONSE,
				SECURITY_SERVER_RETURN_CODE_BAD_REQUEST);
		if(retval != SECURITY_SERVER_SUCCESS)
		{
			SEC_SVR_DBG("Server ERROR: Cannot send generic response: %d", retval);
		}
		goto error;
	}

	/* Receive valid period  */
	retval = TEMP_FAILURE_RETRY(read(sockfd, &valid_days, sizeof(unsigned int)));
	if(retval < sizeof(unsigned int))
	{
		SEC_SVR_DBG("Sever Error:  Max attempt receive failed: %d", retval);
		retval = send_generic_response(sockfd,
				SECURITY_SERVER_MSG_TYPE_SET_PWD_RESPONSE,
				SECURITY_SERVER_RETURN_CODE_BAD_REQUEST);
		if(retval != SECURITY_SERVER_SUCCESS)
		{
			SEC_SVR_DBG("Server ERROR: Cannot send generic response: %d", retval);
		}
		goto error;
	}

	/* Hash requested password */
	SHA256_Init(&context);
	SHA256_Update(&context, (unsigned char*)requested_cur_pwd, strlen(requested_cur_pwd));
	SHA256_Final(hashed_challenge, &context);

	SHA256_Init(&context);
	SHA256_Update(&context, (unsigned char*)requested_new_pwd, strlen(requested_new_pwd));
	SHA256_Final(hashed_new_pw, &context);

	/* check current password */
	if(password_set  == SECURITY_SERVER_SUCCESS)
	{
		retval = check_password(cur_pwd, hashed_challenge, max_attempt, expire_time, &current_attempt);
		if(retval == SECURITY_SERVER_ERROR_PASSWORD_MISMATCH)
		{
			SEC_SVR_DBG("%s", "Server: Wrong password");
			retval = send_generic_response(sockfd,
					SECURITY_SERVER_MSG_TYPE_SET_PWD_RESPONSE,
					SECURITY_SERVER_RETURN_CODE_PASSWORD_MISMATCH);
			if(retval != SECURITY_SERVER_SUCCESS)
			{
				SEC_SVR_DBG("Server ERROR: Cannot send generic response: %d", retval);
			}
			goto error;
		}
		if(retval == SECURITY_SERVER_ERROR_PASSWORD_MAX_ATTEMPTS_EXCEEDED)
		{
			SEC_SVR_DBG("%s", "Server: Too many challange");
			retval = send_generic_response(sockfd,
					SECURITY_SERVER_MSG_TYPE_SET_PWD_RESPONSE,
					SECURITY_SERVER_RETURN_CODE_PASSWORD_MAX_ATTEMPTS_EXCEEDED);
			if(retval != SECURITY_SERVER_SUCCESS)
			{
				SEC_SVR_DBG("Server ERROR: Cannot send generic response: %d", retval);
			}
			goto error;
		}
		if(retval == SECURITY_SERVER_ERROR_PASSWORD_EXPIRED)
		{
			SEC_SVR_DBG("%s", "Server: Password expired");
			retval = send_generic_response(sockfd,
					SECURITY_SERVER_MSG_TYPE_SET_PWD_RESPONSE,
					SECURITY_SERVER_RETURN_CODE_PASSWORD_EXPIRED);
			if(retval != SECURITY_SERVER_SUCCESS)
			{
				SEC_SVR_DBG("Server ERROR: Cannot send generic response: %d", retval);
			}
			goto error;
		}
		if(retval != SECURITY_SERVER_SUCCESS)
		{
			SEC_SVR_DBG("Error: Password check failed: %d", retval);
			retval = send_generic_response(sockfd,
					SECURITY_SERVER_MSG_TYPE_SET_PWD_RESPONSE,
					SECURITY_SERVER_RETURN_CODE_SERVER_ERROR);
			if(retval != SECURITY_SERVER_SUCCESS)
			{
				SEC_SVR_DBG("Server ERROR: Cannot send generic response: %d", retval);
			}
			goto error;
		}
		retval = check_history(hashed_new_pw);
		if(retval == SECURITY_SERVER_ERROR_PASSWORD_REUSED)
		{
			retval = send_generic_response(sockfd,
					SECURITY_SERVER_MSG_TYPE_SET_PWD_RESPONSE,
					SECURITY_SERVER_RETURN_CODE_PASSWORD_REUSED);
			if(retval != SECURITY_SERVER_SUCCESS)
			{
				SEC_SVR_DBG("Server ERROR: Cannot send generic response: %d", retval);
			}
			goto error;
		}
	}
	else if(cur_pwd_len != 0)
	{
		/* Client ask to set with current password, but there is no password now */
		SEC_SVR_DBG("%s", "Server: There is no current password. But try to set with current password");
		retval = send_generic_response(sockfd,
				SECURITY_SERVER_MSG_TYPE_SET_PWD_RESPONSE,
				SECURITY_SERVER_RETURN_CODE_PASSWORD_MISMATCH);
		if(retval != SECURITY_SERVER_SUCCESS)
		{
			SEC_SVR_DBG("Server ERROR: Cannot send generic response: %d", retval);
		}
		goto error;
	}

	/* Calculate expire time in seconds */
	if(valid_days == 0)
		expire_time = 0;
	else
		expire_time = time(NULL) + (valid_days * 86400);

	/* set new password */
	retval = set_password(hashed_new_pw, received_attempts, expire_time);
	if(retval != SECURITY_SERVER_SUCCESS)
	{
		SEC_SVR_DBG("Server Error: Password set failed: %d", retval);
		retval = send_generic_response(sockfd,
				SECURITY_SERVER_MSG_TYPE_SET_PWD_RESPONSE,
				SECURITY_SERVER_RETURN_CODE_SERVER_ERROR);
		if(retval != SECURITY_SERVER_SUCCESS)
		{
			SEC_SVR_DBG("Server ERROR: Cannot send generic response: %d", retval);
		}
		password_set = SECURITY_SERVER_ERROR_SERVER_ERROR;
		goto error;
	}
	password_set = SECURITY_SERVER_SUCCESS;
	retval = reset_attempt();

	/* All done. send response */
	SEC_SVR_DBG("%s", "Server: Password has been successfully modified");
	retval = send_generic_response(sockfd,
			SECURITY_SERVER_MSG_TYPE_SET_PWD_RESPONSE,
			SECURITY_SERVER_RETURN_CODE_SUCCESS);
	if(retval != SECURITY_SERVER_SUCCESS)
	{
		SEC_SVR_DBG("Server ERROR: Cannot send generic response: %d", retval);
	}
error:
	return retval;
}

int process_reset_pwd_request(int sockfd)
{
	int retval, password_set;
	char new_pwd_len;
	unsigned int valid_days, received_attempts, expire_time;
	char requested_new_pwd[SECURITY_SERVER_MAX_PASSWORD_LEN +1];
	unsigned char hashed_new_pw[SECURITY_SERVER_HASHED_PWD_LEN];
	unsigned char cur_pwd[SECURITY_SERVER_HASHED_PWD_LEN];
	struct timeval cur_try;

	SHA256_CTX context;

	/* Authenticate client that peer is setting app goes here*/
/*
	if(retval != SECURITY_SERVER_SUCCESS)
	{
		SEC_SVR_DBG("%s", "Client Authentication Failed");
		retval = send_generic_response(client_sockfd,
				SECURITY_SERVER_MSG_TYPE_TOOL_RESPONSE,
				SECURITY_SERVER_RETURN_CODE_AUTHENTICATION_FAILED);
		if(retval != SECURITY_SERVER_SUCCESS)
		{
			SEC_SVR_DBG("ERROR: Cannot send generic response: %d", retval);
		}
		goto error;
	}
*/

	/* Check retry timer */
	gettimeofday(&cur_try, NULL);
	retval = check_retry(cur_try);
	if(retval != SECURITY_SERVER_SUCCESS)
	{
		SEC_SVR_DBG("%s", "Server: Retry timeout occurred");
		retval = send_generic_response(sockfd,
				SECURITY_SERVER_MSG_TYPE_RESET_PWD_RESPONSE,
				SECURITY_SERVER_RETURN_CODE_PASSWORD_RETRY_TIMER);
		if(retval != SECURITY_SERVER_SUCCESS)
		{
			SEC_SVR_DBG("Server ERROR: Cannot send generic response: %d", retval);
		}
		goto error;
	}

	password_set = load_password(cur_pwd, &valid_days, &expire_time);
	if(password_set == SECURITY_SERVER_ERROR_SERVER_ERROR)
	{
		SEC_SVR_DBG("%s", "Server: Responding error because we cannot provide password service");
		retval = send_generic_response(sockfd,
				SECURITY_SERVER_MSG_TYPE_GENERIC_RESPONSE,
				SECURITY_SERVER_RETURN_CODE_SERVER_ERROR);
		if(retval != SECURITY_SERVER_SUCCESS)
		{
			SEC_SVR_DBG("Server ERROR: Cannot send generic response: %d", retval);
		}
		goto error;
	}

	/* Receive size of pwd */
	retval = TEMP_FAILURE_RETRY(read(sockfd, &new_pwd_len, sizeof(char)));
	if(retval < sizeof(char) || new_pwd_len < 0 || new_pwd_len > SECURITY_SERVER_MAX_PASSWORD_LEN)
	{
		SEC_SVR_DBG("Server Error: new password length recieve failed: %d, %d", retval, new_pwd_len);
		retval = send_generic_response(sockfd,
				SECURITY_SERVER_MSG_TYPE_RESET_PWD_RESPONSE,
				SECURITY_SERVER_RETURN_CODE_BAD_REQUEST);
		if(retval != SECURITY_SERVER_SUCCESS)
		{
			SEC_SVR_DBG("Server ERROR: Cannot send generic response: %d", retval);
		}
		goto error;
	}

	/* Receive new password */
	retval = TEMP_FAILURE_RETRY(read(sockfd, requested_new_pwd, new_pwd_len));
	if(retval < new_pwd_len)
	{
		SEC_SVR_DBG("Server Error:  new password recieve failed: %d", retval);
		retval = send_generic_response(sockfd,
				SECURITY_SERVER_MSG_TYPE_RESET_PWD_RESPONSE,
				SECURITY_SERVER_RETURN_CODE_BAD_REQUEST);
		if(retval != SECURITY_SERVER_SUCCESS)
		{
			SEC_SVR_DBG("Server ERROR: Cannot send generic response: %d", retval);
		}
		goto error;
	}
	requested_new_pwd[new_pwd_len] = 0;

	/* Receive max attempt */
	retval = TEMP_FAILURE_RETRY(read(sockfd, &received_attempts, sizeof(unsigned int)));
	if(retval < sizeof(unsigned int))
	{
		SEC_SVR_DBG("Sever Error:  Max attempt receive failed: %d", retval);
		retval = send_generic_response(sockfd,
				SECURITY_SERVER_MSG_TYPE_RESET_PWD_RESPONSE,
				SECURITY_SERVER_RETURN_CODE_BAD_REQUEST);
		if(retval != SECURITY_SERVER_SUCCESS)
		{
			SEC_SVR_DBG("Server ERROR: Cannot send generic response: %d", retval);
		}
		goto error;
	}

	/* Receive valid period  */
	retval = TEMP_FAILURE_RETRY(read(sockfd, &valid_days, sizeof(unsigned int)));
	if(retval < sizeof(unsigned int))
	{
		SEC_SVR_DBG("Sever Error:  Max attempt receive failed: %d", retval);
		retval = send_generic_response(sockfd,
				SECURITY_SERVER_MSG_TYPE_RESET_PWD_RESPONSE,
				SECURITY_SERVER_RETURN_CODE_BAD_REQUEST);
		if(retval != SECURITY_SERVER_SUCCESS)
		{
			SEC_SVR_DBG("Server ERROR: Cannot send generic response: %d", retval);
		}
		goto error;
	}

	/* Calculate expire time in seconds */
	if(valid_days == 0)
		expire_time = 0;
	else
		expire_time = time(NULL) + (valid_days * 86400);

	/* Hash requested password */
	SHA256_Init(&context);
	SHA256_Update(&context, (unsigned char*)requested_new_pwd, strlen(requested_new_pwd));
	SHA256_Final(hashed_new_pw, &context);
	/* set new password */
	retval = set_password(hashed_new_pw, received_attempts, expire_time);
	if(retval != SECURITY_SERVER_SUCCESS)
	{
		SEC_SVR_DBG("Server Error: Password set failed: %d", retval);
		retval = send_generic_response(sockfd,
				SECURITY_SERVER_MSG_TYPE_RESET_PWD_RESPONSE,
				SECURITY_SERVER_RETURN_CODE_SERVER_ERROR);
		if(retval != SECURITY_SERVER_SUCCESS)
		{
			SEC_SVR_DBG("Server ERROR: Cannot send generic response: %d", retval);
		}
		goto error;
	}
	retval = reset_attempt();

	/* All done. send response */
	SEC_SVR_DBG("%s", "Server: Password has been successfully modified");
	retval = send_generic_response(sockfd,
			SECURITY_SERVER_MSG_TYPE_RESET_PWD_RESPONSE,
			SECURITY_SERVER_RETURN_CODE_SUCCESS);
	if(retval != SECURITY_SERVER_SUCCESS)
	{
		SEC_SVR_DBG("Server ERROR: Cannot send generic response: %d", retval);
	}
error:
	return retval;
}

int process_chk_pwd_request(int sockfd)
{
	int retval, password_set, current_attempt;
	unsigned int max_attempt, expire_time;
	char requested_challenge[SECURITY_SERVER_MAX_PASSWORD_LEN+1];
	char challenge_len;
	unsigned char cur_pwd[SECURITY_SERVER_HASHED_PWD_LEN];
	unsigned char hashed_challenge[SECURITY_SERVER_HASHED_PWD_LEN];
	struct timeval cur_try;

	SHA256_CTX context;

	/* Authenticate client that peer is proper app goes here*/
	/* Check SMACK rule for the 'r' for password */
	retval = SECURITY_SERVER_SUCCESS;
/*
	if(retval != SECURITY_SERVER_SUCCESS)
	{
		SEC_SVR_DBG("%s", "Client Authentication Failed");
		retval = send_generic_response(sockfd,
				SECURITY_SERVER_MSG_TYPE_TOOL_RESPONSE,
				SECURITY_SERVER_RETURN_CODE_AUTHENTICATION_FAILED);
		if(retval != SECURITY_SERVER_SUCCESS)
		{
			SEC_SVR_DBG("ERROR: Cannot send generic response: %d", retval);
		}
		goto error;
	}
*/
	/* Check retry timer */
	gettimeofday(&cur_try, NULL);
	retval = check_retry(cur_try);
	if(retval != SECURITY_SERVER_SUCCESS)
	{
		SEC_SVR_DBG("%s", "Server: Retry timeout occurred");
		retval = send_generic_response(sockfd,
				SECURITY_SERVER_MSG_TYPE_CHK_PWD_RESPONSE,
				SECURITY_SERVER_RETURN_CODE_PASSWORD_RETRY_TIMER);
		if(retval != SECURITY_SERVER_SUCCESS)
		{
			SEC_SVR_DBG("Server ERROR: Cannot send generic response: %d", retval);
		}
		goto error;
	}

	/* If we cannot load password file */
	password_set = load_password(cur_pwd, &max_attempt, &expire_time);;
	if(password_set == SECURITY_SERVER_ERROR_SERVER_ERROR)
	{
		SEC_SVR_DBG("%s", "ServerERROR: Responding error because we cannot provide password service");
		retval = send_generic_response(sockfd,
				SECURITY_SERVER_MSG_TYPE_CHK_PWD_RESPONSE,
				SECURITY_SERVER_RETURN_CODE_SERVER_ERROR);
		if(retval != SECURITY_SERVER_SUCCESS)
		{
			SEC_SVR_DBG("Server ERROR: Cannot send generic response: %d", retval);
		}
		goto error;
	}

	/* Receive size of challenge */
	retval = TEMP_FAILURE_RETRY(read(sockfd, &challenge_len, sizeof(char)));
	if(retval < sizeof(char) || challenge_len > SECURITY_SERVER_MAX_PASSWORD_LEN)
	{
		SEC_SVR_DBG("Server ERROR: challenge length recieve failed: %d", retval);
		retval = send_generic_response(sockfd,
				SECURITY_SERVER_MSG_TYPE_CHK_PWD_RESPONSE,
				SECURITY_SERVER_RETURN_CODE_BAD_REQUEST);
		if(retval != SECURITY_SERVER_SUCCESS)
		{
			SEC_SVR_DBG("Server ERROR: Cannot send generic response: %d", retval);
		}
		goto error;
	}
	/* Receive challenge */
	if(challenge_len > 0)
	{
		retval = TEMP_FAILURE_RETRY(read(sockfd, requested_challenge, challenge_len));
		if(retval < challenge_len)
		{
			SEC_SVR_DBG("Server ERROR: current password recieve failed: %d", retval);
			retval = send_generic_response(sockfd,
					SECURITY_SERVER_MSG_TYPE_CHK_PWD_RESPONSE,
					SECURITY_SERVER_RETURN_CODE_BAD_REQUEST);
			if(retval != SECURITY_SERVER_SUCCESS)
			{
				SEC_SVR_DBG("Server ERROR: Cannot send generic response: %d", retval);
			}
			goto error;
		}
		requested_challenge[challenge_len] = 0;
	}
	else
	{
		SEC_SVR_DBG("Error: Challenge length too short: %d", retval);
		retval = send_generic_response(sockfd,
				SECURITY_SERVER_MSG_TYPE_CHK_PWD_RESPONSE,
				SECURITY_SERVER_RETURN_CODE_BAD_REQUEST);
		if(retval != SECURITY_SERVER_SUCCESS)
		{
			SEC_SVR_DBG("Server ERROR: Cannot send generic response: %d", retval);
		}
		goto error;
	}

	/* Hash requested password */
	SHA256_Init(&context);
	SHA256_Update(&context, (unsigned char*)requested_challenge, challenge_len);
	SHA256_Final(hashed_challenge, &context);

	/* check current password */
	if(password_set  == SECURITY_SERVER_SUCCESS)
	{
		retval = check_password(cur_pwd, hashed_challenge, max_attempt, expire_time, &current_attempt);
		if(retval == SECURITY_SERVER_ERROR_PASSWORD_MISMATCH)
		{
			SEC_SVR_DBG("%s", "Server: Wrong password");
			retval = send_pwd_response(sockfd,
					SECURITY_SERVER_MSG_TYPE_CHK_PWD_RESPONSE,
					SECURITY_SERVER_RETURN_CODE_PASSWORD_MISMATCH,
					current_attempt, max_attempt, expire_time);
			if(retval != SECURITY_SERVER_SUCCESS)
			{
				SEC_SVR_DBG("Server ERROR: Cannot send generic response: %d", retval);
			}
			goto error;
		}
		if(retval == SECURITY_SERVER_ERROR_PASSWORD_MAX_ATTEMPTS_EXCEEDED)
		{
			SEC_SVR_DBG("%s", "Server: Too many trial");
			retval = send_pwd_response(sockfd,
					SECURITY_SERVER_MSG_TYPE_CHK_PWD_RESPONSE,
					SECURITY_SERVER_RETURN_CODE_PASSWORD_MAX_ATTEMPTS_EXCEEDED,
					current_attempt, max_attempt, expire_time);
			if(retval != SECURITY_SERVER_SUCCESS)
			{
				SEC_SVR_DBG("Server ERROR: Cannot send generic response: %d", retval);
			}
			goto error;
		}
		if(retval == SECURITY_SERVER_ERROR_PASSWORD_EXPIRED)
		{
			SEC_SVR_DBG("%s", "Server: Password expired");
			retval = send_pwd_response(sockfd,
					SECURITY_SERVER_MSG_TYPE_CHK_PWD_RESPONSE,
					SECURITY_SERVER_RETURN_CODE_PASSWORD_EXPIRED,
					current_attempt, max_attempt, 0);
			if(retval != SECURITY_SERVER_SUCCESS)
			{
				SEC_SVR_DBG("Server ERROR: Cannot send generic response: %d", retval);
			}
			goto error;
		}
		if(retval != SECURITY_SERVER_SUCCESS)
		{
			SEC_SVR_DBG("Server ERROR: Password check failed: %d", retval);
			retval = send_generic_response(sockfd,
					SECURITY_SERVER_MSG_TYPE_CHK_PWD_RESPONSE,
					SECURITY_SERVER_RETURN_CODE_SERVER_ERROR);
			if(retval != SECURITY_SERVER_SUCCESS)
			{
				SEC_SVR_DBG("Server ERROR: Cannot send generic response: %d", retval);
			}
			goto error;
		}

		/* Password matched */
		SEC_SVR_DBG("%s", "Server: Password matched");
		retval = send_pwd_response(sockfd,
				SECURITY_SERVER_MSG_TYPE_CHK_PWD_RESPONSE,
				SECURITY_SERVER_RETURN_CODE_SUCCESS,
				current_attempt, max_attempt, expire_time);
		if(retval != SECURITY_SERVER_SUCCESS)
		{
			SEC_SVR_DBG("Server ERROR: Cannot send generic response: %d", retval);
		}
		retval = reset_attempt();
		goto error;
	}

	/* There is no password */

	SEC_SVR_DBG("%s", "Server: There is no password to be checked");
	retval = send_generic_response(sockfd,
			SECURITY_SERVER_MSG_TYPE_CHK_PWD_RESPONSE,
			SECURITY_SERVER_RETURN_CODE_NO_PASSWORD);
	if(retval != SECURITY_SERVER_SUCCESS)
	{
		SEC_SVR_DBG("Server ERROR: Cannot send generic response: %d", retval);
	}
error:
	return retval;
}

int process_set_pwd_history_request(int sockfd)
{
	int retval;
	char history_num;
	struct timeval cur_try;

	/* Authenticate client that peer is setting app goes here*/
/*
	f(retval != SECURITY_SERVER_SUCCESS)
	{
		SEC_SVR_DBG("%s", "Client Authentication Failed");
		retval = send_generic_response(client_sockfd,
				SECURITY_SERVER_MSG_TYPE_TOOL_RESPONSE,
				SECURITY_SERVER_RETURN_CODE_AUTHENTICATION_FAILED);
		if(retval != SECURITY_SERVER_SUCCESS)
		{
			SEC_SVR_DBG("ERROR: Cannot send generic response: %d", retval);
		}
		goto error;
	}
*/

	/* Check retry timer */
	gettimeofday(&cur_try, NULL);
	retval = check_retry(cur_try);
	if(retval != SECURITY_SERVER_SUCCESS)
	{
		SEC_SVR_DBG("%s", "Server: Retry timeout occurred");
		retval = send_generic_response(sockfd,
				SECURITY_SERVER_MSG_TYPE_SET_PWD_HISTORY_RESPONSE,
				SECURITY_SERVER_RETURN_CODE_PASSWORD_RETRY_TIMER);
		if(retval != SECURITY_SERVER_SUCCESS)
		{
			SEC_SVR_DBG("Server ERROR: Cannot send generic response: %d", retval);
		}
		goto error;
	}

	/* Receive size of pwds */
	retval = TEMP_FAILURE_RETRY(read(sockfd, &history_num, sizeof(char)));
	if(retval < sizeof(char) || history_num > SECURITY_SERVER_MAX_PASSWORD_HISTORY || history_num < 0 )
	{
		SEC_SVR_DBG("Server Error: History number recieve failed: %d, %d", retval, history_num);
		retval = send_generic_response(sockfd,
				SECURITY_SERVER_MSG_TYPE_SET_PWD_HISTORY_RESPONSE,
				SECURITY_SERVER_RETURN_CODE_BAD_REQUEST);
		if(retval != SECURITY_SERVER_SUCCESS)
		{
			SEC_SVR_DBG("Server ERROR: Cannot send generic response: %d", retval);
		}
		goto error;
	}

	retval = set_history((int)history_num);
	if(retval != SECURITY_SERVER_SUCCESS)
	{
		SEC_SVR_DBG("Server Error: History number set failed: %d", retval);
		retval = send_generic_response(sockfd,
				SECURITY_SERVER_MSG_TYPE_SET_PWD_HISTORY_RESPONSE,
				SECURITY_SERVER_RETURN_CODE_SERVER_ERROR);
		if(retval != SECURITY_SERVER_SUCCESS)
		{
			SEC_SVR_DBG("Server ERROR: Cannot send generic response: %d", retval);
		}
	}
	SEC_SVR_DBG("Server History has been set to %d", history_num);
	retval = send_generic_response(sockfd,
			SECURITY_SERVER_MSG_TYPE_SET_PWD_HISTORY_RESPONSE,
			SECURITY_SERVER_RETURN_CODE_SUCCESS);
	if(retval != SECURITY_SERVER_SUCCESS)
	{
		SEC_SVR_DBG("Server ERROR: Cannot send generic response: %d", retval);
	}
error:
	return retval;
}


int process_set_pwd_max_challenge_request(int sockfd)
{
    unsigned int max_challenge, current_challenge, current_validity;
    unsigned char cur_pwd[SECURITY_SERVER_HASHED_PWD_LEN];
    int retval;

    // TODO here we should probably check if the peer has rights to change
    // this value (max challenge) for current password

    retval = TEMP_FAILURE_RETRY(read(sockfd, &max_challenge, sizeof(unsigned int)));
    if(retval < sizeof(unsigned int))
    {
        SEC_SVR_DBG("Server Error: recieve failed: %d", retval);
        retval = send_generic_response(sockfd,
                SECURITY_SERVER_MSG_TYPE_SET_PWD_MAX_CHALLENGE_RESPONSE,
                SECURITY_SERVER_RETURN_CODE_BAD_REQUEST);
        if(retval != SECURITY_SERVER_SUCCESS)
        {
            SEC_SVR_DBG("Server ERROR: Cannot send generic response: %d", retval);
        }
        goto error;
    }

    SEC_SVR_DBG("Server max challenge request: %d", max_challenge);

    // Getting currently set password
    retval = load_password(cur_pwd, &current_challenge, &current_validity);
    /* If we cannot load password file */
    if(retval == SECURITY_SERVER_ERROR_NO_PASSWORD)
    {
        SEC_SVR_DBG("%s", "Server: can't read current password");
        retval = send_generic_response(sockfd,
                SECURITY_SERVER_MSG_TYPE_SET_PWD_MAX_CHALLENGE_RESPONSE,
                SECURITY_SERVER_RETURN_CODE_NO_PASSWORD);
        if(retval != SECURITY_SERVER_SUCCESS)
        {
            SEC_SVR_DBG("Server ERROR: Cannot send generic response: %d", retval);
        }
        goto error;
    }
    else if(retval != SECURITY_SERVER_SUCCESS)
    {
        SEC_SVR_DBG("%s", "Server: can't read current password");
        retval = send_generic_response(sockfd,
                SECURITY_SERVER_MSG_TYPE_SET_PWD_MAX_CHALLENGE_RESPONSE,
                SECURITY_SERVER_RETURN_CODE_SERVER_ERROR);
        if(retval != SECURITY_SERVER_SUCCESS)
        {
            SEC_SVR_DBG("Server ERROR: Cannot send generic response: %d", retval);
        }
        goto error;
    }

    // Set 'new' password file with old password and new max challenge
    retval = set_password(cur_pwd, max_challenge, time(NULL) + current_validity);
    if(retval != SECURITY_SERVER_SUCCESS)
    {
        SEC_SVR_DBG("Server Error: Password set failed: %d", retval);
        retval = send_generic_response(sockfd,
                SECURITY_SERVER_MSG_TYPE_SET_PWD_MAX_CHALLENGE_RESPONSE,
                SECURITY_SERVER_RETURN_CODE_SERVER_ERROR);
        if(retval != SECURITY_SERVER_SUCCESS)
        {
            SEC_SVR_DBG("Server ERROR: Cannot send generic response: %d", retval);
        }
        goto error;
    }

    retval = send_generic_response(sockfd,
            SECURITY_SERVER_MSG_TYPE_SET_PWD_MAX_CHALLENGE_RESPONSE,
            SECURITY_SERVER_RETURN_CODE_SUCCESS);
    if(retval != SECURITY_SERVER_SUCCESS)
    {
        SEC_SVR_DBG("Server ERROR: Cannot send generic response: %d", retval);
    }
    retval = reset_attempt();
error:
    return retval;
}

int process_set_pwd_validity_request(int sockfd)
{
    unsigned int current_challenge, current_validity, validity;
    unsigned char cur_pwd[SECURITY_SERVER_HASHED_PWD_LEN];
    int retval;

    // TODO here we should probably check if the peer has rights to change
    // this value (validity) for current password

    retval = TEMP_FAILURE_RETRY(read(sockfd, &validity, sizeof(unsigned int)));
    if(retval < sizeof(unsigned int))
    {
        SEC_SVR_DBG("Server Error: recieve failed: %d", retval);
        retval = send_generic_response(sockfd,
                SECURITY_SERVER_MSG_TYPE_SET_PWD_VALIDITY_RESPONSE,
                SECURITY_SERVER_RETURN_CODE_BAD_REQUEST);
        if(retval != SECURITY_SERVER_SUCCESS)
        {
            SEC_SVR_DBG("Server ERROR: Cannot send generic response: %d", retval);
        }
        goto error;
    }

    SEC_SVR_DBG("Server validity request: %d", validity);

    // Calculating validity in seconds
    if(validity == 0)
        validity = 0;
    else
        validity = time(NULL) + (validity * 86400);

    // Getting currently set password
    retval = load_password(cur_pwd, &current_challenge, &current_validity);
    /* If we cannot load password file */
    if(retval == SECURITY_SERVER_ERROR_NO_PASSWORD)
    {
        SEC_SVR_DBG("%s", "Server: can't read current password");
        retval = send_generic_response(sockfd,
                SECURITY_SERVER_MSG_TYPE_SET_PWD_VALIDITY_RESPONSE,
                SECURITY_SERVER_RETURN_CODE_NO_PASSWORD);
        if(retval != SECURITY_SERVER_SUCCESS)
        {
            SEC_SVR_DBG("Server ERROR: Cannot send generic response: %d", retval);
        }
        goto error;
    }
    else if(retval != SECURITY_SERVER_SUCCESS)
    {
        SEC_SVR_DBG("%s", "Server: can't read current password");
        retval = send_generic_response(sockfd,
                SECURITY_SERVER_MSG_TYPE_SET_PWD_VALIDITY_RESPONSE,
                SECURITY_SERVER_RETURN_CODE_SERVER_ERROR);
        if(retval != SECURITY_SERVER_SUCCESS)
        {
            SEC_SVR_DBG("Server ERROR: Cannot send generic response: %d", retval);
        }
        goto error;
    }

    // Set 'new' password file with old password and new validity
    retval = set_password(cur_pwd, current_challenge, validity);
    if(retval != SECURITY_SERVER_SUCCESS)
    {
        SEC_SVR_DBG("Server Error: Password set failed: %d", retval);
        retval = send_generic_response(sockfd,
                SECURITY_SERVER_MSG_TYPE_SET_PWD_VALIDITY_RESPONSE,
                SECURITY_SERVER_RETURN_CODE_SERVER_ERROR);
        if(retval != SECURITY_SERVER_SUCCESS)
        {
            SEC_SVR_DBG("Server ERROR: Cannot send generic response: %d", retval);
        }
        goto error;
    }

    retval = send_generic_response(sockfd,
            SECURITY_SERVER_MSG_TYPE_SET_PWD_VALIDITY_RESPONSE,
            SECURITY_SERVER_RETURN_CODE_SUCCESS);
    if(retval != SECURITY_SERVER_SUCCESS)
    {
        SEC_SVR_DBG("Server ERROR: Cannot send generic response: %d", retval);
    }
    retval = reset_attempt();
error:
    return retval;
}

