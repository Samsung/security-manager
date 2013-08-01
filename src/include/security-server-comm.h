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

#ifndef SECURITY_SERVER_COMM_H
#define SECURITY_SERVER_COMM_H

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

#define SECURITY_SERVER_MIDDLEWARE_USER "app"

/* Message Types */
// #define SECURITY_SERVER_MSG_TYPE_OBJECT_NAME_REQUEST            0x05
// #define SECURITY_SERVER_MSG_TYPE_OBJECT_NAME_RESPONSE           0x06
#define SECURITY_SERVER_MSG_TYPE_GID_REQUEST                    0x07
#define SECURITY_SERVER_MSG_TYPE_GID_RESPONSE                   0x08
#define SECURITY_SERVER_MSG_TYPE_VALID_PWD_REQUEST              0x0d
#define SECURITY_SERVER_MSG_TYPE_VALID_PWD_RESPONSE             0x0e
#define SECURITY_SERVER_MSG_TYPE_SET_PWD_REQUEST                0x0f
#define SECURITY_SERVER_MSG_TYPE_SET_PWD_RESPONSE               0x10
#define SECURITY_SERVER_MSG_TYPE_RESET_PWD_REQUEST              0x11
#define SECURITY_SERVER_MSG_TYPE_RESET_PWD_RESPONSE             0x12
#define SECURITY_SERVER_MSG_TYPE_CHK_PWD_REQUEST                0x13
#define SECURITY_SERVER_MSG_TYPE_CHK_PWD_RESPONSE               0x14
#define SECURITY_SERVER_MSG_TYPE_SET_PWD_HISTORY_REQUEST        0x15
#define SECURITY_SERVER_MSG_TYPE_SET_PWD_HISTORY_RESPONSE       0x16
#define SECURITY_SERVER_MSG_TYPE_SET_PWD_MAX_CHALLENGE_REQUEST  0x19
#define SECURITY_SERVER_MSG_TYPE_SET_PWD_MAX_CHALLENGE_RESPONSE 0x1a
#define SECURITY_SERVER_MSG_TYPE_SET_PWD_VALIDITY_REQUEST       0x1b
#define SECURITY_SERVER_MSG_TYPE_SET_PWD_VALIDITY_RESPONSE      0x1c
#ifdef  USE_SEC_SRV1_FOR_CHECK_PRIVILEGE_BY_PID
#define SECURITY_SERVER_MSG_TYPE_CHECK_PID_PRIVILEGE_REQUEST    0x21
#define SECURITY_SERVER_MSG_TYPE_CHECK_PID_PRIVILEGE_RESPONSE   0x22
#endif
#define SECURITY_SERVER_MSG_TYPE_GENERIC_RESPONSE               0xff

/* Return code */
#define SECURITY_SERVER_RETURN_CODE_SUCCESS                        0x00
#define SECURITY_SERVER_RETURN_CODE_BAD_REQUEST                    0x01
#define SECURITY_SERVER_RETURN_CODE_AUTHENTICATION_FAILED          0x02
#define SECURITY_SERVER_RETURN_CODE_ACCESS_GRANTED                 0x03
#define SECURITY_SERVER_RETURN_CODE_ACCESS_DENIED                  0x04
#define SECURITY_SERVER_RETURN_CODE_NO_SUCH_OBJECT                 0x05
#define SECURITY_SERVER_RETURN_CODE_NO_SUCH_COOKIE                 0x06
#define SECURITY_SERVER_RETURN_CODE_NO_PASSWORD                    0x07
#define SECURITY_SERVER_RETURN_CODE_PASSWORD_EXIST                 0x08
#define SECURITY_SERVER_RETURN_CODE_PASSWORD_MISMATCH              0x09
#define SECURITY_SERVER_RETURN_CODE_PASSWORD_MAX_ATTEMPTS_EXCEEDED 0x0a
#define SECURITY_SERVER_RETURN_CODE_PASSWORD_EXPIRED               0x0b
#define SECURITY_SERVER_RETURN_CODE_PASSWORD_REUSED                0x0c
#define SECURITY_SERVER_RETURN_CODE_PASSWORD_RETRY_TIMER           0x0d
#define SECURITY_SERVER_RETURN_CODE_SERVER_ERROR                   0x0e

int return_code_to_error_code(int ret_code);
int create_new_socket(int *sockfd);
int safe_server_sock_close(int client_sockfd);
int connect_to_server(int *fd);
int accept_client(int server_sockfd);
int authenticate_client_application(int sockfd, int *pid, int *uid);
int authenticate_client_middleware(int sockfd, int *pid);
int get_client_gid_list(int sockfd, int **privileges);
int send_generic_response (int sockfd, unsigned char msgid, unsigned char return_code);
int send_object_name(int sockfd, char *obj);
int send_gid(int sockfd, int gid);
int send_gid_request(int sock_fd, const char *object);
int send_object_name_request(int sock_fd, int gid);
int recv_get_gid_response(int sockfd, response_header *hdr, int *gid);
int recv_get_object_name(int sockfd, response_header *hdr, char *object, int max_object_size);

int recv_hdr(int client_sockfd, basic_header *basic_hdr);

#ifdef USE_SEC_SRV1_FOR_CHECK_PRIVILEGE_BY_PID
int send_pid_privilege_request(int sockfd, int pid, const char *object, const char *access_rights);
int recv_pid_privilege_request(int sockfd, int datasize, int *pid, char **object, char **access_rights);
int recv_pid_privilege_response(int sockfdi, response_header *hdr);
#endif

int recv_generic_response(int sockfd, response_header *hdr);
int recv_pwd_response(int sockfd, response_header *hdr, unsigned int *current_attempts,
                      unsigned int *max_attempts, unsigned int *valid_days);
int send_set_pwd_request(int sock_fd, const char *cur_pwd, const char *new_pwd,
                         const unsigned int max_challenge, const unsigned int valid_period_in_days);
int send_set_pwd_validity_request(int sock_fd, const unsigned int valid_period_in_days);
int send_set_pwd_max_challenge_request(int sock_fd, const unsigned int max_challenge);
int send_chk_pwd_request(int sock_fd, const char *challenge);
int check_socket_poll(int sockfd, int event, int timeout);
int free_argv(char **argv, int argc);
int send_valid_pwd_request(int sock_fd);
int send_reset_pwd_request(int sock_fd,
                           const char *new_pwd,
                           const unsigned int max_challenge,
                           const unsigned int valid_period_in_days);
int send_set_pwd_history_request(int sock_fd, int num);
int get_socket_from_systemd(int *sockfd);

int send_pwd_response(const int sockfd,
                      const unsigned char msg_id,
                      const unsigned char return_code,
                      const unsigned int current_attempts,
                      const unsigned int max_attempts,
                      const unsigned int expire_time);

#endif
