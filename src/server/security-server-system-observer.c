/*
 * security-server
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
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/connector.h>
#include <linux/cn_proc.h>

#include <unistd.h>
#include <string.h>
#include <strings.h>
#include <stdio.h>
#include <errno.h>

#include <security-server-common.h>
#include <security-server-system-observer.h>

#define NL_MESSAGE_SIZE (sizeof(struct nlmsghdr) + sizeof(struct cn_msg) + \
                         sizeof(int))

static int nl_sock;

int connect_to_netlink()
{
    struct sockaddr_nl sa_nl; /* netlink interface info */
    char buff[NL_MESSAGE_SIZE];
    struct nlmsghdr *hdr; /* for telling netlink what we want */
    struct cn_msg *msg;   /* the actual connector message */

    /* connect to netlink socket */
    nl_sock = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_CONNECTOR);

    if (-1 == nl_sock) {
        SEC_SVR_ERR("socket failed: %s", strerror(errno));
        return SECURITY_SERVER_ERROR_SOCKET;
    }

    bzero(&sa_nl, sizeof(sa_nl));
    sa_nl.nl_family = AF_NETLINK;
    sa_nl.nl_groups = CN_IDX_PROC;
    sa_nl.nl_pid = getpid();

    if (-1 == bind(nl_sock, (struct sockaddr*)&sa_nl, sizeof(sa_nl))) {
        SEC_SVR_ERR("bind failed: %s", strerror(errno));
        close(nl_sock);
        return SECURITY_SERVER_ERROR_SOCKET;
    }

    /* Fill header */
    hdr = (struct nlmsghdr*)buff;
    hdr->nlmsg_len = NL_MESSAGE_SIZE;
    hdr->nlmsg_type = NLMSG_DONE;
    hdr->nlmsg_flags = 0;
    hdr->nlmsg_seq = 0;
    hdr->nlmsg_pid = getpid();

    /* Fill message */
    msg = (struct cn_msg*)NLMSG_DATA(hdr);
    msg->id.idx = CN_IDX_PROC;  /* Connecting to process information */
    msg->id.val = CN_VAL_PROC;
    msg->seq = 0;
    msg->ack = 0;
    msg->flags = 0;
    msg->len = sizeof(int);
    *(int*)msg->data = PROC_CN_MCAST_LISTEN;

    if (-1 == send(nl_sock, hdr, hdr->nlmsg_len, 0)) {
        SEC_SVR_ERR("send failed: %s", strerror(errno));
        close(nl_sock);
        return SECURITY_SERVER_ERROR_SOCKET;
    }

    return SECURITY_SERVER_SUCCESS;
}

void handle_events(system_observer_config *data)
{
    char buff[CONNECTOR_MAX_MSG_SIZE];
    struct nlmsghdr *hdr;
    struct proc_event *event;

    fd_set fds;

    while (1) {
        FD_ZERO(&fds);
        FD_SET(nl_sock, &fds);

        if (0 > select(nl_sock + 1, &fds, NULL, NULL, NULL)) {
            SEC_SVR_ERR("select failed: %s", strerror(errno));
            return;
        }

        /* If there were no events detected, return */
        if (!FD_ISSET(nl_sock, &fds)) {
            return;
        }

        /* if there are events, make calls */
        if (-1 == recv(nl_sock, buff, sizeof(buff), 0)) {
            SEC_SVR_ERR("recv failed: %s", strerror(errno));
            return;
        }

        hdr = (struct nlmsghdr*)buff;

        if (NLMSG_ERROR == hdr->nlmsg_type) {
            SEC_SVR_ERR("%s", "NLMSG_ERROR");
        } else if (NLMSG_DONE == hdr->nlmsg_type) {
            event = (struct proc_event*)((struct cn_msg*)NLMSG_DATA(hdr))->data;
            if (data->event_callback)
                (data->event_callback)(event);
        }
    }
}

void *system_observer_main(void *data)
{
    if (SECURITY_SERVER_SUCCESS == connect_to_netlink()) {
        handle_events((system_observer_config*)data);
        close(nl_sock);
    }
    return NULL;
}

