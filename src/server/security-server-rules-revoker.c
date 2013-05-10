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
#include <pthread.h>
#include <search.h>
#include <stdlib.h>
#include <string.h>

#include <privilege-control.h>

#include <security-server-rules-revoker.h>

static pthread_mutex_t tree_mutex;
static void *tree_root = NULL;

typedef struct tree_info_t {
    int pid;
    char *subject;
    char *object;
} tree_info;

static int tree_cmp(const void *first, const void *second) {
    return (((tree_info*)first)->pid) - (((tree_info*)second)->pid);
}

static int tree_info_push(tree_info *node) {
    int ret = 0;
    pthread_mutex_lock(&tree_mutex);

    if (NULL != tfind(node, &tree_root, tree_cmp)) {
        ret = -1;
        goto end;
    }

    tsearch(node, &tree_root, tree_cmp);
end:
    pthread_mutex_unlock(&tree_mutex);
    return ret;
}


static int tree_info_add(int pid, const char *subject_param, const char *object_param) {
    tree_info *node = malloc(sizeof(tree_info));
    char *subject = strdup(subject_param);
    char *object = strdup(object_param);

    if (!node || !subject || !object)
        goto error;

    node->pid = pid;
    node->subject = subject;
    node->object = object;

    if (0 == tree_info_push(node))
        return 0;

error:
    free(node);
    free(subject);
    free(object);
    return -1;
}

static tree_info* tree_info_pop_new(int pid) {
    tree_info search, *node = NULL;
    void *wtf;
    search.pid = pid;

    pthread_mutex_lock(&tree_mutex);

    wtf = tfind(&search, &tree_root, tree_cmp);
    if (!wtf)
        goto end;

    node = *(tree_info**)wtf;
    if (!node)
        goto end;

    tdelete(node, &tree_root, tree_cmp);
end:
    pthread_mutex_unlock(&tree_mutex);
    return node;
}

static int rules_revoker_pid(int pid) {
    tree_info *node = NULL;
    int ret = 0;

    node = tree_info_pop_new(pid);
    if (!node)
        return 0;

    if (PC_OPERATION_SUCCESS != app_revoke_access(node->subject, node->object))
        ret = -1;

    free(node->subject);
    free(node->object);
    free(node);
    return ret;
}

void rules_revoker_init(void) {
   pthread_mutex_init(&tree_mutex, NULL);
}

int rules_revoker_add(int pid, const char *subject, const char *object) {
    return tree_info_add(pid, subject, object);
}

void rules_revoker_callback(const struct proc_event *event) {
    if (PROC_EVENT_EXIT != event->what)
        return;
    rules_revoker_pid(event->event_data.exit.process_pid);
}

