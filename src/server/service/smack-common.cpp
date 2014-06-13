#include <sys/capability.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/smack.h>
#include <string.h>
#include <stdio.h>

#include <smack-check.h>

namespace SecurityManager {

int get_smack_label_from_process(pid_t pid, char *smack_label)
{
    int ret = -1;
    int fd = -1;
    const int PATH_MAX_LEN = 64;
    char path[PATH_MAX_LEN + 1];

    if (pid < 0) {
        goto out;
    }

    if(smack_label == NULL) {
        goto out;
    }

    bzero(smack_label, SMACK_LABEL_LEN + 1);
    if (!smack_check()) { // If no smack just return success with empty label
        ret = 0;
        goto out;
    }

    bzero(path, PATH_MAX_LEN + 1);
    snprintf(path, PATH_MAX_LEN, "/proc/%d/attr/current", pid);
    fd = open(path, O_RDONLY);
    if (fd < 0) {
        goto out;
    }

    ret = read(fd, smack_label, SMACK_LABEL_LEN);
    if (ret < 0) {
        goto out;
    }

    ret = 0;

out:
    if (fd >= 0)
        close(fd);
    return ret;
}


int smack_pid_have_access(pid_t pid,
                          const char* object,
                          const char *access_type)
{
    int ret;
    char pid_subject_label[SMACK_LABEL_LEN + 1];
    cap_t cap;
    cap_flag_value_t cap_v;

    if (!smack_check()) {
        return 1;
    }

    if (pid < 0) {
        return -1;
    }

    if(object == NULL) {
        return -1;
    }

    if(access_type == NULL) {
        return -1;
    }

    //get SMACK label of process
    ret = get_smack_label_from_process(pid, pid_subject_label);
    if (0 != ret) {
        return -1;
    }

    // do not call smack_have_access() if label is empty
    if (pid_subject_label[0] != '\0') {
        ret = smack_have_access(pid_subject_label, object, access_type);
        if ( -1 == ret) {
            return -1;
        }
        if ( 1 == ret ) { // smack_have_access return 1 (access granted)
            return 1;
        }
    }

    // smack_have_access returned 0 (access denied). Now CAP_MAC_OVERRIDE should be checked
    cap = cap_get_pid(pid);
    if (cap == NULL) {
        return -1;
    }
    ret = cap_get_flag(cap, CAP_MAC_OVERRIDE, CAP_EFFECTIVE, &cap_v);
    if (0 != ret) {
        return -1;
    }

    if (cap_v == CAP_SET) {
        return 1;
    } else {
        return 0;
    }
}



} // namespace SecurityManager

