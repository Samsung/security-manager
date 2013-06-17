#include <sys/smack.h>

#include <security-server-common.h>
#include <smack-check.h>

int smack_runtime_check(void)
{
    static int smack_present = -1;
    if (-1 == smack_present) {
        if (NULL == smack_smackfs_path()) {
            SECURE_LOGD("%s","security-server: no smack found on device");
            smack_present = 0;
        } else {
            SECURE_LOGD("%s","security-server: found smack on device");
            smack_present = 1;
        }
    }
    return smack_present;
}

int smack_check(void)
{
#ifndef SMACK_ENABLED
    return 0;
#else
    return smack_runtime_check();
#endif

}
