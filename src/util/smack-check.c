#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include <security-server-common.h>
#include <smack-check.h>

int smack_runtime_check(void)
{
    static int smack_present = -1;
    if (-1 == smack_present) {
        int fd = open("/smack/load2", O_WRONLY);
        if (-1 == fd) {
            SEC_SVR_DBG("%s","security-server: no smack found on device");
            smack_present = 0;
        } else {
            SEC_SVR_DBG("%s","security-server: found smack on device");
            close(fd);
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
