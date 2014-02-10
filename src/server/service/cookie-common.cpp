#include <cookie-common.h>
#include <stdio.h>
#include <unistd.h>
#include <dpl/log/log.h>

namespace SecurityServer {

int getPidPath(char *path, unsigned int pathSize, int pid)
{
    int retval;
    char link[pathSize];

    snprintf(link, pathSize, "/proc/%d/exe", pid);
    retval = readlink(link, path, pathSize-1);
    if (retval < 0) {
        LogDebug("Unable to get process path");
        return -1;
    }
    path[retval] = '\0';

    return 0;
}

} // namespace SecurityServer
