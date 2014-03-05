#ifndef _SMACK_COMMON_H_
#define _SMACK_COMMON_H_

#include <sys/types.h>

namespace SecurityServer {

int get_smack_label_from_process(pid_t pid, char *smack_label);
int smack_pid_have_access(pid_t pid, const char *object, const char *access_type);

} // namespace SecurityServer

#endif
