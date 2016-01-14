/*
 *  Copyright (c) 2015 Samsung Electronics Co., Ltd All Rights Reserved
 *
 *  Contact: Rafal Krypa <r.krypa@samsung.com>
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
 */
/*
 * @file        check-proper-drop.cpp
 * @author      Rafal Krypa <r.krypa@samsung.com>
 * @version     1.0
 * @brief       Implementation of proper privilege dropping check utilities
 */

#include "check-proper-drop.h"
#include "smack-labels.h"
#include <dpl/log/log.h>

#include <sys/capability.h>

#include <memory>
#include <string>

namespace SecurityManager {

using proctabPtr = std::unique_ptr<PROCTAB, void (*)(PROCTAB*)>;
using capPtr = std::unique_ptr<_cap_struct, int (*)(void*)>;
using capStrPtr = std::unique_ptr<char, int(*)(void*)>;

CheckProperDrop::~CheckProperDrop()
{
    for (const auto &thread : m_threads)
        freeproc(thread);
    freeproc(m_proc);
}

void CheckProperDrop::getThreads()
{
    pid_t pid[2] = {m_pid, 0};
    proctabPtr PT(openproc(PROC_FILLSTATUS | PROC_PID, pid), closeproc);
    if (!PT)
        ThrowMsg(Exception::ProcError,
            "Unable to open proc interface");

    m_proc = readproc(PT.get(), nullptr);
    if (!m_proc)
        ThrowMsg(Exception::ProcError,
            "Unable read process information for " << pid);

    proc_t *thread;
    while ((thread = readtask(PT.get(), m_proc, nullptr)))
        if (thread->tid != m_pid)
            m_threads.push_back(thread);
}

bool CheckProperDrop::checkThreads()
{
#define REPORT_THREAD_ERROR(TID, NAME, VAL1, VAL2) {                           \
    LogError("Invalid value of " << (NAME) << " for thread " << (TID) << "."   \
        << ". Process has " << (VAL1) << ", thread has " << (VAL2) << ".");    \
    return false;                                                              \
}

#define CHECK_THREAD_CRED_FIELD(P, T, FIELD) {                                 \
    int pval = (P)->FIELD, tval = (T)->FIELD;                                  \
    if (pval != tval)                                                          \
        REPORT_THREAD_ERROR((T)->tid, #FIELD, pval, tval);                     \
}

    std::string smackProc = SmackLabels::getSmackLabelFromPid(m_pid);

    capPtr capProc(cap_get_pid(m_pid), cap_free);
    if (!capProc)
        ThrowMsg(Exception::CapError,
            "Unable to get capabilities for " << m_pid);

    capStrPtr capStrProc(cap_to_text(capProc.get(), nullptr), cap_free);
    if (!capStrProc)
        ThrowMsg(Exception::CapError,
            "Unable to get capabilities for " << m_pid);

    for (const auto &thread : m_threads) {
        capPtr capThread(cap_get_pid(thread->tid), cap_free);
        if (!capThread)
            ThrowMsg(Exception::CapError,
                "Unable to get capabilities for " << thread->tid);

        if (cap_compare(capProc.get(), capThread.get())) {
            capStrPtr capStrThread(cap_to_text(capThread.get(), nullptr), cap_free);
            if (!capStrThread)
                ThrowMsg(Exception::CapError, "Unable to get capabilities for " << thread->tid);

            REPORT_THREAD_ERROR(thread->tid, "capabilities",
                capStrProc.get(), capStrThread.get());
        }

        std::string smackThread = SmackLabels::getSmackLabelFromPid(thread->tid);
        if (smackProc != smackThread)
            REPORT_THREAD_ERROR(thread->tid, "Smack label",
                smackProc, smackThread);

        if (strcmp(m_proc->supgid, thread->supgid))
            REPORT_THREAD_ERROR(thread->tid, "Supplementary groups",
                m_proc->supgid, thread->supgid);

            CHECK_THREAD_CRED_FIELD(m_proc, thread, euid);
            CHECK_THREAD_CRED_FIELD(m_proc, thread, egid);
            CHECK_THREAD_CRED_FIELD(m_proc, thread, ruid);
            CHECK_THREAD_CRED_FIELD(m_proc, thread, rgid);
            CHECK_THREAD_CRED_FIELD(m_proc, thread, suid);
            CHECK_THREAD_CRED_FIELD(m_proc, thread, sgid);
            CHECK_THREAD_CRED_FIELD(m_proc, thread, fuid);
            CHECK_THREAD_CRED_FIELD(m_proc, thread, fgid);
    }

    return true;
}

} // namespace SecurityManager
