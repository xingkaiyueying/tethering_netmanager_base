/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "iptables_wrapper.h"

#include <unistd.h>
#include <sys/syscall.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <cerrno>
#include <vector>

#include "datetime_ex.h"
#include "net_manager_constants.h"
#include "netmanager_base_common_utils.h"
#include "netnative_log_wrapper.h"

#ifdef UNITTEST_WAIT_FFRT
#undef UNITTEST_WAIT_FFRT
#endif
#define UNITTEST_WAIT_FFRT 1

namespace OHOS {
namespace nmd {
using namespace NetManagerStandard;
namespace {
constexpr const char *IPATBLES_CMD_PATH = "/system/bin/iptables";
constexpr const char *IP6TABLES_CMD_PATH = "/system/bin/ip6tables";
constexpr const char *IPTABLES_RESTORE_CMD_PATH = "/system/bin/iptables-restore";
constexpr const char *IP6TABLES_RESTORE_CMD_PATH = "/system/bin/ip6tables-restore";
constexpr const char *IPTABLES_RULE_PATH = "/data/service/el1/public/netsysnative/iptables.rule";
constexpr const int32_t MAX_IPTABLES_FFRT_TASK_NUM = 200;
constexpr const int32_t IPTABLES_PROCESS_PRIORITY = -20;
constexpr const int32_t DEFAULT_PROCESS_PRIORITY = 0;
int32_t ExecuteChecked(const std::string &binary, const std::string &arguments)
{
    // No shell. Arguments originate from validated internal sharing rules and fixed paths.
    std::vector<std::string> words = CommonUtils::Split(binary + " " + arguments, " ");
    std::vector<char *> argv;
    for (auto &word : words)
        if (!word.empty())
            argv.push_back(word.data());
    argv.push_back(nullptr);
    pid_t child = fork();
    if (child < 0)
        return NETMANAGER_ERROR;
    if (child == 0) {
        execv(binary.c_str(), argv.data());
        _exit(127);
    }
    int status = 0;
    pid_t result;
    do {
        result = waitpid(child, &status, 0);
    } while (result < 0 && errno == EINTR);
    return result == child && WIFEXITED(status) && WEXITSTATUS(status) == 0 ? NETMANAGER_SUCCESS : NETMANAGER_ERROR;
}
} // namespace

IptablesWrapper::IptablesWrapper()
{
    isRunningFlag_ = true;
    isIptablesSystemAccess_ = access(IPATBLES_CMD_PATH, F_OK) == 0;
    isIp6tablesSystemAccess_ = access(IP6TABLES_CMD_PATH, F_OK) == 0;

    iptablesWrapperFfrtQueue_ = std::make_shared<ffrt::queue>("IptablesWrapper");
}

IptablesWrapper::~IptablesWrapper()
{
    isRunningFlag_ = false;
    iptablesWrapperFfrtQueue_.reset();
}

void IptablesWrapper::ExecuteCommand(const std::string &command)
{
    std::string cmdWithWait = command + " -w 5 ";
    NETNATIVE_LOGI("ExecuteCommand %{public}s", CommonUtils::AnonymousIpInStr(cmdWithWait).c_str());
    setpriority(PRIO_PROCESS, syscall(SYS_gettid), IPTABLES_PROCESS_PRIORITY);
    if (CommonUtils::ForkExec(cmdWithWait) == NETMANAGER_ERROR) {
        NETNATIVE_LOGE("run exec faild");
    }
    setpriority(PRIO_PROCESS, syscall(SYS_gettid), DEFAULT_PROCESS_PRIORITY);
}

void IptablesWrapper::ExecuteCommandForRes(const std::string &command)
{
    std::string cmdWithWait = command + " -w 5 ";
    NETNATIVE_LOGI("ExecuteCommandForRes %{public}s", CommonUtils::AnonymousIpInStr(cmdWithWait).c_str());
    setpriority(PRIO_PROCESS, syscall(SYS_gettid), IPTABLES_PROCESS_PRIORITY);
    if (CommonUtils::ForkExec(cmdWithWait, &result_) == NETMANAGER_ERROR) {
        NETNATIVE_LOGE("run exec faild");
    }
    setpriority(PRIO_PROCESS, syscall(SYS_gettid), DEFAULT_PROCESS_PRIORITY);
}

void IptablesWrapper::ExecuteRestoreCommand(const std::string &restoreCmd, const std::string &command)
{
    if (!CommonUtils::WriteFile(IPTABLES_RULE_PATH, command)) {
        NETNATIVE_LOGE("iptables restore rule file write err");
        return;
    }

    std::string cmdWithWait = restoreCmd + " --wait=5 ";
    NETNATIVE_LOGI("ExecuteCommand %{public}s", CommonUtils::AnonymousIpInStr(cmdWithWait).c_str());
    setpriority(PRIO_PROCESS, syscall(SYS_gettid), IPTABLES_PROCESS_PRIORITY);
    if (CommonUtils::ForkExec(cmdWithWait) == NETMANAGER_ERROR) {
        NETNATIVE_LOGE("run exec faild");
    }
    setpriority(PRIO_PROCESS, syscall(SYS_gettid), DEFAULT_PROCESS_PRIORITY);
}

int32_t IptablesWrapper::RunCommand(const IpType &ipType, const std::string &command)
{
    NETNATIVE_LOG_D("IptablesWrapper::RunCommand, ipType:%{public}d", ipType);
    if (!iptablesWrapperFfrtQueue_) {
        NETNATIVE_LOGE("FFRT Init Fail");
        return NETMANAGER_ERROR;
    }

    if (isIptablesSystemAccess_ && (ipType == IPTYPE_IPV4 || ipType == IPTYPE_IPV4V6)) {
        std::string cmd = std::string(IPATBLES_CMD_PATH) + " " + command;
        std::function<void()> executeCommand = std::bind(&IptablesWrapper::ExecuteCommand, shared_from_this(), cmd);
#if UNITTEST_FORBID_FFRT // Forbid FFRT for unittest, which will cause crash in destructor process
        ExecuteCommand(cmd);
#elif UNITTEST_WAIT_FFRT
        // if too much task in queue, wait until task finish
        if (iptablesWrapperFfrtQueue_->get_task_cnt() >= MAX_IPTABLES_FFRT_TASK_NUM) {
            NETNATIVE_LOGE("iptables queue task count overmax, wait");
            ffrt::task_handle handle = iptablesWrapperFfrtQueue_->submit_h(executeCommand);
            iptablesWrapperFfrtQueue_->wait(handle);
        } else {
            iptablesWrapperFfrtQueue_->submit(executeCommand);
        }
#else
        iptablesWrapperFfrtQueue_->submit(executeCommand);
#endif // UNITTEST_FORBID_FFRT
    }

    if (isIp6tablesSystemAccess_ && (ipType == IPTYPE_IPV6 || ipType == IPTYPE_IPV4V6)) {
        std::string cmd = std::string(IP6TABLES_CMD_PATH) + " " + command;
        std::function<void()> executeCommand = std::bind(&IptablesWrapper::ExecuteCommand, shared_from_this(), cmd);
#if UNITTEST_FORBID_FFRT // Forbid FFRT for unittest, which will cause crash in destructor process
        ExecuteCommand(cmd);
#elif UNITTEST_WAIT_FFRT
        // if too much task in queue, wait until task finish
        if (iptablesWrapperFfrtQueue_->get_task_cnt() >= MAX_IPTABLES_FFRT_TASK_NUM) {
            NETNATIVE_LOGE("iptables queue task count overmax, wait");
            ffrt::task_handle handle = iptablesWrapperFfrtQueue_->submit_h(executeCommand);
            iptablesWrapperFfrtQueue_->wait(handle);
        } else {
            iptablesWrapperFfrtQueue_->submit(executeCommand);
        }
#else
        iptablesWrapperFfrtQueue_->submit(executeCommand);
#endif // UNITTEST_FORBID_FFRT
    }

    return NetManagerStandard::NETMANAGER_SUCCESS;
}

std::string IptablesWrapper::RunCommandForRes(const IpType &ipType, const std::string &command)
{
    NETNATIVE_LOGI("IptablesWrapper::RunCommandForRes, ipType:%{public}d", ipType);
    if (!iptablesWrapperFfrtQueue_) {
        NETNATIVE_LOGE("FFRT Init Fail");
        return result_;
    }

    if (ipType == IPTYPE_IPV4 || ipType == IPTYPE_IPV4V6) {
        std::string cmd = std::string(IPATBLES_CMD_PATH) + " " + command;
        std::function<void()> executeCommandForRes =
            std::bind(&IptablesWrapper::ExecuteCommandForRes, shared_from_this(), cmd);

        int64_t start = GetTickCount();
        ffrt::task_handle RunCommandForResTaskIpv4 = iptablesWrapperFfrtQueue_->submit_h(executeCommandForRes);
        iptablesWrapperFfrtQueue_->wait(RunCommandForResTaskIpv4);
        NETNATIVE_LOGI("FFRT cost:%{public}lld ms", static_cast<long long>(GetTickCount() - start));
    }

    if (ipType == IPTYPE_IPV6 || ipType == IPTYPE_IPV4V6) {
        std::string cmd = std::string(IP6TABLES_CMD_PATH) + " " + command;
        std::function<void()> executeCommandForRes =
            std::bind(&IptablesWrapper::ExecuteCommandForRes, shared_from_this(), cmd);

        int64_t start = GetTickCount();
        ffrt::task_handle RunCommandForResTaskIpv6 = iptablesWrapperFfrtQueue_->submit_h(executeCommandForRes);
        iptablesWrapperFfrtQueue_->wait(RunCommandForResTaskIpv6);
        NETNATIVE_LOGI("FFRT cost:%{public}lld ms", static_cast<long long>(GetTickCount() - start));
    }

    return result_;
}

int32_t IptablesWrapper::RunMutipleCommands(const IpType &ipType, const std::vector<std::string> &commands)
{
    NETNATIVE_LOG_D("IptablesWrapper::RunMutipleCommands, ipType:%{public}d", ipType);
    if (!iptablesWrapperFfrtQueue_) {
        NETNATIVE_LOGE("FFRT Init Fail");
        return NETMANAGER_ERROR;
    }

    for (const std::string& command : commands) {
        if (isIptablesSystemAccess_ && (ipType == IPTYPE_IPV4 || ipType == IPTYPE_IPV4V6)) {
            std::string cmd = std::string(IPATBLES_CMD_PATH) + " " + command;
            std::function<void()> executeCommand = std::bind(&IptablesWrapper::ExecuteCommand, shared_from_this(), cmd);
#if UNITTEST_FORBID_FFRT // Forbid FFRT for unittest, which will cause crash in destructor process
            executeCommand();
#elif UNITTEST_WAIT_FFRT
            // if too much task in queue, wait until task finish
            if (iptablesWrapperFfrtQueue_->get_task_cnt() >= MAX_IPTABLES_FFRT_TASK_NUM) {
                NETNATIVE_LOGE("iptables queue task count overmax, wait");
                ffrt::task_handle handle = iptablesWrapperFfrtQueue_->submit_h(executeCommand);
                iptablesWrapperFfrtQueue_->wait(handle);
            } else {
                iptablesWrapperFfrtQueue_->submit(executeCommand);
            }
#else
            iptablesWrapperFfrtQueue_->submit(executeCommand);
#endif
        }

        if (isIp6tablesSystemAccess_ && (ipType == IPTYPE_IPV6 || ipType == IPTYPE_IPV4V6)) {
            std::string cmd = std::string(IP6TABLES_CMD_PATH) + " " + command;
            std::function<void()> executeCommand = std::bind(&IptablesWrapper::ExecuteCommand, shared_from_this(), cmd);
#if UNITTEST_FORBID_FFRT // Forbid FFRT for unittest, which will cause crash in destructor process
            executeCommand();
#elif UNITTEST_WAIT_FFRT
            // if too much task in queue, wait until task finish
            if (iptablesWrapperFfrtQueue_->get_task_cnt() >= MAX_IPTABLES_FFRT_TASK_NUM) {
                NETNATIVE_LOGE("iptables queue task count overmax, wait");
                ffrt::task_handle handle = iptablesWrapperFfrtQueue_->submit_h(executeCommand);
                iptablesWrapperFfrtQueue_->wait(handle);
            } else {
                iptablesWrapperFfrtQueue_->submit(executeCommand);
            }
#else
            iptablesWrapperFfrtQueue_->submit(executeCommand);
#endif
        }
    }

    return NetManagerStandard::NETMANAGER_SUCCESS;
}

int32_t IptablesWrapper::RunCheckedCommand(const IpType &ipType, const std::string &command, bool restore)
{
    // Call one family at a time so the owner can commit/retry partial dual-stack operations.
    if (!iptablesWrapperFfrtQueue_ || (ipType != IPTYPE_IPV4 && ipType != IPTYPE_IPV6) ||
        !(ipType == IPTYPE_IPV4 ? isIptablesSystemAccess_ : isIp6tablesSystemAccess_))
        return NETMANAGER_ERROR;
    int32_t result = NETMANAGER_ERROR;
    auto task = [&]() {
        if (restore && !CommonUtils::WriteFile(IPTABLES_RULE_PATH, command))
            return;
        std::string binary = restore ? (ipType == IPTYPE_IPV4 ? IPTABLES_RESTORE_CMD_PATH : IP6TABLES_RESTORE_CMD_PATH)
                                     : (ipType == IPTYPE_IPV4 ? IPATBLES_CMD_PATH : IP6TABLES_CMD_PATH);
        result = ExecuteChecked(binary,
                                restore ? std::string(IPTABLES_RULE_PATH) + " --noflush --wait=5" : command + " -w 5");
    };
#if UNITTEST_FORBID_FFRT
    task();
#else
    auto handle = iptablesWrapperFfrtQueue_->submit_h(task);
    iptablesWrapperFfrtQueue_->wait(handle);
#endif
    return result;
}

int32_t IptablesWrapper::RunRestoreCommands(const IpType &ipType, const std::string &command)
{
    NETNATIVE_LOGI("IptablesWrapper::RunRestoreCommands, ipType:%{public}d, command:%{public}s",
        ipType, CommonUtils::AnonymousIpInStr(command).c_str());
    if (!iptablesWrapperFfrtQueue_) {
        NETNATIVE_LOGE("FFRT Init Fail");
        return NETMANAGER_ERROR;
    }

    if (isIptablesSystemAccess_ && (ipType == IPTYPE_IPV4 || ipType == IPTYPE_IPV4V6)) {
        std::string cmd = std::string(IPTABLES_RESTORE_CMD_PATH) + " " + IPTABLES_RULE_PATH + " --noflush";
#if UNITTEST_FORBID_FFRT // Forbid FFRT for unittest, which will cause crash in destructor process
        ExecuteRestoreCommand(cmd, command);
#else
        std::function<void()> executeCommand =
            std::bind(&IptablesWrapper::ExecuteRestoreCommand, shared_from_this(), cmd, command);
        iptablesWrapperFfrtQueue_->submit(executeCommand);
#endif // UNITTEST_FORBID_FFRT
    }

    if (isIptablesSystemAccess_ && (ipType == IPTYPE_IPV6 || ipType == IPTYPE_IPV4V6)) {
        std::string cmd = std::string(IP6TABLES_RESTORE_CMD_PATH) + " " + IPTABLES_RULE_PATH + " --noflush";
#if UNITTEST_FORBID_FFRT // Forbid FFRT for unittest, which will cause crash in destructor process
        ExecuteRestoreCommand(cmd, command);
#else
        std::function<void()> executeCommand =
            std::bind(&IptablesWrapper::ExecuteRestoreCommand, shared_from_this(), cmd, command);
        iptablesWrapperFfrtQueue_->submit(executeCommand);
#endif // UNITTEST_FORBID_FFRT
    }

    return NetManagerStandard::NETMANAGER_SUCCESS;
}
} // namespace nmd
} // namespace OHOS
