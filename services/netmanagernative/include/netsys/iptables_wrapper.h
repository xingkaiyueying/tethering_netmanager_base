/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef NETMANAGER_BASE_IPTABLES_WRAPPER_H
#define NETMANAGER_BASE_IPTABLES_WRAPPER_H

#include <condition_variable>
#include <cstring>
#include <iostream>
#include <mutex>
#include <queue>
#include <thread>

#include "singleton.h"
#include "ffrt.h"

namespace OHOS {
namespace nmd {
enum IpType {
    IPTYPE_IPV4 = 1,
    IPTYPE_IPV6 = 2,
    IPTYPE_IPV4V6 = 3,
};
class IptablesWrapper : public std::enable_shared_from_this<IptablesWrapper> {
public:
    IptablesWrapper();
    ~IptablesWrapper();
    static std::shared_ptr<IptablesWrapper> &GetInstance()
    {
        static std::shared_ptr<IptablesWrapper> instance = std::make_shared<IptablesWrapper>();
        return instance;
    }

    /**
     * @param ipType ipv4 or ipv6
     * @param command iptables command
     * @return NETMANAGER_SUCCESS suceess or NETMANAGER_ERROR failed
     */
    int32_t RunCommand(const IpType &ipType, const std::string &command);

    /**
     * @param ipType ipv4 or ipv6
     * @param command iptables command
     * @return NETMANAGER_SUCCESS suceess or NETMANAGER_ERROR failed
     */
    std::string RunCommandForTraffic(const IpType &ipType, const std::string &command);

    /**
     * @brief run iptables exec for result.
     *
     * @param ipType ipv4 or ipv6.
     * @param command iptables command.
     * @return NETMANAGER_SUCCESS suceess or NETMANAGER_ERROR failed
     */
    std::string RunCommandForRes(const IpType &ipType, const std::string &command);

    /**
     * @brief run mutiple iptables commands.
     *
     * @param ipType ipv4 or ipv6.
     * @param commands iptables commands.
     * @return NETMANAGER_SUCCESS suceess or NETMANAGER_ERROR failed
     */
    int32_t RunMutipleCommands(const IpType &ipType, const std::vector<std::string> &commands);
    
    int32_t RunRestoreCommands(const IpType &ipType, const std::string &command);
    // Internal sharing ledger API: wait for the queue and return the actual child exit status.
    int32_t RunCheckedCommand(const IpType &ipType, const std::string &command, bool restore = false);

  private:
    void ExecuteCommand(const std::string &command);
    void ExecuteCommandForRes(const std::string &command);
    void ExecuteCommandForTraffic(const std::string &command);
    void ExecuteRestoreCommand(const std::string &restoreCmd, const std::string &command);
private:
    std::mutex iptablesMutex_;
    std::condition_variable conditionVarLock_;
    bool isRunningFlag_ = false;
    bool isIptablesSystemAccess_ = false;
    bool isIp6tablesSystemAccess_ = false;
    std::string result_;
    std::string resultTraffic_;
    std::thread iptablesWrapperThread_;
    std::queue<std::string> commandsQueue_;
    std::shared_ptr<ffrt::queue> iptablesWrapperFfrtQueue_ = nullptr;
};
} // namespace nmd
} // namespace OHOS
#endif /* NETMANAGER_BASE_IPTABLES_WRAPPER_H */
