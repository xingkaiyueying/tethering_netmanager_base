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

#ifndef INCLUDE_SHARING_MANAGER_H
#define INCLUDE_SHARING_MANAGER_H

#include <memory>
#include <mutex>
#include <set>
#include <string>
#include <vector>
#include <regex>
#include <map>
#include <shared_mutex>
#include "iptables_wrapper.h"
#include "network_sharing.h"
#include "route_manager.h"

namespace OHOS {
namespace nmd {
class SharingManager {
public:
    SharingManager();
    ~SharingManager() = default;

    /*
     * @brief Enable IP forwarding
     *
     * @param requestor
     * @return NETMANAGER_ERROR code
     */
    int32_t IpEnableForwarding(const std::string &requestor);

    /*
     * @brief Disable IP forwarding
     *
     * @param requestor
     * @return NETMANAGER_ERROR code
     */
    int32_t IpDisableForwarding(const std::string &requestor);

    /*
     * @brief Enable network address forwarding
     *
     * @param downstreamIface
     * @param upstreamIface
     * @return NETMANAGER_ERROR code
     */
    int32_t EnableNat(const std::string &downstreamIface, const std::string &upstreamIface);

    /*
     * @brief Disable network address forwarding
     *
     * @param downstreamIface
     * @param upstreamIface
     * @return NETMANAGER_ERROR code
     */
    int32_t DisableNat(const std::string &downstramIface, const std::string &upstreamIface);

    /*
     * @brief According to the network cark configuration rules of iptables
     *
     * @param fromIface
     * @param toIface
     * @return NETMANAGER_ERROR code
     */
    int32_t IpfwdAddInterfaceForward(const std::string &fromIface, const std::string &toIface);

    /*
     * @brief According to the network cark configuration rules of iptables
     *
     * @param fromIface
     * @param toIface
     * @return NETMANAGER_ERROR code
     */
    int32_t IpfwdRemoveInterfaceForward(const std::string &fromIface, const std::string &toIface);

    /*
     * @brief Get trafic of network sharing
     *
     * @param downIface
     * @param upIface
     * @param traffic
     * @return NETMANAGER_ERROR code
     */
    int32_t GetNetworkSharingTraffic(const std::string &downIface, const std::string &upIface,
                                     NetworkSharingTraffic &traffic);

    /*
     * @brief Get trafic of network cellular sharing
     *
     * @param downIface
     * @param traffic
     * @return NETMANAGER_ERROR code
     */
    int32_t GetNetworkCellularSharingTraffic(NetworkSharingTraffic &traffic, std::string &ifaceName);
    int32_t SetDpaCellularSharingTraffic(NetworkDpaTrafficReport &sharingTrafficMsg);

    int32_t SetIpv6PrivacyExtensions(const std::string &interfaceName, const uint32_t on);
    int32_t SetEnableIpv6(const std::string &interfaceName, const uint32_t on, bool needRestart);
    int32_t SetInternetAccessByIpForWifiShare(
        const std::string &ipAddr, uint8_t family, bool accessInternet, const std::string &clientNetIfName);
private:
    std::shared_mutex forwardingRequestsMutex_;
    std::mutex interfaceForwardsMutex_;
    std::mutex sharingOperationMutex_;
    std::mutex natMutex_;
    std::set<std::pair<std::string, std::string>> natPairs_, nat6Pairs_;
    std::set<std::pair<std::string, std::string>> natRemoving_;
    bool natMangleOwned_{false}, natMangle6Owned_{false};
    std::set<std::string> forwardingRoutes_, forwardingRemoving_, forwarded4_, forwarded6_;
    std::set<std::string> forwardingRequests_;
    std::set<std::string> interfaceForwards_;
    std::map<std::string, uint8_t> forbidIpsMap_;
    std::map<std::string, bool> enableV6Map_;
    std::shared_ptr<IptablesWrapper> iptablesWrapper_ = nullptr;
    bool inited_ = false;
    std::mutex initedMutex_;
    std::mutex forbidIpMutex_;
    std::mutex enableV6mutex_;
    std::mutex wifiShareInterfaceMutex_;
    std::mutex onDpaSharingTrafficMutex_;
    std::string wifiShareInterface_ = "";
    std::vector<DpaWifiTrafficReport> onDpaSharingTraffic_;

    std::map<std::string, std::string> sharingIfaceToIpMap_;
    std::mutex sharingIfaceToIpMutex_;

    int32_t ReconcileNatPairs(const std::set<std::pair<std::string, std::string>> &pairs);
    int32_t SetNearlinkIsolation(bool enabled);
    int32_t ReconcileForwardPairs(const std::set<std::string> &pairs);
    void InitChildChains();
    void CheckInited();
    int32_t SetIpFwdEnable();
    void SetForwardRules(bool set, const std::string &cmds, std::string &cmdSet);
    void CombineRestoreRules(const std::string &cmds, std::string &cmdSet);
    int32_t QueryCellularSharingTraffic(NetworkSharingTraffic &traffic,
        const std::string &result, std::string &ifaceName);
    void QueryDpaCellularSharingTraffic(const std::vector<DpaWifiTrafficReport> &onSharingTraffic,
        NetworkSharingTraffic &traffic, std::string &ifaceName);
    void GetTraffic(std::smatch &matches, std::string &ifaceName, NetworkSharingTraffic &traffic,
        bool &isFindTx, bool &isFindRx);
    int32_t EnableShareUnreachableRoute(RouteManager::TableType tableType);
    int32_t DisableShareUnreachableRoute(RouteManager::TableType tableType);
    void ClearForbidIpRules();
    std::string GetLocalIpAddress(const std::string &upstreamIface);
    void AddSharingSecurityRules(const std::string &fromIface, const std::string &toIface);
    void RemoveSharingSecurityRules(const std::string &fromIface, const std::string &toIface);
};
} // namespace nmd
} // namespace OHOS
#endif // INCLUDE_SHARING_MANAGER_H
