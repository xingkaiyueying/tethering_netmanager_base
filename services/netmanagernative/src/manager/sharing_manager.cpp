/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#include "sharing_manager.h"

#include <cerrno>
#include <fcntl.h>
#include <ifaddrs.h>
#include <regex>
#include <unistd.h>
#include <charconv>
#include <net/if.h>

#include "net_manager_constants.h"
#include "netmanager_base_common_utils.h"
#include "netnative_log_wrapper.h"

namespace OHOS {
namespace nmd {
using namespace NetManagerStandard;
namespace {
constexpr const char *IPV4_FORWARDING_PROC_FILE = "/proc/sys/net/ipv4/ip_forward";
constexpr const char *IPV6_FORWARDING_PROC_FILE = "/proc/sys/net/ipv6/conf/all/forwarding";
constexpr const char *IPV6_PROC_PATH = "/proc/sys/net/ipv6/conf/";
constexpr const int MAX_MATCH_SIZE = 4;
constexpr const int TWO_LIST_CORRECT_DATA = 2;
constexpr const int NEXT_LIST_CORRECT_DATA = 1;
constexpr uint32_t NET_TRAFFIC_RESULT_INDEX_OFFSET = 2;
const std::string CELLULAR_IFACE_NAME = "rmnet";
const std::string WLAN_IFACE_NAME = "wlan";
const std::string P2P_IFACE_NAME = "p2p-p2p0";

// commands of create tables
constexpr const char *CREATE_TETHERCTRL_NAT_POSTROUTING = "-t nat -N tetherctrl_nat_POSTROUTING";
constexpr const char *CREATE_TETHERCTRL_FORWARD = "-t filter -N tetherctrl_FORWARD";
constexpr const char *CREATE_TETHERCTRL_COUNTERS = "-t filter -N tetherctrl_counters";
constexpr const char *CREATE_TETHERCTRL_MANGLE_FORWARD = "-t mangle -N tetherctrl_mangle_FORWARD";
constexpr const char *OPEN_IPV6_PRIVACY_EXTENSIONS = "2";
constexpr const char *CLOSE_IPV6_PRIVACY_EXTENSIONS = "0";
constexpr const char *ENABLE_IPV6_VALUE = "0";
constexpr const char *DISABLE_IPV6_VALUE = "1";

// Sharing security rules constants
constexpr const char *INPUT_CHAIN = " INPUT";
constexpr const char *FORWARD_CHAIN = " FORWARD";
constexpr const char *INPUT_I_OPT = " -i ";
constexpr const char *SRC_OPT = " -s ";
constexpr const char *DST_OPT = " -d ";
constexpr const char *J_DROP = " -j DROP";

// commands of set nat
constexpr const char *APPEND_NAT_POSTROUTING = "-A POSTROUTING -j tetherctrl_nat_POSTROUTING";
constexpr const char *APPEND_MANGLE_FORWARD = "-A FORWARD -j tetherctrl_mangle_FORWARD";
constexpr const char *APPEND_TETHERCTRL_MANGLE_FORWARD =
    "-A tetherctrl_mangle_FORWARD "
    "-p tcp -m tcp --tcp-flags SYN SYN -j TCPMSS --clamp-mss-to-pmtu";
constexpr const char *CLEAR_TETHERCTRL_NAT_POSTROUTING = "-F tetherctrl_nat_POSTROUTING";
constexpr const char *CLEAR_TETHERCTRL_MANGLE_FORWARD = "-F tetherctrl_mangle_FORWARD";
constexpr const char *DELETE_TETHERCTRL_NAT_POSTROUTING = "-D POSTROUTING -j tetherctrl_nat_POSTROUTING";
constexpr const char *DELETE_TETHERCTRL_MANGLE_FORWARD = "-D FORWARD -j tetherctrl_mangle_FORWARD";

constexpr const char *FILTER_TABLE = "*filter";
constexpr const char *MANGLE_TABLE = "*mangle";
constexpr const char *NAT_TABLE = "*nat";
constexpr const char *CMD_COMMIT = "COMMIT";

const std::string EnableNatCmd(const std::string &down)
{
    return "-A tetherctrl_nat_POSTROUTING -o " + down + " -j MASQUERADE";
}

// commands of set ipfwd, all commands with filter
constexpr const char *FORWARD_JUMP_TETHERCTRL_FORWARD = " FORWARD -j tetherctrl_FORWARD";
constexpr const char *SET_TETHERCTRL_FORWARD_DROP = " tetherctrl_FORWARD -j DROP";
const std::string SetTetherctrlForward1(const std::string &from, const std::string &to)
{
    return " tetherctrl_FORWARD -i " + from + " -o " + to +
           " -m state --state RELATED,ESTABLISHED"
           " -g tetherctrl_counters";
}

const std::string SetTetherctrlForward2(const std::string &from, const std::string &to)
{
    return " tetherctrl_FORWARD -i " + to + " -o " + from + " -m state --state INVALID -j DROP";
}

const std::string SetTetherctrlForward3(const std::string &from, const std::string &to)
{
    return " tetherctrl_FORWARD -i " + to + " -o " + from + " -g tetherctrl_counters";
}

const std::string SetTetherctrlCounters1(const std::string &from, const std::string &to)
{
    return " tetherctrl_counters -i " + to + " -o " + from + " -j RETURN";
}

const std::string SetTetherctrlCounters2(const std::string &from, const std::string &to)
{
    return " tetherctrl_counters -i " + from + " -o " + to + " -j RETURN";
}

bool WriteToFile(const char *fileName, const char *value)
{
    if (fileName == nullptr) {
        return false;
    }
    int fd = open(fileName, O_WRONLY | O_CLOEXEC);
    if (fd < 0) {
        NETNATIVE_LOGE("failed to open file: %{public}s", strerror(errno));
        return false;
    }

    const ssize_t len = strlen(value);
    if (write(fd, value, len) != len) {
        NETNATIVE_LOGE("faield to write %{public}s: %{public}s", value, strerror(errno));
        close(fd);
        return false;
    }

    close(fd);
    return true;
}

} // namespace

SharingManager::SharingManager()
{
    iptablesWrapper_ = IptablesWrapper::GetInstance();
}

void SharingManager::InitChildChains()
{
    bool ready = true;
    for (auto family : {IPTYPE_IPV4, IPTYPE_IPV6}) {
        for (const auto &rule : {std::string(CREATE_TETHERCTRL_FORWARD), std::string(CREATE_TETHERCTRL_COUNTERS),
                                 std::string(CREATE_TETHERCTRL_MANGLE_FORWARD),
                                 std::string(CREATE_TETHERCTRL_NAT_POSTROUTING)}) {
            auto check = rule;
            check.replace(check.find("-N"), 2, "-S");
            bool exists = iptablesWrapper_->RunCheckedCommand(family, check) == 0;
            ready = (exists || iptablesWrapper_->RunCheckedCommand(family, rule) == 0) && ready;
        }
    }
    inited_ = ready;
}

int32_t SharingManager::SetNearlinkIsolation(bool enabled)
{
    // A gateway's downlinks are independent logical links. Keep this ahead of all forwarding accepts.
    const std::string rule = " FORWARD -i sleip+ -o sleip+ -j DROP";
    for (auto family : {IPTYPE_IPV4, IPTYPE_IPV6}) {
        bool exists = iptablesWrapper_->RunCheckedCommand(family, "-t filter -C" + rule) == 0;
        if ((enabled && !exists && iptablesWrapper_->RunCheckedCommand(family, "-t filter -I" + rule) != 0) ||
            (!enabled && exists && iptablesWrapper_->RunCheckedCommand(family, "-t filter -D" + rule) != 0))
            return -1;
    }
    return 0;
}

int32_t SharingManager::IpEnableForwarding(const std::string &requestor)
{
    std::lock_guard<std::mutex> guard(initedMutex_);
    if (requestor == "NearlinkIpShare" && SetNearlinkIsolation(true) != 0)
        return -1;
    bool inserted = forwardingRequests_.insert(requestor).second;
    int32_t ret = SetIpFwdEnable();
    if (ret != 0 && inserted) {
        forwardingRequests_.erase(requestor);
        SetIpFwdEnable();
    }
    return ret;
}

int32_t SharingManager::IpDisableForwarding(const std::string &requestor)
{
    std::lock_guard<std::mutex> guard(initedMutex_);
    bool removed = forwardingRequests_.erase(requestor) != 0;
    int32_t ret = SetIpFwdEnable();
    if (ret != 0) {
        if (removed)
            forwardingRequests_.insert(requestor);
        return ret;
    }
    return requestor == "NearlinkIpShare" ? SetNearlinkIsolation(false) : 0;
}

int32_t SharingManager::ReconcileNatPairs(const std::set<std::pair<std::string, std::string>> &pairs)
{
    // Commit one table at a time. Failed MSS/NAT operations retain exactly the resource still owned.
    for (auto family : {IPTYPE_IPV4, IPTYPE_IPV6}) {
        auto &owned = family == IPTYPE_IPV4 ? natMangleOwned_ : natMangle6Owned_;
        if (pairs.empty() || owned) {
            continue;
        }
        std::string cmds;
        CombineRestoreRules(MANGLE_TABLE, cmds);
        CombineRestoreRules(CLEAR_TETHERCTRL_MANGLE_FORWARD, cmds);
        CombineRestoreRules(APPEND_MANGLE_FORWARD, cmds);
        CombineRestoreRules(APPEND_TETHERCTRL_MANGLE_FORWARD, cmds);
        CombineRestoreRules(CMD_COMMIT, cmds);
        int32_t ret = iptablesWrapper_->RunCheckedCommand(family, cmds, true);
        if (ret != 0)
            return ret;
        owned = true;
    }
    // P2 submitted MASQUERADE for both families. Keep that behavior with separate
    // committed ledgers so a partial restore can be retried or released safely.
    for (auto family : {IPTYPE_IPV4, IPTYPE_IPV6}) {
        auto &committed = family == IPTYPE_IPV4 ? natPairs_ : nat6Pairs_;
        if (pairs == committed)
            continue;
        std::string cmds;
        CombineRestoreRules(NAT_TABLE, cmds);
        CombineRestoreRules(CLEAR_TETHERCTRL_NAT_POSTROUTING, cmds);
        if (committed.empty() && !pairs.empty())
            CombineRestoreRules(APPEND_NAT_POSTROUTING, cmds);
        if (!committed.empty() && pairs.empty())
            CombineRestoreRules(DELETE_TETHERCTRL_NAT_POSTROUTING, cmds);
        std::set<std::string> upstreams;
        for (const auto &pair : pairs)
            upstreams.insert(pair.second);
        for (const auto &upstream : upstreams)
            CombineRestoreRules(EnableNatCmd(upstream), cmds);
        CombineRestoreRules(CMD_COMMIT, cmds);
        int32_t ret = iptablesWrapper_->RunCheckedCommand(family, cmds, true);
        if (ret != 0)
            return ret;
        committed = pairs;
        NETNATIVE_LOGI("[NearlinkIpShare][NatFamilies] family=%{public}d holders=%{public}zu upstreams=%{public}zu",
                      static_cast<int>(family), committed.size(), upstreams.size());
    }
    for (auto family : {IPTYPE_IPV4, IPTYPE_IPV6}) {
        auto &owned = family == IPTYPE_IPV4 ? natMangleOwned_ : natMangle6Owned_;
        if (!pairs.empty() || !owned) {
            continue;
        }
        std::string cmds;
        CombineRestoreRules(MANGLE_TABLE, cmds);
        CombineRestoreRules(CLEAR_TETHERCTRL_MANGLE_FORWARD, cmds);
        CombineRestoreRules(DELETE_TETHERCTRL_MANGLE_FORWARD, cmds);
        CombineRestoreRules(CMD_COMMIT, cmds);
        int32_t ret = iptablesWrapper_->RunCheckedCommand(family, cmds, true);
        if (ret != 0)
            return ret;
        owned = false;
    }
    return 0;
}

int32_t SharingManager::EnableNat(const std::string &downstreamIface, const std::string &upstreamIface)
{
    CheckInited();
    // Legacy NetworkShareMainStateMachine uses an empty downstream as its global NAT holder.
    if (!inited_ || downstreamIface == upstreamIface ||
        (!downstreamIface.empty() && !CommonUtils::CheckIfaceName(downstreamIface)) ||
        !CommonUtils::CheckIfaceName(upstreamIface))
        return -1;
    std::lock_guard<std::mutex> guard(natMutex_);
    if (natRemoving_.count({downstreamIface, upstreamIface}))
        return -EBUSY;
    auto pairs = natPairs_;
    pairs.insert(nat6Pairs_.begin(), nat6Pairs_.end());
    for (const auto &removing : natRemoving_)
        pairs.erase(removing);
    pairs.insert({downstreamIface, upstreamIface});
    return ReconcileNatPairs(pairs);
}

int32_t SharingManager::DisableNat(const std::string &downstreamIface, const std::string &upstreamIface)
{
    CheckInited();
    if (!inited_ || downstreamIface == upstreamIface ||
        (!downstreamIface.empty() && !CommonUtils::CheckIfaceName(downstreamIface)) ||
        !CommonUtils::CheckIfaceName(upstreamIface))
        return -1;
    std::lock_guard<std::mutex> guard(natMutex_);
    const auto key = std::make_pair(downstreamIface, upstreamIface);
    natRemoving_.insert(key);
    auto pairs = natPairs_;
    pairs.insert(nat6Pairs_.begin(), nat6Pairs_.end());
    for (const auto &removing : natRemoving_)
        pairs.erase(removing);
    int32_t ret = ReconcileNatPairs(pairs);
    if (ret == 0)
        natRemoving_.erase(key);
    return ret;
}
int32_t SharingManager::SetIpv6PrivacyExtensions(const std::string &interfaceName, const uint32_t on)
{
    if (!CommonUtils::CheckIfaceName(interfaceName)) {
        NETNATIVE_LOGE("iface name valid check fail: %{public}s", interfaceName.c_str());
        return -1;
    }
    std::string option = IPV6_PROC_PATH + interfaceName + "/use_tempaddr";
    const char *value = on ? OPEN_IPV6_PRIVACY_EXTENSIONS : CLOSE_IPV6_PRIVACY_EXTENSIONS;
    bool ipv6Success = WriteToFile(option.c_str(), value);
    return ipv6Success ? 0 : -1;
}

int32_t SharingManager::SetEnableIpv6(const std::string &interfaceName, const uint32_t on, bool needRestart)
{
    if (!CommonUtils::CheckIfaceName(interfaceName)) {
        NETNATIVE_LOGE("iface name valid check fail: %{public}s", interfaceName.c_str());
        return -1;
    }
    std::string option = IPV6_PROC_PATH + interfaceName + "/disable_ipv6";
    const char *value = on ? ENABLE_IPV6_VALUE : DISABLE_IPV6_VALUE;
    std::lock_guard<std::mutex> guard(enableV6mutex_);
    bool ipv6Success = WriteToFile(option.c_str(), value);
    bool isIfEnabled = true;
    if (enableV6Map_.find(interfaceName) != enableV6Map_.end()) {
        isIfEnabled = enableV6Map_[interfaceName];
    }
    if (!on && needRestart && isIfEnabled) {
        bool restartSuccess = WriteToFile(option.c_str(), ENABLE_IPV6_VALUE);
        NETMGR_LOG_I("SetEnableIpv6: interfaceName=%{public}s, restart V6, result = %{public}d",
            interfaceName.c_str(), restartSuccess);
        enableV6Map_[interfaceName] = true;
        return restartSuccess ? 0 : -1;
    }
    enableV6Map_[interfaceName] = static_cast<bool>(on);
    return ipv6Success ? 0 : -1;
}

int32_t SharingManager::SetIpFwdEnable()
{
    bool disable = forwardingRequests_.empty();
    const char *value = disable ? "0" : "1";
    bool ipv4Success = WriteToFile(IPV4_FORWARDING_PROC_FILE, value);
    bool ipv6Success = WriteToFile(IPV6_FORWARDING_PROC_FILE, value);
    return (ipv4Success && ipv6Success) ? 0 : -1;
}

int32_t SharingManager::ReconcileForwardPairs(const std::set<std::string> &pairs)
{
    for (auto family : {IPTYPE_IPV4, IPTYPE_IPV6}) {
        auto &committed = family == IPTYPE_IPV4 ? forwarded4_ : forwarded6_;
        if (pairs == committed)
            continue;
        std::string cmds;
        CombineRestoreRules(FILTER_TABLE, cmds);
        CombineRestoreRules("-F tetherctrl_FORWARD", cmds);
        if (committed.empty() && !pairs.empty())
            SetForwardRules(true, FORWARD_JUMP_TETHERCTRL_FORWARD, cmds);
        if (!committed.empty() && pairs.empty())
            SetForwardRules(false, FORWARD_JUMP_TETHERCTRL_FORWARD, cmds);
        for (const auto &key : pairs) {
            auto split = key.find(':');
            auto from = key.substr(0, split), to = key.substr(split + 1);
            SetForwardRules(true, SetTetherctrlForward1(to, from), cmds);
            SetForwardRules(true, SetTetherctrlForward2(to, from), cmds);
            SetForwardRules(true, SetTetherctrlForward3(to, from), cmds);
        }
        // Keep counters for unchanged pairs: restore --noflush preserves their values.
        for (const auto &key : committed) {
            if (pairs.count(key) != 0) {
                continue;
            }
            auto split = key.find(':');
            auto from = key.substr(0, split), to = key.substr(split + 1);
            SetForwardRules(false, SetTetherctrlCounters1(from, to), cmds);
            SetForwardRules(false, SetTetherctrlCounters2(from, to), cmds);
        }
        for (const auto &key : pairs) {
            if (committed.count(key) != 0) {
                continue;
            }
            auto split = key.find(':');
            auto from = key.substr(0, split), to = key.substr(split + 1);
            SetForwardRules(true, SetTetherctrlCounters1(from, to), cmds);
            SetForwardRules(true, SetTetherctrlCounters2(from, to), cmds);
        }
        if (!pairs.empty())
            SetForwardRules(true, SET_TETHERCTRL_FORWARD_DROP, cmds);
        CombineRestoreRules(CMD_COMMIT, cmds);
        int32_t ret = iptablesWrapper_->RunCheckedCommand(family, cmds, true);
        if (ret != 0)
            return ret;
        committed = pairs;
    }
    return 0;
}

int32_t SharingManager::IpfwdAddInterfaceForward(const std::string &fromIface, const std::string &toIface)
{
    std::lock_guard<std::mutex> operation(sharingOperationMutex_);
    CheckInited();
    if (!inited_ || fromIface == toIface || !CommonUtils::CheckIfaceName(fromIface) ||
        !CommonUtils::CheckIfaceName(toIface))
        return -1;
    const auto key = fromIface + ":" + toIface;
    if (forwardingRemoving_.count(key))
        return -EBUSY;
    if (interfaceForwards_.count(key) && forwarded4_.count(key) && forwarded6_.count(key))
        return 0;
    if (!forwardingRoutes_.count(key)) {
        int32_t ret = RouteManager::EnableSharing(fromIface, toIface);
        if (ret != 0)
            return ret;
        forwardingRoutes_.insert(key);
    }
    {
        std::lock_guard<std::mutex> guard(interfaceForwardsMutex_);
        interfaceForwards_.insert(key);
    }
    auto pairs = interfaceForwards_;
    for (const auto &removing : forwardingRemoving_)
        pairs.erase(removing);
    int32_t ret = ReconcileForwardPairs(pairs);
    if (ret != 0)
        return ret;
    if (fromIface.find(WLAN_IFACE_NAME) != std::string::npos || fromIface.find(P2P_IFACE_NAME) != std::string::npos) {
        std::lock_guard<std::mutex> guard(wifiShareInterfaceMutex_);
        wifiShareInterface_ = fromIface;
        EnableShareUnreachableRoute(RouteManager::UNREACHABLE_NETWORK);
    }
    AddSharingSecurityRules(fromIface, toIface);
    return 0;
}

int32_t SharingManager::IpfwdRemoveInterfaceForward(const std::string &fromIface, const std::string &toIface)
{
    std::lock_guard<std::mutex> operation(sharingOperationMutex_);
    CheckInited();
    if (!inited_ || fromIface == toIface || !CommonUtils::CheckIfaceName(fromIface) ||
        !CommonUtils::CheckIfaceName(toIface))
        return -1;
    const auto key = fromIface + ":" + toIface;
    if (!interfaceForwards_.count(key))
        return 0;
    forwardingRemoving_.insert(key);
    if (forwardingRoutes_.count(key)) {
        int32_t ret = RouteManager::DisableSharing(fromIface, toIface);
        if (ret != 0 && ret != -ESRCH && ret != -ENODEV)
            return ret;
        forwardingRoutes_.erase(key);
    }
    auto pairs = interfaceForwards_;
    for (const auto &removing : forwardingRemoving_)
        pairs.erase(removing);
    int32_t ret = ReconcileForwardPairs(pairs);
    if (ret != 0)
        return ret;
    {
        std::lock_guard<std::mutex> guard(interfaceForwardsMutex_);
        interfaceForwards_.erase(key);
        forwardingRemoving_.erase(key);
    }
    {
        std::lock_guard<std::mutex> guard(onDpaSharingTrafficMutex_);
        onDpaSharingTraffic_.clear();
    }
    if (fromIface.find(WLAN_IFACE_NAME) != std::string::npos || fromIface.find(P2P_IFACE_NAME) != std::string::npos) {
        ClearForbidIpRules();
        DisableShareUnreachableRoute(RouteManager::UNREACHABLE_NETWORK);
        std::lock_guard<std::mutex> guard(wifiShareInterfaceMutex_);
        wifiShareInterface_.clear();
    }
    RemoveSharingSecurityRules(fromIface, toIface);
    return 0;
}

int32_t SharingManager::GetNetworkSharingTraffic(const std::string &downIface, const std::string &upIface,
                                                 NetworkSharingTraffic &traffic)
{
    const std::string cmds = "-t filter -L tetherctrl_counters -nvx";
    std::string result = iptablesWrapper_->RunCommandForRes(IPTYPE_IPV4V6, cmds);
    const std::string num = "(\\d+)";
    const std::string iface = "([^\\s]+)";
    const std::string dst = "(0.0.0.0/0|::/0)";
    const std::string counters = "\\s*" + num + "\\s+" + num + " RETURN     all(  --  |      )" + iface + "\\s+" +
                                 iface + "\\s+" + dst + "\\s+" + dst;
    static const std::regex IP_RE(counters);

    bool isFindTx = false;
    bool isFindRx = false;
    const std::vector<std::string> lines = CommonUtils::Split(result, "\n");
    std::size_t size1 = lines.size();
    for (auto line : lines) {
        std::smatch matches;
        std::regex_search(line, matches, IP_RE);
        if (matches.size() < MAX_MATCH_SIZE) {
            continue;
        }
        for (uint32_t i = 0; i < matches.size() - 1; i++) {
            std::string tempMatch = matches[i];
            NETNATIVE_LOG_D("GetNetworkSharingTraffic matche[%{public}s]", tempMatch.c_str());
            if (matches[i] == downIface && matches[i + NEXT_LIST_CORRECT_DATA] == upIface &&
                (i >= TWO_LIST_CORRECT_DATA)) {
                int64_t send =
                    static_cast<int64_t>(strtoul(matches[i - TWO_LIST_CORRECT_DATA].str().c_str(), nullptr, 0));
                isFindTx = true;
                traffic.send = send;
                traffic.all += send;
            } else if (matches[i] == upIface && matches[i + NEXT_LIST_CORRECT_DATA] == downIface &&
                       (i >= NET_TRAFFIC_RESULT_INDEX_OFFSET)) {
                int64_t receive =
                    static_cast<int64_t>(strtoul(matches[i - TWO_LIST_CORRECT_DATA].str().c_str(), nullptr, 0));
                isFindRx = true;
                traffic.receive = receive;
                traffic.all += receive;
            }
            if (isFindTx && isFindRx) {
                NETNATIVE_LOG_D("GetNetworkSharingTraffic success total");
                return NETMANAGER_SUCCESS;
            }
        }
    }
    NETNATIVE_LOGE("GetNetworkSharingTraffic failed");
    return NETMANAGER_ERROR;
}

int32_t SharingManager::GetNetworkCellularSharingTraffic(NetworkSharingTraffic &traffic, std::string &ifaceName)
{
    const std::string cmds = "-t filter -L tetherctrl_counters -nvx";
    for (IpType ipType : {IPTYPE_IPV4, IPTYPE_IPV6}) {
        NetworkSharingTraffic traffic0;
        std::string ifaceName0 = "";
        std::string result = iptablesWrapper_->RunCommandForRes(ipType, cmds);
        int32_t ret = QueryCellularSharingTraffic(traffic0, result, ifaceName0);
        if (ret != NETMANAGER_SUCCESS) {
            NETNATIVE_LOGI("ipv4 GetNetworkSharingTraffic failed");
            return NETMANAGER_ERROR;
        }
        traffic.receive += traffic0.receive;
        traffic.send += traffic0.send;
        traffic.all += traffic0.all;
        ifaceName = ifaceName0;
    }
    // LCOV_EXCL_START
    NetworkSharingTraffic traffic1;
    std::string ifaceName1 = ifaceName;
    QueryDpaCellularSharingTraffic(onDpaSharingTraffic_, traffic1, ifaceName1);
    traffic.receive += traffic1.receive;
    traffic.send += traffic1.send;
    traffic.all += traffic1.all;
    // LCOV_EXCL_STOP
    NETNATIVE_LOG_D("GetNetworkCellularSharingTraffic success");
    return NETMANAGER_SUCCESS;
}

int32_t SharingManager::SetDpaCellularSharingTraffic(NetworkDpaTrafficReport &sharingTrafficMsg)
{
    DpaWifiTrafficReport wifiSharingTrafficMsg;
    char src_if_name[32] = {0};
    char dst_if_name[32] = {0};
    char *pSrcName = if_indextoname(sharingTrafficMsg.src_if_index, src_if_name);
    char *pDstName = if_indextoname(sharingTrafficMsg.dst_if_index, dst_if_name);
    // LCOV_EXCL_START
    if (pSrcName != nullptr && pDstName != nullptr) {
        wifiSharingTrafficMsg.srcIface_ = pSrcName;
        wifiSharingTrafficMsg.dstIface_ = pDstName;
    }
    // LCOV_EXCL_STOP
    wifiSharingTrafficMsg.pkts = sharingTrafficMsg.pkts;
    wifiSharingTrafficMsg.bytes = sharingTrafficMsg.bytes;
    std::lock_guard<std::mutex> guard(onDpaSharingTrafficMutex_);
    onDpaSharingTraffic_.push_back(wifiSharingTrafficMsg);
    return NETMANAGER_SUCCESS;
}

void SharingManager::QueryDpaCellularSharingTraffic(const std::vector<DpaWifiTrafficReport> &onSharingTraffic,
    NetworkSharingTraffic &traffic, std::string &ifaceName)
{
    std::lock_guard<std::mutex> guard(onDpaSharingTrafficMutex_);
    if (onSharingTraffic.empty()) {
        traffic.send = 0;
        traffic.receive = 0;
        traffic.all = 0;
        return;
    }
    for (auto sharing : onSharingTraffic) {
        if (sharing.srcIface_.find(CELLULAR_IFACE_NAME) != std::string::npos
            && sharing.dstIface_.find(WLAN_IFACE_NAME) != std::string::npos) {
                traffic.send = sharing.bytes;
                traffic.all += sharing.bytes;
        } else if (sharing.srcIface_.find(WLAN_IFACE_NAME) != std::string::npos
            && sharing.dstIface_.find(CELLULAR_IFACE_NAME) != std::string::npos) {
                traffic.receive = sharing.bytes;
                traffic.all += sharing.bytes;
        } else if (sharing.srcIface_.find(WLAN_IFACE_NAME) != std::string::npos
            && sharing.dstIface_.find(WLAN_IFACE_NAME) != std::string::npos
            && sharing.srcIface_.find(ifaceName) != std::string::npos) {
                traffic.send = sharing.bytes;
                traffic.all += sharing.bytes;
        } else if (sharing.srcIface_.find(WLAN_IFACE_NAME) != std::string::npos
            && sharing.dstIface_.find(WLAN_IFACE_NAME) != std::string::npos
            && sharing.dstIface_.find(ifaceName) != std::string::npos) {
                traffic.receive = sharing.bytes;
                traffic.all += sharing.bytes;
        }
    }
}

int32_t SharingManager::QueryCellularSharingTraffic(NetworkSharingTraffic &traffic,
    const std::string &result, std::string &ifaceName)
{
    const std::string num = "(\\d+)";
    const std::string iface = "([^\\s]+)";
    const std::string dst = "(0.0.0.0/0|::/0)";
    const std::string counters = "\\s*" + num + "\\s+" + num + " RETURN     all(  --  |      )" + iface + "\\s+" +
                                 iface + "\\s+" + dst + "\\s+" + dst;
    static const std::regex IP_RE(counters);

    bool isFindTx = false;
    bool isFindRx = false;
    const std::vector<std::string> lines = CommonUtils::Split(result, "\n");
    for (auto line : lines) {
        std::smatch matches;
        std::regex_search(line, matches, IP_RE);
        if (matches.size() < MAX_MATCH_SIZE) {
            continue;
        }
        GetTraffic(matches, ifaceName, traffic, isFindTx, isFindRx);
        if (isFindTx && isFindRx) {
            NETNATIVE_LOG_D("GetNetworkSharingTraffic success total");
            return NETMANAGER_SUCCESS;
        }
    }
    NETNATIVE_LOGI("GetNetworkSharingTraffic failed");
    return NETMANAGER_ERROR;
}

static bool ConvertStrToLong(const std::string &str, int64_t &value)
{
    auto [ptr, ec] = std::from_chars(str.data(), str.data() + str.size(), value);
    return ec == std::errc{} && ptr == str.data() + str.size();
}

void SharingManager::GetTraffic(std::smatch &matches, std::string &ifaceName, NetworkSharingTraffic &traffic,
    bool &isFindTx, bool &isFindRx)
{
    if (matches.empty()) {
        return;
    }
    for (uint32_t i = 0; i < matches.size() - 1; i++) {
        std::string matchTemp = matches[i];
        NETNATIVE_LOG_D("GetNetworkCellularSharingTraffic matche[%{public}s]", matchTemp.c_str());
        std::string matchNext = matches[i + NEXT_LIST_CORRECT_DATA];
        if (matchTemp.find(CELLULAR_IFACE_NAME) != std::string::npos
            && matchNext.find(WLAN_IFACE_NAME) != std::string::npos && ((i - TWO_LIST_CORRECT_DATA) >= 0)) {
            int64_t send = 0;
            if (!ConvertStrToLong(matches[i - TWO_LIST_CORRECT_DATA].str(), send)) {
                return;
            }
            isFindTx = true;
            traffic.send = send;
            traffic.all += send;
            ifaceName = matchTemp;
        } else if (matchTemp.find(WLAN_IFACE_NAME) != std::string::npos
            && matchNext.find(CELLULAR_IFACE_NAME) != std::string::npos && ((i - TWO_LIST_CORRECT_DATA) >= 0)) {
            int64_t receive = 0;
            if (!ConvertStrToLong(matches[i - TWO_LIST_CORRECT_DATA].str(), receive)) {
                return;
            }
            isFindRx = true;
            traffic.receive = receive;
            traffic.all += receive;
        } else if (matchTemp.find(WLAN_IFACE_NAME) != std::string::npos
            && matchNext.find(WLAN_IFACE_NAME) != std::string::npos && ((i - TWO_LIST_CORRECT_DATA) >= 0)
            && ifaceName == "") {
            int64_t send = 0;
            if (!ConvertStrToLong(matches[i - TWO_LIST_CORRECT_DATA].str(), send)) {
                return;
            }
            isFindTx = true;
            traffic.send = send;
            traffic.all += send;
            ifaceName = matchTemp;
        } else if (matchTemp.find(WLAN_IFACE_NAME) != std::string::npos
            && matchNext.find(WLAN_IFACE_NAME) != std::string::npos && ((i - TWO_LIST_CORRECT_DATA) >= 0)
            && ifaceName.find(WLAN_IFACE_NAME) != std::string::npos) {
            int64_t receive = 0;
            if (!ConvertStrToLong(matches[i - TWO_LIST_CORRECT_DATA].str(), receive)) {
                return;
            }
            isFindRx = true;
            traffic.receive = receive;
            traffic.all += receive;
        }
    }
}

void SharingManager::CheckInited()
{
    std::lock_guard<std::mutex> guard(initedMutex_);
    if (inited_) {
        return;
    }
    InitChildChains();
}

void SharingManager::SetForwardRules(bool set, const std::string &cmds, std::string &cmdSet)
{
    const std::string op = set ? "-A" : "-D";
    cmdSet.append(op + cmds + "\n");
}

void SharingManager::CombineRestoreRules(const std::string &cmds, std::string &cmdSet)
{
    cmdSet.append(cmds + "\n");
}

int32_t SharingManager::EnableShareUnreachableRoute(RouteManager::TableType tableType)
{
    NETNATIVE_LOGI("EnableShareUnreachableRoute enter");
    bool routeRepeat = false;

    NetworkRouteInfo networkRouteInfo;
    networkRouteInfo.destination = "0.0.0.0/0";
    networkRouteInfo.nextHop = "unreachable";

    int32_t ret = RouteManager::AddRoute(tableType, networkRouteInfo, routeRepeat);
    if (ret != 0 && !routeRepeat) {
        NETNATIVE_LOGE("EnableShareUnreachableRoute fail, ret = %{public}d", ret);
    }

    NetworkRouteInfo networkRouteInfoV6;
    networkRouteInfoV6.destination = "::/0";
    networkRouteInfoV6.nextHop = "unreachable";

    ret = RouteManager::AddRoute(tableType, networkRouteInfoV6, routeRepeat);
    if (ret != 0 && !routeRepeat) {
        NETNATIVE_LOGE("EnableShareUnreachableRoute v6 fail, ret = %{public}d", ret);
    }
    return ret;
}

int32_t SharingManager::DisableShareUnreachableRoute(RouteManager::TableType tableType)
{
    NETNATIVE_LOGI("DisableShareUnreachableRoute enter");
    std::string interfaceName = "";
    std::string destinationName = "0.0.0.0/0";
    std::string nextHop = "unreachable";

    int32_t ret = RouteManager::RemoveRoute(tableType, interfaceName, destinationName, nextHop);
    if (ret != 0) {
        NETNATIVE_LOGE("DisableShareUnreachableRoute fail, ret = %{public}d", ret);
    }
    
    std::string destinationV6Name = "::/0";
    ret = RouteManager::RemoveRoute(tableType, interfaceName, destinationV6Name, nextHop);
    if (ret != 0) {
        NETNATIVE_LOGE("DisableShareUnreachableRoute V6 fail, ret = %{public}d", ret);
    }
    return ret;
}

void SharingManager::ClearForbidIpRules()
{
    std::lock_guard<std::mutex> guard(forbidIpMutex_);
    for (auto ip : forbidIpsMap_) {
        std::lock_guard<std::mutex> guard(wifiShareInterfaceMutex_);
        if (RouteManager::SetSharingUnreachableIpRule(
            RTM_DELRULE, wifiShareInterface_, ip.first, ip.second) != NETMANAGER_SUCCESS) {
            NETNATIVE_LOGE("SetSharingUnreachableIpRule fail");
        }
    }
    forbidIpsMap_.clear();
}

int32_t SharingManager::SetInternetAccessByIpForWifiShare(
    const std::string &ipAddr, uint8_t family, bool accessInternet, const std::string &clientNetIfName)
{
    {
        std::lock_guard<std::mutex> guard(wifiShareInterfaceMutex_);
        if (wifiShareInterface_ == "") {
            NETNATIVE_LOGE("wifi share network not enable");
            return -1;
        }
    }
    std::lock_guard<std::mutex> guard(forbidIpMutex_);
    if ((accessInternet && forbidIpsMap_.find(ipAddr) == forbidIpsMap_.end()) ||
        (!accessInternet && forbidIpsMap_.find(ipAddr) != forbidIpsMap_.end())) {
        NETNATIVE_LOGE("ip[%{public}s] set conflict, access[%{public}d]",
            NetManagerStandard::CommonUtils::ToAnonymousIp(ipAddr, true).c_str(), accessInternet);
        return -1;
    }
    int32_t res;
    uint16_t action = accessInternet ? RTM_DELRULE : RTM_NEWRULE;
    {
        std::lock_guard<std::mutex> guard(wifiShareInterfaceMutex_);
        res = RouteManager::SetSharingUnreachableIpRule(action, wifiShareInterface_, ipAddr, family);
    }
    if (res == NETMANAGER_SUCCESS) {
        if (accessInternet) {
            forbidIpsMap_.erase(ipAddr);
        } else {
            forbidIpsMap_[ipAddr] = family;
        }
    }
    return res;
}

std::string SharingManager::GetLocalIpAddress(const std::string &upstreamIface)
{
    struct ifaddrs *ifaddr = nullptr;
    struct ifaddrs *ifa = nullptr;
    std::string localIp;

    if (getifaddrs(&ifaddr) == -1) {
        NETNATIVE_LOGE("GetLocalIpAddress: getifaddrs failed");
        return localIp;
    }

    for (ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == nullptr) {
            continue;
        }

        if (ifa->ifa_addr->sa_family != AF_INET) {
            continue;
        }

        if (ifa->ifa_name == nullptr) {
            continue;
        }

        std::string ifaceName(ifa->ifa_name);
        if (ifaceName != upstreamIface) {
            continue;
        }

        struct sockaddr_in *ipv4 = reinterpret_cast<sockaddr_in *>(ifa->ifa_addr);
        char ip[INET_ADDRSTRLEN] = {0};
        if (inet_ntop(AF_INET, &(ipv4->sin_addr), ip, INET_ADDRSTRLEN) != nullptr) {
            localIp = ip;
            break;
        }
    }

    freeifaddrs(ifaddr);
    return localIp;
}

void SharingManager::AddSharingSecurityRules(const std::string &fromIface, const std::string &toIface)
{
    std::string localIp = GetLocalIpAddress(toIface);
    if (localIp.empty()) {
        NETNATIVE_LOGW("AddSharingSecurityRules: localIp is empty, skip adding security rules");
        return;
    }

    // Record the mapping of fromIface to localIp for use during Remove
    {
        std::lock_guard<std::mutex> guard(sharingIfaceToIpMutex_);
        sharingIfaceToIpMap_[fromIface] = localIp;
    }

    std::string cmdSet = "";
    CombineRestoreRules(FILTER_TABLE, cmdSet);

    std::string inputDropRule = std::string(INPUT_CHAIN) + INPUT_I_OPT + fromIface + SRC_OPT + localIp + J_DROP;
    SetForwardRules(true, inputDropRule, cmdSet);

    std::string inputDropRuleDst = std::string(INPUT_CHAIN) + INPUT_I_OPT + fromIface + DST_OPT + localIp + J_DROP;
    SetForwardRules(true, inputDropRuleDst, cmdSet);

    std::string forwardDropRule = std::string(FORWARD_CHAIN) + INPUT_I_OPT + fromIface + SRC_OPT + localIp + J_DROP;
    SetForwardRules(true, forwardDropRule, cmdSet);

    std::string forwardDropRuleDst = std::string(FORWARD_CHAIN) + INPUT_I_OPT + fromIface + DST_OPT + localIp + J_DROP;
    SetForwardRules(true, forwardDropRuleDst, cmdSet);

    CombineRestoreRules(CMD_COMMIT, cmdSet);
    iptablesWrapper_->RunRestoreCommands(IPTYPE_IPV4, cmdSet);
    NETNATIVE_LOGI("AddSharingSecurityRules: added security rules for interface %{public}s with IP %{private}s",
        fromIface.c_str(), localIp.c_str());
}

void SharingManager::RemoveSharingSecurityRules(const std::string &fromIface, const std::string &toIface)
{
    // First try to get IP from the recorded mapping
    std::string localIp;
    {
        std::lock_guard<std::mutex> guard(sharingIfaceToIpMutex_);
        auto it = sharingIfaceToIpMap_.find(fromIface);
        if (it != sharingIfaceToIpMap_.end()) {
            localIp = it->second;
            sharingIfaceToIpMap_.erase(it);
        }
    }

    // If not found in mapping, try to get IP from interface (may fail if interface is already down)
    if (localIp.empty()) {
        localIp = GetLocalIpAddress(toIface);
        if (localIp.empty()) {
            NETNATIVE_LOGW("RemoveSharingSecurityRules: localIp is empty, skip removing security rules");
            return;
        }
    }

    std::string cmdSet = "";
    CombineRestoreRules(FILTER_TABLE, cmdSet);

    std::string inputDropRule = std::string(INPUT_CHAIN) + INPUT_I_OPT + fromIface + SRC_OPT + localIp + J_DROP;
    SetForwardRules(false, inputDropRule, cmdSet);

    std::string inputDropRuleDst = std::string(INPUT_CHAIN) + INPUT_I_OPT + fromIface + DST_OPT + localIp + J_DROP;
    SetForwardRules(false, inputDropRuleDst, cmdSet);

    std::string forwardDropRule = std::string(FORWARD_CHAIN) + INPUT_I_OPT + fromIface + SRC_OPT + localIp + J_DROP;
    SetForwardRules(false, forwardDropRule, cmdSet);

    std::string forwardDropRuleDst = std::string(FORWARD_CHAIN) + INPUT_I_OPT + fromIface + DST_OPT + localIp + J_DROP;
    SetForwardRules(false, forwardDropRuleDst, cmdSet);

    CombineRestoreRules(CMD_COMMIT, cmdSet);
    iptablesWrapper_->RunRestoreCommands(IPTYPE_IPV4, cmdSet);
    NETNATIVE_LOGI("RemoveSharingSecurityRules: removed security rules for interface %{public}s with IP %{private}s",
        fromIface.c_str(), localIp.c_str());
}
} // namespace nmd
} // namespace OHOS
