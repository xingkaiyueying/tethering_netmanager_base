// Platform double for the actual Network::UpdateNetLinkInfo and its private reconciliation helpers.
#include <algorithm>
#include <cassert>
#include <cerrno>
#include <cstdio>
#include <cstdint>
#include <list>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <shared_mutex>
#include <sstream>
#include <string>
#include <vector>
#define NETMGR_LOG_D(...) ((void)0)
#define NETMGR_LOG_I(...) ((void)0)
#define NETMGR_LOG_W(...) ((void)0)
constexpr int NETMANAGER_SUCCESS = 0, LOCAL_NET_ID = 99, AF_INET = 2, AF_INET6 = 10;
constexpr int FAULT_UPDATE_NETLINK_INFO_FAILED = 1, MAX_IPV4_DNS_NUM = 5, MAX_IPV6_DNS_NUM = 2;
constexpr int NAT464_SERVICE_CONTINUE = 1, NAT464_SERVICE_STOP = 0;
constexpr const char *LOCAL_ROUTE_NEXT_HOP = "0.0.0.0", *LOCAL_ROUTE_IPV6_DESTINATION = "::";
constexpr const char *INVALID_IPV4 = "0.0.0.0", *INVALID_IPV6 = "::", *ERROR_MSG_ADD_NET_ROUTES_FAILED = "route";
enum NetBearType { BEARER_BLUETOOTH, BEARER_WIFI, BEARER_VPN };
int GetAddrFamily(const std::string &address)
{
    return address.find(':') == std::string::npos ? AF_INET : AF_INET6;
}
namespace CommonUtils {
std::string ToAnonymousIp(const std::string &address)
{
    return address;
}
bool IsIPv6LinkLocal(const std::string &address)
{
    return address.rfind("fe80:", 0) == 0;
}
} // namespace CommonUtils
struct INetAddr {
    enum IpType { IPV4, IPV6 };
    int family_ = AF_INET, prefixlen_ = 24, type_ = IPV4;
    std::string address_, hostName_;
    bool operator==(const INetAddr &o) const
    {
        return address_ == o.address_ && prefixlen_ == o.prefixlen_;
    }
};
namespace NetManagerStandard {
using INetAddr = ::INetAddr;
}
struct Route {
    INetAddr destination_, gateway_;
    std::string iface_ = "sleip0";
    bool isExcludedRoute_ = false;
    bool operator==(const Route &o) const
    {
        return destination_ == o.destination_ && gateway_ == o.gateway_;
    }
};
struct NetLinkInfo {
    std::string ifaceName_;
    std::list<INetAddr> netAddrList_, dnsList_;
    std::list<Route> routeList_;
    int mtu_ = 0;
    bool isUserDefinedDnsServer_ = false;
    bool HasNetAddr(const INetAddr &a) const
    {
        return std::find(netAddrList_.begin(), netAddrList_.end(), a) != netAddrList_.end();
    }
    bool HasRoute(const Route &r) const
    {
        return std::find(routeList_.begin(), routeList_.end(), r) != routeList_.end();
    }
};
struct NetsysController {
    std::string failure;
    int calls = 0;
    std::set<std::string> resources;
    std::vector<std::string> dns;
    static NetsysController &GetInstance()
    {
        static NetsysController n;
        return n;
    }
    int Change(const std::string &operation, const std::string &key, bool adding)
    {
        ++calls;
        if (failure == operation) {
            return -EACCES;
        }
        if (adding) {
            return resources.insert(key).second ? 0 : -EEXIST;
        }
        return resources.erase(key) ? 0 : -ESRCH;
    }
    int NetworkAddInterface(int, const std::string &, NetBearType)
    {
        return Change("iface", "iface", true);
    }
    int AddInterfaceAddress(const std::string &, const std::string &a, int)
    {
        return Change("address+", "a" + a, true);
    }
    int DelInterfaceAddress(const std::string &, const std::string &a, int)
    {
        return Change("address-", "a" + a, false);
    }
    int NetworkAddRoute(int id, const std::string &, const std::string &d, const std::string &, bool = false)
    {
        return Change(id == 99 ? "local+" : "route+", std::to_string(id) + d, true);
    }
    int NetworkRemoveRoute(int id, const std::string &, const std::string &d, const std::string &)
    {
        return Change(id == 99 ? "local-" : "route-", std::to_string(id) + d, false);
    }
    int SetResolverConfig(int, int, int, const std::vector<std::string> &s, const std::vector<std::string> &)
    {
        if (failure == "dns") {
            return -EACCES;
        }
        dns = s;
        return 0;
    }
    int SetUserDefinedServerFlag(int, bool)
    {
        return failure == "dns-flag" ? -EACCES : 0;
    }
    int SetInterfaceMtu(const std::string &, int)
    {
        return failure == "mtu" ? -EACCES : 0;
    }
};
struct NetConnServiceIface {
    bool IsIfaceNameInUse(const std::string &, int)
    {
        return false;
    }
};
struct Nat464Service {
    Nat464Service(int, const std::string &) {}
    void MaybeUpdateV6Iface(const std::string &) {}
    void UpdateService(int) {}
};
class Network {
public:
    NetLinkInfo netLinkInfo_;
    std::shared_mutex netLinkInfoMutex_;
    int netId_ = 42, legacy = 0;
    NetBearType netSupplierType_ = BEARER_BLUETOOTH;
    bool isSupportInternet_ = false;
    std::shared_ptr<Nat464Service> nat464Service_;
    bool UpdateNetLinkInfo(const NetLinkInfo &);
    void UpdateStatsCached(const NetLinkInfo &) {}
    void UpdateInterfaces(const NetLinkInfo &)
    {
        ++legacy;
    }
    bool UpdateIpAddrs(const NetLinkInfo &)
    {
        ++legacy;
        return false;
    }
    void UpdateRoutes(const NetLinkInfo &)
    {
        ++legacy;
    }
    void UpdateDns(const NetLinkInfo &)
    {
        ++legacy;
    }
    void UpdateMtu(const NetLinkInfo &)
    {
        ++legacy;
    }
    void UpdateTcpBufferSize(const NetLinkInfo &)
    {
        ++legacy;
    }
    void UpdateNetLinkInfoLinkType(const NetLinkInfo &n)
    {
        netLinkInfo_ = n;
    }
    bool IsNat464Prefered()
    {
        return false;
    }
    bool DelayStartDetectionForIpUpdate(bool)
    {
        return false;
    }
    void StartNetDetection(bool) {}
    void SendSupplierFaultHiSysEvent(int, const char *) {}
};
#include "production.inc"
int main()
{
    auto &sys = NetsysController::GetInstance();
    NetLinkInfo desired;
    desired.ifaceName_ = "sleip0";
    desired.mtu_ = 1500;
    INetAddr v4;
    v4.address_ = "192.168.77.2";
    desired.netAddrList_.push_back(v4);
    Route route;
    route.destination_.address_ = "192.168.77.0";
    desired.routeList_.push_back(route);
    INetAddr dns;
    dns.address_ = "192.168.77.1";
    desired.dnsList_.push_back(dns);
    for (const std::string failure : {"iface", "address+", "route+", "local+", "dns", "dns-flag", "mtu"}) {
        sys.resources.clear();
        sys.dns.clear();
        sys.failure = failure;
        Network n;
        assert(!n.UpdateNetLinkInfo(desired));
        if (failure == "iface") {
            assert(n.netLinkInfo_.ifaceName_.empty());
        }
        if (failure == "address+") {
            assert(n.netLinkInfo_.netAddrList_.empty());
        }
        if (failure == "route+") {
            assert(n.netLinkInfo_.routeList_.empty());
        }
        if (failure == "dns") {
            assert(n.netLinkInfo_.dnsList_.empty());
        }
        sys.failure.clear();
        assert(n.UpdateNetLinkInfo(desired));
        assert(n.legacy == 0);
        assert(n.netLinkInfo_.HasNetAddr(v4) && n.netLinkInfo_.HasRoute(route));
        assert(sys.resources.count("42192.168.77.0/24") && sys.resources.count("99192.168.77.0/24"));
        assert(n.UpdateNetLinkInfo(desired));
    }
    sys.resources.clear();
    Network n;
    assert(n.UpdateNetLinkInfo(desired));
    INetAddr v6;
    v6.address_ = "fd77::2";
    v6.family_ = AF_INET6;
    v6.type_ = INetAddr::IPV6;
    v6.prefixlen_ = 64;
    desired.netAddrList_.push_back(v6);
    Route route6;
    route6.destination_ = v6;
    route6.destination_.address_ = "fd77::";
    desired.routeList_.push_back(route6);
    assert(n.UpdateNetLinkInfo(desired));
    // The kernel created this SLAAC address. Publishing it must not reset its
    // lifetime, and withdrawing a transient snapshot must not remove it.
    assert(!sys.resources.count("afd77::2"));
    NetLinkInfo without6 = desired;
    without6.netAddrList_.pop_back();
    without6.routeList_.pop_back();
    sys.failure = "address-";
    assert(n.UpdateNetLinkInfo(without6));
    assert(!n.netLinkInfo_.HasNetAddr(v6));
    assert(!sys.resources.count("afd77::2"));
    sys.failure.clear();
    assert(n.UpdateNetLinkInfo(desired));
    NetLinkInfo only6 = desired;
    only6.netAddrList_.pop_front();
    only6.routeList_.pop_front();
    only6.dnsList_.clear();
    for (const std::string failure : {"local-", "route-", "address-", "dns"}) {
        sys.failure = failure;
        assert(!n.UpdateNetLinkInfo(only6));
        assert(n.netLinkInfo_.HasNetAddr(v6) && n.netLinkInfo_.HasRoute(route6));
        sys.failure.clear();
        assert(n.UpdateNetLinkInfo(only6));
        assert(!n.netLinkInfo_.HasNetAddr(v4) && !n.netLinkInfo_.HasRoute(route));
        assert(sys.dns.empty());
        assert(n.UpdateNetLinkInfo(desired));
    }
    Network legacy;
    desired.ifaceName_ = "wlan0";
    assert(legacy.UpdateNetLinkInfo(desired));
    assert(legacy.legacy == 6);
    puts("Network real update: address/route/local-route/DNS/MTU faults propagate, partial ownership retries, family "
         "isolation, legacy path PASS");
}
