/*
 * Copyright (C) 2021-2023 Huawei Device Co., Ltd.
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

#ifndef INCLUDE_NETLINK_SOCKET_H
#define INCLUDE_NETLINK_SOCKET_H

#include <functional>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <memory>
#include <netinet/in.h>
#include <sys/epoll.h>
#include "net_ip_mac_info.h"
#include "netlink_msg.h"

namespace OHOS {
namespace nmd {
constexpr uint32_t NETLINKMESSAGE_MAX_LEN = 1024;
constexpr uint32_t KERNEL_BUFFER_SIZE = 8192;
constexpr uint32_t LOCAL_PRIORITY = 32767;
/**
 * Send netklink message to kernel
 *
 * @param msg nlmsghdr struct
 * @param table If clear route，this is table number, otherwise it will is 0
 * @return Returns 0, send netklink message to kernel successfully, otherwise it will fail
 */
int32_t SendNetlinkMsgToKernel(nlmsghdr *msg, uint32_t table = 0);

// Internal Netsys helper for callers that must observe the kernel result of a mutation.
int32_t SendNetlinkMsgToKernelWithAck(nlmsghdr *msg);

/**
 * Clear route or rule configure
 *
 * @param clearThing Decide to clear route or rule. Must be one of RTM_GETRULE/RTM_GETROUTE
 * @param table If clear route，this is table number, otherwise it will is 0
 * @return Returns 0, clear route or rule configure successfully, otherwise it will fail
 */
int32_t ClearRouteInfo(uint16_t clearThing, uint32_t table);

/**
 * Get info from kernel
 *
 * @param sock Sock for read
 * @param clearThing Type for kernel nlmsg_type
 * @param table Route property for RTA_TABLE
 * @return Returns 0, get info from kernel successfully, otherwise it will fail
 */
int32_t GetInfoFromKernel(int32_t sock, uint16_t clearThing, uint32_t table);

/**
 * Deal info from kernel
 *
 * @param nlmsgHeader nlmsghdr
 * @param clearThing Type for kernel nlmsg_type
 * @param table Route property for RTA_TABLE
 * @return Returns 0, deal info from kernel successfully, otherwise it will fail
 */
void DealInfoFromKernel(nlmsghdr *nlmsgHeader, uint16_t clearThing, uint32_t table);

/**
 * Get route property
 *
 * @param nlmsgHeader nlmsghdr
 * @param property Property for route
 * @return Returns 0, get route property successfully, otherwise it will fail
 */
int32_t GetRouteProperty(const nlmsghdr *nlmsgHeader, int32_t property);

#ifdef SUPPORT_SYSVPN
/**
 * Create vpn Interface by netlink
 *
 * @param name ifname
 * @param ifNameId interface name id
 * @param mtu mtu
 * @param phys phy interface
 * @return Returns 0, create vpn interface successfully, otherwise it will fail
 */
int32_t CreateVpnIfByNetlink(const char *name, uint32_t ifNameId, const char *phys, uint32_t mtu);

/**
 * Delete Vpn Interface by netlink
 *
 * @param name ifname
 * @return Returns 0, delete vpn interface successfully, otherwise it will fail
 */
int32_t DeleteVpnIfByNetlink(const char *name);
#endif

/**
 * Send netklink message to kernel and Get message from kernel
 *
 * @param msg nlmsghdr struct
 * @param table If clear route，this is table number, otherwise it will is 0
 * @param rcvMsg message from kernel
 * @return Returns 0, send netklink message to kernel successfully, otherwise it will fail
 */
int32_t ReceiveMsgFromKernel(struct nlmsghdr *msg, uint32_t table, void* rcvMsg);

/**
 * Receive netlink message from kernel
 *
 * @param sock Sock for read
 * @param msgType for kernel nlmsg_type
 * @param table Route property for RTA_TABLE
 * @param rcvMsg message from kernel
 * @return Returns 0, get info from kernel successfully, otherwise it will fail
 */
int32_t GetRcvMsgFromKernel(int32_t &sock, uint16_t msgType, uint32_t table, void* rcvMsg);

/**
 * Deal receive message from kernel
 *
 * @param nlmsgHeader nlmsghdr
 * @param msgType for kernel nlmsg_type
 * @param table Route property for RTA_TABLE
 * @param rcvMsg message from kernel
 */
void DealRcvMsgFromKernel(nlmsghdr *nlmsgHeader, uint16_t msgType, uint32_t table, void* rcvMsg);

/**
 * transfer mac from array to string
 *
 * @param mac array mac address
 * @return Returns string mac address
 */
std::string MacArrayToString(const uint8_t *mac);

/**
 * deal ip neigh info from kernel
 *
 * @param nlmsgHeader nlmsghdr
 * @param msgType for kernel nlmsg_type
 * @param table Route property for RTA_TABLE
 * @param ipMacInfoVec vector NetIpMacInfo
 */
void DealNeighInfo(nlmsghdr *nlmsgHeader, uint16_t msgType, uint32_t table,
    std::vector<NetManagerStandard::NetIpMacInfo>& ipMacInfoVec);

/**
 * create netlink msg and send to kernel
 *
 * @param nlmsgHeader nlmsghdr
 * @param kernelSocket socket to kernel
 */
static ssize_t SendMsgToKernel(struct nlmsghdr *msg, int32_t &kernelSocket);

/**
 * Send netlink messages to kernel
 *
 * @param msgs Vector of netlink message to send
 * @return Returns number of bytes sent if successful, otherwise returns -1
 */
int32_t SendNetlinkMsgsToKernel(std::vector<NetlinkMsg> &msgs);
} // namespace nmd
} // namespace OHOS
#endif // !INCLUDE_NETLINK_SOCKET_H
