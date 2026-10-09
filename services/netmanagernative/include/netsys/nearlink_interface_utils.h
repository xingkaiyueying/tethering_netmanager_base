/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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
#ifndef NEARLINK_INTERFACE_UTILS_H
#define NEARLINK_INTERFACE_UTILS_H

#include <string>

namespace OHOS::nmd {
inline bool IsNearlinkInterface(const std::string &iface)
{
    constexpr size_t prefixLength = 5;
    constexpr size_t maxInterfaceLength = 15;
    if (iface.size() <= prefixLength || iface.size() > maxInterfaceLength ||
        iface.compare(0, prefixLength, "sleip") != 0 ||
        (iface.size() > prefixLength + 1 && iface[prefixLength] == '0')) {
        return false;
    }
    for (size_t i = prefixLength; i < iface.size(); ++i) {
        if (iface[i] < '0' || iface[i] > '9') {
            return false;
        }
    }
    return true;
}
} // namespace OHOS::nmd
#endif // NEARLINK_INTERFACE_UTILS_H
