/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include <algorithm>

#include "drag_auth_types.h"

namespace OHOS::UDMF {
namespace {
constexpr int64_t WATCHDOG_GRACE_PERIOD_MS = 100;
constexpr int64_t DEFAULT_WATCHDOG_TIMEOUT_MS = 5000;
} // namespace

AuthTimeoutPolicy ClientPolicySnapshot::Resolve(int64_t eventId) const
{
    AuthTimeoutPolicy defaults{ DragAuthDecision::DENY, std::chrono::milliseconds(DEFAULT_WATCHDOG_TIMEOUT_MS),
        version, true };
    auto it = policies.find(eventId);
    if (!initialized || it == policies.end() || it->second.empty()) {
        return defaults;
    }
    auto fallback = DragAuthDecision::ALLOW;
    int64_t maximum = 0;
    for (const auto &client : it->second) {
        if ((client.strategy != DragAuthDecision::ALLOW && client.strategy != DragAuthDecision::DENY) ||
            client.timeoutMs < MIN_AUTH_CLIENT_TIMEOUT_MS || client.timeoutMs > MAX_AUTH_CLIENT_TIMEOUT_MS) {
            return defaults;
        }
        if (client.strategy == DragAuthDecision::DENY) {
            fallback = DragAuthDecision::DENY;
        }
        maximum = std::max(maximum, client.timeoutMs);
    }
    return { fallback, std::chrono::milliseconds(maximum + WATCHDOG_GRACE_PERIOD_MS), version, false };
}

} // namespace OHOS::UDMF
