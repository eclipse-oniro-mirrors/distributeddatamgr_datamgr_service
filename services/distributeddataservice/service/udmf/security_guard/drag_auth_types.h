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

#ifndef UDMF_DRAG_AUTH_TYPES_H
#define UDMF_DRAG_AUTH_TYPES_H

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <string>
#include <utility>
#include <vector>

#include "security_guard/security_guard_delegate.h"

namespace OHOS::UDMF {
using SecurityGuardDelegate = DistributedData::SecurityGuardDelegate;
using DragAuthDecision = SecurityGuardDelegate::Strategy;
using DragAuthEvent = SecurityGuardDelegate::Event;
using ClientTimeoutPolicy = SecurityGuardDelegate::ClientPolicy;
using AdapterStatus = SecurityGuardDelegate::Status;
using DispatchStatus = SecurityGuardDelegate::DispatchStatus;
constexpr int64_t MIN_AUTH_CLIENT_TIMEOUT_MS = 1;
constexpr int64_t MAX_AUTH_CLIENT_TIMEOUT_MS = 400;
enum class AuthReason {
    MERGED_RESULT,
    SKIPPED,
    PROVIDER_UNAVAILABLE,
    EVENT_BUILD_FAILED,
    INVALID_RESULT,
    AUTH_RESULT_TIMEOUT,
    WATCHDOG_TIMEOUT,
    CAPACITY_LIMIT,
    INVALID_CLIENT_TIMEOUT_POLICY,
    LATE_RESULT_DROPPED,
    REQUEST_REJECTED,
    PAYLOAD_TOO_LARGE,
    REQUEST_DISPATCHED,
    RESULT_ALLOWED,
    SAME_APP_SKIPPED,
    NO_SUBSCRIBERS,
    INVALID_PAYLOAD,
    COUNT,
};

struct DragAuthResult {
    DragAuthDecision decision = DragAuthDecision::ALLOW;
    AuthReason reason = AuthReason::SKIPPED;
};

struct AuthTimeoutPolicy {
    DragAuthDecision fallback = DragAuthDecision::DENY;
    std::chrono::milliseconds watchdog{ 0 };
    uint64_t snapshotVersion = 0;
    bool defaultApplied = true;
};

struct ClientPolicySnapshot : public SecurityGuardDelegate::ClientSnapshot {
    ClientPolicySnapshot() = default;
    explicit ClientPolicySnapshot(SecurityGuardDelegate::ClientSnapshot snapshot)
        : SecurityGuardDelegate::ClientSnapshot(std::move(snapshot))
    {
    }
    AuthTimeoutPolicy Resolve(int64_t eventId) const;
};

struct AuthDiagnosticInfo {
    int64_t eventId = 0;
    uint64_t snapshotVersion = 0;
    size_t clientCount = 0;
    int64_t watchdogMs = 0;
    int64_t elapsedMs = 0;
    DragAuthDecision fallback = DragAuthDecision::DENY;
    uint64_t requestId = 0;
    size_t contentBytes = 0;
    size_t degradedCount = 0;
};

using AuthCompletion = SecurityGuardDelegate::Completion;
} // namespace OHOS::UDMF
#endif // UDMF_DRAG_AUTH_TYPES_H
