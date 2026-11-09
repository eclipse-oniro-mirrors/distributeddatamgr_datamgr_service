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

#ifndef UDMF_AUTH_DEGRADATION_POLICY_H
#define UDMF_AUTH_DEGRADATION_POLICY_H

#include <mutex>

#include "drag_auth_types.h"

namespace OHOS::UDMF {
class AuthDegradationPolicy {
public:
    using Clock = std::chrono::steady_clock;
    using Now = std::function<Clock::time_point()>;
    struct Ticket {
        std::string clientId;
        uint64_t epoch = 0;
        bool probe = false;
    };
    struct Request {
        int64_t eventId = 0;
        uint64_t sequence = 0;
        std::vector<std::string> degradedClients;
        std::vector<Ticket> tickets;
    };

    explicit AuthDegradationPolicy(Now now = Clock::now);
    void UpdateSnapshot(const ClientPolicySnapshot &snapshot);
    Request Prepare(const ClientPolicySnapshot &snapshot, int64_t eventId);
    void Finish(const Request &request, const SecurityGuardDelegate::Result &result);
    void Reset();

private:
    enum class State { NORMAL, DEGRADED, PROBING };
    using Key = std::pair<int64_t, std::string>;
    struct Health {
        int64_t timeoutMs = 0;
        uint64_t epoch = 0;
        uint64_t lastSequence = 0;
        uint64_t generation = 0;
        uint32_t timeouts = 0;
        State state = State::NORMAL;
        Clock::time_point windowStart;
        Clock::time_point retryAt;
    };
    static std::map<Key, ClientTimeoutPolicy> EligibleClients(const ClientPolicySnapshot &snapshot);
    static DragAuthDecision FindStrategy(const SecurityGuardDelegate::Result &result, const std::string &clientId);
    void UpdateLocked(const ClientPolicySnapshot &snapshot);
    void Observe(int64_t eventId, Health &health, DragAuthDecision strategy, Clock::time_point now);
    void Degrade(int64_t eventId, Health &health, Clock::time_point now);
    std::mutex mutex_;
    std::map<Key, Health> clients_;
    uint64_t snapshotVersion_ = 0;
    uint64_t nextEpoch_ = 0;
    uint64_t nextSequence_ = 0;
    Now now_;
};
} // namespace OHOS::UDMF
#endif // UDMF_AUTH_DEGRADATION_POLICY_H
