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

#define LOG_TAG "UdmfAuthDegradation"
#include "auth_degradation_policy.h"

#include <set>

#include "log_print.h"

namespace OHOS::UDMF {
namespace {
constexpr uint32_t CONSECUTIVE_TIMEOUT_THRESHOLD = 3;
constexpr std::chrono::seconds TIMEOUT_OBSERVATION_WINDOW{ 60 };
constexpr std::chrono::seconds DEGRADATION_COOLDOWN{ 30 };
} // namespace

AuthDegradationPolicy::AuthDegradationPolicy(Now now) : now_(std::move(now))
{
}

std::map<AuthDegradationPolicy::Key, ClientTimeoutPolicy> AuthDegradationPolicy::EligibleClients(
    const ClientPolicySnapshot &snapshot)
{
    std::map<Key, ClientTimeoutPolicy> eligible;
    if (!snapshot.initialized) {
        return eligible;
    }
    for (const auto &[eventId, clients] : snapshot.policies) {
        std::set<std::string> seen;
        std::set<std::string> duplicates;
        for (const auto &client : clients) {
            if (!seen.insert(client.clientId).second) {
                duplicates.insert(client.clientId);
            }
            if (!client.clientId.empty() && client.strategy == DragAuthDecision::ALLOW &&
                client.timeoutMs >= MIN_AUTH_CLIENT_TIMEOUT_MS && client.timeoutMs <= MAX_AUTH_CLIENT_TIMEOUT_MS) {
                eligible.emplace(Key{ eventId, client.clientId }, client);
            }
        }
        for (const auto &clientId : duplicates) {
            eligible.erase({ eventId, clientId });
        }
    }
    return eligible;
}

void AuthDegradationPolicy::UpdateLocked(const ClientPolicySnapshot &snapshot)
{
    if (snapshot.version < snapshotVersion_) {
        return;
    }
    snapshotVersion_ = snapshot.version;
    auto eligible = EligibleClients(snapshot);
    for (auto it = clients_.begin(); it != clients_.end();) {
        auto candidate = eligible.find(it->first);
        if (candidate == eligible.end() || candidate->second.timeoutMs != it->second.timeoutMs ||
            candidate->second.generation != it->second.generation) {
            it = clients_.erase(it);
        } else {
            ++it;
        }
    }
    for (const auto &[key, client] : eligible) {
        if (clients_.find(key) == clients_.end()) {
            Health health;
            health.timeoutMs = client.timeoutMs;
            health.generation = client.generation;
            health.epoch = ++nextEpoch_;
            clients_.emplace(key, health);
        }
    }
}

void AuthDegradationPolicy::UpdateSnapshot(const ClientPolicySnapshot &snapshot)
{
    std::lock_guard<std::mutex> lock(mutex_);
    UpdateLocked(snapshot);
}

AuthDegradationPolicy::Request AuthDegradationPolicy::Prepare(const ClientPolicySnapshot &snapshot, int64_t eventId)
{
    std::lock_guard<std::mutex> lock(mutex_);
    UpdateLocked(snapshot);
    Request request;
    request.eventId = eventId;
    if (snapshot.version != snapshotVersion_) {
        return request;
    }
    request.sequence = ++nextSequence_;
    auto now = now_();
    for (auto &[key, health] : clients_) {
        if (key.first != eventId) {
            continue;
        }
        if (health.state == State::PROBING || (health.state == State::DEGRADED && now < health.retryAt)) {
            request.degradedClients.push_back(key.second);
            continue;
        }
        if (health.state == State::DEGRADED) {
            health.state = State::PROBING;
            health.epoch = ++nextEpoch_;
            ZLOGI("probe event=%{public}lld clientEpoch=%{public}llu", static_cast<long long>(eventId),
                static_cast<unsigned long long>(health.epoch));
        }
        request.tickets.push_back({ key.second, health.epoch, health.state == State::PROBING });
    }
    return request;
}

DragAuthDecision AuthDegradationPolicy::FindStrategy(
    const SecurityGuardDelegate::Result &result, const std::string &clientId)
{
    if (result.mergedStrategy != DragAuthDecision::ALLOW && result.mergedStrategy != DragAuthDecision::DENY) {
        return DragAuthDecision::ERROR;
    }
    auto strategy = DragAuthDecision::ERROR;
    bool found = false;
    for (const auto &client : result.clients) {
        if (client.clientId != clientId) {
            continue;
        }
        if (found) {
            return DragAuthDecision::ERROR;
        }
        found = true;
        strategy = client.strategy;
    }
    return strategy;
}

void AuthDegradationPolicy::Degrade(int64_t eventId, Health &health, Clock::time_point now)
{
    health.state = State::DEGRADED;
    health.epoch = ++nextEpoch_;
    health.retryAt = now + DEGRADATION_COOLDOWN;
    health.timeouts = 0;
    ZLOGW("degraded event=%{public}lld clientEpoch=%{public}llu cooldownMs=%{public}lld",
        static_cast<long long>(eventId), static_cast<unsigned long long>(health.epoch),
        static_cast<long long>(std::chrono::duration_cast<std::chrono::milliseconds>(DEGRADATION_COOLDOWN).count()));
}

void AuthDegradationPolicy::Observe(int64_t eventId, Health &health, DragAuthDecision strategy, Clock::time_point now)
{
    if (health.state == State::PROBING) {
        if (strategy == DragAuthDecision::ALLOW || strategy == DragAuthDecision::DENY) {
            health.state = State::NORMAL;
            health.epoch = ++nextEpoch_;
            health.timeouts = 0;
            ZLOGI("recovered event=%{public}lld clientEpoch=%{public}llu", static_cast<long long>(eventId),
                static_cast<unsigned long long>(health.epoch));
        } else {
            Degrade(eventId, health, now);
        }
        return;
    }
    if (strategy != DragAuthDecision::TIMEOUT) {
        health.timeouts = 0;
        return;
    }
    if (health.timeouts == 0 || now - health.windowStart > TIMEOUT_OBSERVATION_WINDOW) {
        health.timeouts = 0;
        health.windowStart = now;
    }
    if (++health.timeouts >= CONSECUTIVE_TIMEOUT_THRESHOLD) {
        Degrade(eventId, health, now);
    }
}

void AuthDegradationPolicy::Finish(const Request &request, const SecurityGuardDelegate::Result &result)
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto now = now_();
    for (const auto &ticket : request.tickets) {
        auto it = clients_.find({ request.eventId, ticket.clientId });
        if (it == clients_.end()) {
            continue;
        }
        auto &health = it->second;
        if (health.epoch != ticket.epoch || request.sequence <= health.lastSequence) {
            continue;
        }
        health.lastSequence = request.sequence;
        Observe(request.eventId, health, FindStrategy(result, ticket.clientId), now);
    }
}

void AuthDegradationPolicy::Reset()
{
    std::lock_guard<std::mutex> lock(mutex_);
    clients_.clear();
    snapshotVersion_ = 0;
}
} // namespace OHOS::UDMF
