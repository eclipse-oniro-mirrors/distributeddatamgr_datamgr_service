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

#define LOG_TAG "UdmfDragAuth"
#include "drag_auth_coordinator.h"

#include <array>
#include <utility>

#include "log_print.h"

namespace OHOS::UDMF {
namespace {
constexpr uint32_t MAX_PENDING_AUTH_REQUESTS = 8;
constexpr std::chrono::seconds DIAGNOSTIC_LOG_INTERVAL{ 5 };
void WriteDiagnostic(
    AuthReason reason, const char *name, const AuthDiagnosticInfo &info, uint64_t suppressed, uint32_t pending)
{
    if (reason == AuthReason::REQUEST_DISPATCHED || reason == AuthReason::RESULT_ALLOWED ||
        reason == AuthReason::SAME_APP_SKIPPED || reason == AuthReason::NO_SUBSCRIBERS) {
        ZLOGI("reason=%{public}s request=%{public}llu event=%{public}lld version=%{public}llu "
              "clients=%{public}zu bytes=%{public}zu degraded=%{public}zu elapsedMs=%{public}lld "
              "suppressed=%{public}llu",
            name, static_cast<unsigned long long>(info.requestId), static_cast<long long>(info.eventId),
            static_cast<unsigned long long>(info.snapshotVersion), info.clientCount, info.contentBytes,
            info.degradedCount, static_cast<long long>(info.elapsedMs), static_cast<unsigned long long>(suppressed));
        return;
    }
    ZLOGW("reason=%{public}s request=%{public}llu event=%{public}lld version=%{public}llu "
          "clients=%{public}zu bytes=%{public}zu degraded=%{public}zu watchdogMs=%{public}lld "
          "elapsedMs=%{public}lld fallback=%{public}d pending=%{public}u suppressed=%{public}llu",
        name, static_cast<unsigned long long>(info.requestId), static_cast<long long>(info.eventId),
        static_cast<unsigned long long>(info.snapshotVersion), info.clientCount, info.contentBytes, info.degradedCount,
        static_cast<long long>(info.watchdogMs), static_cast<long long>(info.elapsedMs),
        static_cast<int>(info.fallback), pending, static_cast<unsigned long long>(suppressed));
}
} // namespace

PendingAuthLimiter DragAuthCoordinator::limiter_;

bool TimedAuthRequest::TryComplete(DragAuthResult result, const SecurityGuardDelegate::Result &response)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (completed_) {
        return false;
    }
    const bool expired = std::chrono::steady_clock::now() >= deadline_;
    result_ = expired ? fallback_ : result;
    response_ = expired ? SecurityGuardDelegate::Result{} : response;
    completed_ = true;
    condition_.notify_all();
    return !expired;
}

SecurityGuardDelegate::Result TimedAuthRequest::GetResponse()
{
    std::lock_guard<std::mutex> lock(mutex_);
    return response_;
}

DragAuthResult TimedAuthRequest::WaitUntil(std::chrono::steady_clock::time_point deadline, DragAuthResult fallback)
{
    std::unique_lock<std::mutex> lock(mutex_);
    while (!completed_) {
        if (condition_.wait_until(lock, deadline) == std::cv_status::timeout && !completed_) {
            result_ = fallback;
            completed_ = true;
        }
    }
    return result_;
}

std::unique_ptr<PendingAuthLimiter::Permit> PendingAuthLimiter::TryAcquire()
{
    uint32_t current = count_.load();
    while (current < MAX_PENDING_AUTH_REQUESTS) {
        if (count_.compare_exchange_weak(current, current + 1)) {
            return std::make_unique<Permit>(count_);
        }
    }
    return nullptr;
}

DragAuthCoordinator::DragAuthCoordinator(SecurityGuardDelegate *delegate,
    std::shared_ptr<const AuthEventBuilder> builder, AuthRequestWaiter waiter,
    std::shared_ptr<AuthDegradationPolicy> degradation)
    : delegate_(delegate), builder_(std::move(builder)), waiter_(std::move(waiter)),
      degradation_(degradation ? std::move(degradation) : std::make_shared<AuthDegradationPolicy>())
{
}

uint32_t PendingAuthLimiter::PendingCount() const
{
    return count_.load();
}

void DragAuthCoordinator::Diagnose(AuthReason reason, const AuthDiagnosticInfo &info)
{
    static std::mutex logMutex;
    constexpr auto reasonCount = static_cast<size_t>(AuthReason::COUNT);
    static std::array<std::chrono::steady_clock::time_point, reasonCount> lastLogs{};
    static std::array<bool, reasonCount> logged{};
    static std::array<uint64_t, reasonCount> skipped{};
    static const std::array<const char *, reasonCount> names = { "BLOCKED_BY_SECURITY_GUARD", "SKIPPED",
        "PROVIDER_UNAVAILABLE", "EVENT_BUILD_FAILED", "INVALID_RESULT", "AUTH_RESULT_TIMEOUT", "WATCHDOG_TIMEOUT",
        "CAPACITY_LIMIT", "INVALID_CLIENT_TIMEOUT_POLICY", "LATE_RESULT_DROPPED", "REQUEST_REJECTED",
        "PAYLOAD_TOO_LARGE", "REQUEST_DISPATCHED", "RESULT_ALLOWED", "SAME_APP_SKIPPED", "NO_SUBSCRIBERS",
        "INVALID_PAYLOAD" };
    auto index = static_cast<size_t>(reason);
    if (index >= lastLogs.size()) {
        return;
    }
    uint64_t suppressed = 0;
    {
        std::lock_guard<std::mutex> lock(logMutex);
        auto now = std::chrono::steady_clock::now();
        if (logged[index] && now - lastLogs[index] < DIAGNOSTIC_LOG_INTERVAL) {
            ++skipped[index];
            return;
        }
        logged[index] = true;
        lastLogs[index] = now;
        suppressed = std::exchange(skipped[index], 0);
    }
    WriteDiagnostic(reason, names[index], info, suppressed, limiter_.PendingCount());
}

DragAuthResult DragAuthCoordinator::Authorize(const DragAuthContext &context)
{
    if (!context.crossApplication) {
        Diagnose(AuthReason::SAME_APP_SKIPPED);
        return {};
    }
    if (!delegate_ || !delegate_->IsReady()) {
        degradation_->Reset();
        Diagnose(AuthReason::PROVIDER_UNAVAILABLE);
        return { DragAuthDecision::ALLOW, AuthReason::PROVIDER_UNAVAILABLE };
    }
    if (!builder_ || !builder_->IsReady()) {
        Diagnose(AuthReason::EVENT_BUILD_FAILED);
        return { DragAuthDecision::ALLOW, AuthReason::EVENT_BUILD_FAILED };
    }
    const ClientPolicySnapshot snapshot(delegate_->GetClientSnapshot());
    degradation_->UpdateSnapshot(snapshot);
    if (!snapshot.HasSubscribers(builder_->GetEventId())) {
        AuthDiagnosticInfo info;
        info.eventId = builder_->GetEventId();
        info.snapshotVersion = snapshot.version;
        Diagnose(AuthReason::NO_SUBSCRIBERS, info);
        return {};
    }
    DragAuthEvent event;
    auto buildStatus = builder_->Build(context, event);
    if (buildStatus == AuthBuildStatus::TOO_LARGE) {
        Diagnose(AuthReason::PAYLOAD_TOO_LARGE);
        return { DragAuthDecision::DENY, AuthReason::PAYLOAD_TOO_LARGE };
    }
    if (buildStatus == AuthBuildStatus::INVALID_ENCODING) {
        Diagnose(AuthReason::INVALID_PAYLOAD);
        return { DragAuthDecision::DENY, AuthReason::INVALID_PAYLOAD };
    }
    if (buildStatus != AuthBuildStatus::SUCCESS) {
        Diagnose(AuthReason::EVENT_BUILD_FAILED);
        return { DragAuthDecision::ALLOW, AuthReason::EVENT_BUILD_FAILED };
    }
    return AuthorizeEvent(event, snapshot);
}

DragAuthResult DragAuthCoordinator::AuthorizeEvent(const DragAuthEvent &event, const ClientPolicySnapshot &snapshot)
{
    const auto policy = snapshot.Resolve(event.eventId);
    auto subscribers = snapshot.policies.find(event.eventId);
    AuthDiagnosticInfo info{ event.eventId, policy.snapshotVersion,
        subscribers == snapshot.policies.end() ? 0 : subscribers->second.size(), policy.watchdog.count(), 0,
        policy.fallback };
    if (policy.defaultApplied) {
        Diagnose(AuthReason::INVALID_CLIENT_TIMEOUT_POLICY, info);
    }
    auto permit = limiter_.TryAcquire();
    if (!permit) {
        Diagnose(AuthReason::CAPACITY_LIMIT, info);
        return { policy.fallback, AuthReason::CAPACITY_LIMIT };
    }
    return RequestAndWait(event, snapshot, policy, info);
}

void DragAuthCoordinator::CompleteRequest(const std::weak_ptr<TimedAuthRequest> &weakState,
    const SecurityGuardDelegate::Result &response, DragAuthDecision fallback, const AuthDiagnosticInfo &info)
{
    auto pending = weakState.lock();
    if (!pending) {
        Diagnose(AuthReason::LATE_RESULT_DROPPED, info);
        return;
    }
    if (response.dispatchStatus != DispatchStatus::DISPATCHED) {
        const auto reason = response.dispatchStatus == DispatchStatus::REJECTED ? AuthReason::REQUEST_REJECTED
                                                                                : AuthReason::PROVIDER_UNAVAILABLE;
        pending->TryComplete({ DragAuthDecision::ALLOW, reason });
        return;
    }
    const auto decision = response.mergedStrategy;
    DragAuthResult result{ decision, AuthReason::MERGED_RESULT };
    if (decision == DragAuthDecision::TIMEOUT) {
        result = { fallback, AuthReason::AUTH_RESULT_TIMEOUT };
    } else if (decision != DragAuthDecision::ALLOW && decision != DragAuthDecision::DENY) {
        result = { DragAuthDecision::ALLOW, AuthReason::INVALID_RESULT };
    }
    if (!pending->TryComplete(result, response)) {
        Diagnose(AuthReason::LATE_RESULT_DROPPED, info);
    }
}

DragAuthResult DragAuthCoordinator::RequestAndWait(DragAuthEvent event, const ClientPolicySnapshot &snapshot,
    const AuthTimeoutPolicy &policy, AuthDiagnosticInfo info)
{
    const auto healthRequest = degradation_->Prepare(snapshot, event.eventId);
    event.degradedClients = healthRequest.degradedClients;
    static std::atomic<uint64_t> nextRequestId{ 0 };
    info.requestId = nextRequestId.fetch_add(1) + 1;
    info.contentBytes = event.jsonContent.size();
    info.degradedCount = event.degradedClients.size();
    const auto started = std::chrono::steady_clock::now();
    const auto deadline = started + policy.watchdog;
    const DragAuthResult fallback{ policy.fallback, AuthReason::WATCHDOG_TIMEOUT };
    auto state = std::make_shared<TimedAuthRequest>(deadline, fallback);
    std::weak_ptr<TimedAuthRequest> weakState = state;
    event.deadline = deadline;
    auto status = delegate_->Request(event, [weakState, fallback = policy.fallback, info](const auto &response) {
        CompleteRequest(weakState, response, fallback, info);
    });
    if (status != DispatchStatus::DISPATCHED) {
        degradation_->Finish(healthRequest, {});
        if (status == DispatchStatus::BUSY) {
            Diagnose(AuthReason::CAPACITY_LIMIT, info);
            return { policy.fallback, AuthReason::CAPACITY_LIMIT };
        }
        const auto reason = status == DispatchStatus::REJECTED ? AuthReason::REQUEST_REJECTED
                                                               : AuthReason::PROVIDER_UNAVAILABLE;
        Diagnose(reason, info);
        return { DragAuthDecision::ALLOW, reason };
    }
    Diagnose(AuthReason::REQUEST_DISPATCHED, info);
    auto result = waiter_ ? waiter_(*state, deadline, fallback) : state->WaitUntil(deadline, fallback);
    degradation_->Finish(healthRequest,
        result.reason == AuthReason::MERGED_RESULT ? state->GetResponse() : SecurityGuardDelegate::Result{});
    info.elapsedMs =
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - started).count();
    if (result.decision == DragAuthDecision::DENY || result.reason != AuthReason::MERGED_RESULT) {
        Diagnose(result.reason, info);
    } else {
        Diagnose(AuthReason::RESULT_ALLOWED, info);
    }
    return result;
}
} // namespace OHOS::UDMF
