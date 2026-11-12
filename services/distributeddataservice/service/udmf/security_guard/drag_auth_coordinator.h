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

#ifndef UDMF_DRAG_AUTH_COORDINATOR_H
#define UDMF_DRAG_AUTH_COORDINATOR_H

#include <atomic>
#include <condition_variable>
#include <mutex>

#include "auth_degradation_policy.h"
#include "auth_event_builder.h"

namespace OHOS::UDMF {
class TimedAuthRequest {
public:
    explicit TimedAuthRequest(
        std::chrono::steady_clock::time_point deadline = std::chrono::steady_clock::time_point::max(),
        DragAuthResult fallback = {})
        : deadline_(deadline), fallback_(fallback)
    {
    }
    bool TryComplete(DragAuthResult result, const SecurityGuardDelegate::Result &response = {});
    SecurityGuardDelegate::Result GetResponse();
    DragAuthResult WaitUntil(std::chrono::steady_clock::time_point deadline, DragAuthResult fallback);

private:
    const std::chrono::steady_clock::time_point deadline_;
    const DragAuthResult fallback_;
    std::mutex mutex_;
    std::condition_variable condition_;
    bool completed_ = false;
    DragAuthResult result_;
    SecurityGuardDelegate::Result response_;
};

class PendingAuthLimiter {
public:
    class Permit {
    public:
        explicit Permit(std::atomic<uint32_t> &count) : count_(count)
        {
        }
        ~Permit()
        {
            count_.fetch_sub(1);
        }
        Permit(const Permit &) = delete;
        Permit &operator=(const Permit &) = delete;

    private:
        std::atomic<uint32_t> &count_;
    };
    std::unique_ptr<Permit> TryAcquire();
    uint32_t PendingCount() const;

private:
    std::atomic<uint32_t> count_{ 0 };
};

using AuthRequestWaiter =
    std::function<DragAuthResult(TimedAuthRequest &, std::chrono::steady_clock::time_point, DragAuthResult)>;

class DragAuthCoordinator {
public:
    explicit DragAuthCoordinator(SecurityGuardDelegate *delegate,
        std::shared_ptr<const AuthEventBuilder> builder = std::make_shared<AuthEventBuilder>(),
        AuthRequestWaiter waiter = {}, std::shared_ptr<AuthDegradationPolicy> degradation = {});
    DragAuthResult Authorize(const DragAuthContext &context);
    static void Diagnose(AuthReason reason, const AuthDiagnosticInfo &info = {});

private:
    DragAuthResult AuthorizeEvent(const DragAuthEvent &event, const ClientPolicySnapshot &snapshot);
    DragAuthResult RequestAndWait(DragAuthEvent event, const ClientPolicySnapshot &snapshot,
        const AuthTimeoutPolicy &policy, AuthDiagnosticInfo info);
    static void CompleteRequest(const std::weak_ptr<TimedAuthRequest> &weakState,
        const SecurityGuardDelegate::Result &response, DragAuthDecision fallback, const AuthDiagnosticInfo &info);
    SecurityGuardDelegate *delegate_ = nullptr;
    std::shared_ptr<const AuthEventBuilder> builder_;
    AuthRequestWaiter waiter_;
    std::shared_ptr<AuthDegradationPolicy> degradation_;
    static PendingAuthLimiter limiter_;
};
} // namespace OHOS::UDMF
#endif // UDMF_DRAG_AUTH_COORDINATOR_H
