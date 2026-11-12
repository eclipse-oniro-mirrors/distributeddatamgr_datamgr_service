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

#include <gtest/gtest.h>

#include <future>
#include <iostream>
#include <thread>

#include "drag_auth_coordinator.h"
using namespace testing::ext;
namespace OHOS::UDMF {
class FakeSecurityGuardDelegate final : public SecurityGuardDelegate {
public:
    AdapterStatus Start() override
    {
        return AdapterStatus::READY;
    }
    bool IsReady() const override
    {
        return ready_;
    }
    SecurityGuardDelegate::ClientSnapshot GetClientSnapshot() const override
    {
        return snapshot_;
    }
    void Stop() override
    {
        ready_ = false;
    }
    DispatchStatus Request(const DragAuthEvent &, AuthCompletion completion) override
    {
        requests_++;
        saved_.push_back(completion);
        if (onRequest_) {
            onRequest_();
        }
        if (respond_) {
            completion({ result_, {} });
        }
        return dispatch_;
    }
    bool ready_ = true;
    bool respond_ = true;
    int requests_ = 0;
    ClientPolicySnapshot snapshot_;
    DragAuthDecision result_ = DragAuthDecision::ALLOW;
    DispatchStatus dispatch_ = DispatchStatus::DISPATCHED;
    std::vector<AuthCompletion> saved_;
    std::function<void()> onRequest_;
};
class UdmfAuthTimeoutTest : public testing::Test {
public:
    std::shared_ptr<const AuthEventBuilder> Builder()
    {
        return std::make_shared<AuthEventBuilder>(AuthEventContract{
            11, "test-only", 64, [](const DragAuthContext &, DistributedData::Serializable::json &node) {
                node["test"] = 1;
                return AuthBuildStatus::SUCCESS;
            } });
    }
    DragAuthContext Context()
    {
        DragAuthContext context;
        context.crossApplication = true;
        return context;
    }
};
/**
 * @tc.name: Resolve_UnknownAndInvalid_UsesWholeStageDefault
 * @tc.desc: Verify authorization behavior through public interfaces.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfAuthTimeoutTest, Resolve_UnknownAndInvalid_UsesWholeStageDefault, TestSize.Level1)
{
    ClientPolicySnapshot snapshot;
    EXPECT_TRUE(snapshot.HasSubscribers(11));
    EXPECT_EQ(snapshot.Resolve(11).watchdog.count(), 500);
    EXPECT_EQ(snapshot.Resolve(12).watchdog.count(), 500);
    snapshot.initialized = true;
    snapshot.version = 7;
    EXPECT_FALSE(snapshot.HasSubscribers(11));
    for (auto timeout : { 0, 401 }) {
        snapshot.policies[11] = { { DragAuthDecision::ALLOW, 400 }, { DragAuthDecision::DENY, timeout } };
        auto policy = snapshot.Resolve(11);
        EXPECT_TRUE(policy.defaultApplied);
        EXPECT_EQ(policy.fallback, DragAuthDecision::DENY);
        EXPECT_EQ(policy.watchdog.count(), 500);
        EXPECT_EQ(policy.snapshotVersion, 7u);
    }
    for (auto strategy : { DragAuthDecision::TIMEOUT, DragAuthDecision::ERROR }) {
        snapshot.policies[12] = { { strategy, 400 } };
        EXPECT_TRUE(snapshot.Resolve(12).defaultApplied);
    }
}
/**
 * @tc.name: Resolve_MultipleClients_AnyDenyAndMaximumTimeout
 * @tc.desc: Verify authorization behavior through public interfaces.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfAuthTimeoutTest, Resolve_MultipleClients_AnyDenyAndMaximumTimeout, TestSize.Level1)
{
    ClientPolicySnapshot snapshot;
    snapshot.initialized = true;
    snapshot.policies[11] = { { DragAuthDecision::ALLOW, 1 }, { DragAuthDecision::ALLOW, 400 } };
    auto policy = snapshot.Resolve(11);
    EXPECT_EQ(policy.fallback, DragAuthDecision::ALLOW);
    EXPECT_EQ(policy.watchdog.count(), 500);
    EXPECT_FALSE(policy.defaultApplied);
    snapshot.policies[11][0].strategy = DragAuthDecision::DENY;
    EXPECT_EQ(snapshot.Resolve(11).fallback, DragAuthDecision::DENY);
}
/**
 * @tc.name: Complete_ResultAndExpiredDeadline_ExactlyOneTerminal
 * @tc.desc: Verify authorization behavior through public interfaces.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfAuthTimeoutTest, Complete_ResultAndExpiredDeadline_ExactlyOneTerminal, TestSize.Level1)
{
    TimedAuthRequest request;
    EXPECT_TRUE(request.TryComplete({ DragAuthDecision::ALLOW, AuthReason::MERGED_RESULT }));
    EXPECT_FALSE(request.TryComplete({ DragAuthDecision::DENY, AuthReason::MERGED_RESULT }));
    auto result = request.WaitUntil(std::chrono::steady_clock::now() - std::chrono::milliseconds(1),
        { DragAuthDecision::DENY, AuthReason::WATCHDOG_TIMEOUT });
    EXPECT_EQ(result.decision, DragAuthDecision::ALLOW);
    TimedAuthRequest expired;
    result = expired.WaitUntil(std::chrono::steady_clock::now() - std::chrono::milliseconds(1),
        { DragAuthDecision::DENY, AuthReason::WATCHDOG_TIMEOUT });
    EXPECT_EQ(result.reason, AuthReason::WATCHDOG_TIMEOUT);
    EXPECT_FALSE(expired.TryComplete({ DragAuthDecision::ALLOW, AuthReason::MERGED_RESULT }));
}
/**
 * @tc.name: Complete_DeadlineRace1000Rounds_NoDoubleCompletion
 * @tc.desc: Verify authorization behavior through public interfaces.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfAuthTimeoutTest, Complete_DeadlineRace1000Rounds_NoDoubleCompletion, TestSize.Level1)
{
    for (int round = 0; round < 1000; round++) {
        TimedAuthRequest request;
        std::promise<void> release;
        auto barrier = release.get_future().share();
        auto callback = std::async(std::launch::async, [&] {
            barrier.wait();
            return request.TryComplete({ DragAuthDecision::ALLOW, AuthReason::MERGED_RESULT });
        });
        release.set_value();
        auto result = request.WaitUntil(
            std::chrono::steady_clock::now(), { DragAuthDecision::DENY, AuthReason::WATCHDOG_TIMEOUT });
        const auto callbackWon = callback.get();
        EXPECT_EQ(result.decision, callbackWon ? DragAuthDecision::ALLOW : DragAuthDecision::DENY);
        EXPECT_FALSE(request.TryComplete({ DragAuthDecision::ALLOW, AuthReason::MERGED_RESULT }));
    }
}
/**
 * @tc.name: Limiter_EightPlusOne_ReleaseRestoresCapacity
 * @tc.desc: Verify authorization behavior through public interfaces.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfAuthTimeoutTest, Limiter_EightPlusOne_ReleaseRestoresCapacity, TestSize.Level1)
{
    PendingAuthLimiter limiter;
    std::vector<std::unique_ptr<PendingAuthLimiter::Permit>> permits;
    for (int i = 0; i < 8; i++) {
        auto permit = limiter.TryAcquire();
        ASSERT_NE(permit, nullptr);
        permits.push_back(std::move(permit));
    }
    EXPECT_EQ(limiter.TryAcquire(), nullptr);
    EXPECT_EQ(limiter.PendingCount(), 8u);
    permits.pop_back();
    EXPECT_NE(limiter.TryAcquire(), nullptr);
}
/**
 * @tc.name: Authorize_FastMergedResults_PreserveOrMapInvalid
 * @tc.desc: Verify authorization behavior through public interfaces.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfAuthTimeoutTest, Authorize_FastMergedResults_PreserveOrMapInvalid, TestSize.Level1)
{
    auto adapter = std::make_shared<FakeSecurityGuardDelegate>();
    DragAuthCoordinator coordinator(adapter.get(), Builder());
    for (auto decision : { DragAuthDecision::ALLOW, DragAuthDecision::DENY, DragAuthDecision::ERROR }) {
        adapter->result_ = decision;
        auto result = coordinator.Authorize(Context());
        EXPECT_EQ(result.decision, decision == DragAuthDecision::ERROR ? DragAuthDecision::ALLOW : decision);
    }
    EXPECT_EQ(adapter->requests_, 3);
    adapter->respond_ = false;
    adapter->dispatch_ = DispatchStatus::REJECTED;
    EXPECT_EQ(coordinator.Authorize(Context()).reason, AuthReason::REQUEST_REJECTED);
    adapter->dispatch_ = DispatchStatus::UNAVAILABLE;
    EXPECT_EQ(coordinator.Authorize(Context()).reason, AuthReason::PROVIDER_UNAVAILABLE);
}
/**
 * @tc.name: Authorize_ImmediateFaultOrSkip_DoesNotDispatch
 * @tc.desc: Verify authorization behavior through public interfaces.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfAuthTimeoutTest, Authorize_ImmediateFaultOrSkip_DoesNotDispatch, TestSize.Level1)
{
    auto adapter = std::make_shared<FakeSecurityGuardDelegate>();
    DragAuthCoordinator coordinator(adapter.get(), Builder());
    auto context = Context();
    context.crossApplication = false;
    EXPECT_EQ(coordinator.Authorize(context).reason, AuthReason::SKIPPED);
    adapter->ready_ = false;
    EXPECT_EQ(coordinator.Authorize(Context()).reason, AuthReason::PROVIDER_UNAVAILABLE);
    adapter->ready_ = true;
    EXPECT_EQ(DragAuthCoordinator(adapter.get()).Authorize(Context()).reason, AuthReason::EVENT_BUILD_FAILED);
    EXPECT_EQ(DragAuthCoordinator(adapter.get(), nullptr).Authorize(Context()).reason, AuthReason::EVENT_BUILD_FAILED);
    EXPECT_EQ(DragAuthCoordinator(nullptr, Builder()).Authorize(Context()).reason, AuthReason::PROVIDER_UNAVAILABLE);
    adapter->snapshot_.initialized = true;
    EXPECT_EQ(coordinator.Authorize(Context()).reason, AuthReason::SKIPPED);
    EXPECT_EQ(adapter->requests_, 0);
}
/**
 * @tc.name: Authorize_TimeoutCallback_FrozenFallbackAndNoWait
 * @tc.desc: Verify authorization behavior through public interfaces.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfAuthTimeoutTest, Authorize_TimeoutCallback_FrozenFallbackAndNoWait, TestSize.Level1)
{
    auto adapter = std::make_shared<FakeSecurityGuardDelegate>();
    adapter->snapshot_.initialized = true;
    adapter->snapshot_.version = 1;
    adapter->snapshot_.policies[11] = { { DragAuthDecision::DENY, 100 } };
    adapter->onRequest_ = [&] { adapter->snapshot_.policies[11][0].strategy = DragAuthDecision::ALLOW; };
    adapter->result_ = DragAuthDecision::TIMEOUT;
    DragAuthCoordinator coordinator(adapter.get(), Builder());
    auto begin = std::chrono::steady_clock::now();
    auto first = coordinator.Authorize(Context());
    EXPECT_EQ(first.decision, DragAuthDecision::DENY);
    EXPECT_EQ(first.reason, AuthReason::AUTH_RESULT_TIMEOUT);
    EXPECT_LT(std::chrono::steady_clock::now() - begin, std::chrono::milliseconds(100));
    EXPECT_EQ(coordinator.Authorize(Context()).decision, DragAuthDecision::ALLOW);
    adapter->saved_[0]({ DragAuthDecision::ALLOW, {} });
}
/**
 * @tc.name: Authorize_NoCallback_DeadlineAndLateResultSafe
 * @tc.desc: Verify authorization behavior through public interfaces.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfAuthTimeoutTest, Authorize_NoCallback_DeadlineAndLateResultSafe, TestSize.Level1)
{
    auto adapter = std::make_shared<FakeSecurityGuardDelegate>();
    adapter->respond_ = false;
    adapter->snapshot_.initialized = true;
    adapter->snapshot_.policies[11] = { { DragAuthDecision::DENY, 100 } };
    DragAuthCoordinator coordinator(adapter.get(), Builder());
    const auto begin = std::chrono::steady_clock::now();
    auto result = coordinator.Authorize(Context());
    const auto elapsed = std::chrono::steady_clock::now() - begin;
    EXPECT_EQ(result.decision, DragAuthDecision::DENY);
    EXPECT_EQ(result.reason, AuthReason::WATCHDOG_TIMEOUT);
    EXPECT_GE(elapsed, std::chrono::milliseconds(200));
    EXPECT_LE(elapsed, std::chrono::milliseconds(250));
    adapter->saved_[0]({ DragAuthDecision::ALLOW, {} });
    adapter->respond_ = true;
    EXPECT_EQ(coordinator.Authorize(Context()).decision, DragAuthDecision::ALLOW);
}
/**
 * @tc.name: Authorize_NinthNestedRequest_NoDispatchAndPermitRecovered
 * @tc.desc: Verify authorization behavior through public interfaces.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfAuthTimeoutTest, Authorize_NinthNestedRequest_NoDispatchAndPermitRecovered, TestSize.Level1)
{
    auto adapter = std::make_shared<FakeSecurityGuardDelegate>();
    DragAuthCoordinator coordinator(adapter.get(), Builder());
    int depth = 0;
    DragAuthResult ninth;
    adapter->onRequest_ = [&] {
        depth++;
        auto nested = coordinator.Authorize(Context());
        if (depth == 8) {
            ninth = nested;
        }
        depth--;
    };
    EXPECT_EQ(coordinator.Authorize(Context()).decision, DragAuthDecision::ALLOW);
    EXPECT_EQ(adapter->requests_, 8);
    EXPECT_EQ(ninth.reason, AuthReason::CAPACITY_LIMIT);
    EXPECT_EQ(ninth.decision, DragAuthDecision::DENY);
    adapter->onRequest_ = {};
    EXPECT_EQ(coordinator.Authorize(Context()).decision, DragAuthDecision::ALLOW);
    EXPECT_EQ(adapter->requests_, 9);
}
/**
 * @tc.name: Authorize_InjectedWait_UsesFrozenStageDeadlines
 * @tc.desc: Verify authorization behavior through public interfaces.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfAuthTimeoutTest, Authorize_InjectedWait_UsesFrozenStageDeadlines, TestSize.Level1)
{
    auto adapter = std::make_shared<FakeSecurityGuardDelegate>();
    adapter->respond_ = false;
    std::vector<int64_t> deadlines;
    auto wait = [&](TimedAuthRequest &request, std::chrono::steady_clock::time_point deadline,
                    DragAuthResult fallback) {
        const auto remaining =
            std::chrono::duration_cast<std::chrono::milliseconds>(deadline - std::chrono::steady_clock::now()).count();
        deadlines.push_back(remaining);
        return request.WaitUntil(std::chrono::steady_clock::now() - std::chrono::milliseconds(1), fallback);
    };
    DragAuthCoordinator coordinator(adapter.get(), Builder(), wait);
    EXPECT_EQ(coordinator.Authorize(Context()).decision, DragAuthDecision::DENY);
    EXPECT_EQ(coordinator.Authorize(Context()).decision, DragAuthDecision::DENY);
    adapter->snapshot_.initialized = true;
    adapter->snapshot_.policies[11] = { { DragAuthDecision::ALLOW, 100 } };
    EXPECT_EQ(coordinator.Authorize(Context()).decision, DragAuthDecision::ALLOW);
    ASSERT_EQ(deadlines.size(), 3u);
    EXPECT_GE(deadlines[0], 450);
    EXPECT_LE(deadlines[0], 500);
    EXPECT_GE(deadlines[1], 450);
    EXPECT_LE(deadlines[1], 500);
    EXPECT_GE(deadlines[2], 150);
    EXPECT_LE(deadlines[2], 200);
}
/**
 * @tc.name: Authorize_EightConcurrentWaiters_NinthDoesNotDispatch
 * @tc.desc: Verify authorization behavior through public interfaces.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfAuthTimeoutTest, Authorize_EightConcurrentWaiters_NinthDoesNotDispatch, TestSize.Level1)
{
    std::mutex mutex;
    std::condition_variable condition;
    int pending = 0;
    bool release = false;
    auto waiter = [&](TimedAuthRequest &request, std::chrono::steady_clock::time_point, DragAuthResult fallback) {
        std::unique_lock<std::mutex> lock(mutex);
        pending++;
        condition.notify_all();
        condition.wait(lock, [&] { return release; });
        lock.unlock();
        return request.WaitUntil(std::chrono::steady_clock::now() - std::chrono::milliseconds(1), fallback);
    };
    std::vector<std::future<DragAuthResult>> requests;
    for (int i = 0; i < 8; i++) {
        requests.push_back(std::async(std::launch::async, [&] {
            auto adapter = std::make_shared<FakeSecurityGuardDelegate>();
            adapter->respond_ = false;
            return DragAuthCoordinator(adapter.get(), Builder(), waiter).Authorize(Context());
        }));
    }
    bool allWaiting;
    {
        std::unique_lock<std::mutex> lock(mutex);
        allWaiting = condition.wait_for(lock, std::chrono::seconds(5), [&] { return pending == 8; });
    }
    auto ninthAdapter = std::make_shared<FakeSecurityGuardDelegate>();
    auto ninth = DragAuthCoordinator(ninthAdapter.get(), Builder()).Authorize(Context());
    {
        std::lock_guard<std::mutex> lock(mutex);
        release = true;
    }
    condition.notify_all();
    for (auto &request : requests) {
        EXPECT_EQ(request.get().reason, AuthReason::WATCHDOG_TIMEOUT);
    }
    EXPECT_TRUE(allWaiting);
    EXPECT_EQ(ninth.reason, AuthReason::CAPACITY_LIMIT);
    EXPECT_EQ(ninthAdapter->requests_, 0);
    EXPECT_EQ(
        DragAuthCoordinator(ninthAdapter.get(), Builder()).Authorize(Context()).decision, DragAuthDecision::ALLOW);
    EXPECT_EQ(ninthAdapter->requests_, 1);
}
/**
 * @tc.name: Authorize_RealDefaultAndMaximumDeadlines_ReturnWithinTolerance
 * @tc.desc: Verify authorization behavior through public interfaces.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfAuthTimeoutTest, Authorize_RealDefaultAndMaximumDeadlines_ReturnWithinTolerance, TestSize.Level2)
{
    {
        auto adapter = std::make_shared<FakeSecurityGuardDelegate>();
        adapter->respond_ = false;
        const int64_t expected = 500;
        const auto begin = std::chrono::steady_clock::now();
        auto result = DragAuthCoordinator(adapter.get(), Builder()).Authorize(Context());
        auto elapsed =
            std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - begin).count();
        std::cout << "default deadline=" << expected << "ms elapsed=" << elapsed << "ms" << std::endl;
        EXPECT_EQ(result.decision, DragAuthDecision::DENY);
        EXPECT_GE(elapsed, expected);
        EXPECT_LE(elapsed, expected + 50);
    }
    auto adapter = std::make_shared<FakeSecurityGuardDelegate>();
    adapter->respond_ = false;
    adapter->snapshot_.initialized = true;
    adapter->snapshot_.policies[11] = { { DragAuthDecision::ALLOW, 400 } };
    const auto begin = std::chrono::steady_clock::now();
    auto result = DragAuthCoordinator(adapter.get(), Builder()).Authorize(Context());
    auto elapsed =
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - begin).count();
    std::cout << "maximum deadline=500ms elapsed=" << elapsed << "ms" << std::endl;
    EXPECT_EQ(result.decision, DragAuthDecision::ALLOW);
    EXPECT_GE(elapsed, 500);
    EXPECT_LE(elapsed, 550);
}
/**
 * @tc.name: Authorize_InlineDuplicateCallbacks_FirstResultWins
 * @tc.desc: Verify authorization behavior through public interfaces.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfAuthTimeoutTest, Authorize_InlineDuplicateCallbacks_FirstResultWins, TestSize.Level1)
{
    auto adapter = std::make_shared<FakeSecurityGuardDelegate>();
    adapter->onRequest_ = [&] {
        auto complete = adapter->saved_.back();
        complete({ DragAuthDecision::DENY, {} });
        complete({ DragAuthDecision::ALLOW, {} });
    };
    DragAuthCoordinator coordinator(adapter.get(), Builder());
    auto result = coordinator.Authorize(Context());
    EXPECT_EQ(result.decision, DragAuthDecision::DENY);
    EXPECT_EQ(adapter->requests_, 1);
    adapter->saved_.front()({ DragAuthDecision::ALLOW, {} });
    adapter->onRequest_ = {};
    EXPECT_EQ(coordinator.Authorize(Context()).decision, DragAuthDecision::ALLOW);
    EXPECT_EQ(adapter->requests_, 2);
}
/**
 * @tc.name: Authorize_OverLimit_DeniesWithoutDispatchOrWait
 * @tc.desc: Verify the receiver-side event contract through public interfaces.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfAuthTimeoutTest, Authorize_OverLimit_DeniesWithoutDispatchOrWait, TestSize.Level1)
{
    auto adapter = std::make_shared<FakeSecurityGuardDelegate>();
    AuthEventContract contract;
    contract.encode = [](const DragAuthContext &, DistributedData::Serializable::json &content) {
        content["text"] = std::string(10240, 'x');
        return AuthBuildStatus::SUCCESS;
    };
    bool waited = false;
    auto waiter = [&waited](TimedAuthRequest &, auto, DragAuthResult fallback) {
        waited = true;
        return fallback;
    };
    auto builder = std::make_shared<AuthEventBuilder>(contract);
    auto result = DragAuthCoordinator(adapter.get(), builder, waiter).Authorize(Context());
    EXPECT_EQ(result.decision, DragAuthDecision::DENY);
    EXPECT_EQ(result.reason, AuthReason::PAYLOAD_TOO_LARGE);
    EXPECT_EQ(adapter->requests_, 0);
    EXPECT_FALSE(waited);
    EXPECT_EQ(DragAuthCoordinator(adapter.get(), Builder()).Authorize(Context()).decision, DragAuthDecision::ALLOW);
}
} // namespace OHOS::UDMF
