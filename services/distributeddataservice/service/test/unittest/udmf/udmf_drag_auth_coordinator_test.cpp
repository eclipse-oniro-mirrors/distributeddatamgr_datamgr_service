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

#include "drag_auth_coordinator.h"

using namespace testing::ext;
namespace OHOS::UDMF {
namespace {
constexpr int64_t EVENT_ID = INT64_C(0x0F810000);
class RecordingGuardDelegate final : public SecurityGuardDelegate {
public:
    Status Start() override
    {
        return Status::READY;
    }
    bool IsReady() const override
    {
        return ready_;
    }
    ClientSnapshot GetClientSnapshot() const override
    {
        ++snapshots_;
        return snapshot_;
    }
    void Stop() override
    {
        ready_ = false;
    }
    DispatchStatus Request(const Event &event, Completion completion) override
    {
        ++requests_;
        events_.push_back(event);
        saved_ = completion;
        if (onRequest_) {
            onRequest_(completion);
        } else {
            completion({ result_, clients_ });
        }
        return dispatch_;
    }
    bool ready_ = true;
    mutable int snapshots_ = 0;
    int requests_ = 0;
    ClientSnapshot snapshot_;
    Strategy result_ = Strategy::ALLOW;
    std::vector<ClientResult> clients_;
    DispatchStatus dispatch_ = DispatchStatus::DISPATCHED;
    Completion saved_;
    std::function<void(Completion)> onRequest_;
    std::vector<Event> events_;
};
std::shared_ptr<const AuthEventBuilder> MakeCoordinatorBuilder(AuthBuildStatus status = AuthBuildStatus::SUCCESS)
{
    AuthEventContract contract;
    contract.encode = [status](const DragAuthContext &context, DistributedData::Serializable::json &node) {
        node["source"] = context.sourceTokenId;
        node["target"] = context.targetTokenId;
        return status;
    };
    return std::make_shared<AuthEventBuilder>(std::move(contract));
}
DragAuthContext MakeCoordinatorContext()
{
    return { true, 17, 19, nullptr };
}
} // namespace
class UdmfDragAuthCoordinatorTest : public testing::Test {};
/**
 * @tc.name: Authorize_NotCrossApplication_SkipsEveryDependency
 * @tc.desc: Verify the public contract and observable side effects for this branch.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfDragAuthCoordinatorTest, Authorize_NotCrossApplication_SkipsEveryDependency, TestSize.Level1)
{
    RecordingGuardDelegate delegate;
    auto context = MakeCoordinatorContext();
    context.crossApplication = false;
    auto result = DragAuthCoordinator(&delegate, nullptr).Authorize(context);
    EXPECT_EQ(result.decision, DragAuthDecision::ALLOW);
    EXPECT_EQ(result.reason, AuthReason::SKIPPED);
    EXPECT_EQ(delegate.snapshots_, 0);
    EXPECT_EQ(delegate.requests_, 0);
}
/**
 * @tc.name: Authorize_UnavailableProvider_DoesNotReadSnapshotOrWait
 * @tc.desc: Verify the public contract and observable side effects for this branch.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfDragAuthCoordinatorTest, Authorize_UnavailableProvider_DoesNotReadSnapshotOrWait, TestSize.Level1)
{
    RecordingGuardDelegate delegate;
    delegate.ready_ = false;
    int waits = 0;
    auto wait = [&waits](TimedAuthRequest &, auto, DragAuthResult fallback) {
        ++waits;
        return fallback;
    };
    for (auto *provider :
        { static_cast<SecurityGuardDelegate *>(&delegate), static_cast<SecurityGuardDelegate *>(nullptr) }) {
        auto result =
            DragAuthCoordinator(provider, MakeCoordinatorBuilder(), wait).Authorize(MakeCoordinatorContext());
        EXPECT_EQ(result.decision, DragAuthDecision::ALLOW);
        EXPECT_EQ(result.reason, AuthReason::PROVIDER_UNAVAILABLE);
    }
    EXPECT_EQ(delegate.snapshots_, 0);
    EXPECT_EQ(delegate.requests_, 0);
    EXPECT_EQ(waits, 0);
}
/**
 * @tc.name: Authorize_KnownEmptySubscriptions_DoesNotEncodeOrDispatch
 * @tc.desc: Verify the public contract and observable side effects for this branch.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfDragAuthCoordinatorTest, Authorize_KnownEmptySubscriptions_DoesNotEncodeOrDispatch, TestSize.Level1)
{
    RecordingGuardDelegate delegate;
    delegate.snapshot_.initialized = true;
    delegate.snapshot_.policies[EVENT_ID] = {};
    int encodes = 0;
    AuthEventContract contract;
    contract.encode = [&encodes](const DragAuthContext &, auto &) {
        ++encodes;
        return AuthBuildStatus::TOO_LARGE;
    };
    auto builder = std::make_shared<AuthEventBuilder>(contract);
    auto result = DragAuthCoordinator(&delegate, builder).Authorize(MakeCoordinatorContext());
    EXPECT_EQ(result.reason, AuthReason::SKIPPED);
    EXPECT_EQ(result.decision, DragAuthDecision::ALLOW);
    EXPECT_EQ(encodes, 0);
    EXPECT_EQ(delegate.requests_, 0);
}
/**
 * @tc.name: Authorize_EncoderFailureAndOversize_HaveDifferentOutcomes
 * @tc.desc: Verify the public contract and observable side effects for this branch.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfDragAuthCoordinatorTest, Authorize_EncoderFailureAndOversize_HaveDifferentOutcomes, TestSize.Level1)
{
    RecordingGuardDelegate delegate;
    int waits = 0;
    auto wait = [&waits](TimedAuthRequest &, auto, DragAuthResult fallback) {
        ++waits;
        return fallback;
    };
    auto invalid = DragAuthCoordinator(&delegate, MakeCoordinatorBuilder(AuthBuildStatus::INVALID_DATA), wait)
                       .Authorize(MakeCoordinatorContext());
    auto oversized = DragAuthCoordinator(&delegate, MakeCoordinatorBuilder(AuthBuildStatus::TOO_LARGE), wait)
                         .Authorize(MakeCoordinatorContext());
    EXPECT_EQ(invalid.decision, DragAuthDecision::ALLOW);
    EXPECT_EQ(invalid.reason, AuthReason::EVENT_BUILD_FAILED);
    EXPECT_EQ(oversized.decision, DragAuthDecision::DENY);
    EXPECT_EQ(oversized.reason, AuthReason::PAYLOAD_TOO_LARGE);
    EXPECT_EQ(delegate.requests_, 0);
    EXPECT_EQ(waits, 0);
}
/**
 * @tc.name: Authorize_DispatchFailures_DoNotApplyTimeoutDeny
 * @tc.desc: Verify the public contract and observable side effects for this branch.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfDragAuthCoordinatorTest, Authorize_DispatchFailures_DoNotApplyTimeoutDeny, TestSize.Level1)
{
    RecordingGuardDelegate delegate;
    delegate.snapshot_.initialized = true;
    delegate.snapshot_.policies[EVENT_ID] = { { DragAuthDecision::DENY, 100 } };
    delegate.onRequest_ = [](auto) {};
    int waits = 0;
    auto wait = [&waits](TimedAuthRequest &, auto, DragAuthResult fallback) {
        ++waits;
        return fallback;
    };
    for (auto dispatch : { DispatchStatus::REJECTED, DispatchStatus::UNAVAILABLE }) {
        delegate.dispatch_ = dispatch;
        auto result =
            DragAuthCoordinator(&delegate, MakeCoordinatorBuilder(), wait).Authorize(MakeCoordinatorContext());
        EXPECT_EQ(result.decision, DragAuthDecision::ALLOW);
        EXPECT_EQ(result.reason,
            dispatch == DispatchStatus::REJECTED ? AuthReason::REQUEST_REJECTED : AuthReason::PROVIDER_UNAVAILABLE);
    }
    EXPECT_EQ(waits, 0);
    EXPECT_EQ(delegate.requests_, 2);
}
/**
 * @tc.name: Authorize_MergedDecision_OverridesOppositeDefaultPolicy
 * @tc.desc: Verify the public contract and observable side effects for this branch.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfDragAuthCoordinatorTest, Authorize_MergedDecision_OverridesOppositeDefaultPolicy, TestSize.Level1)
{
    RecordingGuardDelegate delegate;
    delegate.snapshot_.initialized = true;
    for (auto result : { DragAuthDecision::ALLOW, DragAuthDecision::DENY }) {
        delegate.result_ = result;
        delegate.snapshot_.policies[EVENT_ID] = {
            { result == DragAuthDecision::ALLOW ? DragAuthDecision::DENY : DragAuthDecision::ALLOW, 400 }
        };
        auto actual = DragAuthCoordinator(&delegate, MakeCoordinatorBuilder()).Authorize(MakeCoordinatorContext());
        EXPECT_EQ(actual.decision, result);
        EXPECT_EQ(actual.reason, AuthReason::MERGED_RESULT);
    }
    ASSERT_EQ(delegate.events_.size(), 2u);
    EXPECT_EQ(delegate.events_[0].eventId, EVENT_ID);
    EXPECT_EQ(delegate.events_[0].version, "1.0");
    auto content = DistributedData::Serializable::json::parse(delegate.events_[0].jsonContent);
    EXPECT_EQ(content["source"], 17);
    EXPECT_EQ(content["target"], 19);
}
/**
 * @tc.name: Authorize_InvalidMergedDecision_PreservesExistingFaultFallback
 * @tc.desc: Verify the public contract and observable side effects for this branch.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfDragAuthCoordinatorTest, Authorize_InvalidMergedDecision_PreservesExistingFaultFallback, TestSize.Level1)
{
    RecordingGuardDelegate delegate;
    for (auto strategy : { DragAuthDecision::ERROR, static_cast<DragAuthDecision>(99) }) {
        delegate.result_ = strategy;
        auto result = DragAuthCoordinator(&delegate, MakeCoordinatorBuilder()).Authorize(MakeCoordinatorContext());
        EXPECT_EQ(result.decision, DragAuthDecision::ALLOW);
        EXPECT_EQ(result.reason, AuthReason::INVALID_RESULT);
    }
    EXPECT_EQ(delegate.requests_, 2);
}
/**
 * @tc.name: Authorize_DuplicateInlineResults_KeepFirstDecision
 * @tc.desc: Verify the public contract and observable side effects for this branch.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfDragAuthCoordinatorTest, Authorize_DuplicateInlineResults_KeepFirstDecision, TestSize.Level1)
{
    RecordingGuardDelegate delegate;
    delegate.onRequest_ = [](auto complete) {
        complete({ DragAuthDecision::DENY, {} });
        complete({ DragAuthDecision::ALLOW, {} });
        complete({ DragAuthDecision::TIMEOUT, {} });
    };
    auto result = DragAuthCoordinator(&delegate, MakeCoordinatorBuilder()).Authorize(MakeCoordinatorContext());
    EXPECT_EQ(result.decision, DragAuthDecision::DENY);
    EXPECT_EQ(result.reason, AuthReason::MERGED_RESULT);
    EXPECT_EQ(delegate.requests_, 1);
}
/**
 * @tc.name: Authorize_LateResultAfterDeadline_DoesNotChangeNextRequest
 * @tc.desc: Verify the public contract and observable side effects for this branch.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfDragAuthCoordinatorTest, Authorize_LateResultAfterDeadline_DoesNotChangeNextRequest, TestSize.Level1)
{
    RecordingGuardDelegate delegate;
    delegate.onRequest_ = [](auto) {};
    auto wait = [](TimedAuthRequest &request, auto, DragAuthResult fallback) {
        return request.WaitUntil(std::chrono::steady_clock::now() - std::chrono::milliseconds(1), fallback);
    };
    auto first = DragAuthCoordinator(&delegate, MakeCoordinatorBuilder(), wait).Authorize(MakeCoordinatorContext());
    auto late = delegate.saved_;
    ASSERT_TRUE(static_cast<bool>(late));
    EXPECT_EQ(first.reason, AuthReason::WATCHDOG_TIMEOUT);
    EXPECT_EQ(first.decision, DragAuthDecision::DENY);
    delegate.onRequest_ = [late](auto current) {
        late({ DragAuthDecision::ALLOW, {} });
        current({ DragAuthDecision::DENY, {} });
    };
    auto next = DragAuthCoordinator(&delegate, MakeCoordinatorBuilder(), wait).Authorize(MakeCoordinatorContext());
    EXPECT_EQ(next.decision, DragAuthDecision::DENY);
    EXPECT_EQ(next.reason, AuthReason::MERGED_RESULT);
    EXPECT_EQ(delegate.requests_, 2);
}
/**
 * @tc.name: Authorize_CapacityWithAllowPolicy_DoesNotDispatchNinthRequest
 * @tc.desc: Verify the public contract and observable side effects for this branch.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfDragAuthCoordinatorTest, Authorize_CapacityWithAllowPolicy_DoesNotDispatchNinthRequest, TestSize.Level1)
{
    RecordingGuardDelegate delegate;
    delegate.snapshot_.initialized = true;
    delegate.snapshot_.policies[EVENT_ID] = { { DragAuthDecision::ALLOW, 100 } };
    int depth = 0;
    DragAuthResult ninth;
    DragAuthCoordinator coordinator(&delegate, MakeCoordinatorBuilder());
    delegate.onRequest_ = [&](auto complete) {
        ++depth;
        auto nested = coordinator.Authorize(MakeCoordinatorContext());
        if (depth == 8) {
            ninth = nested;
        }
        --depth;
        complete({ DragAuthDecision::DENY, {} });
    };
    auto result = coordinator.Authorize(MakeCoordinatorContext());
    EXPECT_EQ(result.decision, DragAuthDecision::DENY);
    EXPECT_EQ(ninth.reason, AuthReason::CAPACITY_LIMIT);
    EXPECT_EQ(ninth.decision, DragAuthDecision::ALLOW);
    EXPECT_EQ(delegate.requests_, 8);
    delegate.onRequest_ = [](auto complete) { complete({ DragAuthDecision::ALLOW, {} }); };
    EXPECT_EQ(coordinator.Authorize(MakeCoordinatorContext()).decision, DragAuthDecision::ALLOW);
    EXPECT_EQ(delegate.requests_, 9);
}
/**
 * @tc.name: Authorize_TimeoutAllowAndInvalidPolicy_UseTheirOwnFallback
 * @tc.desc: Verify the public contract and observable side effects for this branch.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfDragAuthCoordinatorTest, Authorize_TimeoutAllowAndInvalidPolicy_UseTheirOwnFallback, TestSize.Level1)
{
    RecordingGuardDelegate delegate;
    delegate.snapshot_.initialized = true;
    delegate.snapshot_.policies[EVENT_ID] = { { DragAuthDecision::ALLOW, 400 } };
    delegate.result_ = DragAuthDecision::TIMEOUT;
    DragAuthCoordinator coordinator(&delegate, MakeCoordinatorBuilder());
    auto allowed = coordinator.Authorize(MakeCoordinatorContext());
    EXPECT_EQ(allowed.decision, DragAuthDecision::ALLOW);
    EXPECT_EQ(allowed.reason, AuthReason::AUTH_RESULT_TIMEOUT);
    delegate.snapshot_.policies[EVENT_ID][0].timeoutMs = 401;
    auto denied = coordinator.Authorize(MakeCoordinatorContext());
    EXPECT_EQ(denied.decision, DragAuthDecision::DENY);
    EXPECT_EQ(denied.reason, AuthReason::AUTH_RESULT_TIMEOUT);
}
/**
 * @tc.name: TryComplete_AfterExpiredDeadline_CannotOverwriteFallback
 * @tc.desc: Verify the public contract and observable side effects for this branch.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfDragAuthCoordinatorTest, TryComplete_AfterExpiredDeadline_CannotOverwriteFallback, TestSize.Level1)
{
    TimedAuthRequest request;
    auto expired = request.WaitUntil(std::chrono::steady_clock::now() - std::chrono::milliseconds(1),
        { DragAuthDecision::DENY, AuthReason::WATCHDOG_TIMEOUT });
    EXPECT_FALSE(request.TryComplete({ DragAuthDecision::ALLOW, AuthReason::MERGED_RESULT }));
    auto repeated =
        request.WaitUntil(std::chrono::steady_clock::now(), { DragAuthDecision::ALLOW, AuthReason::MERGED_RESULT });
    EXPECT_EQ(expired.decision, DragAuthDecision::DENY);
    EXPECT_EQ(repeated.decision, expired.decision);
    EXPECT_EQ(repeated.reason, expired.reason);
}
/**
 * @tc.name: Authorize_ExplicitClientTimeouts_PassesDegradationWithoutOverridingOtherDeny
 * @tc.desc: Default ALLOW timeouts degrade only that session; another subscriber can still deny.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfDragAuthCoordinatorTest, Authorize_ExplicitClientTimeouts_PassesDegradationWithoutOverridingOtherDeny,
    TestSize.Level1)
{
    RecordingGuardDelegate delegate;
    delegate.snapshot_.initialized = true;
    delegate.snapshot_.version = 1;
    delegate.snapshot_.policies[EVENT_ID] = { { DragAuthDecision::ALLOW, 400, "slow" },
        { DragAuthDecision::DENY, 400, "required" } };
    delegate.clients_ = { { "slow", DragAuthDecision::TIMEOUT }, { "required", DragAuthDecision::DENY } };
    delegate.result_ = DragAuthDecision::DENY;
    DragAuthCoordinator coordinator(&delegate, MakeCoordinatorBuilder());
    for (unsigned i = 0; i < 4; ++i) {
        auto actual = coordinator.Authorize(MakeCoordinatorContext());
        EXPECT_EQ(actual.decision, DragAuthDecision::DENY);
        EXPECT_EQ(actual.reason, AuthReason::MERGED_RESULT);
    }
    ASSERT_EQ(delegate.events_.size(), 4u);
    EXPECT_TRUE(delegate.events_[2].degradedClients.empty());
    EXPECT_EQ(delegate.events_[3].degradedClients, std::vector<std::string>({ "slow" }));
}

/**
 * @tc.name: Authorize_DuplicateCallbacks_CountsOneHealthObservation
 * @tc.desc: One accepted request can contribute only one explicit client timeout.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfDragAuthCoordinatorTest, Authorize_DuplicateCallbacks_CountsOneHealthObservation, TestSize.Level1)
{
    RecordingGuardDelegate delegate;
    delegate.snapshot_.initialized = true;
    delegate.snapshot_.policies[EVENT_ID] = { { DragAuthDecision::ALLOW, 400, "slow" } };
    delegate.onRequest_ = [](auto complete) {
        for (unsigned i = 0; i < 3; ++i) {
            complete({ DragAuthDecision::ALLOW, { { "slow", DragAuthDecision::TIMEOUT } } });
        }
    };
    DragAuthCoordinator coordinator(&delegate, MakeCoordinatorBuilder());
    for (unsigned i = 0; i < 3; ++i) {
        EXPECT_EQ(coordinator.Authorize(MakeCoordinatorContext()).decision, DragAuthDecision::ALLOW);
    }
    ASSERT_EQ(delegate.events_.size(), 3u);
    EXPECT_TRUE(delegate.events_.back().degradedClients.empty());
    EXPECT_EQ(coordinator.Authorize(MakeCoordinatorContext()).decision, DragAuthDecision::ALLOW);
    EXPECT_EQ(delegate.events_.back().degradedClients, std::vector<std::string>({ "slow" }));
}

/**
 * @tc.name: Authorize_RejectedInlineCallback_DoesNotCountTimeout
 * @tc.desc: A callback accompanying synchronous rejection is not an admitted request observation.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfDragAuthCoordinatorTest, Authorize_RejectedInlineCallback_DoesNotCountTimeout, TestSize.Level1)
{
    RecordingGuardDelegate delegate;
    delegate.snapshot_.initialized = true;
    delegate.snapshot_.policies[EVENT_ID] = { { DragAuthDecision::ALLOW, 400, "slow" } };
    delegate.clients_ = { { "slow", DragAuthDecision::TIMEOUT } };
    delegate.dispatch_ = DispatchStatus::REJECTED;
    DragAuthCoordinator coordinator(&delegate, MakeCoordinatorBuilder());
    for (unsigned i = 0; i < 4; ++i) {
        EXPECT_EQ(coordinator.Authorize(MakeCoordinatorContext()).reason, AuthReason::REQUEST_REJECTED);
        EXPECT_TRUE(delegate.events_.back().degradedClients.empty());
    }
    delegate.dispatch_ = DispatchStatus::DISPATCHED;
    EXPECT_EQ(coordinator.Authorize(MakeCoordinatorContext()).decision, DragAuthDecision::ALLOW);
    EXPECT_TRUE(delegate.events_.back().degradedClients.empty());
}

/**
 * @tc.name: Authorize_LateTimeoutAfterWatchdog_DoesNotDegradeSession
 * @tc.desc: A callback arriving after local completion cannot update subscriber health.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfDragAuthCoordinatorTest, Authorize_LateTimeoutAfterWatchdog_DoesNotDegradeSession, TestSize.Level1)
{
    RecordingGuardDelegate delegate;
    delegate.snapshot_.initialized = true;
    delegate.snapshot_.policies[EVENT_ID] = { { DragAuthDecision::ALLOW, 400, "slow" } };
    delegate.onRequest_ = [](auto) {};
    auto wait = [](TimedAuthRequest &request, auto, DragAuthResult fallback) {
        return request.WaitUntil(std::chrono::steady_clock::now() - std::chrono::milliseconds(1), fallback);
    };
    DragAuthCoordinator coordinator(&delegate, MakeCoordinatorBuilder(), wait);
    for (unsigned i = 0; i < 4; ++i) {
        EXPECT_EQ(coordinator.Authorize(MakeCoordinatorContext()).reason, AuthReason::WATCHDOG_TIMEOUT);
        delegate.saved_({ DragAuthDecision::ALLOW, { { "slow", DragAuthDecision::TIMEOUT } } });
        EXPECT_TRUE(delegate.events_.back().degradedClients.empty());
    }
}

/**
 * @tc.name: Authorize_RecoveryProbeDeny_RestoresSessionAndDeniesCurrentDrag
 * @tc.desc: A real deny probe response restores health while preserving the denied drag.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfDragAuthCoordinatorTest, Authorize_RecoveryProbeDeny_RestoresSessionAndDeniesCurrentDrag, TestSize.Level1)
{
    RecordingGuardDelegate delegate;
    delegate.snapshot_.initialized = true;
    delegate.snapshot_.policies[EVENT_ID] = { { DragAuthDecision::ALLOW, 400, "slow" } };
    delegate.clients_ = { { "slow", DragAuthDecision::TIMEOUT } };
    auto now = AuthDegradationPolicy::Clock::time_point(std::chrono::seconds(100));
    DragAuthCoordinator coordinator(
        &delegate, MakeCoordinatorBuilder(), {}, std::make_shared<AuthDegradationPolicy>([&] { return now; }));
    for (unsigned i = 0; i < 3; ++i) {
        EXPECT_EQ(coordinator.Authorize(MakeCoordinatorContext()).decision, DragAuthDecision::ALLOW);
    }
    EXPECT_EQ(coordinator.Authorize(MakeCoordinatorContext()).decision, DragAuthDecision::ALLOW);
    EXPECT_EQ(delegate.events_.back().degradedClients.size(), 1u);
    now += std::chrono::seconds(30);
    delegate.clients_[0].strategy = DragAuthDecision::DENY;
    delegate.result_ = DragAuthDecision::DENY;
    EXPECT_EQ(coordinator.Authorize(MakeCoordinatorContext()).decision, DragAuthDecision::DENY);
    EXPECT_TRUE(delegate.events_.back().degradedClients.empty());
    EXPECT_EQ(coordinator.Authorize(MakeCoordinatorContext()).decision, DragAuthDecision::DENY);
    EXPECT_TRUE(delegate.events_.back().degradedClients.empty());
}

/**
 * @tc.name: Authorize_ProbeRejected_ReleasesReservationAndCoolsDown
 * @tc.desc: Failed admission releases a recovery probe rather than leaving it permanently in flight.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfDragAuthCoordinatorTest, Authorize_ProbeRejected_ReleasesReservationAndCoolsDown, TestSize.Level1)
{
    RecordingGuardDelegate delegate;
    delegate.snapshot_.initialized = true;
    delegate.snapshot_.policies[EVENT_ID] = { { DragAuthDecision::ALLOW, 400, "slow" } };
    delegate.clients_ = { { "slow", DragAuthDecision::TIMEOUT } };
    auto now = AuthDegradationPolicy::Clock::time_point(std::chrono::seconds(100));
    DragAuthCoordinator coordinator(
        &delegate, MakeCoordinatorBuilder(), {}, std::make_shared<AuthDegradationPolicy>([&] { return now; }));
    for (unsigned i = 0; i < 3; ++i) {
        EXPECT_EQ(coordinator.Authorize(MakeCoordinatorContext()).decision, DragAuthDecision::ALLOW);
    }
    now += std::chrono::seconds(30);
    delegate.dispatch_ = DispatchStatus::REJECTED;
    EXPECT_EQ(coordinator.Authorize(MakeCoordinatorContext()).reason, AuthReason::REQUEST_REJECTED);
    EXPECT_TRUE(delegate.events_.back().degradedClients.empty());
    delegate.dispatch_ = DispatchStatus::DISPATCHED;
    EXPECT_EQ(coordinator.Authorize(MakeCoordinatorContext()).decision, DragAuthDecision::ALLOW);
    EXPECT_EQ(delegate.events_.back().degradedClients.size(), 1u);
    now += std::chrono::seconds(30);
    EXPECT_EQ(coordinator.Authorize(MakeCoordinatorContext()).decision, DragAuthDecision::ALLOW);
    EXPECT_TRUE(delegate.events_.back().degradedClients.empty());
}

/**
 * @tc.name: Authorize_ProviderUnavailable_ClearsPriorDegradation
 * @tc.desc: Explicit provider unavailability invalidates all prior health epochs.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfDragAuthCoordinatorTest, Authorize_ProviderUnavailable_ClearsPriorDegradation, TestSize.Level1)
{
    RecordingGuardDelegate delegate;
    delegate.snapshot_.initialized = true;
    delegate.snapshot_.policies[EVENT_ID] = { { DragAuthDecision::ALLOW, 400, "slow" } };
    delegate.clients_ = { { "slow", DragAuthDecision::TIMEOUT } };
    DragAuthCoordinator coordinator(&delegate, MakeCoordinatorBuilder());
    for (unsigned i = 0; i < 3; ++i) {
        EXPECT_EQ(coordinator.Authorize(MakeCoordinatorContext()).decision, DragAuthDecision::ALLOW);
    }
    delegate.ready_ = false;
    EXPECT_EQ(coordinator.Authorize(MakeCoordinatorContext()).reason, AuthReason::PROVIDER_UNAVAILABLE);
    delegate.ready_ = true;
    EXPECT_EQ(coordinator.Authorize(MakeCoordinatorContext()).decision, DragAuthDecision::ALLOW);
    EXPECT_TRUE(delegate.events_.back().degradedClients.empty());
}

/**
 * @tc.name: Diagnose_NewSampleReasonsAndInvalidEnum_PreserveDecisionBehavior
 * @tc.desc: Exercise bounded information diagnostics without changing authorization outcomes.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(
    UdmfDragAuthCoordinatorTest, Diagnose_NewSampleReasonsAndInvalidEnum_PreserveDecisionBehavior, TestSize.Level1)
{
    AuthDiagnosticInfo info;
    info.requestId = 42;
    info.eventId = EVENT_ID;
    info.contentBytes = 10;
    for (auto reason : { AuthReason::REQUEST_DISPATCHED, AuthReason::RESULT_ALLOWED, AuthReason::SAME_APP_SKIPPED,
             AuthReason::NO_SUBSCRIBERS, AuthReason::COUNT }) {
        DragAuthCoordinator::Diagnose(reason, info);
        DragAuthCoordinator::Diagnose(reason, info);
    }
    RecordingGuardDelegate delegate;
    DragAuthCoordinator coordinator(&delegate, MakeCoordinatorBuilder());
    EXPECT_EQ(coordinator.Authorize(MakeCoordinatorContext()).decision, DragAuthDecision::ALLOW);
    EXPECT_EQ(delegate.requests_, 1);
}

/**
 * @tc.name: Authorize_InvalidEncoding_FailsClosedWithoutSdk
 * @tc.desc: Lossy event encoding uses the existing invalid parameter path.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfDragAuthCoordinatorTest, Authorize_InvalidEncoding_FailsClosedWithoutSdk, TestSize.Level1)
{
    RecordingGuardDelegate delegate;
    auto result = DragAuthCoordinator(&delegate, MakeCoordinatorBuilder(AuthBuildStatus::INVALID_ENCODING))
                      .Authorize(MakeCoordinatorContext());
    EXPECT_EQ(result.decision, DragAuthDecision::DENY);
    EXPECT_EQ(result.reason, AuthReason::INVALID_PAYLOAD);
    EXPECT_EQ(delegate.requests_, 0);
}

/**
 * @tc.name: Authorize_AsyncAdmissionFailureAndBusy_UseExistingPolicies
 * @tc.desc: Accepted queue errors retain fail-open policy; saturated SDK dispatch uses the frozen fallback.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfDragAuthCoordinatorTest, Authorize_AsyncAdmissionFailureAndBusy_UseExistingPolicies, TestSize.Level1)
{
    RecordingGuardDelegate delegate;
    for (auto status : { DispatchStatus::REJECTED, DispatchStatus::UNAVAILABLE }) {
        delegate.onRequest_ = [status](auto callback) {
            SecurityGuardDelegate::Result response;
            response.dispatchStatus = status;
            callback(response);
        };
        auto result = DragAuthCoordinator(&delegate, MakeCoordinatorBuilder()).Authorize(MakeCoordinatorContext());
        EXPECT_EQ(result.decision, DragAuthDecision::ALLOW);
        EXPECT_EQ(result.reason,
            status == DispatchStatus::REJECTED ? AuthReason::REQUEST_REJECTED : AuthReason::PROVIDER_UNAVAILABLE);
    }
    delegate.dispatch_ = DispatchStatus::BUSY;
    auto result = DragAuthCoordinator(&delegate, MakeCoordinatorBuilder()).Authorize(MakeCoordinatorContext());
    EXPECT_EQ(result.decision, DragAuthDecision::DENY);
    EXPECT_EQ(result.reason, AuthReason::CAPACITY_LIMIT);
}

/**
 * @tc.name: TimedRequest_LateInlineAllow_UsesAbsoluteDeadline
 * @tc.desc: A callback that arrives before WaitUntil but after the deadline cannot allow delivery.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfDragAuthCoordinatorTest, TimedRequest_LateInlineAllow_UsesAbsoluteDeadline, TestSize.Level1)
{
    const auto deadline = std::chrono::steady_clock::now();
    DragAuthResult fallback{ DragAuthDecision::DENY, AuthReason::WATCHDOG_TIMEOUT };
    TimedAuthRequest request(deadline, fallback);
    EXPECT_FALSE(
        request.TryComplete({ DragAuthDecision::ALLOW, AuthReason::MERGED_RESULT }, { DragAuthDecision::ALLOW, {} }));
    auto result = request.WaitUntil(deadline, fallback);
    EXPECT_EQ(result.decision, DragAuthDecision::DENY);
    EXPECT_EQ(result.reason, AuthReason::WATCHDOG_TIMEOUT);
    EXPECT_TRUE(request.GetResponse().clients.empty());
    EXPECT_EQ(request.GetResponse().mergedStrategy, DragAuthDecision::ERROR);
}

} // namespace OHOS::UDMF
