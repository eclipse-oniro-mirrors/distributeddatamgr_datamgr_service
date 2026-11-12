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

#include <array>
#include <memory>
#include <thread>

#include "auth_degradation_policy.h"

using namespace testing::ext;
namespace OHOS::UDMF {
namespace {
constexpr int64_t EVENT_ID = 0x0F810000;
using Strategy = SecurityGuardDelegate::Strategy;
using GuardResult = SecurityGuardDelegate::Result;
ClientPolicySnapshot Snapshot()
{
    ClientPolicySnapshot snapshot;
    snapshot.initialized = true;
    snapshot.version = 1;
    snapshot.policies[EVENT_ID] = { { Strategy::ALLOW, 400, "client-a" } };
    return snapshot;
}
GuardResult Reply(Strategy strategy)
{
    return { Strategy::ALLOW, { { "client-a", strategy } } };
}
} // namespace
class UdmfAuthDegradationPolicyTest : public testing::Test {
public:
    void SetUp() override
    {
        snapshot_ = Snapshot();
        policy_ = std::make_unique<AuthDegradationPolicy>([this] { return now_; });
    }
    void Timeouts(unsigned count)
    {
        for (unsigned i = 0; i < count; ++i) {
            policy_->Finish(policy_->Prepare(snapshot_, EVENT_ID), Reply(Strategy::TIMEOUT));
        }
    }
    AuthDegradationPolicy::Clock::time_point now_{ std::chrono::seconds(100) };
    ClientPolicySnapshot snapshot_;
    std::unique_ptr<AuthDegradationPolicy> policy_;
};
/**
 * @tc.name: Prepare_ThreeTimeouts_DegradesOnlySubsequentRequests
 * @tc.desc: Three explicit timeout observations open the circuit for this subscriber.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfAuthDegradationPolicyTest, Prepare_ThreeTimeouts_DegradesOnlySubsequentRequests, TestSize.Level1)
{
    for (unsigned i = 0; i < 3; ++i) {
        auto request = policy_->Prepare(snapshot_, EVENT_ID);
        EXPECT_TRUE(request.degradedClients.empty());
        ASSERT_EQ(request.tickets.size(), 1u);
        policy_->Finish(request, Reply(Strategy::TIMEOUT));
    }
    auto next = policy_->Prepare(snapshot_, EVENT_ID);
    EXPECT_EQ(next.degradedClients, std::vector<std::string>({ "client-a" }));
    EXPECT_TRUE(next.tickets.empty());
}

/**
 * @tc.name: Finish_HealthyDecision_BreaksTimeoutStreak
 * @tc.desc: ALLOW and actual DENY both prove a response rather than a health failure.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfAuthDegradationPolicyTest, Finish_HealthyDecision_BreaksTimeoutStreak, TestSize.Level1)
{
    for (auto strategy : { Strategy::ALLOW, Strategy::DENY }) {
        Timeouts(2);
        policy_->Finish(policy_->Prepare(snapshot_, EVENT_ID), Reply(strategy));
        Timeouts(2);
        EXPECT_TRUE(policy_->Prepare(snapshot_, EVENT_ID).degradedClients.empty());
        policy_->Finish(policy_->Prepare(snapshot_, EVENT_ID), Reply(Strategy::ALLOW));
    }
}

/**
 * @tc.name: Finish_UnknownOrMissingResult_DoesNotAttributeFailure
 * @tc.desc: Missing, duplicate, unrelated and invalid merged results break an ambiguous streak.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfAuthDegradationPolicyTest, Finish_UnknownOrMissingResult_DoesNotAttributeFailure, TestSize.Level1)
{
    const std::vector<GuardResult> results = { {}, { Strategy::ALLOW, {} },
        { Strategy::ALLOW, { { "other", Strategy::TIMEOUT } } }, Reply(Strategy::ERROR),
        { Strategy::ERROR, { { "client-a", Strategy::TIMEOUT } } },
        { Strategy::ALLOW, { { "client-a", Strategy::TIMEOUT }, { "client-a", Strategy::TIMEOUT } } } };
    for (const auto &result : results) {
        Timeouts(2);
        policy_->Finish(policy_->Prepare(snapshot_, EVENT_ID), result);
        Timeouts(1);
        EXPECT_TRUE(policy_->Prepare(snapshot_, EVENT_ID).degradedClients.empty());
        policy_->Finish(policy_->Prepare(snapshot_, EVENT_ID), Reply(Strategy::ALLOW));
    }
}

/**
 * @tc.name: Prepare_CooldownBoundary_AdmitsExactlyOneProbe
 * @tc.desc: At thirty seconds one request probes while concurrent requests stay degraded.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfAuthDegradationPolicyTest, Prepare_CooldownBoundary_AdmitsExactlyOneProbe, TestSize.Level1)
{
    Timeouts(3);
    now_ += std::chrono::seconds(30) - std::chrono::milliseconds(1);
    EXPECT_EQ(policy_->Prepare(snapshot_, EVENT_ID).degradedClients.size(), 1u);
    now_ += std::chrono::milliseconds(1);
    auto probe = policy_->Prepare(snapshot_, EVENT_ID);
    EXPECT_TRUE(probe.degradedClients.empty());
    ASSERT_EQ(probe.tickets.size(), 1u);
    EXPECT_TRUE(probe.tickets.front().probe);
    EXPECT_EQ(policy_->Prepare(snapshot_, EVENT_ID).degradedClients.size(), 1u);
    policy_->Finish(probe, Reply(Strategy::ALLOW));
    auto healthy = policy_->Prepare(snapshot_, EVENT_ID);
    EXPECT_TRUE(healthy.degradedClients.empty());
    ASSERT_EQ(healthy.tickets.size(), 1u);
    EXPECT_FALSE(healthy.tickets.front().probe);
}

/**
 * @tc.name: Finish_ProbeDeny_RestoresParticipationWithoutChangingVerdict
 * @tc.desc: An actual deny is a healthy probe response and remains an SG deny.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfAuthDegradationPolicyTest, Finish_ProbeDeny_RestoresParticipationWithoutChangingVerdict, TestSize.Level1)
{
    Timeouts(3);
    now_ += std::chrono::seconds(30);
    auto probe = policy_->Prepare(snapshot_, EVENT_ID);
    policy_->Finish(probe, { Strategy::DENY, { { "client-a", Strategy::DENY } } });
    EXPECT_TRUE(policy_->Prepare(snapshot_, EVENT_ID).degradedClients.empty());
}

/**
 * @tc.name: Finish_ProbeTimeoutOrMissingResult_ReleasesProbeForNextCooldown
 * @tc.desc: An inconclusive probe must not leave a permanent probe reservation.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(
    UdmfAuthDegradationPolicyTest, Finish_ProbeTimeoutOrMissingResult_ReleasesProbeForNextCooldown, TestSize.Level1)
{
    Timeouts(3);
    for (const auto &response : std::vector<GuardResult>{ Reply(Strategy::TIMEOUT), {} }) {
        now_ += std::chrono::seconds(30);
        auto probe = policy_->Prepare(snapshot_, EVENT_ID);
        ASSERT_EQ(probe.tickets.size(), 1u);
        policy_->Finish(probe, response);
        EXPECT_EQ(policy_->Prepare(snapshot_, EVENT_ID).degradedClients.size(), 1u);
    }
    now_ += std::chrono::seconds(30);
    EXPECT_TRUE(policy_->Prepare(snapshot_, EVENT_ID).degradedClients.empty());
}

/**
 * @tc.name: Finish_TimeoutsOutsideWindow_StartsNewStreak
 * @tc.desc: Sixty seconds bounds the evidence window for consecutive timeouts.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfAuthDegradationPolicyTest, Finish_TimeoutsOutsideWindow_StartsNewStreak, TestSize.Level1)
{
    Timeouts(2);
    now_ += std::chrono::seconds(60) + std::chrono::milliseconds(1);
    Timeouts(1);
    EXPECT_TRUE(policy_->Prepare(snapshot_, EVENT_ID).degradedClients.empty());
    Timeouts(2);
    EXPECT_EQ(policy_->Prepare(snapshot_, EVENT_ID).degradedClients.size(), 1u);
}

/**
 * @tc.name: Finish_TimeoutsAtWindowBoundary_CountsCurrentStreak
 * @tc.desc: The sixty second boundary includes the oldest timeout.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfAuthDegradationPolicyTest, Finish_TimeoutsAtWindowBoundary_CountsCurrentStreak, TestSize.Level1)
{
    Timeouts(2);
    now_ += std::chrono::seconds(60);
    Timeouts(1);
    EXPECT_EQ(policy_->Prepare(snapshot_, EVENT_ID).degradedClients.size(), 1u);
}

/**
 * @tc.name: Prepare_DenyAndInvalidIdentity_NeverAutoDegrades
 * @tc.desc: Only unique named default ALLOW subscribers with legal timeouts are eligible.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfAuthDegradationPolicyTest, Prepare_DenyAndInvalidIdentity_NeverAutoDegrades, TestSize.Level1)
{
    snapshot_.policies[EVENT_ID] = { { Strategy::DENY, 400, "deny" }, { Strategy::ALLOW, 400, "" },
        { Strategy::ALLOW, 0, "short" }, { Strategy::ALLOW, 401, "long" }, { Strategy::ERROR, 400, "bad" },
        { Strategy::ALLOW, 400, "duplicate" }, { Strategy::DENY, 400, "duplicate" } };
    for (unsigned i = 0; i < 4; ++i) {
        auto request = policy_->Prepare(snapshot_, EVENT_ID);
        EXPECT_TRUE(request.tickets.empty());
        EXPECT_TRUE(request.degradedClients.empty());
        policy_->Finish(request, { Strategy::ALLOW, { { "deny", Strategy::TIMEOUT } } });
    }
}

/**
 * @tc.name: Prepare_ClientAndEventIsolation_DegradesOnlyMatchingSubscriber
 * @tc.desc: Event and session identity separate counters and degradation flags.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(
    UdmfAuthDegradationPolicyTest, Prepare_ClientAndEventIsolation_DegradesOnlyMatchingSubscriber, TestSize.Level1)
{
    snapshot_.policies[EVENT_ID].push_back({ Strategy::ALLOW, 100, "client-b" });
    snapshot_.policies[EVENT_ID + 1] = { { Strategy::ALLOW, 400, "client-a" } };
    Timeouts(3);
    auto request = policy_->Prepare(snapshot_, EVENT_ID);
    EXPECT_EQ(request.degradedClients, std::vector<std::string>({ "client-a" }));
    ASSERT_EQ(request.tickets.size(), 1u);
    EXPECT_EQ(request.tickets.front().clientId, "client-b");
    EXPECT_TRUE(policy_->Prepare(snapshot_, EVENT_ID + 1).degradedClients.empty());
}

/**
 * @tc.name: UpdateSnapshot_UnchangedClient_PreservesStateAcrossFullNotifications
 * @tc.desc: Unrelated full-list notifications do not clear valid degradation evidence.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfAuthDegradationPolicyTest, UpdateSnapshot_UnchangedClient_PreservesStateAcrossFullNotifications,
    TestSize.Level1)
{
    Timeouts(3);
    ++snapshot_.version;
    snapshot_.policies[EVENT_ID + 1] = { { Strategy::ALLOW, 400, "new" } };
    policy_->UpdateSnapshot(snapshot_);
    EXPECT_EQ(policy_->Prepare(snapshot_, EVENT_ID).degradedClients.size(), 1u);
}

/**
 * @tc.name: UpdateSnapshot_RemovedClient_DiscardsOldResultsAndHealth
 * @tc.desc: Removing then readding a subscriber starts fresh even if its identifier repeats.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfAuthDegradationPolicyTest, UpdateSnapshot_RemovedClient_DiscardsOldResultsAndHealth, TestSize.Level1)
{
    auto old = policy_->Prepare(snapshot_, EVENT_ID);
    Timeouts(3);
    auto empty = snapshot_;
    empty.policies.clear();
    ++empty.version;
    policy_->UpdateSnapshot(empty);
    snapshot_.version = empty.version + 1;
    policy_->Finish(old, Reply(Strategy::TIMEOUT));
    EXPECT_TRUE(policy_->Prepare(snapshot_, EVENT_ID).degradedClients.empty());
}

/**
 * @tc.name: UpdateSnapshot_PolicyChange_ResetsHealthAndInvalidatesInFlightResults
 * @tc.desc: A timeout policy change starts a new health epoch.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfAuthDegradationPolicyTest, UpdateSnapshot_PolicyChange_ResetsHealthAndInvalidatesInFlightResults,
    TestSize.Level1)
{
    auto old = policy_->Prepare(snapshot_, EVENT_ID);
    Timeouts(2);
    ++snapshot_.version;
    snapshot_.policies[EVENT_ID][0].timeoutMs = 399;
    policy_->UpdateSnapshot(snapshot_);
    policy_->Finish(old, Reply(Strategy::TIMEOUT));
    Timeouts(1);
    EXPECT_TRUE(policy_->Prepare(snapshot_, EVENT_ID).degradedClients.empty());
    snapshot_.policies[EVENT_ID][0].strategy = Strategy::DENY;
    policy_->UpdateSnapshot(snapshot_);
    EXPECT_TRUE(policy_->Prepare(snapshot_, EVENT_ID).tickets.empty());
}

/**
 * @tc.name: Prepare_StaleSnapshot_DoesNotReintroduceRemovedSubscriber
 * @tc.desc: An older concurrent snapshot cannot undo newer membership.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfAuthDegradationPolicyTest, Prepare_StaleSnapshot_DoesNotReintroduceRemovedSubscriber, TestSize.Level1)
{
    auto newer = snapshot_;
    newer.version = 2;
    newer.policies.clear();
    policy_->UpdateSnapshot(newer);
    auto stale = policy_->Prepare(snapshot_, EVENT_ID);
    EXPECT_TRUE(stale.tickets.empty());
    EXPECT_TRUE(stale.degradedClients.empty());
    EXPECT_TRUE(policy_->Prepare(newer, EVENT_ID).tickets.empty());
}

/**
 * @tc.name: Finish_DuplicateOrOutOfOrderResult_DoesNotCountTwice
 * @tc.desc: Every request contributes at most once and older requests cannot overwrite newer evidence.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfAuthDegradationPolicyTest, Finish_DuplicateOrOutOfOrderResult_DoesNotCountTwice, TestSize.Level1)
{
    auto old = policy_->Prepare(snapshot_, EVENT_ID);
    auto recent = policy_->Prepare(snapshot_, EVENT_ID);
    policy_->Finish(recent, Reply(Strategy::TIMEOUT));
    policy_->Finish(recent, Reply(Strategy::TIMEOUT));
    policy_->Finish(old, Reply(Strategy::TIMEOUT));
    Timeouts(1);
    EXPECT_TRUE(policy_->Prepare(snapshot_, EVENT_ID).degradedClients.empty());
    Timeouts(1);
    EXPECT_EQ(policy_->Prepare(snapshot_, EVENT_ID).degradedClients.size(), 1u);
}

/**
 * @tc.name: Finish_PreDegradationResult_DoesNotRecoverOpenCircuit
 * @tc.desc: Late normal responses cannot stand in for an explicit recovery probe.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfAuthDegradationPolicyTest, Finish_PreDegradationResult_DoesNotRecoverOpenCircuit, TestSize.Level1)
{
    auto old = policy_->Prepare(snapshot_, EVENT_ID);
    Timeouts(3);
    policy_->Finish(old, Reply(Strategy::ALLOW));
    EXPECT_EQ(policy_->Prepare(snapshot_, EVENT_ID).degradedClients.size(), 1u);
}

/**
 * @tc.name: Reset_ProviderUnavailable_InvalidatesOutstandingTickets
 * @tc.desc: Reset clears health but does not recycle ticket epochs.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfAuthDegradationPolicyTest, Reset_ProviderUnavailable_InvalidatesOutstandingTickets, TestSize.Level1)
{
    auto old = policy_->Prepare(snapshot_, EVENT_ID);
    Timeouts(3);
    policy_->Reset();
    auto fresh = policy_->Prepare(snapshot_, EVENT_ID);
    policy_->Finish(old, Reply(Strategy::TIMEOUT));
    EXPECT_TRUE(fresh.degradedClients.empty());
    Timeouts(1);
    EXPECT_TRUE(policy_->Prepare(snapshot_, EVENT_ID).degradedClients.empty());
}

/**
 * @tc.name: Prepare_UninitializedSnapshot_TracksNoSubscriber
 * @tc.desc: Unknown membership must not trigger proactive exclusions.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfAuthDegradationPolicyTest, Prepare_UninitializedSnapshot_TracksNoSubscriber, TestSize.Level1)
{
    Timeouts(3);
    snapshot_.initialized = false;
    ++snapshot_.version;
    auto unknown = policy_->Prepare(snapshot_, EVENT_ID);
    EXPECT_TRUE(unknown.tickets.empty());
    EXPECT_TRUE(unknown.degradedClients.empty());
}
/**
 * @tc.name: UpdateSnapshot_SameIdNewGeneration_DiscardsOldHealth
 * @tc.desc: An observed adapter generation change clears a hidden unsubscribe and resubscribe.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfAuthDegradationPolicyTest, UpdateSnapshot_SameIdNewGeneration_DiscardsOldHealth, TestSize.Level1)
{
    auto old = policy_->Prepare(snapshot_, EVENT_ID);
    Timeouts(3);
    ++snapshot_.version;
    ++snapshot_.policies[EVENT_ID][0].generation;
    policy_->UpdateSnapshot(snapshot_);
    policy_->Finish(old, Reply(Strategy::TIMEOUT));
    EXPECT_TRUE(policy_->Prepare(snapshot_, EVENT_ID).degradedClients.empty());
    Timeouts(2);
    EXPECT_TRUE(policy_->Prepare(snapshot_, EVENT_ID).degradedClients.empty());
}

/**
 * @tc.name: Prepare_ConcurrentRecoveryRequests_ReservesOneProbe
 * @tc.desc: Parallel requests reserve one recovery probe per subscriber session.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfAuthDegradationPolicyTest, Prepare_ConcurrentRecoveryRequests_ReservesOneProbe, TestSize.Level1)
{
    Timeouts(3);
    now_ += std::chrono::seconds(30);
    constexpr size_t REQUEST_COUNT = 8;
    std::array<AuthDegradationPolicy::Request, REQUEST_COUNT> requests;
    std::vector<std::thread> workers;
    for (size_t i = 0; i < REQUEST_COUNT; ++i) {
        workers.emplace_back([&, i] { requests[i] = policy_->Prepare(snapshot_, EVENT_ID); });
    }
    for (auto &worker : workers) {
        worker.join();
    }
    size_t probes = 0;
    size_t degraded = 0;
    for (const auto &request : requests) {
        probes += request.tickets.size();
        degraded += request.degradedClients.size();
        if (!request.tickets.empty()) {
            policy_->Finish(request, Reply(Strategy::ALLOW));
        }
    }
    EXPECT_EQ(probes, 1u);
    EXPECT_EQ(degraded, REQUEST_COUNT - 1);
    EXPECT_TRUE(policy_->Prepare(snapshot_, EVENT_ID).degradedClients.empty());
}
/**
 * @tc.name: Finish_ConcurrentDuplicateResults_UpdatesHealthOnce
 * @tc.desc: Concurrent duplicate completion attempts cannot consume multiple timeout counts.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfAuthDegradationPolicyTest, Finish_ConcurrentDuplicateResults_UpdatesHealthOnce, TestSize.Level1)
{
    auto request = policy_->Prepare(snapshot_, EVENT_ID);
    std::vector<std::thread> workers;
    for (unsigned i = 0; i < 8; ++i) {
        workers.emplace_back([&] { policy_->Finish(request, Reply(Strategy::TIMEOUT)); });
    }
    for (auto &worker : workers) {
        worker.join();
    }
    Timeouts(1);
    EXPECT_TRUE(policy_->Prepare(snapshot_, EVENT_ID).degradedClients.empty());
    Timeouts(1);
    EXPECT_EQ(policy_->Prepare(snapshot_, EVENT_ID).degradedClients.size(), 1u);
}

} // namespace OHOS::UDMF
