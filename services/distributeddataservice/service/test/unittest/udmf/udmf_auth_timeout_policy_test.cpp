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

#include <limits>

#include "drag_auth_types.h"

using namespace testing::ext;
namespace OHOS::UDMF {
namespace {
constexpr int64_t EVENT_ID = INT64_C(0x0F810000);
constexpr int64_t LARGE_EVENT_ID = INT64_C(5000000001);
constexpr int64_t DEFAULT_TIMEOUT_MS = 5000;
constexpr int64_t PROTECTION_MS = 100;
} // namespace
class UdmfAuthTimeoutPolicyTest : public testing::Test {};
/**
 * @tc.name: Resolve_UninitializedSnapshotWithPolicies_UsesSafeDefault
 * @tc.desc: Verify the public contract and observable side effects for this branch.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfAuthTimeoutPolicyTest, Resolve_UninitializedSnapshotWithPolicies_UsesSafeDefault, TestSize.Level1)
{
    ClientPolicySnapshot snapshot;
    snapshot.version = 17;
    snapshot.policies[EVENT_ID] = { { DragAuthDecision::ALLOW, 400 } };
    auto policy = snapshot.Resolve(EVENT_ID);
    EXPECT_TRUE(policy.defaultApplied);
    EXPECT_EQ(policy.fallback, DragAuthDecision::DENY);
    EXPECT_EQ(policy.watchdog.count(), DEFAULT_TIMEOUT_MS);
    EXPECT_EQ(policy.snapshotVersion, 17u);
}
/**
 * @tc.name: Resolve_MissingOrEmptyEvent_UsesSafeDefault
 * @tc.desc: Verify the public contract and observable side effects for this branch.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfAuthTimeoutPolicyTest, Resolve_MissingOrEmptyEvent_UsesSafeDefault, TestSize.Level1)
{
    ClientPolicySnapshot snapshot;
    snapshot.initialized = true;
    snapshot.version = 23;
    snapshot.policies[EVENT_ID] = {};
    snapshot.policies[LARGE_EVENT_ID] = { { DragAuthDecision::ALLOW, 400 } };
    for (auto event : { EVENT_ID, int64_t(0) }) {
        auto policy = snapshot.Resolve(event);
        EXPECT_TRUE(policy.defaultApplied);
        EXPECT_EQ(policy.fallback, DragAuthDecision::DENY);
        EXPECT_EQ(policy.watchdog.count(), DEFAULT_TIMEOUT_MS);
        EXPECT_EQ(policy.snapshotVersion, 23u);
    }
}
/**
 * @tc.name: Resolve_LegalBoundaryTimeouts_AddsProtection
 * @tc.desc: Verify the public contract and observable side effects for this branch.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfAuthTimeoutPolicyTest, Resolve_LegalBoundaryTimeouts_AddsProtection, TestSize.Level1)
{
    ClientPolicySnapshot snapshot;
    snapshot.initialized = true;
    for (int64_t timeout : { 100, 400, 10000 }) {
        for (auto strategy : { DragAuthDecision::ALLOW, DragAuthDecision::DENY }) {
            snapshot.policies[EVENT_ID] = { { strategy, timeout } };
            auto policy = snapshot.Resolve(EVENT_ID);
            EXPECT_FALSE(policy.defaultApplied);
            EXPECT_EQ(policy.fallback, strategy);
            EXPECT_EQ(policy.watchdog.count(), timeout + PROTECTION_MS);
        }
    }
}
/**
 * @tc.name: Resolve_IllegalTimeouts_RejectsWholePolicy
 * @tc.desc: Verify the public contract and observable side effects for this branch.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfAuthTimeoutPolicyTest, Resolve_IllegalTimeouts_RejectsWholePolicy, TestSize.Level1)
{
    ClientPolicySnapshot snapshot;
    snapshot.initialized = true;
    const std::vector<int64_t> invalid = { std::numeric_limits<int64_t>::min(), -1, 0, 99, 10001,
        std::numeric_limits<int64_t>::max() };
    for (auto timeout : invalid) {
        snapshot.policies[EVENT_ID] = { { DragAuthDecision::ALLOW, 400 }, { DragAuthDecision::ALLOW, timeout } };
        auto policy = snapshot.Resolve(EVENT_ID);
        EXPECT_TRUE(policy.defaultApplied);
        EXPECT_EQ(policy.fallback, DragAuthDecision::DENY);
        EXPECT_EQ(policy.watchdog.count(), DEFAULT_TIMEOUT_MS);
    }
}
/**
 * @tc.name: Resolve_IllegalStrategies_RejectsWholePolicy
 * @tc.desc: Verify the public contract and observable side effects for this branch.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfAuthTimeoutPolicyTest, Resolve_IllegalStrategies_RejectsWholePolicy, TestSize.Level1)
{
    ClientPolicySnapshot snapshot;
    snapshot.initialized = true;
    for (auto strategy : { DragAuthDecision::TIMEOUT, DragAuthDecision::ERROR, static_cast<DragAuthDecision>(99) }) {
        snapshot.policies[EVENT_ID] = { { DragAuthDecision::ALLOW, 400 }, { strategy, 100 } };
        auto policy = snapshot.Resolve(EVENT_ID);
        EXPECT_TRUE(policy.defaultApplied);
        EXPECT_EQ(policy.fallback, DragAuthDecision::DENY);
        EXPECT_EQ(policy.watchdog.count(), DEFAULT_TIMEOUT_MS);
    }
}
/**
 * @tc.name: Resolve_AnyDenyAndMaximumAcrossClients_AreIndependent
 * @tc.desc: Verify the public contract and observable side effects for this branch.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfAuthTimeoutPolicyTest, Resolve_AnyDenyAndMaximumAcrossClients_AreIndependent, TestSize.Level1)
{
    ClientPolicySnapshot snapshot;
    snapshot.initialized = true;
    snapshot.version = 31;
    snapshot.policies[EVENT_ID] = { { DragAuthDecision::ALLOW, 10000 }, { DragAuthDecision::DENY, 100 },
        { DragAuthDecision::ALLOW, 400 } };
    const auto policy = snapshot.Resolve(EVENT_ID);
    EXPECT_EQ(policy.fallback, DragAuthDecision::DENY);
    EXPECT_EQ(policy.watchdog.count(), 10100);
    EXPECT_EQ(policy.snapshotVersion, 31u);
    EXPECT_FALSE(policy.defaultApplied);
    snapshot.policies[EVENT_ID][1].strategy = DragAuthDecision::ALLOW;
    EXPECT_EQ(snapshot.Resolve(EVENT_ID).fallback, DragAuthDecision::ALLOW);
    EXPECT_EQ(policy.fallback, DragAuthDecision::DENY);
}
/**
 * @tc.name: Resolve_Int64EventSelection_DoesNotUseUnrelatedClient
 * @tc.desc: Verify the public contract and observable side effects for this branch.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfAuthTimeoutPolicyTest, Resolve_Int64EventSelection_DoesNotUseUnrelatedClient, TestSize.Level1)
{
    ClientPolicySnapshot snapshot;
    snapshot.initialized = true;
    snapshot.policies[LARGE_EVENT_ID] = { { DragAuthDecision::ALLOW, 100 } };
    snapshot.policies[EVENT_ID] = { { DragAuthDecision::DENY, 10000 } };
    auto selected = snapshot.Resolve(LARGE_EVENT_ID);
    EXPECT_EQ(selected.fallback, DragAuthDecision::ALLOW);
    EXPECT_EQ(selected.watchdog.count(), 200);
    EXPECT_FALSE(selected.defaultApplied);
}
/**
 * @tc.name: Resolve_IdentifiedSubscribers_RetainsRequiredDenyAndConservativeDeadline
 * @tc.desc: Health identity does not remove required DENY or shorten the frozen watchdog.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfAuthTimeoutPolicyTest, Resolve_IdentifiedSubscribers_RetainsRequiredDenyAndConservativeDeadline,
    TestSize.Level1)
{
    ClientPolicySnapshot snapshot;
    snapshot.initialized = true;
    snapshot.version = 7;
    snapshot.policies[EVENT_ID] = { { DragAuthDecision::ALLOW, 10000, "degradable" },
        { DragAuthDecision::DENY, 400, "required" } };
    auto policy = snapshot.Resolve(EVENT_ID);
    EXPECT_EQ(policy.fallback, DragAuthDecision::DENY);
    EXPECT_EQ(policy.watchdog, std::chrono::milliseconds(10100));
    EXPECT_EQ(policy.snapshotVersion, 7u);
    EXPECT_FALSE(policy.defaultApplied);
    snapshot.policies[EVENT_ID].pop_back();
    EXPECT_EQ(snapshot.Resolve(EVENT_ID).fallback, DragAuthDecision::ALLOW);
}

} // namespace OHOS::UDMF
