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

#include "security_guard_delegate_normal_impl.h"

#include <gtest/gtest.h>

#include "mock/security_guard_sdk_mock.h"
#include "security_guard/security_guard_delegate.h"

using namespace testing::ext;
namespace OHOS {
namespace DistributedData {
class SecurityGuardDelegateNormalTest : public testing::Test {};
/**
 * @tc.name: GetInstance_NormalBackend_RegistersWithoutConnecting
 * @tc.desc: Verify adapter registration and virtual dispatch through the framework interface.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(SecurityGuardDelegateNormalTest, GetInstance_NormalBackend_RegistersWithoutConnecting, TestSize.Level1)
{
    auto *delegate = SecurityGuardDelegate::GetInstance();
    ASSERT_NE(delegate, nullptr);
    EXPECT_EQ(SecurityGuardDelegate::GetInstance(), delegate);
    EXPECT_FALSE(delegate->IsReady());
    EXPECT_FALSE(delegate->GetClientSnapshot().initialized);
    // Normal transport rejects an invalid completion before checking session readiness.
    EXPECT_EQ(delegate->Request({}, {}), SecurityGuardDelegate::DispatchStatus::REJECTED);
    bool completed = false;
    EXPECT_EQ(
        delegate->Request({}, [&](auto) { completed = true; }), SecurityGuardDelegate::DispatchStatus::UNAVAILABLE);
    EXPECT_FALSE(completed);
    delegate->Stop();
    EXPECT_EQ(delegate->Start(), SecurityGuardDelegate::Status::UNAVAILABLE);
}

class SecurityGuardSdkBoundaryTest : public testing::Test {
public:
    void SetUp() override
    {
        SecurityGuardSdkMock::instance = &sdk_;
    }
    void TearDown() override
    {
        SecurityGuardSdkMock::instance = nullptr;
    }
    testing::StrictMock<SecurityGuardSdkMock> sdk_;
};
using Strategy = SecurityGuardDelegate::Strategy;
using DispatchStatus = SecurityGuardDelegate::DispatchStatus;
using Status = SecurityGuardDelegate::Status;
using testing::_;
using testing::Return;

/**
 * @tc.name: Start_SdkSuccess_UsesDistributeddataAndDeletesExactlyOnce
 * @tc.desc: Verify public behavior, failure propagation and observable state.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(SecurityGuardSdkBoundaryTest, Start_SdkSuccess_UsesDistributeddataAndDeletesExactlyOnce, TestSize.Level1)
{
    EXPECT_CALL(sdk_, Create(_, "distributeddata")).WillOnce(Return(0));
    EXPECT_CALL(sdk_, Delete()).Times(1);
    SecurityGuardDelegateNormalImpl delegate([](auto task) {
        task();
        return true;
    });
    EXPECT_EQ(delegate.Start(), Status::READY);
    EXPECT_EQ(delegate.Start(), Status::READY);
    EXPECT_TRUE(delegate.IsReady());
    EXPECT_FALSE(delegate.GetClientSnapshot().initialized);
    delegate.Stop();
    delegate.Stop();
    EXPECT_EQ(delegate.Start(), Status::UNAVAILABLE);
}
/**
 * @tc.name: Start_SdkFailureWithAllocatedClient_CleansPartialSession
 * @tc.desc: Verify public behavior, failure propagation and observable state.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(SecurityGuardSdkBoundaryTest, Start_SdkFailureWithAllocatedClient_CleansPartialSession, TestSize.Level1)
{
    EXPECT_CALL(sdk_, Create(_, "distributeddata")).Times(2).WillRepeatedly(Return(-17));
    EXPECT_CALL(sdk_, Delete()).Times(2);
    SecurityGuardDelegateNormalImpl delegate([](auto task) {
        task();
        return true;
    });
    EXPECT_EQ(delegate.Start(), Status::UNAVAILABLE);
    EXPECT_FALSE(delegate.IsReady());
    EXPECT_EQ(delegate.Start(), Status::UNAVAILABLE);
    EXPECT_EQ(delegate.Request({}, [](const SecurityGuardDelegate::Result &) {}), DispatchStatus::UNAVAILABLE);
}
/**
 * @tc.name: Start_SdkNullClientRegardlessOfStatus_IsUnavailable
 * @tc.desc: Verify public behavior, failure propagation and observable state.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(SecurityGuardSdkBoundaryTest, Start_SdkNullClientRegardlessOfStatus_IsUnavailable, TestSize.Level1)
{
    sdk_.returnNull = true;
    EXPECT_CALL(sdk_, Create(_, "distributeddata")).WillOnce(Return(0)).WillOnce(Return(-17));
    EXPECT_CALL(sdk_, Delete()).Times(0);
    SecurityGuardDelegateNormalImpl first([](auto task) {
        task();
        return true;
    });
    SecurityGuardDelegateNormalImpl second([](auto task) {
        task();
        return true;
    });
    EXPECT_EQ(first.Start(), Status::UNAVAILABLE);
    EXPECT_EQ(second.Start(), Status::UNAVAILABLE);
    EXPECT_FALSE(first.IsReady());
    EXPECT_FALSE(second.IsReady());
}
/**
 * @tc.name: Request_SdkMergedStrategiesAndEvent_AreMappedAndPreserved
 * @tc.desc: Verify public behavior, failure propagation and observable state.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(SecurityGuardSdkBoundaryTest, Request_SdkMergedStrategiesAndEvent_AreMappedAndPreserved, TestSize.Level1)
{
    EXPECT_CALL(sdk_, Create(_, "distributeddata")).WillOnce(Return(0));
    EXPECT_CALL(sdk_, Delete()).Times(1);
    const std::vector<std::pair<SG::AuthStrategy, Strategy>> strategies = { { SG::ALLOW, Strategy::ALLOW },
        { SG::DENY, Strategy::DENY }, { SG::TIMEOUT, Strategy::TIMEOUT },
        { static_cast<SG::AuthStrategy>(99), Strategy::ERROR } };
    SecurityGuardDelegateNormalImpl delegate([](auto task) {
        task();
        return true;
    });
    ASSERT_EQ(delegate.Start(), Status::READY);
    SecurityGuardDelegate::Event input{ 0x0F810000, "1.0", R"({"text":"drag"})" };
    for (const auto &entry : strategies) {
        auto sdkResult = entry.first;
        auto expected = entry.second;
        EXPECT_CALL(sdk_, Request(_, _))
            .WillOnce([&](const SG::AuthEventInfo &event, SG::AuthResultCallback callback) {
                EXPECT_EQ(event.GetEventId(), input.eventId);
                EXPECT_EQ(event.GetVersion(), input.version);
                EXPECT_EQ(event.GetContent(), input.jsonContent);
                EXPECT_TRUE(event.GetClientStatus().empty());
                callback(SG::AuthResult(sdkResult, {}));
                return 0;
            });
        std::vector<Strategy> results;
        EXPECT_EQ(delegate.Request(input,
                      [&](const SecurityGuardDelegate::Result &result) { results.push_back(result.mergedStrategy); }),
            DispatchStatus::DISPATCHED);
        ASSERT_EQ(results.size(), 1u);
        EXPECT_EQ(results[0], expected);
    }
}
/**
 * @tc.name: Request_ConflictingClientResults_UsesOnlySdkMergedStrategy
 * @tc.desc: Nonempty SDK result DTOs must link and the adapter must honor the merged strategy.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(SecurityGuardSdkBoundaryTest, Request_ConflictingClientResults_UsesOnlySdkMergedStrategy, TestSize.Level1)
{
    EXPECT_CALL(sdk_, Create(_, _)).WillOnce(Return(0));
    EXPECT_CALL(sdk_, Delete()).Times(1);
    SecurityGuardDelegateNormalImpl delegate([](auto task) {
        task();
        return true;
    });
    ASSERT_EQ(delegate.Start(), Status::READY);
    const std::vector<std::pair<SG::AuthStrategy, Strategy>> strategies = { { SG::ALLOW, Strategy::ALLOW },
        { SG::DENY, Strategy::DENY } };
    for (const auto &entry : strategies) {
        EXPECT_CALL(sdk_, Request(_, _)).WillOnce([&](const SG::AuthEventInfo &, SG::AuthResultCallback callback) {
            auto clientStrategy = entry.first == SG::ALLOW ? SG::DENY : SG::ALLOW;
            SG::AuthResult result(entry.first, { SG::ClientAuthResult("test-client", clientStrategy) });
            callback(result);
            return 0;
        });
        std::vector<Strategy> decisions;
        auto completion = [&](const SecurityGuardDelegate::Result &decision) {
            decisions.push_back(decision.mergedStrategy);
        };
        EXPECT_EQ(delegate.Request({}, completion), DispatchStatus::DISPATCHED);
        ASSERT_EQ(decisions.size(), 1u);
        EXPECT_EQ(decisions.front(), entry.second);
    }
}

/**
 * @tc.name: Request_SynchronousRejection_IsNotAcceptedAsDecision
 * @tc.desc: Verify public behavior, failure propagation and observable state.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(SecurityGuardSdkBoundaryTest, Request_SynchronousRejection_IsNotAcceptedAsDecision, TestSize.Level1)
{
    EXPECT_CALL(sdk_, Create(_, _)).WillOnce(Return(0));
    EXPECT_CALL(sdk_, Delete()).Times(1);
    EXPECT_CALL(sdk_, Request(_, _)).WillOnce(Return(-17));
    SecurityGuardDelegateNormalImpl delegate([](auto task) {
        task();
        return true;
    });
    ASSERT_EQ(delegate.Start(), Status::READY);
    int completed = 0;
    EXPECT_EQ(delegate.Request({ 0x0F810000, "1.0", "{}" },
                  [&](const SecurityGuardDelegate::Result &result) {
                      EXPECT_EQ(result.dispatchStatus, DispatchStatus::REJECTED);
                      ++completed;
                  }),
        DispatchStatus::DISPATCHED);
    EXPECT_EQ(completed, 1);
    EXPECT_EQ(delegate.Request({}, {}), DispatchStatus::REJECTED);
}
/**
 * @tc.name: Snapshot_SdkSubscribersAndReplacement_PreserveAllTimeoutFields
 * @tc.desc: Verify public behavior, failure propagation and observable state.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(SecurityGuardSdkBoundaryTest, Snapshot_SdkSubscribersAndReplacement_PreserveAllTimeoutFields, TestSize.Level1)
{
    SG::AuthProviderCallback publish;
    EXPECT_CALL(sdk_, Create(_, _)).WillOnce([&](auto callback, const auto &) {
        publish = callback;
        return 0;
    });
    EXPECT_CALL(sdk_, Delete()).Times(1);
    SecurityGuardDelegateNormalImpl delegate([](auto task) {
        task();
        return true;
    });
    ASSERT_EQ(delegate.Start(), Status::READY);
    ASSERT_TRUE(static_cast<bool>(publish));
    std::vector<SG::AuthClientInfo> clients(4);
    const std::vector<SG::AuthStrategy> raw = { SG::ALLOW, SG::DENY, SG::TIMEOUT, static_cast<SG::AuthStrategy>(99) };
    const std::vector<Strategy> mapped = { Strategy::ALLOW, Strategy::DENY, Strategy::TIMEOUT, Strategy::ERROR };
    for (size_t i = 0; i < clients.size(); ++i) {
        clients[i].SetClientId("client-" + std::to_string(i));
        clients[i].SetSubscribedEvents({ 0x0F810000, static_cast<int64_t>(i + 1) });
        clients[i].SetDefaultTimeoutStrategy(raw[i]);
        clients[i].SetDefaultTimeoutMs(100 + static_cast<int32_t>(i));
    }
    publish(clients);
    auto snapshot = delegate.GetClientSnapshot();
    ASSERT_TRUE(snapshot.initialized);
    ASSERT_EQ(snapshot.policies.at(0x0F810000).size(), clients.size());
    for (size_t i = 0; i < clients.size(); ++i) {
        EXPECT_EQ(snapshot.policies.at(0x0F810000)[i].clientId, "client-" + std::to_string(i));
        EXPECT_EQ(snapshot.policies.at(0x0F810000)[i].strategy, mapped[i]);
        EXPECT_EQ(snapshot.policies.at(0x0F810000)[i].timeoutMs, 100 + static_cast<int32_t>(i));
    }
    publish({});
    auto empty = delegate.GetClientSnapshot();
    EXPECT_TRUE(empty.initialized);
    EXPECT_TRUE(empty.policies.empty());
    EXPECT_GT(empty.version, snapshot.version);
    EXPECT_TRUE(snapshot.HasSubscribers(0x0F810000));
}
/**
 * @tc.name: Callbacks_AfterStopAndOwnerDestruction_DoNotReachBusiness
 * @tc.desc: Verify public behavior, failure propagation and observable state.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(SecurityGuardSdkBoundaryTest, Callbacks_AfterStopAndOwnerDestruction_DoNotReachBusiness, TestSize.Level1)
{
    SG::AuthProviderCallback publish;
    SG::AuthResultCallback finish;
    EXPECT_CALL(sdk_, Create(_, _)).WillOnce([&](auto callback, const auto &) {
        publish = callback;
        return 0;
    });
    EXPECT_CALL(sdk_, Request(_, _)).WillOnce([&](const auto &, auto callback) {
        finish = callback;
        return 0;
    });
    EXPECT_CALL(sdk_, Delete()).Times(1);
    int completed = 0;
    {
        SecurityGuardDelegateNormalImpl delegate([](auto task) {
            task();
            return true;
        });
        ASSERT_EQ(delegate.Start(), Status::READY);
        EXPECT_EQ(delegate.Request({}, [&](const SecurityGuardDelegate::Result &) { ++completed; }),
            DispatchStatus::DISPATCHED);
        delegate.Stop();
        ASSERT_TRUE(static_cast<bool>(finish));
        finish(SG::AuthResult(SG::ALLOW, {}));
        publish({ SG::AuthClientInfo{} });
        EXPECT_FALSE(delegate.GetClientSnapshot().initialized);
        EXPECT_EQ(delegate.Request({}, [](const SecurityGuardDelegate::Result &) {}), DispatchStatus::UNAVAILABLE);
    }
    finish(SG::AuthResult(SG::DENY, {}));
    publish({});
    EXPECT_EQ(completed, 0);
}
/**
 * @tc.name: Request_ReentrantBusinessStop_DoesNotDeadlockOrDoubleDelete
 * @tc.desc: Verify public behavior, failure propagation and observable state.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(SecurityGuardSdkBoundaryTest, Request_ReentrantBusinessStop_DoesNotDeadlockOrDoubleDelete, TestSize.Level1)
{
    EXPECT_CALL(sdk_, Create(_, _)).WillOnce(Return(0));
    EXPECT_CALL(sdk_, Delete()).Times(1);
    EXPECT_CALL(sdk_, Request(_, _)).WillOnce([](const auto &, auto callback) {
        callback(SG::AuthResult(SG::DENY, {}));
        return 0;
    });
    SecurityGuardDelegateNormalImpl delegate([](auto task) {
        task();
        return true;
    });
    ASSERT_EQ(delegate.Start(), Status::READY);
    int completed = 0;
    auto onComplete = [&](const SecurityGuardDelegate::Result &result) {
        EXPECT_EQ(result.mergedStrategy, Strategy::DENY);
        ++completed;
        delegate.Stop();
    };
    EXPECT_EQ(delegate.Request({}, onComplete), DispatchStatus::DISPATCHED);
    EXPECT_EQ(completed, 1);
    EXPECT_FALSE(delegate.IsReady());
}

/**
 * @tc.name: Request_DegradedClients_MapsOnlyExplicitSessionFlags
 * @tc.desc: Forward degradation as SDK clientStatus while preserving merged and per-client results.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(SecurityGuardSdkBoundaryTest, Request_DegradedClients_MapsOnlyExplicitSessionFlags, TestSize.Level1)
{
    EXPECT_CALL(sdk_, Create(_, _)).WillOnce(Return(0));
    EXPECT_CALL(sdk_, Delete()).Times(1);
    SecurityGuardDelegateNormalImpl delegate([](auto task) {
        task();
        return true;
    });
    ASSERT_EQ(delegate.Start(), Status::READY);
    SecurityGuardDelegate::Event input{ 0x0F810000, "1.0", "{}", { "client-a", "client-b" } };
    EXPECT_CALL(sdk_, Request(_, _)).WillOnce([&](const SG::AuthEventInfo &event, auto callback) {
        auto statuses = event.GetClientStatus();
        EXPECT_EQ(event.GetEventId(), input.eventId);
        EXPECT_EQ(event.GetContent(), input.jsonContent);
        EXPECT_EQ(statuses.size(), 2u);
        if (statuses.size() == 2u) {
            EXPECT_EQ(statuses[0].GetClientId(), "client-a");
            EXPECT_EQ(statuses[1].GetClientId(), "client-b");
            EXPECT_TRUE(statuses[0].IsDegraded());
            EXPECT_TRUE(statuses[1].IsDegraded());
        }
        callback(SG::AuthResult(SG::DENY, { SG::ClientAuthResult("normal", SG::DENY) }));
        return 0;
    });
    SecurityGuardDelegate::Result actual;
    EXPECT_EQ(delegate.Request(input, [&](const auto &result) { actual = result; }), DispatchStatus::DISPATCHED);
    EXPECT_EQ(actual.mergedStrategy, Strategy::DENY);
    ASSERT_EQ(actual.clients.size(), 1u);
    EXPECT_EQ(actual.clients[0].clientId, "normal");
    EXPECT_EQ(actual.clients[0].strategy, Strategy::DENY);
}
/**
 * @tc.name: Request_ClientStrategies_MapsEveryDetailWithoutReaggregating
 * @tc.desc: Invalid per-client strategy does not overwrite the SDK aggregate.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(SecurityGuardSdkBoundaryTest, Request_ClientStrategies_MapsEveryDetailWithoutReaggregating, TestSize.Level1)
{
    EXPECT_CALL(sdk_, Create(_, _)).WillOnce(Return(0));
    EXPECT_CALL(sdk_, Delete()).Times(1);
    EXPECT_CALL(sdk_, Request(_, _)).WillOnce([](const auto &, auto callback) {
        callback(SG::AuthResult(
            SG::ALLOW, { SG::ClientAuthResult("allow", SG::ALLOW), SG::ClientAuthResult("deny", SG::DENY),
                           SG::ClientAuthResult("timeout", SG::TIMEOUT),
                           SG::ClientAuthResult("invalid", static_cast<SG::AuthStrategy>(99)) }));
        return 0;
    });
    SecurityGuardDelegateNormalImpl delegate([](auto task) {
        task();
        return true;
    });
    ASSERT_EQ(delegate.Start(), Status::READY);
    SecurityGuardDelegate::Result actual;
    EXPECT_EQ(delegate.Request({}, [&](const auto &result) { actual = result; }), DispatchStatus::DISPATCHED);
    EXPECT_EQ(actual.mergedStrategy, Strategy::ALLOW);
    ASSERT_EQ(actual.clients.size(), 4u);
    EXPECT_EQ(actual.clients[0].strategy, Strategy::ALLOW);
    EXPECT_EQ(actual.clients[1].strategy, Strategy::DENY);
    EXPECT_EQ(actual.clients[2].strategy, Strategy::TIMEOUT);
    EXPECT_EQ(actual.clients[3].strategy, Strategy::ERROR);
    EXPECT_EQ(actual.clients[2].clientId, "timeout");
}

/**
 * @tc.name: Request_RepeatedSdkRejection_NeverCompletesAsAccepted
 * @tc.desc: Repeated SDK admission errors remain rejections while diagnostic bursts are rate limited.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(SecurityGuardSdkBoundaryTest, Request_RepeatedSdkRejection_NeverCompletesAsAccepted, TestSize.Level1)
{
    EXPECT_CALL(sdk_, Create(_, _)).WillOnce(Return(0));
    EXPECT_CALL(sdk_, Delete()).Times(1);
    EXPECT_CALL(sdk_, Request(_, _)).Times(20).WillRepeatedly(Return(-17));
    SecurityGuardDelegateNormalImpl delegate([](auto task) {
        task();
        return true;
    });
    ASSERT_EQ(delegate.Start(), Status::READY);
    int completions = 0;
    for (unsigned i = 0; i < 20; ++i) {
        EXPECT_EQ(delegate.Request({ 0x0F810000, "1.0", "{}" },
                      [&](const auto &result) {
                          EXPECT_EQ(result.dispatchStatus, DispatchStatus::REJECTED);
                          ++completions;
                      }),
            DispatchStatus::DISPATCHED);
    }
    EXPECT_EQ(completions, 20);
    EXPECT_TRUE(delegate.IsReady());
}

} // namespace DistributedData
} // namespace OHOS
