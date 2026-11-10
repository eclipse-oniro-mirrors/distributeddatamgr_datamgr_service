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

#include "security_guard_delegate_impl.h"

#include <gtest/gtest.h>

#include <condition_variable>
#include <future>
#include <thread>
using namespace testing::ext;
namespace OHOS::DistributedData {
using Provider = SecurityGuardDelegateImpl::Provider;
using ClientStatusCallback = SecurityGuardDelegateImpl::ClientStatusCallback;
using Event = SecurityGuardDelegate::Event;
using Strategy = SecurityGuardDelegate::Strategy;
using Completion = SecurityGuardDelegate::Completion;
using Status = SecurityGuardDelegate::Status;
using DispatchStatus = SecurityGuardDelegate::DispatchStatus;
class FakeAuthProvider final : public Provider {
public:
    DispatchStatus Request(const Event &, Completion completion) override
    {
        requests_++;
        if (onRequest_) {
            onRequest_();
        }
        saved_ = completion;
        if (respond_) {
            completion({ result_, {} });
            if (duplicate_) {
                completion({ result_, {} });
            }
        }
        return dispatch_;
    }
    void Stop() override
    {
        stops_++;
    }
    std::function<void()> onRequest_;
    int32_t requests_ = 0;
    int32_t stops_ = 0;
    bool respond_ = true;
    bool duplicate_ = false;
    DispatchStatus dispatch_ = DispatchStatus::DISPATCHED;
    Strategy result_ = Strategy::ALLOW;
    Completion saved_;
};
class InlineGuardDelegate : public SecurityGuardDelegateImpl {
public:
    explicit InlineGuardDelegate(ProviderFactory factory)
        : SecurityGuardDelegateImpl(std::move(factory), [](auto task) {
              task();
              return true;
          })
    {
    }
};
class SecurityGuardDelegateTest : public testing::Test {};
/**
 * @tc.name: Start_Repeated_CreateAndDestroyOnce
 * @tc.desc: Verify authorization behavior through public interfaces.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(SecurityGuardDelegateTest, Start_Repeated_CreateAndDestroyOnce, TestSize.Level1)
{
    auto provider = std::make_shared<FakeAuthProvider>();
    int creates = 0;
    std::string serviceId;
    InlineGuardDelegate delegate(
        [&](ClientStatusCallback callback, const std::string &id, std::shared_ptr<Provider> &output) {
            creates++;
            serviceId = id;
            callback({ { { INT64_C(5000000001) }, Strategy::DENY, 400 } });
            output = provider;
            return 0;
        });
    EXPECT_EQ(delegate.Start(), Status::READY);
    EXPECT_EQ(delegate.Start(), Status::READY);
    EXPECT_EQ(creates, 1);
    EXPECT_EQ(serviceId, "distributeddata");
    EXPECT_TRUE(delegate.GetClientSnapshot().HasSubscribers(INT64_C(5000000001)));
    EXPECT_FALSE(delegate.GetClientSnapshot().HasSubscribers(1));
    delegate.Stop();
    delegate.Stop();
    EXPECT_EQ(provider->stops_, 1);
    EXPECT_FALSE(delegate.IsReady());
    EXPECT_EQ(delegate.Start(), Status::UNAVAILABLE);
}
/**
 * @tc.name: Start_FailedFactory_CleansPartialProvider
 * @tc.desc: Verify authorization behavior through public interfaces.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(SecurityGuardDelegateTest, Start_FailedFactory_CleansPartialProvider, TestSize.Level1)
{
    auto provider = std::make_shared<FakeAuthProvider>();
    InlineGuardDelegate delegate([&](ClientStatusCallback, const std::string &, std::shared_ptr<Provider> &output) {
        output = provider;
        return -1;
    });
    EXPECT_EQ(delegate.Start(), Status::UNAVAILABLE);
    EXPECT_EQ(provider->stops_, 1);
    EXPECT_EQ(delegate.Request({}, [](const SecurityGuardDelegate::Result &) {}), DispatchStatus::UNAVAILABLE);
}
/**
 * @tc.name: Start_EmptyFactory_Unavailable
 * @tc.desc: Verify authorization behavior through public interfaces.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(SecurityGuardDelegateTest, Start_EmptyFactory_Unavailable, TestSize.Level1)
{
    InlineGuardDelegate delegate({});
    EXPECT_EQ(delegate.Start(), Status::UNAVAILABLE);
    delegate.Stop();
    EXPECT_FALSE(delegate.IsReady());
}
/**
 * @tc.name: Status_FullSnapshots_ReplaceAndIgnoreAfterStop
 * @tc.desc: Verify authorization behavior through public interfaces.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(SecurityGuardDelegateTest, Status_FullSnapshots_ReplaceAndIgnoreAfterStop, TestSize.Level1)
{
    ClientStatusCallback publish;
    auto provider = std::make_shared<FakeAuthProvider>();
    InlineGuardDelegate delegate(
        [&](ClientStatusCallback callback, const std::string &, std::shared_ptr<Provider> &output) {
            publish = callback;
            output = provider;
            return 0;
        });
    ASSERT_EQ(delegate.Start(), Status::READY);
    EXPECT_FALSE(delegate.GetClientSnapshot().initialized);
    publish({ { { 10 }, Strategy::ALLOW, 400 } });
    const auto first = delegate.GetClientSnapshot();
    publish({});
    auto empty = delegate.GetClientSnapshot();
    EXPECT_EQ(empty.version, first.version + 1);
    EXPECT_FALSE(empty.HasSubscribers(10));
    EXPECT_TRUE(first.HasSubscribers(10));
    delegate.Stop();
    publish({ { { 10 }, Strategy::DENY, 400 } });
    EXPECT_EQ(delegate.GetClientSnapshot().version, empty.version);
}
/**
 * @tc.name: Request_InlineAndRejected_MapDispatchStatus
 * @tc.desc: Verify authorization behavior through public interfaces.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(SecurityGuardDelegateTest, Request_InlineAndRejected_MapDispatchStatus, TestSize.Level1)
{
    auto provider = std::make_shared<FakeAuthProvider>();
    InlineGuardDelegate delegate([&](ClientStatusCallback, const std::string &, std::shared_ptr<Provider> &output) {
        output = provider;
        return 0;
    });
    ASSERT_EQ(delegate.Start(), Status::READY);
    int completions = 0;
    EXPECT_EQ(delegate.Request({},
                  [&](const SecurityGuardDelegate::Result &result) {
                      EXPECT_EQ(result.mergedStrategy, Strategy::ALLOW);
                      completions++;
                  }),
        DispatchStatus::DISPATCHED);
    EXPECT_EQ(completions, 1);
    provider->respond_ = false;
    provider->dispatch_ = DispatchStatus::REJECTED;
    EXPECT_EQ(delegate.Request({},
                  [&](const SecurityGuardDelegate::Result &result) {
                      EXPECT_EQ(result.dispatchStatus, DispatchStatus::REJECTED);
                      completions++;
                  }),
        DispatchStatus::DISPATCHED);
    EXPECT_EQ(completions, 2);
    EXPECT_EQ(delegate.Request({}, {}), DispatchStatus::REJECTED);
    delegate.Stop();
    provider->saved_({ Strategy::DENY, {} });
    EXPECT_EQ(completions, 2);
}
/**
 * @tc.name: Request_ReentrantStop_NoLockHeldAcrossProvider
 * @tc.desc: Verify authorization behavior through public interfaces.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(SecurityGuardDelegateTest, Request_ReentrantStop_NoLockHeldAcrossProvider, TestSize.Level1)
{
    auto provider = std::make_shared<FakeAuthProvider>();
    InlineGuardDelegate delegate([&](ClientStatusCallback, const std::string &, std::shared_ptr<Provider> &output) {
        output = provider;
        return 0;
    });
    ASSERT_EQ(delegate.Start(), Status::READY);
    EXPECT_EQ(delegate.Request({}, [&](const SecurityGuardDelegate::Result &) { delegate.Stop(); }),
        DispatchStatus::DISPATCHED);
    EXPECT_EQ(provider->stops_, 1);
}
/**
 * @tc.name: Start_ConcurrentStop_DiscardsLateCreatedProvider
 * @tc.desc: Verify authorization behavior through public interfaces.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(SecurityGuardDelegateTest, Start_ConcurrentStop_DiscardsLateCreatedProvider, TestSize.Level1)
{
    std::promise<void> entered;
    std::promise<void> resume;
    auto ready = resume.get_future().share();
    auto provider = std::make_shared<FakeAuthProvider>();
    InlineGuardDelegate delegate([&](ClientStatusCallback, const std::string &, std::shared_ptr<Provider> &output) {
        entered.set_value();
        ready.wait();
        output = provider;
        return 0;
    });
    auto start = std::async(std::launch::async, [&] { return delegate.Start(); });
    entered.get_future().wait();
    EXPECT_EQ(delegate.Start(), Status::UNAVAILABLE);
    delegate.Stop();
    resume.set_value();
    EXPECT_EQ(start.get(), Status::UNAVAILABLE);
    EXPECT_EQ(provider->stops_, 1);
}
/**
 * @tc.name: Start_SuccessWithoutProvider_RemainsRetryable
 * @tc.desc: Verify public behavior, failure propagation and observable state.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(SecurityGuardDelegateTest, Start_SuccessWithoutProvider_RemainsRetryable, TestSize.Level1)
{
    int creates = 0;
    InlineGuardDelegate delegate([&](ClientStatusCallback, const std::string &, std::shared_ptr<Provider> &) {
        ++creates;
        return 0;
    });
    EXPECT_EQ(delegate.Start(), Status::UNAVAILABLE);
    EXPECT_EQ(delegate.Start(), Status::UNAVAILABLE);
    EXPECT_FALSE(delegate.IsReady());
    EXPECT_EQ(creates, 2);
}
/**
 * @tc.name: Start_ReentrantStart_DoesNotCreateSecondProvider
 * @tc.desc: Verify public behavior, failure propagation and observable state.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(SecurityGuardDelegateTest, Start_ReentrantStart_DoesNotCreateSecondProvider, TestSize.Level1)
{
    int creates = 0;
    Status nested = Status::READY;
    SecurityGuardDelegateImpl *current = nullptr;
    auto provider = std::make_shared<FakeAuthProvider>();
    InlineGuardDelegate delegate([&](ClientStatusCallback, const std::string &, std::shared_ptr<Provider> &output) {
        ++creates;
        nested = current->Start();
        output = provider;
        return 0;
    });
    current = &delegate;
    EXPECT_EQ(delegate.Start(), Status::READY);
    EXPECT_EQ(nested, Status::UNAVAILABLE);
    EXPECT_EQ(creates, 1);
    delegate.Stop();
    EXPECT_EQ(provider->stops_, 1);
}
/**
 * @tc.name: Stop_BeforeStart_IsTerminalWithoutCreatingProvider
 * @tc.desc: Verify public behavior, failure propagation and observable state.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(SecurityGuardDelegateTest, Stop_BeforeStart_IsTerminalWithoutCreatingProvider, TestSize.Level1)
{
    int creates = 0;
    InlineGuardDelegate delegate([&](ClientStatusCallback, const std::string &, std::shared_ptr<Provider> &) {
        ++creates;
        return 0;
    });
    delegate.Stop();
    delegate.Stop();
    EXPECT_EQ(delegate.Start(), Status::UNAVAILABLE);
    EXPECT_EQ(delegate.Request({}, [](const SecurityGuardDelegate::Result &) {}), DispatchStatus::UNAVAILABLE);
    EXPECT_EQ(delegate.Request({}, {}), DispatchStatus::REJECTED);
    EXPECT_FALSE(delegate.IsReady());
    EXPECT_EQ(creates, 0);
}
/**
 * @tc.name: GetClientSnapshot_MultipleClientsAndEvents_IsOwnedCopy
 * @tc.desc: Verify public behavior, failure propagation and observable state.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(SecurityGuardDelegateTest, GetClientSnapshot_MultipleClientsAndEvents_IsOwnedCopy, TestSize.Level1)
{
    ClientStatusCallback publish;
    auto provider = std::make_shared<FakeAuthProvider>();
    InlineGuardDelegate delegate(
        [&](ClientStatusCallback callback, const std::string &, std::shared_ptr<Provider> &output) {
            publish = callback;
            output = provider;
            return 0;
        });
    ASSERT_EQ(delegate.Start(), Status::READY);
    std::vector<SecurityGuardDelegateImpl::Subscriber> clients = { { { 11, 12 }, Strategy::ALLOW, 100 },
        { { 11 }, Strategy::DENY, 400 }, { {}, Strategy::DENY, 10000 } };
    publish(clients);
    clients[0].timeoutMs = 999;
    auto snapshot = delegate.GetClientSnapshot();
    ASSERT_TRUE(snapshot.initialized);
    ASSERT_EQ(snapshot.policies.at(11).size(), 2u);
    ASSERT_EQ(snapshot.policies.at(12).size(), 1u);
    EXPECT_EQ(snapshot.policies.at(11)[0].timeoutMs, 100);
    EXPECT_EQ(snapshot.policies.at(11)[1].strategy, Strategy::DENY);
    EXPECT_FALSE(snapshot.HasSubscribers(13));
    snapshot.policies.clear();
    EXPECT_TRUE(delegate.GetClientSnapshot().HasSubscribers(11));
}
/**
 * @tc.name: Request_AfterOwnerDestruction_DropsLateResultAndStatus
 * @tc.desc: Verify public behavior, failure propagation and observable state.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(SecurityGuardDelegateTest, Request_AfterOwnerDestruction_DropsLateResultAndStatus, TestSize.Level1)
{
    ClientStatusCallback publish;
    auto provider = std::make_shared<FakeAuthProvider>();
    provider->respond_ = false;
    int completed = 0;
    {
        InlineGuardDelegate delegate(
            [&](ClientStatusCallback callback, const std::string &, std::shared_ptr<Provider> &output) {
                publish = callback;
                output = provider;
                return 0;
            });
        ASSERT_EQ(delegate.Start(), Status::READY);
        EXPECT_EQ(delegate.Request({}, [&](const SecurityGuardDelegate::Result &) { ++completed; }),
            DispatchStatus::DISPATCHED);
    }
    ASSERT_TRUE(static_cast<bool>(provider->saved_));
    ASSERT_TRUE(static_cast<bool>(publish));
    provider->saved_({ Strategy::ALLOW, {} });
    publish({ { { 11 }, Strategy::DENY, 400 } });
    EXPECT_EQ(completed, 0);
    EXPECT_EQ(provider->stops_, 1);
}
/**
 * @tc.name: Request_ProviderDecisions_AreForwardedWithoutBusinessMapping
 * @tc.desc: Verify public behavior, failure propagation and observable state.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(SecurityGuardDelegateTest, Request_ProviderDecisions_AreForwardedWithoutBusinessMapping, TestSize.Level1)
{
    auto provider = std::make_shared<FakeAuthProvider>();
    InlineGuardDelegate delegate([&](ClientStatusCallback, const std::string &, std::shared_ptr<Provider> &output) {
        output = provider;
        return 0;
    });
    ASSERT_EQ(delegate.Start(), Status::READY);
    std::vector<Strategy> actual;
    const std::vector<Strategy> expected = { Strategy::ALLOW, Strategy::DENY, Strategy::TIMEOUT, Strategy::ERROR };
    for (auto value : expected) {
        provider->result_ = value;
        EXPECT_EQ(delegate.Request({},
                      [&](const SecurityGuardDelegate::Result &result) { actual.push_back(result.mergedStrategy); }),
            DispatchStatus::DISPATCHED);
    }
    EXPECT_EQ(actual, expected);
    EXPECT_EQ(provider->requests_, static_cast<int>(expected.size()));
}
/**
 * @tc.name: Snapshot_ClientIdentity_PreservesEventAssociationAndCopies
 * @tc.desc: Full snapshot replacement retains subscriber identities without exposing SDK DTOs.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(SecurityGuardDelegateTest, Snapshot_ClientIdentity_PreservesEventAssociationAndCopies, TestSize.Level1)
{
    ClientStatusCallback publish;
    auto provider = std::make_shared<FakeAuthProvider>();
    InlineGuardDelegate delegate(
        [&](ClientStatusCallback callback, const std::string &, std::shared_ptr<Provider> &output) {
            publish = callback;
            output = provider;
            return 0;
        });
    ASSERT_EQ(delegate.Start(), Status::READY);
    publish({ { { 11, 12 }, Strategy::ALLOW, 400, "first" }, { { 11 }, Strategy::DENY, 400, "second" } });
    auto old = delegate.GetClientSnapshot();
    ASSERT_EQ(old.policies.at(11).size(), 2u);
    EXPECT_EQ(old.policies.at(11)[0].clientId, "first");
    EXPECT_EQ(old.policies.at(11)[1].clientId, "second");
    EXPECT_EQ(old.policies.at(12)[0].clientId, "first");
    publish({ { { 11 }, Strategy::ALLOW, 400, "replacement" } });
    EXPECT_EQ(delegate.GetClientSnapshot().policies.at(11)[0].clientId, "replacement");
    EXPECT_EQ(old.policies.at(11)[0].clientId, "first");
}

/**
 * @tc.name: Snapshot_UnsubscribeBetweenRequests_ChangesOnlyAffectedClientGeneration
 * @tc.desc: Retain unaffected generations but invalidate unsubscribe and policy changes even without a read.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(SecurityGuardDelegateTest, Snapshot_UnsubscribeBetweenRequests_ChangesOnlyAffectedClientGeneration,
    TestSize.Level1)
{
    ClientStatusCallback publish;
    auto provider = std::make_shared<FakeAuthProvider>();
    InlineGuardDelegate delegate(
        [&](ClientStatusCallback callback, const std::string &, std::shared_ptr<Provider> &output) {
            publish = callback;
            output = provider;
            return 0;
        });
    ASSERT_EQ(delegate.Start(), Status::READY);
    std::vector<SecurityGuardDelegateImpl::Subscriber> clients = { { { 11 }, Strategy::ALLOW, 400, "first" },
        { { 11 }, Strategy::ALLOW, 400, "second" } };
    publish(clients);
    auto old = delegate.GetClientSnapshot();
    publish(clients);
    EXPECT_EQ(delegate.GetClientSnapshot().policies.at(11)[0].generation, old.policies.at(11)[0].generation);
    publish({ clients[1] });
    publish(clients);
    auto replaced = delegate.GetClientSnapshot();
    EXPECT_GT(replaced.policies.at(11)[0].generation, old.policies.at(11)[0].generation);
    EXPECT_EQ(replaced.policies.at(11)[1].generation, old.policies.at(11)[1].generation);
    clients[0].timeoutMs = 500;
    publish(clients);
    EXPECT_GT(delegate.GetClientSnapshot().policies.at(11)[0].generation, replaced.policies.at(11)[0].generation);
}

/**
 * @tc.name: Request_DetailedResult_PreservesSubscriberObservations
 * @tc.desc: The generic adapter forwards detail without recomputing the merged decision.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(SecurityGuardDelegateTest, Request_DetailedResult_PreservesSubscriberObservations, TestSize.Level1)
{
    auto provider = std::make_shared<FakeAuthProvider>();
    provider->respond_ = false;
    InlineGuardDelegate delegate([&](ClientStatusCallback, const std::string &, std::shared_ptr<Provider> &output) {
        output = provider;
        return 0;
    });
    ASSERT_EQ(delegate.Start(), Status::READY);
    SecurityGuardDelegate::Result actual;
    ASSERT_EQ(delegate.Request({}, [&](const auto &result) { actual = result; }), DispatchStatus::DISPATCHED);
    ASSERT_TRUE(static_cast<bool>(provider->saved_));
    provider->saved_({ Strategy::DENY, { { "slow", Strategy::TIMEOUT }, { "blocking", Strategy::DENY } } });
    EXPECT_EQ(actual.mergedStrategy, Strategy::DENY);
    ASSERT_EQ(actual.clients.size(), 2u);
    EXPECT_EQ(actual.clients[0].clientId, "slow");
    EXPECT_EQ(actual.clients[0].strategy, Strategy::TIMEOUT);
    EXPECT_EQ(actual.clients[1].clientId, "blocking");
}

/**
 * @tc.name: Start_FirstRegistrationFails_LaterReadyNotificationRecovers
 * @tc.desc: Retry initial registration after SG becomes available without creating duplicate ready providers.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(SecurityGuardDelegateTest, Start_FirstRegistrationFails_LaterReadyNotificationRecovers, TestSize.Level1)
{
    int attempts = 0;
    auto provider = std::make_shared<FakeAuthProvider>();
    InlineGuardDelegate delegate([&](ClientStatusCallback, const std::string &, std::shared_ptr<Provider> &output) {
        if (++attempts == 1) {
            return -17;
        }
        output = provider;
        return 0;
    });
    EXPECT_EQ(delegate.Start(), Status::UNAVAILABLE);
    EXPECT_FALSE(delegate.IsReady());
    EXPECT_EQ(delegate.Start(), Status::READY);
    EXPECT_TRUE(delegate.IsReady());
    EXPECT_EQ(delegate.Start(), Status::READY);
    EXPECT_EQ(attempts, 2);
    EXPECT_EQ(delegate.Request({}, [](const auto &) {}), DispatchStatus::DISPATCHED);
    delegate.Stop();
    EXPECT_EQ(provider->stops_, 1);
}
/**
 * @tc.name: Start_FailedSessionCallback_CannotOverwriteRecoveredSnapshot
 * @tc.desc: Failed attempt snapshots and callbacks must not survive into a later provider session.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(SecurityGuardDelegateTest, Start_FailedSessionCallback_CannotOverwriteRecoveredSnapshot, TestSize.Level1)
{
    std::vector<ClientStatusCallback> callbacks;
    auto first = std::make_shared<FakeAuthProvider>();
    auto second = std::make_shared<FakeAuthProvider>();
    InlineGuardDelegate delegate(
        [&](ClientStatusCallback callback, const std::string &, std::shared_ptr<Provider> &output) {
            callbacks.push_back(callback);
            callback({ { { 11 }, Strategy::ALLOW, 400, "old" } });
            output = callbacks.size() == 1 ? first : second;
            return callbacks.size() == 1 ? -17 : 0;
        });
    ASSERT_EQ(delegate.Start(), Status::UNAVAILABLE);
    EXPECT_FALSE(delegate.GetClientSnapshot().initialized);
    ASSERT_EQ(callbacks.size(), 1u);
    callbacks[0]({ { { 12 }, Strategy::ALLOW, 400, "stale" } });
    EXPECT_FALSE(delegate.GetClientSnapshot().initialized);
    ASSERT_EQ(delegate.Start(), Status::READY);
    ASSERT_EQ(callbacks.size(), 2u);
    callbacks[1]({ { { 13 }, Strategy::DENY, 400, "current" } });
    auto snapshot = delegate.GetClientSnapshot();
    callbacks[0]({});
    EXPECT_EQ(delegate.GetClientSnapshot().version, snapshot.version);
    EXPECT_TRUE(delegate.GetClientSnapshot().HasSubscribers(13));
    EXPECT_FALSE(delegate.GetClientSnapshot().HasSubscribers(12));
    EXPECT_EQ(first->stops_, 1);
}

/**
 * @tc.name: Start_RetryRacesWithStop_CleansNewProviderAndRejectsFurtherStarts
 * @tc.desc: A retried registration must not resurrect the stopped singleton or leak its session.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(SecurityGuardDelegateTest, Start_RetryRacesWithStop_CleansNewProviderAndRejectsFurtherStarts, TestSize.Level1)
{
    std::promise<void> entered;
    std::promise<void> resume;
    auto gate = resume.get_future().share();
    auto provider = std::make_shared<FakeAuthProvider>();
    int attempts = 0;
    InlineGuardDelegate delegate([&](ClientStatusCallback, const std::string &, std::shared_ptr<Provider> &output) {
        if (++attempts == 1) {
            return -17;
        }
        entered.set_value();
        gate.wait();
        output = provider;
        return 0;
    });
    ASSERT_EQ(delegate.Start(), Status::UNAVAILABLE);
    auto retried = std::async(std::launch::async, [&] { return delegate.Start(); });
    entered.get_future().wait();
    EXPECT_EQ(delegate.Start(), Status::UNAVAILABLE);
    EXPECT_FALSE(delegate.GetClientSnapshot().initialized);
    delegate.Stop();
    resume.set_value();
    EXPECT_EQ(retried.get(), Status::UNAVAILABLE);
    EXPECT_EQ(delegate.Start(), Status::UNAVAILABLE);
    EXPECT_EQ(provider->stops_, 1);
    EXPECT_EQ(attempts, 2);
}

/**
 * @tc.name: Request_QueuedDispatch_CapsActualSdkCallsUntilReturn
 * @tc.desc: A blocked SDK call retains its permit after the receiver has stopped waiting.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(SecurityGuardDelegateTest, Request_QueuedDispatch_CapsActualSdkCallsUntilReturn, TestSize.Level1)
{
    std::vector<std::function<void()>> tasks;
    auto provider = std::make_shared<FakeAuthProvider>();
    SecurityGuardDelegateImpl delegate(
        [&](auto, const auto &, auto &output) {
            output = provider;
            return 0;
        },
        [&](auto task) {
            tasks.push_back(std::move(task));
            return true;
        });
    ASSERT_EQ(delegate.Start(), Status::READY);
    EXPECT_EQ(delegate.Request({}, [](const auto &) {}), DispatchStatus::DISPATCHED);
    EXPECT_EQ(delegate.Request({}, [](const auto &) {}), DispatchStatus::DISPATCHED);
    EXPECT_EQ(delegate.Request({}, [](const auto &) {}), DispatchStatus::BUSY);
    EXPECT_EQ(provider->requests_, 0);
    std::promise<void> entered;
    std::promise<void> release;
    auto gate = release.get_future().share();
    provider->onRequest_ = [&] {
        entered.set_value();
        gate.wait();
    };
    auto worker = std::async(std::launch::async, std::move(tasks[0]));
    entered.get_future().wait();
    EXPECT_EQ(delegate.Request({}, [](const auto &) {}), DispatchStatus::BUSY);
    release.set_value();
    worker.get();
    provider->onRequest_ = {};
    EXPECT_EQ(delegate.Request({}, [](const auto &) {}), DispatchStatus::DISPATCHED);
    tasks.clear();
    EXPECT_EQ(provider->requests_, 1);
}

/**
 * @tc.name: Request_ExpiredOrStoppedQueue_DoesNotCallSdk
 * @tc.desc: Expired and invalidated tasks are discarded; failed scheduling returns its slot.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(SecurityGuardDelegateTest, Request_ExpiredOrStoppedQueue_DoesNotCallSdk, TestSize.Level1)
{
    std::vector<std::function<void()>> tasks;
    auto provider = std::make_shared<FakeAuthProvider>();
    SecurityGuardDelegateImpl delegate([&](auto, const auto &, auto &output) {
        output = provider;
        return 0;
    });
    ASSERT_EQ(delegate.Start(), Status::READY);
    EXPECT_EQ(delegate.Request({}, [](const auto &) {}), DispatchStatus::UNAVAILABLE);
    delegate.BindTaskDispatcher([](auto) { return false; });
    for (int i = 0; i < 3; ++i) {
        EXPECT_EQ(delegate.Request({}, [](const auto &) {}), DispatchStatus::UNAVAILABLE);
    }
    delegate.BindTaskDispatcher([&](auto task) {
        tasks.push_back(std::move(task));
        return true;
    });
    Event expired;
    expired.deadline = std::chrono::steady_clock::now();
    EXPECT_EQ(delegate.Request(expired, [](const auto &) {}), DispatchStatus::DISPATCHED);
    tasks.back()();
    tasks.clear();
    EXPECT_EQ(delegate.Request({}, [](const auto &) {}), DispatchStatus::DISPATCHED);
    delegate.OnServiceUnavailable();
    tasks.back()();
    tasks.clear();
    EXPECT_EQ(provider->requests_, 0);
}

/**
 * @tc.name: Request_InlineResultBeforeRejection_ReportsAdmissionErrorOnce
 * @tc.desc: An inline ALLOW cannot override a rejected SDK admission or complete twice.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(SecurityGuardDelegateTest, Request_InlineResultBeforeRejection_ReportsAdmissionErrorOnce, TestSize.Level1)
{
    auto provider = std::make_shared<FakeAuthProvider>();
    provider->dispatch_ = DispatchStatus::REJECTED;
    InlineGuardDelegate delegate([&](auto, const auto &, auto &output) {
        output = provider;
        return 0;
    });
    ASSERT_EQ(delegate.Start(), Status::READY);
    int completed = 0;
    EXPECT_EQ(delegate.Request({},
                  [&](const auto &result) {
                      EXPECT_EQ(result.dispatchStatus, DispatchStatus::REJECTED);
                      ++completed;
                  }),
        DispatchStatus::DISPATCHED);
    provider->saved_({ Strategy::ALLOW, {} });
    EXPECT_EQ(completed, 1);
}

/**
 * @tc.name: Start_ServiceRestart_ReplacesSessionAndRejectsOldNotifications
 * @tc.desc: Local SG removal retires the ready provider even when its SDK recovery has stopped.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(SecurityGuardDelegateTest, Start_ServiceRestart_ReplacesSessionAndRejectsOldNotifications, TestSize.Level1)
{
    std::vector<ClientStatusCallback> subscriptions;
    std::vector<std::shared_ptr<FakeAuthProvider>> providers;
    InlineGuardDelegate delegate([&](auto callback, const auto &, auto &output) {
        subscriptions.push_back(callback);
        auto provider = std::make_shared<FakeAuthProvider>();
        providers.push_back(provider);
        output = provider;
        return 0;
    });
    ASSERT_EQ(delegate.Start(), Status::READY);
    subscriptions[0]({ { { 11 }, Strategy::ALLOW, 400, "old" } });
    delegate.OnServiceUnavailable();
    EXPECT_FALSE(delegate.IsReady());
    EXPECT_FALSE(delegate.GetClientSnapshot().initialized);
    EXPECT_TRUE(delegate.GetClientSnapshot().policies.empty());
    EXPECT_EQ(delegate.Start(), Status::UNAVAILABLE);
    delegate.OnServiceAvailable();
    ASSERT_EQ(delegate.Start(), Status::READY);
    EXPECT_EQ(providers[0]->stops_, 1);
    subscriptions[0]({ { { 11 }, Strategy::ALLOW, 400, "stale" } });
    EXPECT_TRUE(delegate.GetClientSnapshot().policies.empty());
    subscriptions[1]({ { { 11 }, Strategy::DENY, 400, "new" } });
    EXPECT_EQ(delegate.GetClientSnapshot().policies.at(11)[0].clientId, "new");
    EXPECT_EQ(delegate.Start(), Status::READY);
    EXPECT_EQ(providers.size(), 2u);
}

/**
 * @tc.name: Start_InvalidatedAttempt_CannotPublishOverNewSession
 * @tc.desc: A late registration result from an old SG lifetime must not replace the new provider.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(SecurityGuardDelegateTest, Start_InvalidatedAttempt_CannotPublishOverNewSession, TestSize.Level1)
{
    std::promise<void> entered;
    std::promise<void> release;
    auto gate = release.get_future().share();
    auto old = std::make_shared<FakeAuthProvider>();
    auto current = std::make_shared<FakeAuthProvider>();
    std::atomic<int> creates{ 0 };
    InlineGuardDelegate delegate([&](auto, const auto &, auto &output) {
        if (creates.fetch_add(1) == 0) {
            entered.set_value();
            gate.wait();
            output = old;
        } else {
            output = current;
        }
        return 0;
    });
    auto first = std::async(std::launch::async, [&] { return delegate.Start(); });
    entered.get_future().wait();
    delegate.OnServiceUnavailable();
    delegate.OnServiceAvailable();
    EXPECT_EQ(delegate.Start(), Status::READY);
    release.set_value();
    EXPECT_EQ(first.get(), Status::UNAVAILABLE);
    EXPECT_EQ(old->stops_, 1);
    EXPECT_TRUE(delegate.IsReady());
    EXPECT_EQ(delegate.Request({}, [](const auto &) {}), DispatchStatus::DISPATCHED);
    EXPECT_EQ(current->requests_, 1);
}

/**
 * @tc.name: Request_DuplicateInlineAndStoppedAsyncResult_CompletesAtMostOnce
 * @tc.desc: Buffer duplicate inline results and drop a pending result when its provider session stops.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(SecurityGuardDelegateTest, Request_DuplicateInlineAndStoppedAsyncResult_CompletesAtMostOnce, TestSize.Level1)
{
    auto provider = std::make_shared<FakeAuthProvider>();
    provider->duplicate_ = true;
    InlineGuardDelegate delegate([&](auto, const auto &, auto &output) {
        output = provider;
        return 0;
    });
    ASSERT_EQ(delegate.Start(), Status::READY);
    int completed = 0;
    EXPECT_EQ(delegate.Request({}, [&](const auto &) { ++completed; }), DispatchStatus::DISPATCHED);
    EXPECT_EQ(completed, 1);
    provider->respond_ = false;
    EXPECT_EQ(delegate.Request({}, [&](const auto &) { ++completed; }), DispatchStatus::DISPATCHED);
    delegate.Stop();
    delegate.OnServiceUnavailable();
    delegate.OnServiceAvailable();
    provider->saved_({ Strategy::ALLOW, {} });
    EXPECT_EQ(completed, 1);
    EXPECT_EQ(delegate.Start(), Status::UNAVAILABLE);
}

/**
 * @tc.name: Request_RepeatedInlineDispatch_CompletesOnce
 * @tc.desc: Repeated task execution cannot invoke a completion already consumed by an inline result.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(SecurityGuardDelegateTest, Request_RepeatedInlineDispatch_CompletesOnce, TestSize.Level1)
{
    auto provider = std::make_shared<FakeAuthProvider>();
    SecurityGuardDelegateImpl delegate(
        [&](auto, const auto &, auto &output) {
            output = provider;
            return 0;
        },
        [](auto task) {
            task();
            task();
            return true;
        });
    ASSERT_EQ(delegate.Start(), Status::READY);
    int32_t completed = 0;
    SecurityGuardDelegate::Result result;
    EXPECT_EQ(delegate.Request({},
        [&](const auto &response) {
            ++completed;
            result = response;
        }),
        DispatchStatus::DISPATCHED);
    EXPECT_EQ(provider->requests_, 2);
    EXPECT_EQ(completed, 1);
    EXPECT_EQ(result.dispatchStatus, DispatchStatus::DISPATCHED);
    EXPECT_EQ(result.mergedStrategy, Strategy::ALLOW);
}

/**
 * @tc.name: Request_RepeatedPendingDispatch_PreservesFirstAdmission
 * @tc.desc: Repeated admission cannot reject an accepted request that is still waiting for its callback.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(SecurityGuardDelegateTest, Request_RepeatedPendingDispatch_PreservesFirstAdmission, TestSize.Level1)
{
    auto provider = std::make_shared<FakeAuthProvider>();
    provider->respond_ = false;
    SecurityGuardDelegateImpl delegate(
        [&](auto, const auto &, auto &output) {
            output = provider;
            return 0;
        },
        [provider](auto task) {
            task();
            provider->dispatch_ = DispatchStatus::REJECTED;
            task();
            return true;
        });
    ASSERT_EQ(delegate.Start(), Status::READY);
    int32_t completed = 0;
    SecurityGuardDelegate::Result result;
    EXPECT_EQ(delegate.Request({},
                  [&](const auto &response) {
                      ++completed;
                      result = response;
                  }),
        DispatchStatus::DISPATCHED);
    EXPECT_EQ(provider->requests_, 2);
    EXPECT_EQ(completed, 0);
    ASSERT_TRUE(provider->saved_);
    provider->saved_({ Strategy::ALLOW, {} });
    provider->saved_({ Strategy::DENY, {} });
    EXPECT_EQ(completed, 1);
    EXPECT_EQ(result.dispatchStatus, DispatchStatus::DISPATCHED);
    EXPECT_EQ(result.mergedStrategy, Strategy::ALLOW);
}

/**
 * @tc.name: Request_OwnerDestroyedBeforeDispatch_DropsQueuedSdkCall
 * @tc.desc: Queued work owns its permit and provider but cannot issue SDK requests for a destroyed session.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(SecurityGuardDelegateTest, Request_OwnerDestroyedBeforeDispatch_DropsQueuedSdkCall, TestSize.Level1)
{
    auto provider = std::make_shared<FakeAuthProvider>();
    std::function<void()> queued;
    {
        SecurityGuardDelegateImpl delegate(
            [&](auto, const auto &, auto &output) {
                output = provider;
                return 0;
            },
            [&](auto task) {
                queued = std::move(task);
                return true;
            });
        ASSERT_EQ(delegate.Start(), Status::READY);
        EXPECT_EQ(delegate.Request({}, [](const auto &) {}), DispatchStatus::DISPATCHED);
    }
    ASSERT_TRUE(queued);
    queued();
    EXPECT_EQ(provider->requests_, 0);
    EXPECT_EQ(provider->stops_, 1);
}

} // namespace OHOS::DistributedData
