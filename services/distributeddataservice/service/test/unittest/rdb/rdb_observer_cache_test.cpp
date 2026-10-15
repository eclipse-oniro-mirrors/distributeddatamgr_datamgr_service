/**
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

#include "../../mock/general_store_mock.h"
#include "ipc_skeleton.h"
#include "mock/observer_cache_test_helper.h"
#include "rdb_service_impl.h"
#include "store/watcher_bridge.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS::DistributedData;
using namespace OHOS::DistributedData::Test;
using namespace OHOS::DistributedRdb;

namespace OHOS::Test {
// Extend the RDB suite's existing mock, avoiding its same-name framework mock.
class RdbObserverStoreMock : public GeneralStoreMock {
public:
    MOCK_METHOD(int32_t, AddRef, (), (override));
    MOCK_METHOD(int32_t, Release, (), (override));
    MOCK_METHOD(int32_t, Watch, (int32_t origin, Watcher &watcher), (override));
    MOCK_METHOD(int32_t, Close, (bool isForce), (override));
};
using ObserverCache = OHOS::DistributedData::Test::ObserverCache<RdbObserverStoreMock>;
class RdbObserverNotifierMock final : public RdbNotifierProxy {
public:
    RdbObserverNotifierMock() : RdbNotifierProxy(nullptr)
    {
    }
    MOCK_METHOD(int32_t, OnChange, (const Origin &, const PrimaryFields &, ChangeInfo &&), (override));
};

class RdbObserverCacheTest : public testing::Test {
public:
    static constexpr int32_t STORE_TYPE = 29;
    void SetUp() override
    {
        service_ = std::make_unique<RdbServiceImpl>();
        param_.bundleName_ = "observer.test";
        param_.storeName_ = "observer_cache_test";
        fixture_ = CreateFixture(IPCSkeleton::GetCallingTokenID());
    }
    void TearDown() override
    {
        fixture_.reset();
        service_.reset();
    }

    std::unique_ptr<ObserverCache> CreateFixture(uint32_t tokenId)
    {
        auto weakAgent = std::weak_ptr<RdbServiceImpl::ClientAgent>(service_->clientAgentHolder_);
        return std::make_unique<ObserverCache>(STORE_TYPE, tokenId, [weakAgent](const StoreMetaData &meta) {
            return [weakAgent, tokenId = meta.tokenId]() {
                auto agent = weakAgent.lock();
                return agent != nullptr ? agent->GetWatchers(tokenId) : AutoCache::Watchers{};
            };
        });
    }

    // Inject only the notifier transport; subscriptions are always made through public APIs.
    void BindNotifier(const sptr<RdbNotifierProxy> &notifier, pid_t pid = IPCSkeleton::GetCallingPid(),
        uint32_t tokenId = IPCSkeleton::GetCallingTokenID())
    {
        service_->clientAgent_.SetNotifier(tokenId, pid, "observer.test", notifier);
    }

    bool HasWatcherCache(uint32_t tokenId = IPCSkeleton::GetCallingTokenID()) const
    {
        std::shared_lock<std::shared_mutex> lock(service_->clientAgent_.mutex_);
        return service_->clientAgent_.watchers_.count(tokenId) != 0;
    }

    std::vector<std::weak_ptr<GeneralWatcher>> CachedWatchers(uint32_t tokenId = IPCSkeleton::GetCallingTokenID()) const
    {
        std::shared_lock<std::shared_mutex> lock(service_->clientAgent_.mutex_);
        auto it = service_->clientAgent_.watchers_.find(tokenId);
        return it != service_->clientAgent_.watchers_.end() ? it->second : std::vector<std::weak_ptr<GeneralWatcher>>{};
    }

    std::unique_ptr<RdbServiceImpl> service_;
    std::unique_ptr<ObserverCache> fixture_;
    RdbSyncerParam param_;
    SubscribeOption option_{};
};

/**
 * @tc.name: Subscribe_AfterOpenAndOff_UsesLatestSnapshot
 * @tc.desc: Existing delegates observe first on, last off, and a fresh on without taking a store again.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(RdbObserverCacheTest, Subscribe_AfterOpenAndOff_UsesLatestSnapshot, TestSize.Level1)
{
    auto store = AutoCache::GetInstance().GetStore(fixture_->meta);
    ASSERT_NE(store, nullptr);
    ASSERT_NE(fixture_->watcher, nullptr);
    sptr<RdbObserverNotifierMock> notifier = new RdbObserverNotifierMock();
    BindNotifier(notifier);
    EXPECT_CALL(*notifier, OnChange(_, _, _)).Times(2).WillRepeatedly(Return(RDB_OK));
    EXPECT_EQ(service_->Subscribe(param_, option_, nullptr), RDB_OK);
    EXPECT_EQ(fixture_->watcher->OnChange({}, GeneralWatcher::PRIFields{}, GeneralWatcher::ChangeInfo{}), E_OK);
    EXPECT_EQ(service_->UnSubscribe(param_, option_, nullptr), RDB_OK);
    EXPECT_EQ(fixture_->watcher->OnChange({}, GeneralWatcher::PRIFields{}, GeneralWatcher::ChangeInfo{}), E_OK);
    EXPECT_EQ(service_->Subscribe(param_, option_, nullptr), RDB_OK);
    EXPECT_EQ(fixture_->watcher->OnChange({}, GeneralWatcher::PRIFields{}, GeneralWatcher::ChangeInfo{}), E_OK);
}

/**
 * @tc.name: OnChange_UnchangedSubscriptions_ReusesWatcherSnapshot
 * @tc.desc: Repeated notifications and non-final unsubscribe reuse the cached weak watcher references.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(RdbObserverCacheTest, OnChange_UnchangedSubscriptions_ReusesWatcherSnapshot, TestSize.Level1)
{
    auto store = AutoCache::GetInstance().GetStore(fixture_->meta);
    ASSERT_NE(store, nullptr);
    ASSERT_NE(fixture_->watcher, nullptr);
    sptr<RdbObserverNotifierMock> notifier = new RdbObserverNotifierMock();
    BindNotifier(notifier);
    EXPECT_CALL(*notifier, OnChange(_, _, _)).Times(3).WillRepeatedly(Return(RDB_OK));
    EXPECT_EQ(service_->Subscribe(param_, option_, nullptr), RDB_OK);
    EXPECT_EQ(fixture_->watcher->OnChange({}, GeneralWatcher::PRIFields{}, GeneralWatcher::ChangeInfo{}), E_OK);
    auto snapshot = CachedWatchers();
    ASSERT_EQ(snapshot.size(), 1);
    ASSERT_FALSE(snapshot.front().expired());
    EXPECT_EQ(fixture_->watcher->OnChange({}, GeneralWatcher::PRIFields{}, GeneralWatcher::ChangeInfo{}), E_OK);
    ASSERT_EQ(CachedWatchers().size(), 1);
    EXPECT_EQ(CachedWatchers().front().lock(), snapshot.front().lock());
    EXPECT_EQ(service_->Subscribe(param_, option_, nullptr), RDB_OK);
    EXPECT_EQ(service_->UnSubscribe(param_, option_, nullptr), RDB_OK);
    EXPECT_TRUE(HasWatcherCache());
    EXPECT_EQ(fixture_->watcher->OnChange({}, GeneralWatcher::PRIFields{}, GeneralWatcher::ChangeInfo{}), E_OK);
    ASSERT_EQ(CachedWatchers().size(), 1);
    EXPECT_EQ(CachedWatchers().front().lock(), snapshot.front().lock());
}

/**
 * @tc.name: OnChange_CachedSubscriptions_DoesNotWaitForAgentMap
 * @tc.desc: A warm watcher cache forwards notifications while the agent map lock is held.
 * @tc.type: RELI
 * @tc.author: agent
 */
HWTEST_F(RdbObserverCacheTest, OnChange_CachedSubscriptions_DoesNotWaitForAgentMap, TestSize.Level1)
{
    auto store = AutoCache::GetInstance().GetStore(fixture_->meta);
    ASSERT_NE(store, nullptr);
    ASSERT_NE(fixture_->watcher, nullptr);
    sptr<RdbObserverNotifierMock> notifier = new RdbObserverNotifierMock();
    BindNotifier(notifier);
    EXPECT_CALL(*notifier, OnChange(_, _, _)).Times(2).WillRepeatedly(Return(RDB_OK));
    EXPECT_EQ(service_->Subscribe(param_, option_, nullptr), RDB_OK);
    EXPECT_EQ(fixture_->watcher->OnChange({}, GeneralWatcher::PRIFields{}, GeneralWatcher::ChangeInfo{}), E_OK);
    ASSERT_TRUE(HasWatcherCache());
    auto gate = std::make_shared<CloseGate>();
    auto tokenId = IPCSkeleton::GetCallingTokenID();
    auto blocker = std::async(std::launch::async, [agent = service_->clientAgentHolder_, gate, tokenId]() {
        return agent->agents_.ContainIf(tokenId, [gate](const auto &) {
            std::unique_lock<std::mutex> lock(gate->mutex);
            gate->entered = true;
            gate->condition.notify_all();
            gate->condition.wait(lock, [gate]() { return gate->released; });
            return true;
        });
    });
    EXPECT_TRUE(gate->WaitEntered());
    auto notify = std::async(std::launch::async, [watcher = fixture_->watcher]() {
        return watcher->OnChange({}, GeneralWatcher::PRIFields{}, GeneralWatcher::ChangeInfo{});
    });
    auto status = notify.wait_for(std::chrono::seconds(CloseGate::WAIT_SECONDS));
    gate->Release();
    EXPECT_TRUE(blocker.get());
    EXPECT_EQ(status, std::future_status::ready);
    EXPECT_EQ(notify.get(), E_OK);
}

/**
 * @tc.name: UnSubscribe_LastSubscription_InvalidatesWatcherSnapshot
 * @tc.desc: Last unsubscribe releases weakly cached watchers, then changes rebuild an empty or fresh cache.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(RdbObserverCacheTest, UnSubscribe_LastSubscription_InvalidatesWatcherSnapshot, TestSize.Level1)
{
    auto store = AutoCache::GetInstance().GetStore(fixture_->meta);
    ASSERT_NE(store, nullptr);
    ASSERT_NE(fixture_->watcher, nullptr);
    sptr<RdbObserverNotifierMock> notifier = new RdbObserverNotifierMock();
    BindNotifier(notifier);
    EXPECT_CALL(*notifier, OnChange(_, _, _)).Times(2).WillRepeatedly(Return(RDB_OK));
    EXPECT_EQ(service_->Subscribe(param_, option_, nullptr), RDB_OK);
    EXPECT_EQ(fixture_->watcher->OnChange({}, GeneralWatcher::PRIFields{}, GeneralWatcher::ChangeInfo{}), E_OK);
    auto snapshot = CachedWatchers();
    ASSERT_EQ(snapshot.size(), 1);
    ASSERT_FALSE(snapshot.front().expired());
    EXPECT_EQ(service_->UnSubscribe(param_, option_, nullptr), RDB_OK);
    EXPECT_FALSE(HasWatcherCache());
    EXPECT_TRUE(snapshot.front().expired());
    EXPECT_EQ(fixture_->watcher->OnChange({}, GeneralWatcher::PRIFields{}, GeneralWatcher::ChangeInfo{}), E_OK);
    EXPECT_TRUE(HasWatcherCache());
    EXPECT_TRUE(CachedWatchers().empty());
    EXPECT_EQ(service_->Subscribe(param_, option_, nullptr), RDB_OK);
    EXPECT_FALSE(HasWatcherCache());
    EXPECT_EQ(fixture_->watcher->OnChange({}, GeneralWatcher::PRIFields{}, GeneralWatcher::ChangeInfo{}), E_OK);
    auto renewedSnapshot = CachedWatchers();
    ASSERT_EQ(renewedSnapshot.size(), 1);
    EXPECT_FALSE(renewedSnapshot.front().expired());
    EXPECT_TRUE(snapshot.front().expired());
}

/**
 * @tc.name: OnChange_NotifierReplaced_ReusesSnapshotAndNotifiesLatestClient
 * @tc.desc: Updating a PID's notifier keeps its watcher snapshot but routes changes to the new notifier.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(RdbObserverCacheTest, OnChange_NotifierReplaced_ReusesSnapshotAndNotifiesLatestClient, TestSize.Level1)
{
    auto store = AutoCache::GetInstance().GetStore(fixture_->meta);
    ASSERT_NE(store, nullptr);
    ASSERT_NE(fixture_->watcher, nullptr);
    sptr<RdbObserverNotifierMock> first = new RdbObserverNotifierMock();
    sptr<RdbObserverNotifierMock> second = new RdbObserverNotifierMock();
    BindNotifier(first);
    EXPECT_CALL(*first, OnChange(_, _, _)).Times(1).WillOnce(Return(RDB_OK));
    EXPECT_CALL(*second, OnChange(_, _, _)).Times(1).WillOnce(Return(RDB_OK));
    EXPECT_EQ(service_->Subscribe(param_, option_, nullptr), RDB_OK);
    EXPECT_EQ(fixture_->watcher->OnChange({}, GeneralWatcher::PRIFields{}, GeneralWatcher::ChangeInfo{}), E_OK);
    auto snapshot = CachedWatchers();
    ASSERT_EQ(snapshot.size(), 1);
    ASSERT_FALSE(snapshot.front().expired());
    BindNotifier(second);
    EXPECT_TRUE(HasWatcherCache());
    EXPECT_EQ(fixture_->watcher->OnChange({}, GeneralWatcher::PRIFields{}, GeneralWatcher::ChangeInfo{}), E_OK);
    ASSERT_EQ(CachedWatchers().size(), 1);
    EXPECT_EQ(CachedWatchers().front().lock(), snapshot.front().lock());
}

/**
 * @tc.name: OnAppExit_ActiveSubscription_InvalidatesWatcherSnapshot
 * @tc.desc: Client exit clears the notifier and retires the cached subscription before later changes.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(RdbObserverCacheTest, OnAppExit_ActiveSubscription_InvalidatesWatcherSnapshot, TestSize.Level1)
{
    auto store = AutoCache::GetInstance().GetStore(fixture_->meta);
    ASSERT_NE(store, nullptr);
    ASSERT_NE(fixture_->watcher, nullptr);
    sptr<RdbObserverNotifierMock> notifier = new RdbObserverNotifierMock();
    BindNotifier(notifier);
    EXPECT_CALL(*notifier, OnChange(_, _, _)).Times(1).WillOnce(Return(RDB_OK));
    EXPECT_EQ(service_->Subscribe(param_, option_, nullptr), RDB_OK);
    EXPECT_EQ(fixture_->watcher->OnChange({}, GeneralWatcher::PRIFields{}, GeneralWatcher::ChangeInfo{}), E_OK);
    auto tokenId = IPCSkeleton::GetCallingTokenID();
    auto snapshot = CachedWatchers();
    ASSERT_EQ(snapshot.size(), 1);
    ASSERT_FALSE(snapshot.front().expired());
    EXPECT_EQ(service_->OnAppExit(0, IPCSkeleton::GetCallingPid(), tokenId, param_.bundleName_), E_OK);
    EXPECT_FALSE(HasWatcherCache());
    EXPECT_TRUE(snapshot.front().expired());
    EXPECT_FALSE(service_->clientAgent_.agents_.Contains(tokenId));
    EXPECT_EQ(fixture_->watcher->OnChange({}, GeneralWatcher::PRIFields{}, GeneralWatcher::ChangeInfo{}), E_OK);
}

/**
 * @tc.name: OnAppExit_OtherTokenSubscribed_LeavesOtherSnapshotIntact
 * @tc.desc: Removing one token does not invalidate or forward notifications to another token's clients.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(RdbObserverCacheTest, OnAppExit_OtherTokenSubscribed_LeavesOtherSnapshotIntact, TestSize.Level1)
{
    auto &cache = AutoCache::GetInstance();
    auto store = cache.GetStore(fixture_->meta);
    ASSERT_NE(store, nullptr);
    ASSERT_NE(fixture_->watcher, nullptr);
    auto tokenId = IPCSkeleton::GetCallingTokenID();
    auto otherToken = ~tokenId;
    auto otherFixture = CreateFixture(otherToken);
    auto otherStore = cache.GetStore(otherFixture->meta);
    ASSERT_NE(otherStore, nullptr);
    ASSERT_NE(otherFixture->watcher, nullptr);
    sptr<RdbObserverNotifierMock> first = new RdbObserverNotifierMock();
    sptr<RdbObserverNotifierMock> second = new RdbObserverNotifierMock();
    auto pid = IPCSkeleton::GetCallingPid();
    BindNotifier(first);
    BindNotifier(second, pid, otherToken);
    EXPECT_CALL(*first, OnChange(_, _, _)).Times(1).WillOnce(Return(RDB_OK));
    EXPECT_CALL(*second, OnChange(_, _, _)).Times(2).WillRepeatedly(Return(RDB_OK));
    EXPECT_EQ(service_->Subscribe(param_, option_, nullptr), RDB_OK);
    service_->clientAgent_.Subscribe(otherToken, pid, param_.bundleName_);
    EXPECT_EQ(fixture_->watcher->OnChange({}, GeneralWatcher::PRIFields{}, GeneralWatcher::ChangeInfo{}), E_OK);
    EXPECT_EQ(otherFixture->watcher->OnChange({}, GeneralWatcher::PRIFields{}, GeneralWatcher::ChangeInfo{}), E_OK);
    auto snapshot = CachedWatchers(otherToken);
    ASSERT_EQ(snapshot.size(), 1);
    ASSERT_FALSE(snapshot.front().expired());
    EXPECT_EQ(service_->OnAppExit(0, pid, tokenId, param_.bundleName_), E_OK);
    EXPECT_FALSE(service_->clientAgent_.agents_.Contains(tokenId));
    EXPECT_TRUE(service_->clientAgent_.agents_.Contains(otherToken));
    ASSERT_EQ(CachedWatchers(otherToken).size(), 1);
    EXPECT_EQ(CachedWatchers(otherToken).front().lock(), snapshot.front().lock());
    EXPECT_EQ(fixture_->watcher->OnChange({}, GeneralWatcher::PRIFields{}, GeneralWatcher::ChangeInfo{}), E_OK);
    EXPECT_EQ(otherFixture->watcher->OnChange({}, GeneralWatcher::PRIFields{}, GeneralWatcher::ChangeInfo{}), E_OK);
}

/**
 * @tc.name: OnAppExit_Resubscribe_RestoresIndexedSubscription
 * @tc.desc: Re-subscribing after the last PID exits creates a fresh watcher without reviving retired watchers.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(RdbObserverCacheTest, OnAppExit_Resubscribe_RestoresIndexedSubscription, TestSize.Level1)
{
    auto store = AutoCache::GetInstance().GetStore(fixture_->meta);
    ASSERT_NE(store, nullptr);
    ASSERT_NE(fixture_->watcher, nullptr);
    sptr<RdbObserverNotifierMock> notifier = new RdbObserverNotifierMock();
    BindNotifier(notifier);
    EXPECT_CALL(*notifier, OnChange(_, _, _)).Times(2).WillRepeatedly(Return(RDB_OK));
    EXPECT_EQ(service_->Subscribe(param_, option_, nullptr), RDB_OK);
    EXPECT_EQ(fixture_->watcher->OnChange({}, GeneralWatcher::PRIFields{}, GeneralWatcher::ChangeInfo{}), E_OK);
    auto tokenId = IPCSkeleton::GetCallingTokenID();
    auto snapshot = CachedWatchers();
    ASSERT_EQ(snapshot.size(), 1);
    ASSERT_FALSE(snapshot.front().expired());
    EXPECT_EQ(service_->OnAppExit(0, IPCSkeleton::GetCallingPid(), tokenId, param_.bundleName_), E_OK);
    EXPECT_FALSE(service_->clientAgent_.agents_.Contains(tokenId));
    EXPECT_TRUE(snapshot.front().expired());
    BindNotifier(notifier);
    EXPECT_EQ(service_->Subscribe(param_, option_, nullptr), RDB_OK);
    EXPECT_TRUE(service_->clientAgent_.agents_.Contains(tokenId));
    EXPECT_EQ(fixture_->watcher->OnChange({}, GeneralWatcher::PRIFields{}, GeneralWatcher::ChangeInfo{}), E_OK);
    auto renewedSnapshot = CachedWatchers();
    ASSERT_EQ(renewedSnapshot.size(), 1);
    EXPECT_FALSE(renewedSnapshot.front().expired());
    EXPECT_TRUE(snapshot.front().expired());
}

/**
 * @tc.name: Subscribe_CloseBlocked_ReturnsBeforeRelease
 * @tc.desc: Both observer on and off finish while a fake Close holds the cache map lock.
 * @tc.type: RELI
 * @tc.author: agent
 */
HWTEST_F(RdbObserverCacheTest, Subscribe_CloseBlocked_ReturnsBeforeRelease, TestSize.Level1)
{
    auto store = AutoCache::GetInstance().GetStore(fixture_->meta);
    ASSERT_NE(store, nullptr);
    fixture_->StartClose();
    ASSERT_TRUE(fixture_->WaitCloseEntered());
    auto request = std::async(std::launch::async, [service = service_.get(), param = param_, option = option_]() {
        auto on = service->Subscribe(param, option, nullptr);
        auto off = service->UnSubscribe(param, option, nullptr);
        return std::pair{ on, off };
    });
    EXPECT_EQ(request.wait_for(std::chrono::seconds(3)), std::future_status::ready);
    fixture_->FinishClose();
    auto [on, off] = request.get();
    EXPECT_EQ(on, RDB_OK);
    EXPECT_EQ(off, RDB_OK);
}

/**
 * @tc.name: OnChange_ServiceDestroyed_StopsForwarding
 * @tc.desc: A retained delegate safely handles a cleared or expired ClientAgent after service destruction.
 * @tc.type: RELI
 * @tc.author: agent
 */
HWTEST_F(RdbObserverCacheTest, OnChange_ServiceDestroyed_StopsForwarding, TestSize.Level2)
{
    auto store = AutoCache::GetInstance().GetStore(fixture_->meta);
    ASSERT_NE(store, nullptr);
    ASSERT_NE(fixture_->watcher, nullptr);
    sptr<RdbObserverNotifierMock> notifier = new RdbObserverNotifierMock();
    BindNotifier(notifier);
    EXPECT_CALL(*notifier, OnChange(_, _, _)).Times(1).WillOnce(Return(RDB_OK));
    EXPECT_EQ(service_->Subscribe(param_, option_, nullptr), RDB_OK);
    EXPECT_EQ(fixture_->watcher->OnChange({}, GeneralWatcher::PRIFields{}, GeneralWatcher::ChangeInfo{}), E_OK);
    auto snapshot = CachedWatchers();
    ASSERT_EQ(snapshot.size(), 1);
    ASSERT_FALSE(snapshot.front().expired());
    auto agent = service_->clientAgentHolder_;
    service_.reset();
    EXPECT_TRUE(agent->agents_.Empty());
    EXPECT_TRUE(snapshot.front().expired());
    {
        std::shared_lock<std::shared_mutex> lock(agent->mutex_);
        EXPECT_TRUE(agent->watchers_.empty());
    }
    EXPECT_EQ(fixture_->watcher->OnChange({}, GeneralWatcher::PRIFields{}, GeneralWatcher::ChangeInfo{}), E_OK);
    agent.reset();
    EXPECT_EQ(fixture_->watcher->OnChange({}, GeneralWatcher::PRIFields{}, GeneralWatcher::ChangeInfo{}), E_OK);
}
} // namespace OHOS::Test
