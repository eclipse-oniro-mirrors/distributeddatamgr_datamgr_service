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
        auto weakAgents = std::weak_ptr<RdbServiceImpl::SyncAgentMap>(service_->syncAgents_);
        fixture_ = std::make_unique<ObserverCache>(
            STORE_TYPE, IPCSkeleton::GetCallingTokenID(), [weakAgents](const StoreMetaData &meta) {
                return std::make_shared<WatcherBridge>([weakAgents, tokenId = meta.tokenId]() {
                    return RdbServiceImpl::GetWatchers(weakAgents.lock(), tokenId);
                });
            });
    }
    void TearDown() override
    {
        fixture_.reset();
        service_.reset();
    }

    // Inject only the notifier transport; subscriptions are always made through public APIs.
    void BindNotifier(const sptr<RdbNotifierProxy> &notifier, pid_t pid = IPCSkeleton::GetCallingPid())
    {
        service_->syncAgents_->Compute(
            IPCSkeleton::GetCallingTokenID(), [notifier, pid](auto, RdbServiceImpl::SyncAgents &agents) {
                auto [it, inserted] = agents.try_emplace(pid, "observer.test");
                it->second.SetNotifier(notifier);
                return true;
            });
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
    auto store = AutoCache::GetInstance().GetStore(fixture_->meta, {});
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
 * @tc.name: Subscribe_CloseBlocked_ReturnsBeforeRelease
 * @tc.desc: Both observer on and off finish while a fake Close holds the cache map lock.
 * @tc.type: RELI
 * @tc.author: agent
 */
HWTEST_F(RdbObserverCacheTest, Subscribe_CloseBlocked_ReturnsBeforeRelease, TestSize.Level1)
{
    auto store = AutoCache::GetInstance().GetStore(fixture_->meta, {});
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
 * @tc.desc: A retained delegate safely handles a cleared or expired shared agent map after service destruction.
 * @tc.type: RELI
 * @tc.author: agent
 */
HWTEST_F(RdbObserverCacheTest, OnChange_ServiceDestroyed_StopsForwarding, TestSize.Level2)
{
    auto store = AutoCache::GetInstance().GetStore(fixture_->meta, {});
    ASSERT_NE(store, nullptr);
    ASSERT_NE(fixture_->watcher, nullptr);
    sptr<RdbObserverNotifierMock> notifier = new RdbObserverNotifierMock();
    BindNotifier(notifier);
    EXPECT_CALL(*notifier, OnChange(_, _, _)).Times(0);
    EXPECT_EQ(service_->Subscribe(param_, option_, nullptr), RDB_OK);
    auto syncAgents = service_->syncAgents_;
    service_.reset();
    EXPECT_TRUE(syncAgents->Empty());
    EXPECT_EQ(fixture_->watcher->OnChange({}, GeneralWatcher::PRIFields{}, GeneralWatcher::ChangeInfo{}), E_OK);
    syncAgents.reset();
    EXPECT_EQ(fixture_->watcher->OnChange({}, GeneralWatcher::PRIFields{}, GeneralWatcher::ChangeInfo{}), E_OK);
}
} // namespace OHOS::Test
