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

#include "account_delegate_mock.h"
#include "ipc_skeleton.h"
#include "kvdb_service_impl.h"
#include "mock/access_token_mock.h"
#include "mock/meta_data_manager_mock.h"
#include "mock/observer_cache_test_helper.h"
#include "store/watcher_bridge.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS::DistributedData;
using namespace OHOS::DistributedData::Test;
using namespace OHOS::DistributedKv;
using namespace OHOS::Security::AccessToken;

namespace OHOS::Test {
class KvObserverMock final : public KvStoreObserverStub {
public:
    MOCK_METHOD(void, OnChange, (const ChangeNotification &), (override));
    MOCK_METHOD(void, OnChange, (const DataOrigin &, Keys &&), (override));
};

class KvObserverCacheTest : public testing::Test {
public:
    static constexpr int32_t STORE_TYPE = 29;
    void SetUp() override
    {
        savedAccount_ = AccountDelegate::instance_;
        savedMeta_ = BMetaDataManager::metaDataManager;
        savedToken_ = BAccessTokenKit::accessTokenkit;
        account_ = std::make_shared<NiceMock<AccountDelegateMock>>();
        AccountDelegate::instance_ = account_.get();
        ON_CALL(*account_, GetUserByToken(_)).WillByDefault(Return(0));
        BMetaDataManager::metaDataManager = std::make_shared<NiceMock<MetaDataManagerMock>>();
        auto token = std::make_shared<NiceMock<AccessTokenKitMock>>();
        ON_CALL(*token, GetTokenTypeFlag(_)).WillByDefault(Return(TOKEN_NATIVE));
        BAccessTokenKit::accessTokenkit = token;
        service_ = std::make_unique<KVDBServiceImpl>();
        auto weakRegistry = std::weak_ptr<KVDBServiceImpl::SyncAgentRegistry>(service_->registry_);
        fixture_ = std::make_unique<ObserverCache>(
            STORE_TYPE, IPCSkeleton::GetCallingTokenID(), [weakRegistry](const StoreMetaData &meta) {
                return std::make_shared<WatcherBridge>(
                    [weakRegistry, tokenId = meta.tokenId, key = meta.user + "###" + meta.storeId]() {
                        auto registry = weakRegistry.lock();
                        return registry == nullptr ? AutoCache::Watchers{} : registry->GetWatchers(tokenId, key);
                    });
            });
    }
    void TearDown() override
    {
        fixture_.reset();
        service_.reset();
        AccountDelegate::instance_ = savedAccount_;
        BMetaDataManager::metaDataManager = savedMeta_;
        BAccessTokenKit::accessTokenkit = savedToken_;
        account_.reset();
    }
    int32_t Notify()
    {
        GeneralWatcher::Origin origin;
        origin.store = storeId_.storeId;
        GeneralWatcher::ChangeInfo info;
        info[origin.store][GeneralWatcher::OP_INSERT].emplace_back(std::string("key"));
        return fixture_->watcher->OnChange(origin, GeneralWatcher::PRIFields{}, std::move(info));
    }

    AppId appId_{ "observer.test" };
    StoreId storeId_{ "observer_cache_test" };
    std::unique_ptr<KVDBServiceImpl> service_;
    std::unique_ptr<ObserverCache> fixture_;

private:
    AccountDelegate *savedAccount_ = nullptr;
    std::shared_ptr<BMetaDataManager> savedMeta_;
    std::shared_ptr<BAccessTokenKit> savedToken_;
    std::shared_ptr<AccountDelegateMock> account_;
};

/**
 * @tc.name: Subscribe_MultipleObservers_RemovesOnlyTarget
 * @tc.desc: Late subscriptions and complete unsubscribe cycles update an existing delegate immediately.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(KvObserverCacheTest, Subscribe_MultipleObservers_RemovesOnlyTarget, TestSize.Level1)
{
    auto store = AutoCache::GetInstance().GetStore(fixture_->meta, {});
    ASSERT_NE(store, nullptr);
    ASSERT_NE(fixture_->watcher, nullptr);
    sptr<KvObserverMock> first = new KvObserverMock();
    sptr<KvObserverMock> second = new KvObserverMock();
    EXPECT_CALL(*first, OnChange(A<const DataOrigin &>(), _)).Times(1);
    EXPECT_CALL(*second, OnChange(A<const DataOrigin &>(), _)).Times(3);
    EXPECT_EQ(service_->Subscribe(appId_, storeId_, 0, first), SUCCESS);
    EXPECT_EQ(service_->Subscribe(appId_, storeId_, 0, second), SUCCESS);
    EXPECT_EQ(Notify(), E_OK);
    EXPECT_EQ(service_->Unsubscribe(appId_, storeId_, 0, first), SUCCESS);
    EXPECT_EQ(Notify(), E_OK);
    EXPECT_EQ(service_->Unsubscribe(appId_, storeId_, 0, second), SUCCESS);
    EXPECT_EQ(Notify(), E_OK);
    EXPECT_EQ(service_->Subscribe(appId_, storeId_, 0, second), SUCCESS);
    EXPECT_EQ(Notify(), E_OK);
}

/**
 * @tc.name: Subscribe_CloseBlocked_ReturnsBeforeRelease
 * @tc.desc: Normal KV on and off do not wait for the cache close lock; AutoLaunch metadata is absent.
 * @tc.type: RELI
 * @tc.author: agent
 */
HWTEST_F(KvObserverCacheTest, Subscribe_CloseBlocked_ReturnsBeforeRelease, TestSize.Level1)
{
    auto store = AutoCache::GetInstance().GetStore(fixture_->meta, {});
    ASSERT_NE(store, nullptr);
    sptr<KvObserverMock> observer = new KvObserverMock();
    fixture_->StartClose();
    ASSERT_TRUE(fixture_->WaitCloseEntered());
    auto request =
        std::async(std::launch::async, [service = service_.get(), app = appId_, storeId = storeId_, observer]() {
            auto on = service->Subscribe(app, storeId, 0, observer);
            auto off = service->Unsubscribe(app, storeId, 0, observer);
            return std::pair{ on, off };
        });
    EXPECT_EQ(request.wait_for(std::chrono::seconds(3)), std::future_status::ready);
    fixture_->FinishClose();
    auto [on, off] = request.get();
    EXPECT_EQ(on, SUCCESS);
    EXPECT_EQ(off, SUCCESS);
}

/**
 * @tc.name: OnChange_DifferentUserOrDestroyedService_DoesNotNotify
 * @tc.desc: Store identity is bound at open time and a destroyed service stops new notifications.
 * @tc.type: RELI
 * @tc.author: agent
 */
HWTEST_F(KvObserverCacheTest, OnChange_DifferentUserOrDestroyedService_DoesNotNotify, TestSize.Level2)
{
    auto store = AutoCache::GetInstance().GetStore(fixture_->meta, {});
    ASSERT_NE(store, nullptr);
    ASSERT_NE(fixture_->watcher, nullptr);
    auto matchingWatcher = fixture_->watcher;
    sptr<KvObserverMock> observer = new KvObserverMock();
    EXPECT_CALL(*observer, OnChange(A<const DataOrigin &>(), _)).Times(1);
    EXPECT_EQ(service_->Subscribe(appId_, storeId_, 0, observer), SUCCESS);
    EXPECT_EQ(Notify(), E_OK);
    auto otherMeta = fixture_->meta;
    otherMeta.storeId = "different_store";
    otherMeta.user = "200";
    auto otherStore = AutoCache::GetInstance().GetStore(otherMeta, {});
    ASSERT_NE(otherStore, nullptr);
    EXPECT_EQ(Notify(), E_OK);
    auto registry = service_->registry_;
    service_.reset();
    EXPECT_FALSE(registry->active);
    GeneralWatcher::Origin origin;
    origin.store = storeId_.storeId;
    GeneralWatcher::ChangeInfo info;
    info[origin.store][GeneralWatcher::OP_INSERT].emplace_back(std::string("key"));
    EXPECT_EQ(matchingWatcher->OnChange(origin, GeneralWatcher::PRIFields{}, std::move(info)), E_OK);
}
} // namespace OHOS::Test
