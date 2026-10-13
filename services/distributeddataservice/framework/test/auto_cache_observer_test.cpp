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

#include "mock/general_watcher_mock.h"
#include "mock/observer_cache_test_helper.h"
#include "store/watcher_bridge.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS::DistributedData;
using namespace OHOS::DistributedData::Test;

namespace OHOS::Test {
class AutoCacheObserverTest : public testing::Test {
public:
    static constexpr int32_t STORE_TYPE = 29;
    static constexpr uint32_t TOKEN_ID = 4294967000;
};

/**
 * @tc.name: GetDBStore_DynamicWatcher_TracksCurrentSubscriptions
 * @tc.desc: Cloud-style empty open and cache hits retain a single forwarding watcher.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(AutoCacheObserverTest, GetDBStore_DynamicWatcher_TracksCurrentSubscriptions, TestSize.Level1)
{
    auto subscriptions = std::make_shared<AutoCache::Watchers>();
    ObserverCache fixture(STORE_TYPE, TOKEN_ID, [subscriptions](const auto &) {
        return std::make_shared<WatcherBridge>([subscriptions]() { return *subscriptions; });
    });
    ASSERT_EQ(fixture.registration, E_OK);
    auto &cache = AutoCache::GetInstance();
    auto [status, store] = cache.GetDBStore(fixture.meta, {});
    ASSERT_EQ(status, E_OK);
    ASSERT_NE(store, nullptr);
    ASSERT_NE(fixture.watcher, nullptr);
    auto client = std::make_shared<GeneralWatcherMock>();
    auto ignored = std::make_shared<GeneralWatcherMock>();
    EXPECT_CALL(*client, OnChange(_, A<const GeneralWatcher::PRIFields &>(), _)).Times(2).WillRepeatedly(Return(E_OK));
    EXPECT_CALL(*ignored, OnChange(_, A<const GeneralWatcher::PRIFields &>(), _)).Times(0);
    EXPECT_EQ(fixture.watcher->OnChange({}, GeneralWatcher::PRIFields{}, GeneralWatcher::ChangeInfo{}), E_OK);
    subscriptions->insert(client);
    EXPECT_EQ(fixture.watcher->OnChange({}, GeneralWatcher::PRIFields{}, GeneralWatcher::ChangeInfo{}), E_OK);
    EXPECT_EQ(cache.GetDBStore(fixture.meta, { ignored }).second.get(), store.get());
    cache.SetObserver(TOKEN_ID, { ignored }, fixture.meta.dataDir, fixture.meta.storeId);
    subscriptions->clear();
    EXPECT_EQ(fixture.watcher->OnChange({}, GeneralWatcher::PRIFields{}, GeneralWatcher::ChangeInfo{}), E_OK);
    subscriptions->insert(client);
    EXPECT_EQ(fixture.watcher->OnChange({}, GeneralWatcher::PRIFields{}, GeneralWatcher::ChangeInfo{}), E_OK);
}

/**
 * @tc.name: GetDBStore_NullForwarder_FailsBeforeOpening
 * @tc.desc: A broken watcher factory must not silently open an unobserved store.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(AutoCacheObserverTest, GetDBStore_NullForwarder_FailsBeforeOpening, TestSize.Level2)
{
    ObserverCache fixture(
        STORE_TYPE, TOKEN_ID, [](const auto &) -> std::shared_ptr<GeneralWatcher> { return nullptr; });
    auto [status, store] = AutoCache::GetInstance().GetDBStore(fixture.meta, {});
    EXPECT_EQ(status, E_ERROR);
    EXPECT_EQ(store, nullptr);
    EXPECT_EQ(fixture.watcher, nullptr);
}

/**
 * @tc.name: RegCreator_LegacyRegistration_ClearsDynamicFactory
 * @tc.desc: Two-argument registration resets the forwarding configuration and keeps legacy updates.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(AutoCacheObserverTest, RegCreator_LegacyRegistration_ClearsDynamicFactory, TestSize.Level1)
{
    ObserverCache fixture(STORE_TYPE, TOKEN_ID, [](const auto &) { return std::make_shared<WatcherBridge>(nullptr); });
    auto &cache = AutoCache::GetInstance();
    AutoCache::Creator creator;
    {
        std::lock_guard<std::mutex> lock(cache.factoryMutex_);
        creator = cache.factories_[STORE_TYPE].creator;
    }
    EXPECT_EQ(cache.RegCreator(STORE_TYPE, creator), E_OK);
    auto first = std::make_shared<GeneralWatcherMock>();
    auto second = std::make_shared<GeneralWatcherMock>();
    auto store = cache.GetStore(fixture.meta, { first });
    ASSERT_NE(store, nullptr);
    ASSERT_NE(fixture.watcher, nullptr);
    EXPECT_CALL(*first, OnChange(_, A<const GeneralWatcher::PRIFields &>(), _)).Times(1).WillOnce(Return(E_OK));
    EXPECT_CALL(*second, OnChange(_, A<const GeneralWatcher::PRIFields &>(), _)).Times(1).WillOnce(Return(E_OK));
    EXPECT_EQ(fixture.watcher->OnChange({}, GeneralWatcher::PRIFields{}, GeneralWatcher::ChangeInfo{}), E_OK);
    cache.SetObserver(TOKEN_ID, { second }, fixture.meta.dataDir, fixture.meta.storeId);
    EXPECT_EQ(fixture.watcher->OnChange({}, GeneralWatcher::PRIFields{}, GeneralWatcher::ChangeInfo{}), E_OK);
}

/**
 * @tc.name: RegCreator_InvalidType_ReturnsError
 * @tc.desc: The new overload validates both index boundaries.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(AutoCacheObserverTest, RegCreator_InvalidType_ReturnsError, TestSize.Level2)
{
    auto &cache = AutoCache::GetInstance();
    EXPECT_EQ(cache.RegCreator(-1, nullptr, nullptr), E_ERROR);
    EXPECT_EQ(cache.RegCreator(30, nullptr, nullptr), E_ERROR);
}
} // namespace OHOS::Test
