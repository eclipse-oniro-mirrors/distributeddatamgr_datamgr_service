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

#include "store/watcher_bridge.h"

#include <gtest/gtest.h>

#include "mock/general_watcher_mock.h"
#include "mock/observer_cache_test_helper.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS::DistributedData;
using namespace OHOS::DistributedData::Test;

namespace OHOS::Test {
class WatcherBridgeTest : public testing::Test {};

/**
 * @tc.name: OnChange_EmptyGetter_ReturnsSuccess
 * @tc.desc: Both overloads tolerate an empty getter.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(WatcherBridgeTest, OnChange_EmptyGetter_ReturnsSuccess, TestSize.Level2)
{
    WatcherBridge bridge(nullptr);
    EXPECT_EQ(bridge.OnChange({}, GeneralWatcher::PRIFields{}, GeneralWatcher::ChangeInfo{}), E_OK);
    EXPECT_EQ(bridge.OnChange({}, GeneralWatcher::Fields{}, GeneralWatcher::ChangeData{}), E_OK);
}

/**
 * @tc.name: OnChange_MultipleWatchers_PreservesBothPayloads
 * @tc.desc: All non-null receivers get complete data even when a receiver returns an error.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(WatcherBridgeTest, OnChange_MultipleWatchers_PreservesBothPayloads, TestSize.Level1)
{
    auto first = std::make_shared<GeneralWatcherMock>();
    auto second = std::make_shared<GeneralWatcherMock>();
    auto queries = std::make_shared<int32_t>(0);
    WatcherBridge bridge([first, second, queries]() {
        ++(*queries);
        return WatcherBridge::Watchers{ nullptr, first, second };
    });
    GeneralWatcher::ChangeInfo info;
    info["table"][GeneralWatcher::OP_INSERT].emplace_back(int64_t(42));
    GeneralWatcher::ChangeData data;
    data["table"][GeneralWatcher::OP_INSERT].push_back({ int64_t(42) });
    GeneralWatcher::ChangeInfo firstInfo;
    GeneralWatcher::ChangeInfo secondInfo;
    GeneralWatcher::ChangeData firstData;
    GeneralWatcher::ChangeData secondData;
    EXPECT_CALL(*first, OnChange(_, A<const GeneralWatcher::PRIFields &>(), _))
        .WillOnce([&firstInfo](const auto &, const auto &, auto &&value) {
            firstInfo = std::move(value);
            return E_ERROR;
        });
    EXPECT_CALL(*second, OnChange(_, A<const GeneralWatcher::PRIFields &>(), _))
        .WillOnce([&secondInfo](const auto &, const auto &, auto &&value) {
            secondInfo = std::move(value);
            return E_OK;
        });
    EXPECT_CALL(*first, OnChange(_, A<const GeneralWatcher::Fields &>(), _))
        .WillOnce([&firstData](const auto &, const auto &, auto &&value) {
            firstData = std::move(value);
            return E_ERROR;
        });
    EXPECT_CALL(*second, OnChange(_, A<const GeneralWatcher::Fields &>(), _))
        .WillOnce([&secondData](const auto &, const auto &, auto &&value) {
            secondData = std::move(value);
            return E_OK;
        });
    auto expectedInfo = info["table"][GeneralWatcher::OP_INSERT];
    auto expectedData = data["table"][GeneralWatcher::OP_INSERT];
    EXPECT_EQ(bridge.OnChange({}, GeneralWatcher::PRIFields{}, std::move(info)), E_OK);
    EXPECT_EQ(bridge.OnChange({}, GeneralWatcher::Fields{}, std::move(data)), E_OK);
    EXPECT_EQ(firstInfo["table"][GeneralWatcher::OP_INSERT], expectedInfo);
    EXPECT_EQ(secondInfo["table"][GeneralWatcher::OP_INSERT], expectedInfo);
    ASSERT_EQ(firstData["table"][GeneralWatcher::OP_INSERT].size(), expectedData.size());
    ASSERT_EQ(secondData["table"][GeneralWatcher::OP_INSERT].size(), expectedData.size());
    ASSERT_EQ(firstData["table"][GeneralWatcher::OP_INSERT][0].size(), 1U);
    ASSERT_EQ(secondData["table"][GeneralWatcher::OP_INSERT][0].size(), 1U);
    EXPECT_EQ(std::get<int64_t>(firstData["table"][GeneralWatcher::OP_INSERT][0][0]), int64_t(42));
    EXPECT_EQ(std::get<int64_t>(secondData["table"][GeneralWatcher::OP_INSERT][0][0]), int64_t(42));
    EXPECT_EQ(*queries, 2);
}

/**
 * @tc.name: OnChange_ReentrantUnsubscribe_UsesNextSnapshot
 * @tc.desc: A callback can remove itself without affecting the current snapshot.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(WatcherBridgeTest, OnChange_ReentrantUnsubscribe_UsesNextSnapshot, TestSize.Level1)
{
    auto watchers = std::make_shared<WatcherBridge::Watchers>();
    auto client = std::make_shared<GeneralWatcherMock>();
    watchers->insert(client);
    WatcherBridge bridge([weakWatchers = std::weak_ptr<WatcherBridge::Watchers>(watchers)]() {
        auto snapshot = weakWatchers.lock();
        return snapshot == nullptr ? WatcherBridge::Watchers{} : *snapshot;
    });
    EXPECT_CALL(*client, OnChange(_, A<const GeneralWatcher::PRIFields &>(), _))
        .WillOnce(
            [weakWatchers = std::weak_ptr<WatcherBridge::Watchers>(watchers)](const auto &, const auto &, auto &&) {
                auto subscriptions = weakWatchers.lock();
                subscriptions->clear();
                return E_OK;
            });
    EXPECT_EQ(bridge.OnChange({}, GeneralWatcher::PRIFields{}, GeneralWatcher::ChangeInfo{}), E_OK);
    EXPECT_TRUE(watchers->empty());
    EXPECT_EQ(bridge.OnChange({}, GeneralWatcher::PRIFields{}, GeneralWatcher::ChangeInfo{}), E_OK);
    watchers.reset();
    EXPECT_EQ(bridge.OnChange({}, GeneralWatcher::PRIFields{}, GeneralWatcher::ChangeInfo{}), E_OK);
}
} // namespace OHOS::Test
