/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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
#define LOG_TAG "UserIdCacheTest"
#include <gtest/gtest.h>
#include <chrono>
#include <vector>

#include "account/account_delegate.h"
#include "account_delegate_mock.h"
#include "log_print.h"
#include "user_id_cache.h"

namespace OHOS {
namespace DataShare {
using namespace testing;
using namespace testing::ext;
using namespace OHOS::DistributedData;
class UserIdCacheTest : public testing::Test {
public:
    void SetUp() override
    {
        AccountDelegate::instance_ = nullptr;
        AccountDelegate::RegisterAccountInstance(&mock_);
        UserIdCache::GetInstance()->Reset();
    }
    void TearDown() override
    {
        UserIdCache::GetInstance()->Reset();
        AccountDelegate::instance_ = nullptr;
    }
    AccountDelegateMock mock_;
};

/**
 * @tc.name: GetUserIds_LazyInitUnionZeroSorted_001
 * @tc.desc: Verify GetUserIds initializes lazily, unions user 0, sorts and dedups
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UserIdCacheTest, GetUserIds_LazyInitUnionZeroSorted_001, TestSize.Level0)
{
    ZLOGI("UserIdCacheTest GetUserIds_LazyInitUnionZeroSorted_001 start");
    EXPECT_CALL(mock_, QueryAllCreatedUsers(_))
        .WillOnce(DoAll(SetArgReferee<0>(std::vector<int> { 101, 100 }), Return(true)));
    auto userIds = UserIdCache::GetInstance()->GetUserIds();
    EXPECT_EQ(userIds, (std::vector<int32_t> { 0, 100, 101 }));

    // duplicate and unsorted input is deduped and sorted, user 0 kept once
    UserIdCache::GetInstance()->Reset();
    EXPECT_CALL(mock_, QueryAllCreatedUsers(_))
        .WillOnce(DoAll(SetArgReferee<0>(std::vector<int> { 101, 100, 100 }), Return(true)));
    userIds = UserIdCache::GetInstance()->GetUserIds();
    EXPECT_EQ(userIds, (std::vector<int32_t> { 0, 100, 101 }));

    // delegate already contains user 0, do not duplicate it
    UserIdCache::GetInstance()->Reset();
    EXPECT_CALL(mock_, QueryAllCreatedUsers(_))
        .WillOnce(DoAll(SetArgReferee<0>(std::vector<int> { 0, 100 }), Return(true)));
    userIds = UserIdCache::GetInstance()->GetUserIds();
    EXPECT_EQ(userIds, (std::vector<int32_t> { 0, 100 }));
    ZLOGI("UserIdCacheTest GetUserIds_LazyInitUnionZeroSorted_001 end");
}

/**
 * @tc.name: GetUserIds_QueryFailedKeepEmpty_001
 * @tc.desc: Verify GetUserIds keeps empty cache when the delegate query fails, then recovers on retry
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UserIdCacheTest, GetUserIds_QueryFailedKeepEmpty_001, TestSize.Level0)
{
    ZLOGI("UserIdCacheTest GetUserIds_QueryFailedKeepEmpty_001 start");
    EXPECT_CALL(mock_, QueryAllCreatedUsers(_)).WillOnce(Return(false));
    auto userIds = UserIdCache::GetInstance()->GetUserIds();
    EXPECT_TRUE(userIds.empty());

    // move the last attempt out of the throttle window, then the next call retries
    auto *cache = UserIdCache::GetInstance();
    cache->lastAttemptTime_ -= std::chrono::seconds(2);
    EXPECT_CALL(mock_, QueryAllCreatedUsers(_))
        .WillOnce(DoAll(SetArgReferee<0>(std::vector<int> { 100 }), Return(true)));
    userIds = cache->GetUserIds();
    EXPECT_EQ(userIds, (std::vector<int32_t> { 0, 100 }));
    ZLOGI("UserIdCacheTest GetUserIds_QueryFailedKeepEmpty_001 end");
}

/**
 * @tc.name: GetUserIds_CacheHitNoRequery_001
 * @tc.desc: Verify GetUserIds does not query the delegate again once initialized
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UserIdCacheTest, GetUserIds_CacheHitNoRequery_001, TestSize.Level0)
{
    ZLOGI("UserIdCacheTest GetUserIds_CacheHitNoRequery_001 start");
    EXPECT_CALL(mock_, QueryAllCreatedUsers(_))
        .WillOnce(DoAll(SetArgReferee<0>(std::vector<int> { 100 }), Return(true)));
    auto userIds = UserIdCache::GetInstance()->GetUserIds();
    EXPECT_EQ(userIds, (std::vector<int32_t> { 0, 100 }));

    EXPECT_CALL(mock_, QueryAllCreatedUsers(_)).Times(0);
    userIds = UserIdCache::GetInstance()->GetUserIds();
    EXPECT_EQ(userIds, (std::vector<int32_t> { 0, 100 }));
    ZLOGI("UserIdCacheTest GetUserIds_CacheHitNoRequery_001 end");
}

/**
 * @tc.name: Refresh_UpdateCache_001
 * @tc.desc: Verify Refresh re-queries the delegate and updates the cached user ids
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UserIdCacheTest, Refresh_UpdateCache_001, TestSize.Level0)
{
    ZLOGI("UserIdCacheTest Refresh_UpdateCache_001 start");
    EXPECT_CALL(mock_, QueryAllCreatedUsers(_))
        .WillOnce(DoAll(SetArgReferee<0>(std::vector<int> { 100 }), Return(true)));
    auto userIds = UserIdCache::GetInstance()->GetUserIds();
    EXPECT_EQ(userIds, (std::vector<int32_t> { 0, 100 }));

    // user 101 created, event-driven refresh makes it visible
    EXPECT_CALL(mock_, QueryAllCreatedUsers(_))
        .WillOnce(DoAll(SetArgReferee<0>(std::vector<int> { 100, 101 }), Return(true)));
    UserIdCache::GetInstance()->Refresh();
    userIds = UserIdCache::GetInstance()->GetUserIds();
    EXPECT_EQ(userIds, (std::vector<int32_t> { 0, 100, 101 }));
    ZLOGI("UserIdCacheTest Refresh_UpdateCache_001 end");
}

/**
 * @tc.name: TryRefresh_Throttled_001
 * @tc.desc: Verify TryRefresh is throttled inside the refresh interval and executes after it
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UserIdCacheTest, TryRefresh_Throttled_001, TestSize.Level0)
{
    ZLOGI("UserIdCacheTest TryRefresh_Throttled_001 start");
    EXPECT_CALL(mock_, QueryAllCreatedUsers(_))
        .WillOnce(DoAll(SetArgReferee<0>(std::vector<int> { 100 }), Return(true)));
    EXPECT_TRUE(UserIdCache::GetInstance()->TryRefresh());
    auto userIds = UserIdCache::GetInstance()->GetUserIds();
    EXPECT_EQ(userIds, (std::vector<int32_t> { 0, 100 }));

    // second refresh inside the throttle window is skipped
    EXPECT_CALL(mock_, QueryAllCreatedUsers(_)).Times(0);
    EXPECT_FALSE(UserIdCache::GetInstance()->TryRefresh());

    // after the throttle window the refresh executes again
    auto *cache = UserIdCache::GetInstance();
    cache->lastAttemptTime_ -= std::chrono::seconds(2);
    EXPECT_CALL(mock_, QueryAllCreatedUsers(_))
        .WillOnce(DoAll(SetArgReferee<0>(std::vector<int> { 100, 101 }), Return(true)));
    EXPECT_TRUE(cache->TryRefresh());
    userIds = cache->GetUserIds();
    EXPECT_EQ(userIds, (std::vector<int32_t> { 0, 100, 101 }));
    ZLOGI("UserIdCacheTest TryRefresh_Throttled_001 end");
}

/**
 * @tc.name: GetUserIds_DelegateNull_001
 * @tc.desc: Verify GetUserIds returns empty when the account delegate is null
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UserIdCacheTest, GetUserIds_DelegateNull_001, TestSize.Level0)
{
    ZLOGI("UserIdCacheTest GetUserIds_DelegateNull_001 start");
    AccountDelegate::instance_ = nullptr;
    auto userIds = UserIdCache::GetInstance()->GetUserIds();
    EXPECT_TRUE(userIds.empty());
    ZLOGI("UserIdCacheTest GetUserIds_DelegateNull_001 end");
}

/**
 * @tc.name: Reset_ClearCache_001
 * @tc.desc: Verify Reset clears cached state so the next GetUserIds re-initializes
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UserIdCacheTest, Reset_ClearCache_001, TestSize.Level0)
{
    ZLOGI("UserIdCacheTest Reset_ClearCache_001 start");
    EXPECT_CALL(mock_, QueryAllCreatedUsers(_))
        .WillOnce(DoAll(SetArgReferee<0>(std::vector<int> { 100 }), Return(true)));
    auto userIds = UserIdCache::GetInstance()->GetUserIds();
    EXPECT_EQ(userIds, (std::vector<int32_t> { 0, 100 }));

    UserIdCache::GetInstance()->Reset();
    EXPECT_CALL(mock_, QueryAllCreatedUsers(_))
        .WillOnce(DoAll(SetArgReferee<0>(std::vector<int> { 100, 101 }), Return(true)));
    userIds = UserIdCache::GetInstance()->GetUserIds();
    EXPECT_EQ(userIds, (std::vector<int32_t> { 0, 100, 101 }));
    ZLOGI("UserIdCacheTest Reset_ClearCache_001 end");
}
} // namespace DataShare
} // namespace OHOS
