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

#include <cstdint>
#include <memory>
#include <vector>
#define LOG_TAG "CloudSyncManagerTest"
#include "sync_manager.h"

#include <gtest/gtest.h>
#include <gmock/gmock.h>

#include "account/account_delegate.h"
#include "account_delegate_mock.h"
#include "cloud/cloud_info.h"
#include "cloud/schema_meta.h"
#include "log_print.h"
#include "metadata/meta_data_manager.h"
#include "metadata/store_meta_data.h"
#include "meta_data_manager_mock.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS::CloudData;
using namespace OHOS::DistributedData;

namespace OHOS::Test {
class CloudSyncManagerTest : public testing::Test {
public:
    static AccountDelegateMock *acctMock_;
    static std::shared_ptr<MetaDataManagerMock> metaMock_;
    SyncManager *syncMgr_ = nullptr;

    static void SetUpTestSuite()
    {
        acctMock_ = new AccountDelegateMock();
        AccountDelegate::RegisterAccountInstance(acctMock_);
        metaMock_ = std::make_shared<MetaDataManagerMock>();
        BMetaDataManager::metaDataManager = metaMock_;
        ON_CALL(*metaMock_, LoadMeta(_, _, _)).WillByDefault(Return(false));
    }

    static void TearDownTestSuite()
    {
        BMetaDataManager::metaDataManager = nullptr;
        metaMock_.reset();
        AccountDelegate::instance_ = nullptr; // -fno-access-control
        delete acctMock_;
        acctMock_ = nullptr;
    }

    void SetUp() override
    {
        syncMgr_ = new SyncManager();
        ASSERT_NE(syncMgr_, nullptr);
        syncMgr_->kvApps_.clear(); // -fno-access-control: controlled state
        ON_CALL(*acctMock_, QueryUsers(_))
            .WillByDefault([](std::vector<int> &users) {
                users.clear();
                return false;
            });
    }

    void TearDown() override
    {
        delete syncMgr_;
        syncMgr_ = nullptr;
        Mock::VerifyAndClearExpectations(acctMock_);
        Mock::VerifyAndClearExpectations(metaMock_.get());
    }

    void MarkKvApp(const std::string &bundle)
    {
        syncMgr_->kvApps_.insert(bundle); // -fno-access-control
    }

    void SetUsers(std::vector<int> users)
    {
        EXPECT_CALL(*acctMock_, QueryUsers(_))
            .WillRepeatedly([users](std::vector<int> &out) {
                out = users;
                return true;
            });
    }
};

AccountDelegateMock *CloudSyncManagerTest::acctMock_ = nullptr;
std::shared_ptr<MetaDataManagerMock> CloudSyncManagerTest::metaMock_ = nullptr;

namespace {
constexpr const char *BUNDLE_KV = "com.test.kvapp";
constexpr const char *BUNDLE_NON_KV = "com.test.notkvapp";
} // namespace

/*
 * T1: user != 0 -> early return false, user unchanged.
 * @tc.name: InitDefaultUser_001_NonZeroUserReturnsFalse
 * @tc.desc: non-zero user early returns false without touching users
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(CloudSyncManagerTest, InitDefaultUser_001_NonZeroUserReturnsFalse, TestSize.Level1)
{
    int32_t user = 100;
    bool ret = syncMgr_->InitDefaultUser(user, BUNDLE_NON_KV);
    EXPECT_FALSE(ret);
    EXPECT_EQ(user, 100);
}

/*
 * T2: non-kv app, users non-empty -> fallback to users[0].
 * @tc.name: InitDefaultUser_002_NonKvAppFallsBackToFirstUser
 * @tc.desc: non-kv app falls back to users[0] directly without scanning
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(CloudSyncManagerTest, InitDefaultUser_002_NonKvAppFallsBackToFirstUser, TestSize.Level1)
{
    SetUsers({ 100 });
    int32_t user = 0;
    bool ret = syncMgr_->InitDefaultUser(user, BUNDLE_NON_KV);
    EXPECT_TRUE(ret);
    EXPECT_EQ(user, 100); // fallback to users[0]
}

/*
 * T3: non-kv app, users[0]==0 -> fallback to users[0] (does not skip zero).
 * @tc.name: InitDefaultUser_003_NonKvAppZeroFirstFallsBackToZero
 * @tc.desc: non-kv app falls back to users[0] even when it is zero
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(CloudSyncManagerTest, InitDefaultUser_003_NonKvAppZeroFirstFallsBackToZero, TestSize.Level1)
{
    SetUsers({ 0, 100 });
    int32_t user = 0;
    bool ret = syncMgr_->InitDefaultUser(user, BUNDLE_NON_KV);
    EXPECT_TRUE(ret);
    EXPECT_EQ(user, 0); // fallback to users[0] (zero, not skipped)
}

/*
 * T4: non-kv app, users empty -> skip fallback, user stays 0.
 * @tc.name: InitDefaultUser_004_NonKvAppEmptyUsersKeepsZero
 * @tc.desc: non-kv app with empty users keeps user 0
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(CloudSyncManagerTest, InitDefaultUser_004_NonKvAppEmptyUsersKeepsZero, TestSize.Level2)
{
    SetUsers({});
    int32_t user = 0;
    bool ret = syncMgr_->InitDefaultUser(user, BUNDLE_NON_KV);
    EXPECT_TRUE(ret);
    EXPECT_EQ(user, 0);
}

/*
 * T5: kv app, users has 0 then 100, CloudInfo load fails -> skip 0, fail 100, fallback to users[0] (0).
 * @tc.name: InitDefaultUser_005_KvAppSkipsZeroNoCloudInfoFallsBack
 * @tc.desc: kv app skips user 0, fails CloudInfo for 100, falls back to users[0]
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(CloudSyncManagerTest, InitDefaultUser_005_KvAppSkipsZeroNoCloudInfoFallsBack, TestSize.Level2)
{
    MarkKvApp(BUNDLE_KV);
    SetUsers({ 0, 100 });
    // LoadMeta not pre-populated -> CloudInfo fails.
    int32_t user = 0;
    bool ret = syncMgr_->InitDefaultUser(user, BUNDLE_KV);
    EXPECT_TRUE(ret);
    EXPECT_EQ(user, 0); // fallback to users[0] (zero)
}

/*
 * T6: kv app, CloudInfo load fails -> continue -> fallback to users[0].
 * @tc.name: InitDefaultUser_006_KvAppNoCloudInfoFallsBack
 * @tc.desc: kv app with no CloudInfo meta falls back to users[0]
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(CloudSyncManagerTest, InitDefaultUser_006_KvAppNoCloudInfoFallsBack, TestSize.Level2)
{
    MarkKvApp(BUNDLE_KV);
    SetUsers({ 100 });
    // LoadMeta not pre-populated -> CloudInfo fails.
    int32_t user = 0;
    bool ret = syncMgr_->InitDefaultUser(user, BUNDLE_KV);
    EXPECT_TRUE(ret);
    EXPECT_EQ(user, 100); // fallback to users[0]
}

/*
 * T7: kv app, CloudInfo ok but Schema fails -> continue -> fallback to users[0].
 * @tc.name: InitDefaultUser_007_KvAppNoSchemaFallsBack
 * @tc.desc: kv app with CloudInfo but no Schema meta falls back to users[0]
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(CloudSyncManagerTest, InitDefaultUser_007_KvAppNoSchemaFallsBack, TestSize.Level2)
{
    MarkKvApp(BUNDLE_KV);
    SetUsers({ 100 });
    CloudInfo cloudInfo;
    cloudInfo.user = 100;
    EXPECT_CALL(*metaMock_, LoadMeta(cloudInfo.GetKey(), _, _)).WillRepeatedly(Return(true));
    auto schemaKey = CloudInfo::GetSchemaKey(100, BUNDLE_KV);
    EXPECT_CALL(*metaMock_, LoadMeta(schemaKey, _, _)).WillRepeatedly(Return(false));
    int32_t user = 0;
    bool ret = syncMgr_->InitDefaultUser(user, BUNDLE_KV);
    EXPECT_TRUE(ret);
    EXPECT_EQ(user, 100); // fallback to users[0]
}

/*
 * T8: kv app, both CloudInfo and Schema ok -> select candidate, return true.
 * @tc.name: InitDefaultUser_008_KvAppCloudInfoAndSchemaSelects
 * @tc.desc: kv app with both CloudInfo and Schema meta selects candidate
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(CloudSyncManagerTest, InitDefaultUser_008_KvAppCloudInfoAndSchemaSelects, TestSize.Level1)
{
    MarkKvApp(BUNDLE_KV);
    SetUsers({ 100 });
    CloudInfo cloudInfo;
    cloudInfo.user = 100;
    EXPECT_CALL(*metaMock_, LoadMeta(cloudInfo.GetKey(), _, _)).WillRepeatedly(Return(true));
    auto schemaKey = CloudInfo::GetSchemaKey(100, BUNDLE_KV);
    EXPECT_CALL(*metaMock_, LoadMeta(schemaKey, _, _)).WillRepeatedly(Return(true));
    int32_t user = 0;
    bool ret = syncMgr_->InitDefaultUser(user, BUNDLE_KV);
    EXPECT_TRUE(ret);
    EXPECT_EQ(user, 100); // selected (not fallback)
}

/*
 * T9: kv app, users empty -> skip fallback, user stays 0.
 * @tc.name: InitDefaultUser_009_KvAppEmptyUsersKeepsZero
 * @tc.desc: kv app with empty users keeps user 0
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(CloudSyncManagerTest, InitDefaultUser_009_KvAppEmptyUsersKeepsZero, TestSize.Level2)
{
    MarkKvApp(BUNDLE_KV);
    SetUsers({});
    int32_t user = 0;
    bool ret = syncMgr_->InitDefaultUser(user, BUNDLE_KV);
    EXPECT_TRUE(ret);
    EXPECT_EQ(user, 0);
}
} // namespace OHOS::Test
