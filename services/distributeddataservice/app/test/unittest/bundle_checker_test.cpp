/*
* Copyright (c) 2025 Huawei Device Co., Ltd.
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
#include "accesstoken_kit.h"
#include "checker/bundle_checker.h"
#include "bootstrap.h"
#include "hap_token_info.h"
#include "iservice_registry.h"
#include "mock_bundle_manager.h"
#include "system_ability_definition.h"
#include "nativetoken_kit.h"
#include "utils/crypto.h"
using namespace testing::ext;
using namespace OHOS::DistributedData;
using namespace OHOS::Security::AccessToken;
class BundleCheckerTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
    void SetUp();
    void TearDown();
    NativeTokenInfoParams infoInstance{0};
    OHOS::sptr<OHOS::ISystemAbilityManager> originalSamgr_;
    OHOS::sptr<testing::NiceMock<OHOS::AppExecFwk::SystemAbilityManagerMock>> samgr_;
    OHOS::sptr<testing::StrictMock<OHOS::AppExecFwk::BundleMgrMock>> bundleMgr_;
};

void BundleCheckerTest::SetUp(void)
{
    auto &client = OHOS::SystemAbilityManagerClient::GetInstance();
    originalSamgr_ = client.systemAbilityManager_;
    samgr_ = new testing::NiceMock<OHOS::AppExecFwk::SystemAbilityManagerMock>();
    bundleMgr_ = new testing::StrictMock<OHOS::AppExecFwk::BundleMgrMock>();
    ON_CALL(*samgr_, GetSystemAbility(OHOS::BUNDLE_MGR_SERVICE_SYS_ABILITY_ID))
        .WillByDefault(testing::Return(bundleMgr_->AsObject()));
    client.systemAbilityManager_ = samgr_;

    infoInstance.processName = "BundleCheckerTest";
    infoInstance.aplStr = "system_core";

    HapInfoParams info = {
        .userID = 100,
        .bundleName = "com.ohos.dlpmanager",
        .instIndex = 0,
        .appIDDesc = "com.ohos.dlpmanager"
    };
    PermissionDef infoManagerTestPermDef = {
        .permissionName = "ohos.permission.test",
        .bundleName = "ohos.test.demo",
        .grantMode = 1,
        .availableLevel = APL_NORMAL,
        .label = "label",
        .labelId = 1,
        .description = "open the door",
        .descriptionId = 1
    };
    PermissionStateFull infoManagerTestState = {
        .permissionName = "ohos.permission.test",
        .isGeneral = true,
        .resDeviceID = {"local"},
        .grantStatus = {PermissionState::PERMISSION_GRANTED},
        .grantFlags = {1}
    };
    HapPolicyParams policy = {
        .apl = APL_NORMAL,
        .domain = "test.domain",
        .permList = {infoManagerTestPermDef},
        .permStateList = {infoManagerTestState}
    };
    AccessTokenKit::AllocHapToken(info, policy);

    Bootstrap::GetInstance().LoadComponents();
    Bootstrap::GetInstance().LoadDirectory();
    Bootstrap::GetInstance().LoadCheckers();
    Bootstrap::GetInstance().LoadNetworks();
}

void BundleCheckerTest::TearDown()
{
    OHOS::SystemAbilityManagerClient::GetInstance().systemAbilityManager_ = originalSamgr_;
    bundleMgr_ = nullptr;
    samgr_ = nullptr;
    CheckerManager::GetInstance().ClearCache();

    auto tokenId = AccessTokenKit::GetHapTokenID(100, "com.ohos.dlpmanager", 0);
    AccessTokenKit::DeleteToken(tokenId);
}

/**
* @tc.name: GetAppIdTest001
* @tc.desc: get appId from cache.
* @tc.type: FUNC
* @tc.require:
* @tc.author: agent
*/
HWTEST_F(BundleCheckerTest, GetAppIdTest001, TestSize.Level0)
{
    const std::string appId = "com.ohos.dlpmanager.test-app-id";
    EXPECT_CALL(*bundleMgr_, GetAppIdByBundleName("com.ohos.dlpmanager", 100))
        .Times(2).WillRepeatedly(testing::Return(appId));

    CheckerManager::StoreInfo info;
    auto tokenId = AccessTokenKit::GetHapTokenID(100, "com.ohos.dlpmanager", 0);
    ASSERT_NE(tokenId, 0u) << "mock HAP token was not allocated";
    ASSERT_EQ(AccessTokenKit::GetTokenTypeFlag(tokenId), TOKEN_HAP);
    info.uid = 100 * 200000;
    info.tokenId = tokenId;
    info.bundleName = "com.ohos.dlpmanager";
    BundleChecker checker;
    std::string appIdInCache;
    ASSERT_TRUE(!checker.GetAppId(info).empty());
    checker.appIds_.Get("com.ohos.dlpmanager###100", appIdInCache);
    ASSERT_EQ(appIdInCache, appId);
    ASSERT_EQ(Crypto::Sha256(appIdInCache), checker.GetAppId(info));

    checker.DeleteCache(info.bundleName, 100, 0);
    std::string appIdInCache1;
    checker.appIds_.Get("com.ohos.dlpmanager###100", appIdInCache1);
    ASSERT_TRUE(appIdInCache1.empty());

    checker.GetAppId(info);
    ASSERT_GE(checker.appIds_.Size(), 1);
    checker.ClearCache();
    ASSERT_EQ(checker.appIds_.Size(), 0);
}
