/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include <thread>
#include "accesstoken_kit.h"
#include "access_token.h"
#include "kvstore_account_observer.h"
#include "kvstore_data_service.h"
#include "token_setproc.h"
#include "types.h"
#include "common_event_subscriber.h"
#include "common_event_support.h"
#include "common_event_manager.h"
#include "gtest/gtest.h"
#include "nativetoken_kit.h"
using namespace testing::ext;
using namespace OHOS::DistributedKv;
using namespace OHOS::DistributedData;
using namespace OHOS;
using namespace OHOS::EventFwk;
using namespace Security::AccessToken;

static const int SYSTEM_USER_ID = 1000;

static const int WAIT_TIME_FOR_ACCOUNT_OPERATION = 2; // indicates the wait time in seconds
namespace OHOS::Test {
class DistributedDataAccountEventTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void ChangeUser(int uid);
    static void TearDownTestCase();
    static void HarmonyAccountLogin();
    static void HarmonyAccountLogout();
    static void HarmonyAccountDelete();

    static void SetTokenPermission();
    static uint64_t tokenId_;
};

void DistributedDataAccountEventTest::SetTokenPermission()
{
    const char *perms[] = { "ohos.permission.PUBLISH_SYSTEM_COMMON_EVENT" };
    NativeTokenInfoParams instance = {
        .dcapsNum = 0,
        .permsNum = 1,
        .aclsNum = 0,
        .dcaps = nullptr;
        .perms = perms;
        .acls = nullptr;
        .aplStr = "system_core",
    };
    instance.processName = "AccountEventTest";
    tokenId_ = GetAccessTokenId(&instance);
    SetSelfTokenID(tokenId_);
    AccessTokenKit::ReloadNativeTokenInfo();
}

void DistributedDataAccountEventTest::SetUpTestCase()
{
    DistributedDataAccountEventTest::SetTokenPermission();
    DistributedDataAccountEventTest::ChangeUser(SYSTEM_USER_ID);
}

void DistributedDataAccountEventTest::TearDownTestCase()
{
    DistributedDataAccountEventTest::HarmonyAccountDelete();
}

void DistributedDataAccountEventTest::HarmonyAccountLogin()
{
    Want want;
    want.SetAction(CommonEventSupport::COMMON_EVENT_HWID_LOGIN);
    CommonEventData commonEventData(want);
    CommonEventData event(want);
    CommonEventPublishInfo publishInfo;
    auto err = CommonEventManager::PublishCommonEvent(event, publishInfo, nullptr);
    EXPECT_EQ(ERR_OK, err);
    sleep(WAIT_TIME_FOR_ACCOUNT_OPERATION);
}

void DistributedDataAccountEventTest::HarmonyAccountLogout()
{
    Want want;
    want.SetAction(CommonEventSupport::COMMON_EVENT_HWID_LOGOUT);
    CommonEventData commonEventData(want);
    CommonEventData event(want);
    CommonEventPublishInfo publishInfo;
    auto err = CommonEventManager::PublishCommonEvent(event, publishInfo, nullptr);
    EXPECT_EQ(ERR_OK, err);
    sleep(WAIT_TIME_FOR_ACCOUNT_OPERATION);
}

void DistributedDataAccountEventTest::HarmonyAccountDelete()
{
    Want want;
    want.SetAction(CommonEventSupport::COMMON_EVENT_HWID_TOKEN_INVALID);
    CommonEventData commonEventData(want);
    CommonEventData event(want);
    CommonEventPublishInfo publishInfo;
    auto err = CommonEventManager::PublishCommonEvent(event, publishInfo, nullptr);
    EXPECT_EQ(ERR_OK, err);
    sleep(WAIT_TIME_FOR_ACCOUNT_OPERATION);
}

void DistributedDataAccountEventTest::ChangeUser(int uid)
{
    if (setgid(uid)) {
        std::cout << "error to set gid " << uid << "errno is " << errno << std::endl;
    }

    if (setuid(uid)) {
        std::cout << "error to set uid " << uid << "errno is " << errno << std::endl;
    }
}
} // namespace OHOS::Test
