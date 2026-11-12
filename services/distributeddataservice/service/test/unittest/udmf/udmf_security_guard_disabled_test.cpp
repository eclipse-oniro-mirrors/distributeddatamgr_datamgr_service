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

#include "udmf_service_impl.h"

#include <gtest/gtest.h>

#include "device_manager_adapter_mock.h"
#include "mock/access_token_mock.h"
#include "security_guard_delegate_mock.h"
#include "udmf_auth_store_mock.h"

namespace OHOS::Test {
using namespace DistributedData;
using namespace Security::AccessToken;
using namespace UDMF;
using namespace testing;
using namespace testing::ext;

class DisabledAuthPermissionCheckerMock : public UDMF::CheckerManager::Checker {
public:
    MOCK_METHOD(bool, IsValid, (const std::vector<Privilege> &, const UDMF::CheckerManager::CheckInfo &), (override));
};

NiceMock<DisabledAuthPermissionCheckerMock> &GetDisabledAuthPermissionChecker()
{
    static NiceMock<DisabledAuthPermissionCheckerMock> checker;
    return checker;
}

class UdmfSecurityGuardDisabledTest : public testing::Test {
public:
    static constexpr int32_t testUserId = 100;
    static constexpr uint32_t sourceTokenId = 17;
    static constexpr uint32_t receiverTokenId = 19;

    void SetUp() override
    {
        tokens_ = std::make_shared<NiceMock<AccessTokenKitMock>>();
        BAccessTokenKit::accessTokenkit = tokens_;
        ON_CALL(*tokens_, GetTokenTypeFlag(_)).WillByDefault(Return(TOKEN_HAP));
        ON_CALL(*tokens_, GetHapTokenInfo(_, _)).WillByDefault([](auto, HapTokenInfo &info) {
            info.bundleName = "com.test.auth";
            info.instIndex = 0;
            info.userID = testUserId;
            return 0;
        });
        devices_ = std::make_shared<NiceMock<DeviceManagerAdapterMock>>();
        BDeviceManagerAdapter::deviceManagerAdapter = devices_;
        ON_CALL(*devices_, CalcClientUuid(_, _)).WillByDefault(Return("local-auth-device"));
        UDMF::CheckerManager::GetInstance().RegisterChecker(
            "DataChecker", []() { return &GetDisabledAuthPermissionChecker(); });
        store_ = std::make_shared<NiceMock<AuthStoreMock>>();
        AuthStoreRegistry::current = store_;
        SecurityGuardTestRegistry::instance = nullptr;
    }

    void TearDown() override
    {
        Mock::VerifyAndClear(&GetDisabledAuthPermissionChecker());
        AuthStoreRegistry::current.reset();
        BAccessTokenKit::accessTokenkit = nullptr;
        BDeviceManagerAdapter::deviceManagerAdapter = nullptr;
    }

    UnifiedData Payload()
    {
        UnifiedData data;
        auto record = std::make_shared<UnifiedRecord>(PLAIN_TEXT, std::string(10241, 'x'));
        record->SetUid("record-sg-disabled");
        data.AddRecord(record);
        Runtime runtime;
        runtime.tokenId = sourceTokenId;
        runtime.recordTotalNum = 1;
        runtime.deviceId = "remote-auth-device";
        runtime.sourcePackage = "com.test.auth";
        Privilege privilege;
        privilege.tokenId = receiverTokenId;
        privilege.readPermission = "readAndKeep";
        runtime.privileges = { privilege };
        data.SetRuntime(runtime);
        return data;
    }

    QueryOption Query()
    {
        QueryOption query;
        query.key = "udmf://drag/com.test.auth/sgdisabled";
        query.intention = UD_INTENTION_DRAG;
        query.tokenId = receiverTokenId;
        return query;
    }

    std::shared_ptr<NiceMock<AccessTokenKitMock>> tokens_;
    std::shared_ptr<NiceMock<DeviceManagerAdapterMock>> devices_;
    std::shared_ptr<NiceMock<AuthStoreMock>> store_;
};

/**
 * @tc.name: GetData_SecurityGuardDisabled_ReturnsAuthorizedPayload
 * @tc.desc: A valid cross-application read remains available without the SG event encoder or size limit.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfSecurityGuardDisabledTest, GetData_SecurityGuardDisabled_ReturnsAuthorizedPayload, TestSize.Level1)
{
    auto query = Query();
    UnifiedKey key(query.key);
    ASSERT_TRUE(key.IsValid());
    EXPECT_CALL(GetDisabledAuthPermissionChecker(), IsValid(_, _)).WillOnce(Return(true));
    EXPECT_CALL(*store_, Get(query.key, _)).WillOnce([&](const auto &, UnifiedData &data) {
        data = Payload();
        return UDMF::E_OK;
    });
    EXPECT_CALL(*store_, Delete(_)).Times(0);
    UdmfServiceImpl service;
    UnifiedData output;
    EXPECT_EQ(service.GetData(query, output), UDMF::E_OK);
    EXPECT_EQ(output.GetRecords().size(), 1);
    EXPECT_GT(output.GetSize(), 10240);
}

/**
 * @tc.name: GetData_SecurityGuardDisabled_PreservesAccessPermissionCheck
 * @tc.desc: Disabling the SG capability still rejects an unauthorized read and clears its payload.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfSecurityGuardDisabledTest, GetData_SecurityGuardDisabled_PreservesAccessPermissionCheck, TestSize.Level1)
{
    auto query = Query();
    UnifiedKey key(query.key);
    ASSERT_TRUE(key.IsValid());
    EXPECT_CALL(GetDisabledAuthPermissionChecker(), IsValid(_, _)).WillOnce(Return(false));
    EXPECT_CALL(*store_, Get(query.key, _)).WillOnce([&](const auto &, UnifiedData &data) {
        data = Payload();
        return UDMF::E_OK;
    });
    EXPECT_CALL(*store_, Delete(_)).Times(0);
    UdmfServiceImpl service;
    UnifiedData output;
    EXPECT_EQ(service.GetData(query, output), UDMF::E_NO_PERMISSION);
    EXPECT_TRUE(output.IsEmpty());
    EXPECT_EQ(output.GetRuntime(), nullptr);
}
} // namespace OHOS::Test
