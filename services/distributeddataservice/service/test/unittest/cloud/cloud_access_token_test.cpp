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
#include <gtest/gtest.h>

#include "cloud_service_impl.h"
#include "mock_access_token_state.h"

namespace OHOS::CloudData {
using namespace Security::AccessToken;
using namespace testing::ext;
namespace {
constexpr int32_t TEST_USER_ID = 100;
constexpr const char *CONFIG_PERMISSION = "ohos.permission.CLOUDDATA_CONFIG";

class CloudAccessTokenTest : public testing::Test {
public:
    static AccessTokenIDEx CreateHap(bool system)
    {
        HapInfoParams info{};
        info.userID = TEST_USER_ID;
        info.bundleName = "ohos.cloud.authorization.tdd";
        info.isSystemApp = system;
        return AccessTokenKit::AllocHapToken(info, {});
    }
};

/**
 * @tc.name: OnRemoteRequest_OrdinaryHap_AllProtectedOperationsDenied
 * @tc.desc: Real Stub authorization covers the denial scenarios formerly sent to a real SA by rdb tests.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(CloudAccessTokenTest, OnRemoteRequest_OrdinaryHap_AllProtectedOperationsDenied, TestSize.Level0)
{
    auto token = CreateHap(false);
    ASSERT_EQ(AccessTokenKit::GrantPermission(token.tokenIdExStruct.tokenID, CONFIG_PERMISSION, 0), RET_SUCCESS)
        << "permission setup failed";
    ScopedMockToken caller(token.tokenIDEx);
    CloudServiceImpl service;
    for (uint32_t code = CloudService::TRANS_CONFIG_HEAD; code < CloudService::TRANS_SHARE_BUTT; ++code) {
        MessageParcel request;
        MessageParcel reply;
        ASSERT_TRUE(request.WriteInterfaceToken(service.GetDescriptor())) << "request setup failed, code=" << code;
        EXPECT_EQ(service.OnRemoteRequest(code, request, reply), ERR_NONE) << "transport failed, code=" << code;
        int32_t result = 0;
        ASSERT_TRUE(reply.ReadInt32(result)) << "no permission reply, code=" << code;
        EXPECT_EQ(result, CloudService::PERMISSION_DENIED) << "ordinary HAP reached a protected handler, code=" << code;
    }
}

/**
 * @tc.name: OnRemoteRequest_SystemHapWithoutConfigPermission_AllConfigOperationsDenied
 * @tc.desc: System-app status does not replace CLOUDDATA_CONFIG permission.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(CloudAccessTokenTest, OnRemoteRequest_SystemHapWithoutConfigPermission_AllConfigOperationsDenied,
    TestSize.Level0)
{
    auto token = CreateHap(true);
    ScopedMockToken caller(token.tokenIDEx);
    CloudServiceImpl service;
    for (uint32_t code = CloudService::TRANS_CONFIG_HEAD; code < CloudService::TRANS_CONFIG_BUTT; ++code) {
        MessageParcel request;
        MessageParcel reply;
        ASSERT_TRUE(request.WriteInterfaceToken(service.GetDescriptor())) << "request setup failed, code=" << code;
        EXPECT_EQ(service.OnRemoteRequest(code, request, reply), ERR_NONE) << "transport failed, code=" << code;
        int32_t result = 0;
        ASSERT_TRUE(reply.ReadInt32(result)) << "no permission reply, code=" << code;
        EXPECT_EQ(result, CloudService::CLOUD_CONFIG_PERMISSION_DENIED)
            << "missing permission was ignored, code=" << code;
    }
}

/**
 * @tc.name: OnRemoteRequest_GrantThenRevoke_ReachesRealHandlerOnlyWhenGranted
 * @tc.desc: Grant/revoke drives the production authorization branch; the allowed call reaches real unmarshalling.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(CloudAccessTokenTest, OnRemoteRequest_GrantThenRevoke_ReachesRealHandlerOnlyWhenGranted, TestSize.Level0)
{
    auto token = CreateHap(true);
    ScopedMockToken caller(token.tokenIDEx);
    CloudServiceImpl service;
    const uint32_t code = CloudService::TRANS_QUERY_STATISTICS;
    ASSERT_EQ(AccessTokenKit::GrantPermission(token.tokenIdExStruct.tokenID, CONFIG_PERMISSION, 0), RET_SUCCESS)
        << "grant failed";
    MessageParcel allowed;
    MessageParcel ignored;
    ASSERT_TRUE(allowed.WriteInterfaceToken(service.GetDescriptor())) << "request setup failed";
    EXPECT_EQ(service.OnRemoteRequest(code, allowed, ignored), IPC_STUB_INVALID_DATA_ERR)
        << "authorized call did not reach the production handler's argument decoding";

    ASSERT_EQ(AccessTokenKit::RevokePermission(token.tokenIdExStruct.tokenID, CONFIG_PERMISSION, 0), RET_SUCCESS)
        << "revoke failed";
    MessageParcel denied;
    MessageParcel reply;
    ASSERT_TRUE(denied.WriteInterfaceToken(service.GetDescriptor())) << "request setup failed";
    EXPECT_EQ(service.OnRemoteRequest(code, denied, reply), ERR_NONE) << "denial transport failed";
    int32_t result = 0;
    ASSERT_TRUE(reply.ReadInt32(result)) << "denial reply missing";
    EXPECT_EQ(result, CloudService::CLOUD_CONFIG_PERMISSION_DENIED) << "real Stub ignored revoked permission";
}
/**
 * @tc.name: OnRemoteRequest_SystemHapSharing_DoesNotRequireConfigPermission
 * @tc.desc: The sharing branch checks system-app identity and reaches the real sharing decoder.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(CloudAccessTokenTest, OnRemoteRequest_SystemHapSharing_DoesNotRequireConfigPermission, TestSize.Level0)
{
    auto token = CreateHap(true);
    ScopedMockToken caller(token.tokenIDEx);
    CloudServiceImpl service;
    MessageParcel request;
    MessageParcel reply;
    ASSERT_TRUE(request.WriteInterfaceToken(service.GetDescriptor()));

    EXPECT_EQ(service.OnRemoteRequest(CloudService::TRANS_SHARE, request, reply), IPC_STUB_INVALID_DATA_ERR)
        << "system sharing call did not reach the real handler without CLOUDDATA_CONFIG";
}
} // namespace
} // namespace OHOS::CloudData
