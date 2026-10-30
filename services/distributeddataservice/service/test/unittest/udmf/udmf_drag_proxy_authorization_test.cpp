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

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "drag_proxy_authorization.h"
#include "mock/access_token_mock.h"

using namespace OHOS::Security::AccessToken;
using namespace testing;
using namespace testing::ext;

namespace OHOS::Test::DistributedDataTest {
namespace {
constexpr uint32_t FILE_MANAGER_TOKEN = 100;
constexpr uint32_t DESKTOP_TOKEN = 200;
constexpr uint32_t OTHER_USER_DESKTOP_TOKEN = 201;
constexpr uint32_t OTHER_APP_TOKEN = 300;
constexpr uint32_t OTHER_REQUESTER_TOKEN = 400;
constexpr uint32_t UNKNOWN_TOKEN = 500;
constexpr int32_t TEST_USER_ID = 100;

int32_t FillKnownHapTokenInfo(AccessTokenID tokenId, HapTokenInfo &tokenInfo)
{
    tokenInfo.userID = TEST_USER_ID;
    if (tokenId == FILE_MANAGER_TOKEN) {
        tokenInfo.bundleName = "com.huawei.hmos.filemanager";
    } else if (tokenId == DESKTOP_TOKEN) {
        tokenInfo.bundleName = "com.ohos.sceneboard";
    } else if (tokenId == OTHER_USER_DESKTOP_TOKEN) {
        tokenInfo.bundleName = "com.ohos.sceneboard";
        tokenInfo.userID = TEST_USER_ID + 1;
    } else if (tokenId == OTHER_REQUESTER_TOKEN || tokenId == OTHER_APP_TOKEN) {
        tokenInfo.bundleName = "com.example.other";
    } else {
        return -1;
    }
    return RET_SUCCESS;
}
} // namespace

class UdmfDragProxyAuthorizationTest : public testing::Test {
public:
    void SetUp() override
    {
        accessTokenKitMock_ = std::make_shared<AccessTokenKitMock>();
        BAccessTokenKit::accessTokenkit = accessTokenKitMock_;
    }

    void TearDown() override
    {
        BAccessTokenKit::accessTokenkit = nullptr;
        accessTokenKitMock_ = nullptr;
    }

protected:
    std::shared_ptr<AccessTokenKitMock> accessTokenKitMock_;
};

/**
 * @tc.name: DesktopToFileManager_SameUser_ReturnTrue
 * @tc.desc: Allow file manager to consume a virtual drag authorized to the desktop in the same user.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfDragProxyAuthorizationTest, DesktopToFileManager_SameUser_ReturnTrue, TestSize.Level0)
{
    EXPECT_CALL(*accessTokenKitMock_, GetTokenTypeFlag(_)).WillRepeatedly(Return(TOKEN_HAP));
    EXPECT_CALL(*accessTokenKitMock_, GetHapTokenInfo(_, _)).WillRepeatedly(Invoke(FillKnownHapTokenInfo));

    EXPECT_TRUE(UDMF::DragProxyAuthorization::IsAuthorized(FILE_MANAGER_TOKEN, { DESKTOP_TOKEN }));
}

/**
 * @tc.name: DesktopToOtherRequester_ReturnFalse
 * @tc.desc: Reject a desktop grant when the requesting application is not file manager.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfDragProxyAuthorizationTest, DesktopToOtherRequester_ReturnFalse, TestSize.Level0)
{
    EXPECT_CALL(*accessTokenKitMock_, GetTokenTypeFlag(_)).WillRepeatedly(Return(TOKEN_HAP));
    EXPECT_CALL(*accessTokenKitMock_, GetHapTokenInfo(_, _)).WillRepeatedly(Invoke(FillKnownHapTokenInfo));

    EXPECT_FALSE(UDMF::DragProxyAuthorization::IsAuthorized(OTHER_REQUESTER_TOKEN, { DESKTOP_TOKEN }));
}

/**
 * @tc.name: OtherGrantToFileManager_ReturnFalse
 * @tc.desc: Reject file manager when the authorized application is not the desktop.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfDragProxyAuthorizationTest, OtherGrantToFileManager_ReturnFalse, TestSize.Level0)
{
    EXPECT_CALL(*accessTokenKitMock_, GetTokenTypeFlag(_)).WillRepeatedly(Return(TOKEN_HAP));
    EXPECT_CALL(*accessTokenKitMock_, GetHapTokenInfo(_, _)).WillRepeatedly(Invoke(FillKnownHapTokenInfo));

    EXPECT_FALSE(UDMF::DragProxyAuthorization::IsAuthorized(FILE_MANAGER_TOKEN, { OTHER_APP_TOKEN }));
}

/**
 * @tc.name: CrossUserDesktopToFileManager_ReturnFalse
 * @tc.desc: Reject the desktop delegation when desktop and file manager belong to different users.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfDragProxyAuthorizationTest, CrossUserDesktopToFileManager_ReturnFalse, TestSize.Level0)
{
    EXPECT_CALL(*accessTokenKitMock_, GetTokenTypeFlag(_)).WillRepeatedly(Return(TOKEN_HAP));
    EXPECT_CALL(*accessTokenKitMock_, GetHapTokenInfo(_, _)).WillRepeatedly(Invoke(FillKnownHapTokenInfo));

    EXPECT_FALSE(UDMF::DragProxyAuthorization::IsAuthorized(FILE_MANAGER_TOKEN, { OTHER_USER_DESKTOP_TOKEN }));
}

/**
 * @tc.name: NativeRequester_ReturnFalse
 * @tc.desc: Reject non-HAP requesters before resolving application identity.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfDragProxyAuthorizationTest, NativeRequester_ReturnFalse, TestSize.Level0)
{
    EXPECT_CALL(*accessTokenKitMock_, GetTokenTypeFlag(FILE_MANAGER_TOKEN)).WillOnce(Return(TOKEN_NATIVE));
    EXPECT_CALL(*accessTokenKitMock_, GetHapTokenInfo(_, _)).Times(0);

    EXPECT_FALSE(UDMF::DragProxyAuthorization::IsAuthorized(FILE_MANAGER_TOKEN, { DESKTOP_TOKEN }));
}

/**
 * @tc.name: RequesterLookupFailure_ReturnFalse
 * @tc.desc: Fail closed when the requester token cannot be resolved.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfDragProxyAuthorizationTest, RequesterLookupFailure_ReturnFalse, TestSize.Level0)
{
    EXPECT_CALL(*accessTokenKitMock_, GetTokenTypeFlag(FILE_MANAGER_TOKEN)).WillOnce(Return(TOKEN_HAP));
    EXPECT_CALL(*accessTokenKitMock_, GetHapTokenInfo(FILE_MANAGER_TOKEN, _)).WillOnce(Return(-1));

    EXPECT_FALSE(UDMF::DragProxyAuthorization::IsAuthorized(FILE_MANAGER_TOKEN, { DESKTOP_TOKEN }));
}

/**
 * @tc.name: ZeroRequester_ReturnFalse
 * @tc.desc: Reject an empty requester identity without querying access token metadata.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfDragProxyAuthorizationTest, ZeroRequester_ReturnFalse, TestSize.Level0)
{
    EXPECT_CALL(*accessTokenKitMock_, GetTokenTypeFlag(_)).Times(0);
    EXPECT_CALL(*accessTokenKitMock_, GetHapTokenInfo(_, _)).Times(0);

    EXPECT_FALSE(UDMF::DragProxyAuthorization::IsAuthorized(0, { DESKTOP_TOKEN }));
}

/**
 * @tc.name: InvalidGrantBeforeDesktop_ReturnTrue
 * @tc.desc: Ignore an unresolvable grant and allow a later same-user desktop grant.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfDragProxyAuthorizationTest, InvalidGrantBeforeDesktop_ReturnTrue, TestSize.Level0)
{
    EXPECT_CALL(*accessTokenKitMock_, GetTokenTypeFlag(_)).WillRepeatedly(Return(TOKEN_HAP));
    EXPECT_CALL(*accessTokenKitMock_, GetHapTokenInfo(_, _)).WillRepeatedly(Invoke(FillKnownHapTokenInfo));

    EXPECT_TRUE(UDMF::DragProxyAuthorization::IsAuthorized(FILE_MANAGER_TOKEN, { UNKNOWN_TOKEN, DESKTOP_TOKEN }));
}

/**
 * @tc.name: EmptyGrantList_ReturnFalse
 * @tc.desc: Reject file manager when no application has been authorized for the drag data.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfDragProxyAuthorizationTest, EmptyGrantList_ReturnFalse, TestSize.Level0)
{
    EXPECT_CALL(*accessTokenKitMock_, GetTokenTypeFlag(FILE_MANAGER_TOKEN)).WillOnce(Return(TOKEN_HAP));
    EXPECT_CALL(*accessTokenKitMock_, GetHapTokenInfo(FILE_MANAGER_TOKEN, _)).WillOnce(Invoke(FillKnownHapTokenInfo));

    EXPECT_FALSE(UDMF::DragProxyAuthorization::IsAuthorized(FILE_MANAGER_TOKEN, {}));
}
} // namespace OHOS::Test::DistributedDataTest
