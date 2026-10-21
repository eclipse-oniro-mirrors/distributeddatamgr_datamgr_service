/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <cstdint>
#include <string>
#include <vector>

#include <gtest/gtest.h>

#include "data_fabric_address_callback.h"
#include "data_fabric_address_callback_proxy.h"
#include "data_fabric_address_errors.h"
#include "data_fabric_address_types.h"
#include "iremote_object.h"
#include "message_parcel.h"

using namespace OHOS;
using namespace OHOS::DataFabricAddress;
using namespace NativePreferences;
using namespace testing::ext;

namespace {
constexpr uint32_t CMD_DATA_CHANGED_CODE = static_cast<uint32_t>(
    IDataFabricAddressCallback::CMD_DATA_CHANGED);
constexpr size_t OVERSIZE_RESULT_LENGTH = 300 * 1024;

class MockCallbackRemote : public IRemoteObject {
public:
    explicit MockCallbackRemote(std::u16string descriptor) : IRemoteObject(descriptor) {}
    ~MockCallbackRemote() override = default;

    int32_t GetObjectRefCount() override
    {
        return 0;
    }

    int SendRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override
    {
        (void)reply;
        (void)option;
        requestCount++;
        receivedCode = code;
        if (captureParcel) {
            receivedToken = data.ReadInterfaceToken();
            data.ReadInt32(receivedCodeValue);
            data.ReadString(receivedResult);
        }
        return sendRequestResult;
    }

    bool AddDeathRecipient(const sptr<DeathRecipient> &recipient) override
    {
        (void)recipient;
        return true;
    }

    bool RemoveDeathRecipient(const sptr<DeathRecipient> &recipient) override
    {
        (void)recipient;
        return true;
    }

    int Dump(int fd, const std::vector<std::u16string> &args) override
    {
        (void)fd;
        (void)args;
        return 0;
    }

    int sendRequestResult = RUN_OK;
    bool captureParcel = false;
    uint32_t requestCount = 0;
    uint32_t receivedCode = 0;
    std::u16string receivedToken;
    int32_t receivedCodeValue = 0;
    std::string receivedResult;
};

NativePreferences::DataProcessingResponse MakeResponse(StatusCode code, const std::string &result)
{
    NativePreferences::DataProcessingResponse response;
    response.code = code;
    response.result = result;
    return response;
}
} // namespace

class DataFabricAddressCallbackProxyTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() override {}
    void TearDown() override {}
};

/**
 * @tc.name: DataFabricAddressCallbackProxyTest001
 * @tc.desc: Test OnDataFabricAddressChanged with a valid response and a successful send request.
 * @tc.type: FUNC
 */
HWTEST_F(DataFabricAddressCallbackProxyTest, DataFabricAddressCallbackProxyTest001, TestSize.Level0)
{
    MockCallbackRemote *mock = new (std::nothrow) MockCallbackRemote(u"mock_remote");
    ASSERT_TRUE(mock != nullptr);
    sptr<IRemoteObject> remote(mock);
    ASSERT_TRUE(remote != nullptr);
    mock->sendRequestResult = RUN_OK;
    mock->captureParcel = true;

    DataFabricAddressCallbackProxy proxy(remote);
    NativePreferences::DataProcessingResponse response = MakeResponse(StatusCode::SUCCESS, "data changed");
    proxy.OnDataFabricAddressChanged(response);

    EXPECT_EQ(mock->requestCount, 1u);
    EXPECT_EQ(mock->receivedCode, CMD_DATA_CHANGED_CODE);
    EXPECT_EQ(mock->receivedToken, IDataFabricAddressCallback::GetDescriptor());
    EXPECT_EQ(mock->receivedCodeValue, static_cast<int32_t>(StatusCode::SUCCESS));
    EXPECT_EQ(mock->receivedResult, "data changed");
}

/**
 * @tc.name: DataFabricAddressCallbackProxyTest002
 * @tc.desc: Test OnDataFabricAddressChanged when the send request returns an error code.
 * @tc.type: FUNC
 */
HWTEST_F(DataFabricAddressCallbackProxyTest, DataFabricAddressCallbackProxyTest002, TestSize.Level0)
{
    MockCallbackRemote *mock = new (std::nothrow) MockCallbackRemote(u"mock_remote");
    ASSERT_TRUE(mock != nullptr);
    sptr<IRemoteObject> remote(mock);
    ASSERT_TRUE(remote != nullptr);
    mock->sendRequestResult = INTERNAL_EXCEPTION;
    mock->captureParcel = true;

    DataFabricAddressCallbackProxy proxy(remote);
    NativePreferences::DataProcessingResponse response = MakeResponse(StatusCode::FAILURE, "server error");
    proxy.OnDataFabricAddressChanged(response);

    EXPECT_EQ(mock->requestCount, 1u);
    EXPECT_EQ(mock->receivedCode, CMD_DATA_CHANGED_CODE);
    EXPECT_EQ(mock->receivedCodeValue, static_cast<int32_t>(StatusCode::FAILURE));
    EXPECT_EQ(mock->receivedResult, "server error");
}

/**
 * @tc.name: DataFabricAddressCallbackProxyTest003
 * @tc.desc: Test OnDataFabricAddressChanged when the result string exceeds the parcel capacity so the write fails.
 * @tc.type: FUNC
 */
HWTEST_F(DataFabricAddressCallbackProxyTest, DataFabricAddressCallbackProxyTest003, TestSize.Level0)
{
    MockCallbackRemote *mock = new (std::nothrow) MockCallbackRemote(u"mock_remote");
    ASSERT_TRUE(mock != nullptr);
    sptr<IRemoteObject> remote(mock);
    ASSERT_TRUE(remote != nullptr);

    DataFabricAddressCallbackProxy proxy(remote);
    NativePreferences::DataProcessingResponse response =
        MakeResponse(StatusCode::SUCCESS, std::string(OVERSIZE_RESULT_LENGTH, 'x'));
    proxy.OnDataFabricAddressChanged(response);

    EXPECT_EQ(mock->requestCount, 0u);
}