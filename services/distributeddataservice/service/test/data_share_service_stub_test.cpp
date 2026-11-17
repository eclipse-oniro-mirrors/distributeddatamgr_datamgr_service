/*
* Copyright (c) 2024 Huawei Device Co., Ltd.
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
#define LOG_TAG "DataShareServiceStubTest"

#include "data_share_service_stub.h"

#include <gtest/gtest.h>
#include <unistd.h>

#include "data_share_service_impl.h"
#include "data_share_types_util.h"
#include "ipc_skeleton.h"
#include "log_print.h"

using namespace testing::ext;
using namespace OHOS::DataShare;
using namespace OHOS::DistributedData;
const std::u16string INTERFACE_TOKEN = u"OHOS.DataShare.IDataShareService";
constexpr uint32_t CODE_MIN = 0;
constexpr size_t TEST_SIZE = 1;
constexpr uint8_t TEST_DATA = 1;
constexpr uint32_t CODE_MAX = IDataShareService::DATA_SHARE_SERVICE_CMD_MAX + 1;
namespace OHOS::Test {
using OHOS::DataShare::LogLabel;
class DataShareServiceStubTest : public testing::Test {
public:
    static void SetUpTestCase(void){};
    static void TearDownTestCase(void){};
    void SetUp(){};
    void TearDown(){};
};
std::shared_ptr<DataShareServiceImpl> dataShareServiceImpl = std::make_shared<DataShareServiceImpl>();
std::shared_ptr<DataShareServiceStub> dataShareServiceStub = dataShareServiceImpl;

/**
* @tc.name: OnRemoteRequest001
* @tc.desc: test OnRemoteRequest data error scene
* @tc.type: FUNC
* @tc.require:SQL
*/
HWTEST_F(DataShareServiceStubTest, OnRemoteRequest001, TestSize.Level1)
{
    uint8_t value = TEST_DATA;
    uint8_t *data = &value;
    size_t size = TEST_SIZE;
    uint32_t code = static_cast<uint32_t>(*data) % (CODE_MAX - CODE_MIN + 1) + CODE_MIN;
    MessageParcel request;
    request.WriteInterfaceToken(INTERFACE_TOKEN);
    request.WriteBuffer(data, size);
    request.RewindRead(0);
    MessageParcel reply;
    auto result = dataShareServiceStub->OnRemoteRequest(code, request, reply);
    EXPECT_EQ(result, IDataShareService::DATA_SHARE_ERROR);

    result = dataShareServiceStub->OnNotifyConnectDone(request, reply);
    EXPECT_EQ(result, IDataShareService::DATA_SHARE_OK);
}

/**
* @tc.name: OnRemoteRequest002
* @tc.desc: test OnRemoteRequest abnormal scene
* @tc.type: FUNC
* @tc.require:SQL
*/
HWTEST_F(DataShareServiceStubTest, OnRemoteRequest002, TestSize.Level1)
{
    uint8_t value = TEST_DATA;
    uint8_t *data = &value;
    uint32_t code = static_cast<uint32_t>(*data) % (CODE_MAX - CODE_MIN + 1) + CODE_MIN;
    MessageParcel request;
    MessageParcel reply;
    auto result = dataShareServiceStub->OnRemoteRequest(code, request, reply);
    EXPECT_EQ(result, IDataShareService::DATA_SHARE_ERROR);

    result = dataShareServiceStub->OnNotifyConnectDone(request, reply);
    EXPECT_EQ(result, IDataShareService::DATA_SHARE_OK);
}

/**
* @tc.name: OnInsert001
* @tc.desc: test InsertEx UpdateEx Query DeleteEx function of abnormal scene
* @tc.type: FUNC
* @tc.require:SQL
*/
HWTEST_F(DataShareServiceStubTest, OnInsert001, TestSize.Level1)
{
    uint8_t value = TEST_DATA;
    uint8_t *data = &value;
    size_t size = TEST_SIZE;
    MessageParcel request;
    request.WriteInterfaceToken(INTERFACE_TOKEN);
    request.WriteBuffer(data, size);
    request.RewindRead(0);
    MessageParcel reply;
    auto result = dataShareServiceStub->OnInsertEx(request, reply);
    EXPECT_EQ(result, IPC_STUB_INVALID_DATA_ERR);

    result = dataShareServiceStub->OnUpdateEx(request, reply);
    EXPECT_EQ(result, IPC_STUB_INVALID_DATA_ERR);

    result = dataShareServiceStub->OnQuery(request, reply);
    EXPECT_EQ(result, IPC_STUB_INVALID_DATA_ERR);

    result = dataShareServiceStub->OnDeleteEx(request, reply);
    EXPECT_EQ(result, IPC_STUB_INVALID_DATA_ERR);
}

/**
* @tc.name: OnAddTemplate001
* @tc.desc: test OnAddTemplate function abnormal scene
* @tc.type: FUNC
* @tc.require:SQL
*/
HWTEST_F(DataShareServiceStubTest, OnAddTemplate001, TestSize.Level1)
{
    uint8_t value = TEST_DATA;
    uint8_t *data = &value;
    size_t size = TEST_SIZE;
    MessageParcel request;
    request.WriteInterfaceToken(INTERFACE_TOKEN);
    request.WriteBuffer(data, size);
    request.RewindRead(0);
    MessageParcel reply;
    auto result = dataShareServiceStub->OnAddTemplate(request, reply);
    EXPECT_EQ(result, IDataShareService::DATA_SHARE_ERROR);

    result = dataShareServiceStub->OnDelTemplate(request, reply);
    EXPECT_EQ(result, IDataShareService::DATA_SHARE_ERROR);
}

/**
* @tc.name: OnEnablePubSubs001
* @tc.desc: test OnEnablePubSubs function abnormal scene
* @tc.type: FUNC
* @tc.require:SQL
*/
HWTEST_F(DataShareServiceStubTest, OnEnablePubSubs001, TestSize.Level1)
{
    uint8_t value = TEST_DATA;
    uint8_t *data = &value;
    size_t size = TEST_SIZE;
    MessageParcel request;
    request.WriteInterfaceToken(INTERFACE_TOKEN);
    request.WriteBuffer(data, size);
    request.RewindRead(0);
    MessageParcel reply;
    auto result = dataShareServiceStub->OnEnablePubSubs(request, reply);
    EXPECT_EQ(result, IDataShareService::DATA_SHARE_ERROR);

    result = dataShareServiceStub->OnPublish(request, reply);
    EXPECT_EQ(result, IDataShareService::DATA_SHARE_ERROR);

    result = dataShareServiceStub->OnGetData(request, reply);
    EXPECT_EQ(result, IDataShareService::DATA_SHARE_ERROR);

    result = dataShareServiceStub->OnSubscribePublishedData(request, reply);
    EXPECT_EQ(result, IDataShareService::DATA_SHARE_ERROR);

    result = dataShareServiceStub->OnUnsubscribePublishedData(request, reply);
    EXPECT_EQ(result, IDataShareService::DATA_SHARE_ERROR);

    result = dataShareServiceStub->OnDisablePubSubs(request, reply);
    EXPECT_EQ(result, IDataShareService::DATA_SHARE_ERROR);
}

/**
* @tc.name: OnEnableRdbSubs001
* @tc.desc: test OnEnableRdbSubs function abnormal scene
* @tc.type: FUNC
* @tc.require:SQL
*/
HWTEST_F(DataShareServiceStubTest, OnEnableRdbSubs001, TestSize.Level1)
{
    uint8_t value = TEST_DATA;
    uint8_t *data = &value;
    size_t size = TEST_SIZE;
    MessageParcel request;
    request.WriteInterfaceToken(INTERFACE_TOKEN);
    request.WriteBuffer(data, size);
    request.RewindRead(0);
    MessageParcel reply;
    auto result = dataShareServiceStub->OnEnablePubSubs(request, reply);
    EXPECT_EQ(result, IDataShareService::DATA_SHARE_ERROR);

    result = dataShareServiceStub->OnPublish(request, reply);
    EXPECT_EQ(result, IDataShareService::DATA_SHARE_ERROR);

    result = dataShareServiceStub->OnEnableRdbSubs(request, reply);
    EXPECT_EQ(result, IDataShareService::DATA_SHARE_ERROR);

    result = dataShareServiceStub->OnSubscribeRdbData(request, reply);
    EXPECT_EQ(result, IDataShareService::DATA_SHARE_ERROR);

    result = dataShareServiceStub->OnUnsubscribeRdbData(request, reply);
    EXPECT_EQ(result, IDataShareService::DATA_SHARE_ERROR);

    result = dataShareServiceStub->OnDisableRdbSubs(request, reply);
    EXPECT_EQ(result, IDataShareService::DATA_SHARE_ERROR);
}

/**
* @tc.name: OnSubscribeRdbData_RemoteObjNull_ReturnError
* @tc.desc: test OnSubscribeRdbData when ReadRemoteObject returns nullptr
* @tc.type: FUNC
* @tc.require:SQL
* @tc.author: agent
*/
HWTEST_F(DataShareServiceStubTest, OnSubscribeRdbData_RemoteObjNull_ReturnError, TestSize.Level1)
{
    ZLOGI("DataShareServiceStubTest::OnSubscribeRdbData_RemoteObjNull_ReturnError start");
    MessageParcel request;
    std::vector<std::string> uris;
    TemplateId templateId;
    ITypesUtil::Marshal(request, uris, templateId);
    MessageParcel reply;
    auto result = dataShareServiceStub->OnSubscribeRdbData(request, reply);
    EXPECT_EQ(result, IPC_STUB_INVALID_DATA_ERR);
    ZLOGI("DataShareServiceStubTest::OnSubscribeRdbData_RemoteObjNull_ReturnError end");
}

/**
* @tc.name: OnSubscribePublishedData_RemoteObjNull_ReturnError
* @tc.desc: test OnSubscribePublishedData when ReadRemoteObject returns nullptr
* @tc.type: FUNC
* @tc.require:SQL
* @tc.author: agent
*/
HWTEST_F(DataShareServiceStubTest, OnSubscribePublishedData_RemoteObjNull_ReturnError, TestSize.Level1)
{
    ZLOGI("DataShareServiceStubTest::OnSubscribePublishedData_RemoteObjNull_ReturnError start");
    MessageParcel request;
    std::vector<std::string> uris;
    int64_t subscriberId = 0;
    ITypesUtil::Marshal(request, uris, subscriberId);
    MessageParcel reply;
    auto result = dataShareServiceStub->OnSubscribePublishedData(request, reply);
    EXPECT_EQ(result, IPC_STUB_INVALID_DATA_ERR);
    ZLOGI("DataShareServiceStubTest::OnSubscribePublishedData_RemoteObjNull_ReturnError end");
}

/**
* @tc.name: OnSubscribeProxyData_RemoteObjNull_ReturnError
* @tc.desc: test OnSubscribeProxyData when ReadRemoteObject returns nullptr
* @tc.type: FUNC
* @tc.require:SQL
* @tc.author: agent
*/
HWTEST_F(DataShareServiceStubTest, OnSubscribeProxyData_RemoteObjNull_ReturnError, TestSize.Level1)
{
    ZLOGI("DataShareServiceStubTest::OnSubscribeProxyData_RemoteObjNull_ReturnError start");
    MessageParcel request;
    std::vector<std::string> uris;
    ITypesUtil::Marshal(request, uris);
    MessageParcel reply;
    auto result = dataShareServiceStub->OnSubscribeProxyData(request, reply);
    EXPECT_EQ(result, IPC_STUB_INVALID_DATA_ERR);
    ZLOGI("DataShareServiceStubTest::OnSubscribeProxyData_RemoteObjNull_ReturnError end");
}
} // namespace OHOS::Test