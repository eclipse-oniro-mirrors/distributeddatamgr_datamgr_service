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

#define LOG_TAG "UdmfServiceStubTest"
#include "udmf_service_stub.h"

#include "gtest/gtest.h"
#include "ipc_object_stub.h"
#include "ipc_skeleton.h"
#include "test/mock/udmf_auth_reply_service_mock.h"
#include "udmf_service_impl.h"
#include "udmf_types_util.h"
#include "unified_key.h"

using namespace OHOS::DistributedData;
namespace OHOS::UDMF {
using namespace testing::ext;
class UdmfServiceStubTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
    void SetUp() {}
    void TearDown() {}
};

constexpr const char *DATA_HUB_KEY = "udmf://DataHub/com.example.app/1233455";
constexpr const char *DRAG_KEY = "udmf://drag/com.example.app/1233455";
constexpr const char *UNKNOWN_INTENTION_KEY = "udmf://Unknown/com.example.app/1233455";
constexpr const char *INVALID_KEY = "invalid_key";

/**
* @tc.name: OnRemoteRequest001
* @tc.desc: Abnormal test of OnRemoteRequest, code is invalid
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(UdmfServiceStubTest, OnRemoteRequest001, TestSize.Level1)
{
    uint32_t code = 17; // invalid code
    MessageParcel data;
    MessageParcel reply;
    UdmfServiceImpl udmfServiceImpl;
    int ret = udmfServiceImpl.OnRemoteRequest(code, data, reply);
    EXPECT_EQ(ret, -1);
}

/**
* @tc.name: OnSetData001
* @tc.desc: Abnormal test of OnSetData, data is invalid
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(UdmfServiceStubTest, OnSetData001, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    UdmfServiceImpl udmfServiceImpl;
    int ret = udmfServiceImpl.OnSetData(data, reply);
    EXPECT_EQ(ret, E_READ_PARCEL_ERROR);
}

/**
* @tc.name: OnGetData001
* @tc.desc: Abnormal test of OnGetData, data is invalid
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(UdmfServiceStubTest, OnGetData001, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    UdmfServiceImpl udmfServiceImpl;
    int ret = udmfServiceImpl.OnGetData(data, reply);
    EXPECT_EQ(ret, E_READ_PARCEL_ERROR);
}

/**
* @tc.name: OnGetBatchData001
* @tc.desc: Abnormal test of OnGetBatchData, data is invalid
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(UdmfServiceStubTest, OnGetBatchData001, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    UdmfServiceImpl udmfServiceImpl;
    int ret = udmfServiceImpl.OnGetBatchData(data, reply);
    EXPECT_EQ(ret, E_READ_PARCEL_ERROR);
}

/**
* @tc.name: OnUpdateData001
* @tc.desc: Abnormal test of OnUpdateData, data is invalid
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(UdmfServiceStubTest, OnUpdateData001, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    UdmfServiceImpl udmfServiceImpl;
    int ret = udmfServiceImpl.OnUpdateData(data, reply);
    EXPECT_EQ(ret, E_READ_PARCEL_ERROR);
}

/**
* @tc.name: OnDeleteData001
* @tc.desc: Abnormal test of OnDeleteData, data is invalid
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(UdmfServiceStubTest, OnDeleteData001, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    UdmfServiceImpl udmfServiceImpl;
    int ret = udmfServiceImpl.OnDeleteData(data, reply);
    EXPECT_EQ(ret, E_READ_PARCEL_ERROR);
}

/**
* @tc.name: OnGetSummary001
* @tc.desc: Abnormal test of OnGetSummary, data is invalid
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(UdmfServiceStubTest, OnGetSummary001, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    UdmfServiceImpl udmfServiceImpl;
    int ret = udmfServiceImpl.OnGetSummary(data, reply);
    EXPECT_EQ(ret, E_READ_PARCEL_ERROR);
}

/**
* @tc.name: OnAddPrivilege001
* @tc.desc: Abnormal test of OnAddPrivilege, data is invalid
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(UdmfServiceStubTest, OnAddPrivilege001, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    UdmfServiceImpl udmfServiceImpl;
    int ret = udmfServiceImpl.OnAddPrivilege(data, reply);
    EXPECT_EQ(ret, E_READ_PARCEL_ERROR);
}

/**
* @tc.name: OnIsRemoteData001
* @tc.desc: Abnormal test of OnIsRemoteData, data is invalid
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(UdmfServiceStubTest, OnIsRemoteData001, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    UdmfServiceImpl udmfServiceImpl;
    int ret = udmfServiceImpl.OnIsRemoteData(data, reply);
    EXPECT_EQ(ret, E_READ_PARCEL_ERROR);
}

/**
* @tc.name: OnSetAppShareOption001
* @tc.desc: Abnormal test of OnSetAppShareOption, data is invalid
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(UdmfServiceStubTest, OnSetAppShareOption001, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    UdmfServiceImpl udmfServiceImpl;
    int ret = udmfServiceImpl.OnSetAppShareOption(data, reply);
    EXPECT_EQ(ret, E_READ_PARCEL_ERROR);
}

/**
* @tc.name: OnGetAppShareOption001
* @tc.desc: Abnormal test of OnGetAppShareOption, data is invalid
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(UdmfServiceStubTest, OnGetAppShareOption001, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    UdmfServiceImpl udmfServiceImpl;
    int ret = udmfServiceImpl.OnGetAppShareOption(data, reply);
    EXPECT_EQ(ret, E_READ_PARCEL_ERROR);
}

/**
* @tc.name: OnRemoveAppShareOption001
* @tc.desc: Abnormal test of OnRemoveAppShareOption, data is invalid
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(UdmfServiceStubTest, OnRemoveAppShareOption001, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    UdmfServiceImpl udmfServiceImpl;
    int ret = udmfServiceImpl.OnRemoveAppShareOption(data, reply);
    EXPECT_EQ(ret, E_READ_PARCEL_ERROR);
}

/**
* @tc.name: OnObtainAsynProcess001
* @tc.desc: Abnormal test of OnObtainAsynProcess, data is invalid
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(UdmfServiceStubTest, OnObtainAsynProcess001, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    UdmfServiceImpl udmfServiceImpl;
    int ret = udmfServiceImpl.OnObtainAsynProcess(data, reply);
    EXPECT_EQ(ret, E_READ_PARCEL_ERROR);
}

/**
* @tc.name: OnClearAsynProcessByKey001
* @tc.desc: Abnormal test of OnClearAsynProcessByKey, data is invalid
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(UdmfServiceStubTest, OnClearAsynProcessByKey001, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    UdmfServiceImpl udmfServiceImpl;
    int ret = udmfServiceImpl.OnClearAsynProcessByKey(data, reply);
    EXPECT_EQ(ret, E_READ_PARCEL_ERROR);
}

/**
* @tc.name: NormalizeQueryOption001
* @tc.desc: BASE intention is normalized from a valid DataHub key
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(UdmfServiceStubTest, NormalizeQueryOption001, TestSize.Level1)
{
    QueryOption query;
    query.key = DATA_HUB_KEY;
    query.intention = UD_INTENTION_BASE;
    UdmfServiceImpl udmfServiceImpl;

    EXPECT_EQ(udmfServiceImpl.NormalizeQueryOption(query), E_OK);
    EXPECT_EQ(query.intention, UD_INTENTION_DATA_HUB);
}

/**
* @tc.name: NormalizeQueryOption002
* @tc.desc: BASE intention is normalized from a valid drag key
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(UdmfServiceStubTest, NormalizeQueryOption002, TestSize.Level1)
{
    QueryOption query;
    query.key = DRAG_KEY;
    query.intention = UD_INTENTION_BASE;
    UdmfServiceImpl udmfServiceImpl;

    EXPECT_EQ(udmfServiceImpl.NormalizeQueryOption(query), E_OK);
    EXPECT_EQ(query.intention, UD_INTENTION_DRAG);
}

/**
* @tc.name: NormalizeQueryOption003
* @tc.desc: Matching query intention and key intention is allowed
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(UdmfServiceStubTest, NormalizeQueryOption003, TestSize.Level1)
{
    QueryOption query;
    query.key = DATA_HUB_KEY;
    query.intention = UD_INTENTION_DATA_HUB;
    UdmfServiceImpl udmfServiceImpl;

    EXPECT_EQ(udmfServiceImpl.NormalizeQueryOption(query), E_OK);
    EXPECT_EQ(query.intention, UD_INTENTION_DATA_HUB);
}

/**
* @tc.name: NormalizeQueryOption004
* @tc.desc: Mismatched query intention and key intention is rejected
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(UdmfServiceStubTest, NormalizeQueryOption004, TestSize.Level1)
{
    QueryOption query;
    query.key = DATA_HUB_KEY;
    query.intention = UD_INTENTION_DRAG;
    UdmfServiceImpl udmfServiceImpl;

    EXPECT_EQ(udmfServiceImpl.NormalizeQueryOption(query), E_INVALID_PARAMETERS);
}

/**
* @tc.name: NormalizeQueryOption005
* @tc.desc: Empty key with BASE intention is rejected
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(UdmfServiceStubTest, NormalizeQueryOption005, TestSize.Level1)
{
    QueryOption query;
    query.intention = UD_INTENTION_BASE;
    UdmfServiceImpl udmfServiceImpl;

    EXPECT_EQ(udmfServiceImpl.NormalizeQueryOption(query), E_INVALID_PARAMETERS);
}

/**
* @tc.name: NormalizeQueryOption006
* @tc.desc: Empty key with explicit intention is allowed
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(UdmfServiceStubTest, NormalizeQueryOption006, TestSize.Level1)
{
    QueryOption query;
    query.intention = UD_INTENTION_DATA_HUB;
    UdmfServiceImpl udmfServiceImpl;

    EXPECT_EQ(udmfServiceImpl.NormalizeQueryOption(query), E_OK);
    EXPECT_EQ(query.intention, UD_INTENTION_DATA_HUB);
}

/**
* @tc.name: NormalizeQueryOption007
* @tc.desc: Invalid key is rejected
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(UdmfServiceStubTest, NormalizeQueryOption007, TestSize.Level1)
{
    QueryOption query;
    query.key = INVALID_KEY;
    query.intention = UD_INTENTION_BASE;
    UdmfServiceImpl udmfServiceImpl;

    EXPECT_EQ(udmfServiceImpl.NormalizeQueryOption(query), E_INVALID_PARAMETERS);
}

/**
* @tc.name: NormalizeQueryOption008
* @tc.desc: Valid key format with unknown intention is rejected
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(UdmfServiceStubTest, NormalizeQueryOption008, TestSize.Level1)
{
    QueryOption query;
    query.key = UNKNOWN_INTENTION_KEY;
    query.intention = UD_INTENTION_BASE;
    UdmfServiceImpl udmfServiceImpl;

    EXPECT_EQ(udmfServiceImpl.NormalizeQueryOption(query), E_INVALID_PARAMETERS);
}
/**
 * @tc.name: OnRemoteRequest_ReadAndDelayDenied_EmptySerializedPayload
 * @tc.desc: Verify authorization behavior through public interfaces.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfServiceStubTest, OnRemoteRequest_ReadAndDelayDenied_EmptySerializedPayload, TestSize.Level1)
{
    for (auto expected : { E_NO_PERMISSION, E_INVALID_PARAMETERS }) {
        for (auto code : { UdmfServiceInterfaceCode::GET_DATA, UdmfServiceInterfaceCode::GET_DELAY_DATA }) {
            testing::StrictMock<UdmfAuthReplyServiceMock> service;
            auto fill = [](UnifiedData &output) {
                output.AddRecord(std::make_shared<UnifiedRecord>(PLAIN_TEXT, std::string("private-content")));
                output.GetProperties()->tag = "private-tag";
                Runtime runtime{};
                runtime.key = UnifiedKey(DRAG_KEY);
                runtime.createPackage = "private-owner";
                output.SetRuntime(runtime);
            };
            if (code == UdmfServiceInterfaceCode::GET_DATA) {
                EXPECT_CALL(service, GetData(testing::_, testing::_))
                    .WillOnce(testing::Invoke([&](const QueryOption &, UnifiedData &output) {
                        fill(output);
                        return expected;
                    }));
            } else {
                EXPECT_CALL(service, GetDataIfAvailable(testing::_, testing::_, testing::_, testing::_))
                    .WillOnce(testing::Invoke([&](const std::string &, const DataLoadInfo &, sptr<IRemoteObject>,
                                                  std::shared_ptr<UnifiedData> output) {
                        fill(*output);
                        return expected;
                    }));
            }
            MessageParcel request;
            MessageParcel reply;
            ASSERT_TRUE(request.WriteInterfaceToken(UdmfServiceStub::GetDescriptor()));
            if (code == UdmfServiceInterfaceCode::GET_DATA) {
                QueryOption query;
                query.key = DRAG_KEY;
                ASSERT_TRUE(ITypesUtil::Marshal(request, query));
            } else {
                DataLoadInfo info;
                sptr<IRemoteObject> notifier = new IPCObjectStub(u"udmf-auth-test");
                ASSERT_TRUE(ITypesUtil::Marshal(request, std::string(DRAG_KEY), info, notifier));
            }
            ASSERT_EQ(service.OnRemoteRequest(static_cast<uint32_t>(code), request, reply), E_OK);
            int32_t status = E_ERROR;
            UnifiedData received;
            ASSERT_TRUE(ITypesUtil::Unmarshal(reply, status, received));
            EXPECT_EQ(status, expected);
            EXPECT_TRUE(received.GetRecords().empty());
            EXPECT_EQ(received.GetRuntime(), nullptr);
            ASSERT_NE(received.GetProperties(), nullptr);
            EXPECT_TRUE(received.GetProperties()->tag.empty());
        }
    }
}
/**
 * @tc.name: OnRemoteRequest_ReadAndDelayAllowed_PreservesSerializedPayload
 * @tc.desc: Verify authorization behavior through public interfaces.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfServiceStubTest, OnRemoteRequest_ReadAndDelayAllowed_PreservesSerializedPayload, TestSize.Level1)
{
    for (auto code : { UdmfServiceInterfaceCode::GET_DATA, UdmfServiceInterfaceCode::GET_DELAY_DATA }) {
        testing::StrictMock<UdmfAuthReplyServiceMock> service;
        auto fill = [](UnifiedData &output) {
            output.AddRecord(std::make_shared<UnifiedRecord>(PLAIN_TEXT, std::string("private-content")));
            output.GetProperties()->tag = "private-tag";
            Runtime runtime{};
            runtime.key = UnifiedKey(DRAG_KEY);
            runtime.createPackage = "private-owner";
            output.SetRuntime(runtime);
        };
        if (code == UdmfServiceInterfaceCode::GET_DATA) {
            EXPECT_CALL(service, GetData(testing::_, testing::_))
                .WillOnce(testing::Invoke([&](const QueryOption &, UnifiedData &output) {
                    fill(output);
                    return E_OK;
                }));
        } else {
            EXPECT_CALL(service, GetDataIfAvailable(testing::_, testing::_, testing::_, testing::_))
                .WillOnce(testing::Invoke([&](const std::string &, const DataLoadInfo &, sptr<IRemoteObject>,
                                              std::shared_ptr<UnifiedData> output) {
                    fill(*output);
                    return E_OK;
                }));
        }
        MessageParcel request;
        MessageParcel reply;
        ASSERT_TRUE(request.WriteInterfaceToken(UdmfServiceStub::GetDescriptor()));
        if (code == UdmfServiceInterfaceCode::GET_DATA) {
            QueryOption query;
            query.key = DRAG_KEY;
            ASSERT_TRUE(ITypesUtil::Marshal(request, query));
        } else {
            DataLoadInfo info;
            sptr<IRemoteObject> notifier = new IPCObjectStub(u"udmf-auth-test");
            ASSERT_TRUE(ITypesUtil::Marshal(request, std::string(DRAG_KEY), info, notifier));
        }
        ASSERT_EQ(service.OnRemoteRequest(static_cast<uint32_t>(code), request, reply), E_OK);
        int32_t status = E_ERROR;
        UnifiedData received;
        ASSERT_TRUE(ITypesUtil::Unmarshal(reply, status, received));
        EXPECT_EQ(status, E_OK);
        ASSERT_EQ(received.GetRecords().size(), 1u);
        auto record = received.GetRecords()[0];
        ASSERT_NE(record, nullptr);
        auto value = record->GetOriginValue();
        ASSERT_TRUE(std::holds_alternative<std::string>(value));
        EXPECT_EQ(std::get<std::string>(value), "private-content");
        ASSERT_NE(received.GetRuntime(), nullptr);
        EXPECT_EQ(received.GetRuntime()->createPackage, "private-owner");
        ASSERT_NE(received.GetProperties(), nullptr);
        EXPECT_EQ(received.GetProperties()->tag, "private-tag");
    }
}

/**
 * @tc.name: OnRemoteRequest_GetData_ReplacesForgedTokenBeforeAuthorization
 * @tc.desc: Verify public behavior, failure propagation and observable state.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfServiceStubTest, OnRemoteRequest_GetData_ReplacesForgedTokenBeforeAuthorization, TestSize.Level1)
{
    testing::StrictMock<UdmfAuthReplyServiceMock> service;
    const uint32_t actual = static_cast<uint32_t>(IPCSkeleton::GetCallingTokenID());
    EXPECT_CALL(service, GetData(testing::_, testing::_)).WillOnce([&](const QueryOption &query, UnifiedData &) {
        EXPECT_EQ(query.tokenId, actual);
        EXPECT_EQ(query.key, DRAG_KEY);
        return E_NO_PERMISSION;
    });
    QueryOption query;
    query.key = DRAG_KEY;
    query.tokenId = actual ^ 0x7FFFFFFF;
    MessageParcel request;
    MessageParcel reply;
    ASSERT_TRUE(request.WriteInterfaceToken(UdmfServiceStub::GetDescriptor()));
    ASSERT_TRUE(ITypesUtil::Marshal(request, query));
    ASSERT_EQ(
        service.OnRemoteRequest(static_cast<uint32_t>(UdmfServiceInterfaceCode::GET_DATA), request, reply), E_OK);
    int32_t status = E_OK;
    UnifiedData output;
    ASSERT_TRUE(ITypesUtil::Unmarshal(reply, status, output));
    EXPECT_EQ(status, E_NO_PERMISSION);
    EXPECT_TRUE(output.IsEmpty());
}
/**
 * @tc.name: OnRemoteRequest_DelayMissingNotifier_RejectsBeforeBusiness
 * @tc.desc: Verify public behavior, failure propagation and observable state.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfServiceStubTest, OnRemoteRequest_DelayMissingNotifier_RejectsBeforeBusiness, TestSize.Level1)
{
    testing::StrictMock<UdmfAuthReplyServiceMock> service;
    MessageParcel request;
    MessageParcel reply;
    ASSERT_TRUE(request.WriteInterfaceToken(UdmfServiceStub::GetDescriptor()));
    DataLoadInfo info;
    ASSERT_TRUE(ITypesUtil::Marshal(request, std::string(DRAG_KEY), info));
    EXPECT_EQ(service.OnRemoteRequest(static_cast<uint32_t>(UdmfServiceInterfaceCode::GET_DELAY_DATA), request, reply),
        E_ERROR);
    EXPECT_EQ(reply.GetDataSize(), 0u);
}
}; // namespace UDMF
