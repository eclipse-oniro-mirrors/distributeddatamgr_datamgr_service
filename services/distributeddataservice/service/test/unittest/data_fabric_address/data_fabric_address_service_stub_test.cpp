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

#include <gtest/gtest.h>

#include "data_fabric_address_callback.h"
#include "data_fabric_address_errors.h"
#include "data_fabric_address_service_stub.h"
#include "data_fabric_address_test_utils.h"
#include "message_parcel.h"
#include "mock/access_token_mock.h"
#include "parameters.h"

using namespace OHOS;
using namespace OHOS::DataFabricAddress;
using namespace OHOS::Security::AccessToken;
using namespace NativePreferences;
using namespace testing;
using namespace testing::ext;
using DataFabricAddressTest::TestDataFabricAddressCallbackStub;

namespace {
constexpr uint32_t CMD_SUBSCRIBE = OHOS::DataFabricAddress::IDataFabricAddressService::RemoteOperation::SUBSCRIBE;
constexpr uint32_t CMD_UNSUBSCRIBE = OHOS::DataFabricAddress::IDataFabricAddressService::RemoteOperation::UNSUBSCRIBE;

class TestDataFabricAddressServiceStub : public DataFabricAddressServiceStub {
public:
    int32_t Subscribe(const DataFabricAddressParams& inputParams,
        sptr<IDataFabricAddressCallback> callback) override
    {
        subscribeCalled = true;
        subscribeParams = inputParams;
        subscribeCallback = callback;
        return subscribeResult;
    }

    int32_t Unsubscribe(const DataFabricAddressParams& inputParams) override
    {
        unsubscribeCalled = true;
        unsubscribeParams = inputParams;
        return unsubscribeResult;
    }

    bool subscribeCalled = false;
    bool unsubscribeCalled = false;
    int32_t subscribeResult = RUN_OK;
    int32_t unsubscribeResult = RUN_OK;
    DataFabricAddressParams subscribeParams;
    DataFabricAddressParams unsubscribeParams;
    sptr<IDataFabricAddressCallback> subscribeCallback;
};

void BuildSubscribeParcel(MessageParcel &data, const DataFabricAddressParams &params, int32_t pointLines,
    bool withRemote = true)
{
    data.WriteInterfaceToken(TestDataFabricAddressServiceStub::GetDescriptor());
    data.WriteInt32(static_cast<int32_t>(params.scenarioType));
    data.WriteInt32(static_cast<int32_t>(params.locationInfo.actionType));
    data.WriteInt32(static_cast<int32_t>(params.locationInfo.points.size()));
    for (int32_t i = 0; i < pointLines; ++i) {
        if (i >= static_cast<int32_t>(params.locationInfo.points.size())) {
            break;
        }
        data.WriteInt32(static_cast<int32_t>(params.locationInfo.points[i].labelType));
        data.WriteInt32(static_cast<int32_t>(params.locationInfo.points[i].coordinateSystemType));
        data.WriteDouble(params.locationInfo.points[i].locationPoint.latitude);
        data.WriteDouble(params.locationInfo.points[i].locationPoint.longitude);
    }
    if (withRemote) {
        data.WriteRemoteObject(sptr<IRemoteObject>(new TestDataFabricAddressCallbackStub()));
    }
}
} // namespace

class DataFabricAddressServiceStubTest : public testing::Test {
public:
    static void SetUpTestCase()
    {
        accTokenMock = std::make_shared<AccessTokenKitMock>();
        tokenIdMock = std::make_shared<TokenIdKitMock>();
        BAccessTokenKit::accessTokenkit = accTokenMock;
        BTokenIdKit::tokenkIdKit = tokenIdMock;
    }

    static void TearDownTestCase()
    {
        accTokenMock = nullptr;
        tokenIdMock = nullptr;
        BAccessTokenKit::accessTokenkit = nullptr;
        BTokenIdKit::tokenkIdKit = nullptr;
    }

    void SetUp() override {}
    void TearDown() override {}

public:
    static inline std::shared_ptr<AccessTokenKitMock> accTokenMock;
    static inline std::shared_ptr<TokenIdKitMock> tokenIdMock;
};

namespace {
bool IsPhoneDevice()
{
    return OHOS::system::GetParameter("const.product.devicetype", "") == "phone";
}

void ExpectSystemNativeCall()
{
    EXPECT_CALL(*DataFabricAddressServiceStubTest::accTokenMock, GetTokenTypeFlag(testing::_))
        .WillRepeatedly(testing::Return(ATokenTypeEnum::TOKEN_NATIVE));
}

void ExpectAllPermissionGranted()
{
    EXPECT_CALL(*DataFabricAddressServiceStubTest::accTokenMock,
        VerifyAccessToken(testing::_, "ohos.permission.APPROXIMATELY_LOCATION"))
        .WillRepeatedly(testing::Return(static_cast<int32_t>(PermissionState::PERMISSION_GRANTED)));
    EXPECT_CALL(*DataFabricAddressServiceStubTest::accTokenMock,
        VerifyAccessToken(testing::_, "ohos.permission.LOCATION"))
        .WillRepeatedly(testing::Return(static_cast<int32_t>(PermissionState::PERMISSION_GRANTED)));
    EXPECT_CALL(*DataFabricAddressServiceStubTest::accTokenMock,
        VerifyAccessToken(testing::_, "ohos.permission.LOCATION_IN_BACKGROUND"))
        .WillRepeatedly(testing::Return(static_cast<int32_t>(PermissionState::PERMISSION_GRANTED)));
}
} // namespace

class DataFabricAddressServiceStubValidCallTest : public DataFabricAddressServiceStubTest {
public:
    void SetUp() override
    {
        if (!IsPhoneDevice()) {
            GTEST_SKIP() << "Only phone devices pass the device type check.";
        }
        ExpectSystemNativeCall();
        ExpectAllPermissionGranted();
    }

    void TearDown() override {}
};

/**
 * @tc.name: DataFabricAddressServiceStubTest001
 * @tc.desc: Test OnRemoteRequest when the remote descriptor does not match local descriptor.
 * @tc.type: FUNC
 */
HWTEST_F(DataFabricAddressServiceStubTest, DataFabricAddressServiceStubTest001, TestSize.Level0)
{
    TestDataFabricAddressServiceStub stub;
    MessageParcel data;
    MessageParcel reply;
    data.WriteInterfaceToken(u"OHOS.DataFabricAddress.UnknownService");
    int result = stub.OnRemoteRequest(CMD_SUBSCRIBE, data, reply);
    EXPECT_EQ(result, INTERNAL_EXCEPTION);
    EXPECT_FALSE(stub.subscribeCalled);
}

/**
 * @tc.name: DataFabricAddressServiceStubTest002
 * @tc.desc: Test OnRemoteRequest when the cmd code is out of the handler enum range.
 * @tc.type: FUNC
 */
HWTEST_F(DataFabricAddressServiceStubTest, DataFabricAddressServiceStubTest002, TestSize.Level0)
{
    TestDataFabricAddressServiceStub stub;
    MessageParcel data;
    MessageParcel reply;
    data.WriteInterfaceToken(TestDataFabricAddressServiceStub::GetDescriptor());
    int result = stub.OnRemoteRequest(100, data, reply);
    EXPECT_EQ(result, INTERNAL_EXCEPTION);
    EXPECT_FALSE(stub.subscribeCalled);
    EXPECT_FALSE(stub.unsubscribeCalled);
}

/**
 * @tc.name: DataFabricAddressServiceStubTest003
 * @tc.desc: Test OnRemoteRequest subscribe when the param data in parcel is incomplete.
 * @tc.type: FUNC
 */
HWTEST_F(DataFabricAddressServiceStubValidCallTest, DataFabricAddressServiceStubTest003, TestSize.Level0)
{
    TestDataFabricAddressServiceStub stub;
    MessageParcel data;
    MessageParcel reply;
    data.WriteInterfaceToken(TestDataFabricAddressServiceStub::GetDescriptor());
    data.WriteInt32(static_cast<int32_t>(BusinessScenario::SCENARIO_NAVIGATION_COMMUTE));
    int result = stub.OnRemoteRequest(CMD_SUBSCRIBE, data, reply);
    EXPECT_EQ(result, INTERNAL_EXCEPTION);
    EXPECT_FALSE(stub.subscribeCalled);
}

/**
 * @tc.name: DataFabricAddressServiceStubTest004
 * @tc.desc: Test OnRemoteRequest subscribe when the points data in parcel is truncated.
 * @tc.type: FUNC
 */
HWTEST_F(DataFabricAddressServiceStubValidCallTest, DataFabricAddressServiceStubTest004, TestSize.Level0)
{
    TestDataFabricAddressServiceStub stub;
    DataFabricAddressParams params;
    params.scenarioType = BusinessScenario::SCENARIO_NAVIGATION_COMMUTE;
    params.locationInfo.actionType = ActionType::SUBSCRIPTION;
    params.locationInfo.points = {
        { LabelType::HOME, CoordinateSystemType::WGS84, { 31.2304, 121.4737 } },
        { LabelType::COMPANY, CoordinateSystemType::WGS84, { 31.2204, 121.4137 } },
    };
    MessageParcel data;
    BuildSubscribeParcel(data, params, 1, false);
    MessageParcel reply;
    int result = stub.OnRemoteRequest(CMD_SUBSCRIBE, data, reply);
    EXPECT_EQ(result, INTERNAL_EXCEPTION);
    EXPECT_FALSE(stub.subscribeCalled);
}

/**
 * @tc.name: DataFabricAddressServiceStubTest005
 * @tc.desc: Test OnRemoteRequest subscribe when the callback remote object is missing.
 * @tc.type: FUNC
 */
HWTEST_F(DataFabricAddressServiceStubValidCallTest, DataFabricAddressServiceStubTest005, TestSize.Level0)
{
    TestDataFabricAddressServiceStub stub;
    DataFabricAddressParams params;
    params.scenarioType = BusinessScenario::SCENARIO_NAVIGATION_COMMUTE;
    params.locationInfo.actionType = ActionType::SUBSCRIPTION;
    params.locationInfo.points = {
        { LabelType::HOME, CoordinateSystemType::WGS84, { 31.2304, 121.4737 } },
        { LabelType::COMPANY, CoordinateSystemType::WGS84, { 31.2204, 121.4137 } },
    };
    MessageParcel data;
    BuildSubscribeParcel(data, params, 2, false);
    MessageParcel reply;
    int result = stub.OnRemoteRequest(CMD_SUBSCRIBE, data, reply);
    EXPECT_EQ(result, INTERNAL_EXCEPTION);
    EXPECT_FALSE(stub.subscribeCalled);
}

/**
 * @tc.name: DataFabricAddressServiceStubTest006
 * @tc.desc: Test OnRemoteRequest subscribe with valid params and callback.
 * @tc.type: FUNC
 */
HWTEST_F(DataFabricAddressServiceStubValidCallTest, DataFabricAddressServiceStubTest006, TestSize.Level0)
{
    TestDataFabricAddressServiceStub stub;
    DataFabricAddressParams params;
    params.scenarioType = BusinessScenario::SCENARIO_NAVIGATION_COMMUTE;
    params.locationInfo.actionType = ActionType::SUBSCRIPTION;
    params.locationInfo.points = {
        { LabelType::HOME, CoordinateSystemType::WGS84, { 31.2304, 121.4737 } },
        { LabelType::COMPANY, CoordinateSystemType::WGS84, { 31.2204, 121.4137 } },
    };
    MessageParcel data;
    BuildSubscribeParcel(data, params, 2);
    MessageParcel reply;
    int result = stub.OnRemoteRequest(CMD_SUBSCRIBE, data, reply);
    EXPECT_EQ(result, RUN_OK);
    EXPECT_TRUE(stub.subscribeCalled);
    EXPECT_EQ(stub.subscribeParams.scenarioType, BusinessScenario::SCENARIO_NAVIGATION_COMMUTE);
    EXPECT_EQ(stub.subscribeParams.locationInfo.actionType, ActionType::SUBSCRIPTION);
    ASSERT_EQ(stub.subscribeParams.locationInfo.points.size(), 2u);
    EXPECT_EQ(stub.subscribeParams.locationInfo.points[0].labelType, LabelType::HOME);
    EXPECT_EQ(stub.subscribeParams.locationInfo.points[0].coordinateSystemType, CoordinateSystemType::WGS84);
    EXPECT_EQ(stub.subscribeParams.locationInfo.points[0].locationPoint.latitude, 31.2304);
    EXPECT_EQ(stub.subscribeParams.locationInfo.points[0].locationPoint.longitude, 121.4737);
    EXPECT_EQ(stub.subscribeParams.locationInfo.points[1].labelType, LabelType::COMPANY);
    EXPECT_EQ(stub.subscribeParams.locationInfo.points[1].coordinateSystemType, CoordinateSystemType::WGS84);
    EXPECT_EQ(stub.subscribeParams.locationInfo.points[1].locationPoint.latitude, 31.2204);
    EXPECT_EQ(stub.subscribeParams.locationInfo.points[1].locationPoint.longitude, 121.4137);
    EXPECT_TRUE(stub.subscribeCallback != nullptr);
    int32_t replyResult = 0;
    EXPECT_TRUE(reply.ReadInt32(replyResult));
    EXPECT_EQ(replyResult, RUN_OK);
}

/**
 * @tc.name: DataFabricAddressServiceStubTest007
 * @tc.desc: Test OnRemoteRequest unsubscribe when the param data in parcel is missing.
 * @tc.type: FUNC
 */
HWTEST_F(DataFabricAddressServiceStubValidCallTest, DataFabricAddressServiceStubTest007, TestSize.Level0)
{
    TestDataFabricAddressServiceStub stub;
    MessageParcel data;
    MessageParcel reply;
    data.WriteInterfaceToken(TestDataFabricAddressServiceStub::GetDescriptor());
    data.WriteInt32(static_cast<int32_t>(BusinessScenario::SCENARIO_NAVIGATION_COMMUTE));
    data.WriteInt32(static_cast<int32_t>(ActionType::UPDATE));
    int result = stub.OnRemoteRequest(CMD_UNSUBSCRIBE, data, reply);
    EXPECT_EQ(result, INTERNAL_EXCEPTION);
    EXPECT_FALSE(stub.unsubscribeCalled);
}

/**
 * @tc.name: DataFabricAddressServiceStubTest008
 * @tc.desc: Test OnRemoteRequest unsubscribe with valid params.
 * @tc.type: FUNC
 */
HWTEST_F(DataFabricAddressServiceStubValidCallTest, DataFabricAddressServiceStubTest008, TestSize.Level0)
{
    TestDataFabricAddressServiceStub stub;
    DataFabricAddressParams params;
    params.scenarioType = BusinessScenario::SCENARIO_NAVIGATION_COMMUTE;
    params.locationInfo.actionType = ActionType::SUBSCRIPTION;
    MessageParcel data;
    MessageParcel reply;
    data.WriteInterfaceToken(TestDataFabricAddressServiceStub::GetDescriptor());
    data.WriteInt32(static_cast<int32_t>(params.scenarioType));
    data.WriteInt32(static_cast<int32_t>(params.locationInfo.actionType));
    data.WriteInt32(0);
    int result = stub.OnRemoteRequest(CMD_UNSUBSCRIBE, data, reply);
    EXPECT_EQ(result, RUN_OK);
    EXPECT_TRUE(stub.unsubscribeCalled);
    EXPECT_EQ(stub.unsubscribeParams.locationInfo.actionType, ActionType::SUBSCRIPTION);
    int32_t replyResult = 0;
    EXPECT_TRUE(reply.ReadInt32(replyResult));
    EXPECT_EQ(replyResult, RUN_OK);
}

/**
 * @tc.name: DataFabricAddressServiceStubTest009
 * @tc.desc: Test OnRemoteRequest subscribe with zero reference points.
 * @tc.type: FUNC
 */
HWTEST_F(DataFabricAddressServiceStubValidCallTest, DataFabricAddressServiceStubTest009, TestSize.Level0)
{
    TestDataFabricAddressServiceStub stub;
    DataFabricAddressParams params;
    params.scenarioType = BusinessScenario::SCENARIO_NAVIGATION_COMMUTE;
    params.locationInfo.actionType = ActionType::SUBSCRIPTION;
    MessageParcel data;
    BuildSubscribeParcel(data, params, 0);
    MessageParcel reply;
    int result = stub.OnRemoteRequest(CMD_SUBSCRIBE, data, reply);
    EXPECT_EQ(result, RUN_OK);
    EXPECT_TRUE(stub.subscribeCalled);
    EXPECT_TRUE(stub.subscribeParams.locationInfo.points.empty());
}

/**
 * @tc.name: DataFabricAddressServiceStubTest010
 * @tc.desc: Test OnRemoteRequest subscribe with a GCJ02 coordinate system point.
 * @tc.type: FUNC
 */
HWTEST_F(DataFabricAddressServiceStubValidCallTest, DataFabricAddressServiceStubTest010, TestSize.Level0)
{
    TestDataFabricAddressServiceStub stub;
    DataFabricAddressParams params;
    params.scenarioType = BusinessScenario::SCENARIO_NAVIGATION_COMMUTE;
    params.locationInfo.actionType = ActionType::SUBSCRIPTION;
    params.locationInfo.points = {
        { LabelType::HOME, CoordinateSystemType::GCJ02, { 31.2304, 121.4737 } },
        { LabelType::COMPANY, CoordinateSystemType::GCJ02, { 31.2204, 121.4137 } },
    };
    MessageParcel data;
    BuildSubscribeParcel(data, params, 2);
    MessageParcel reply;
    int result = stub.OnRemoteRequest(CMD_SUBSCRIBE, data, reply);
    EXPECT_EQ(result, RUN_OK);
    EXPECT_TRUE(stub.subscribeCalled);
    ASSERT_EQ(stub.subscribeParams.locationInfo.points.size(), 2u);
    EXPECT_EQ(stub.subscribeParams.locationInfo.points[0].coordinateSystemType, CoordinateSystemType::GCJ02);
    EXPECT_EQ(stub.subscribeParams.locationInfo.points[0].locationPoint.latitude, 31.2304);
    EXPECT_EQ(stub.subscribeParams.locationInfo.points[0].locationPoint.longitude, 121.4737);
    EXPECT_EQ(stub.subscribeParams.locationInfo.points[1].coordinateSystemType, CoordinateSystemType::GCJ02);
    EXPECT_EQ(stub.subscribeParams.locationInfo.points[1].locationPoint.latitude, 31.2204);
    EXPECT_EQ(stub.subscribeParams.locationInfo.points[1].locationPoint.longitude, 121.4137);
}

/**
 * @tc.name: DataFabricAddressServiceStubTest011
 * @tc.desc: Test OnRemoteRequest unsubscribe with multiple reference points.
 * @tc.type: FUNC
 */
HWTEST_F(DataFabricAddressServiceStubValidCallTest, DataFabricAddressServiceStubTest011, TestSize.Level0)
{
    TestDataFabricAddressServiceStub stub;
    DataFabricAddressParams params;
    params.scenarioType = BusinessScenario::SCENARIO_NAVIGATION_COMMUTE;
    params.locationInfo.actionType = ActionType::SUBSCRIPTION;
    params.locationInfo.points = {
        { LabelType::HOME, CoordinateSystemType::WGS84, { 31.2304, 121.4737 } },
        { LabelType::COMPANY, CoordinateSystemType::GCJ02, { 31.2204, 121.4137 } },
    };
    MessageParcel data;
    MessageParcel reply;
    data.WriteInterfaceToken(TestDataFabricAddressServiceStub::GetDescriptor());
    data.WriteInt32(static_cast<int32_t>(params.scenarioType));
    data.WriteInt32(static_cast<int32_t>(params.locationInfo.actionType));
    data.WriteInt32(static_cast<int32_t>(params.locationInfo.points.size()));
    for (const auto &point : params.locationInfo.points) {
        data.WriteInt32(static_cast<int32_t>(point.labelType));
        data.WriteInt32(static_cast<int32_t>(point.coordinateSystemType));
        data.WriteDouble(point.locationPoint.latitude);
        data.WriteDouble(point.locationPoint.longitude);
    }
    int result = stub.OnRemoteRequest(CMD_UNSUBSCRIBE, data, reply);
    EXPECT_EQ(result, RUN_OK);
    EXPECT_TRUE(stub.unsubscribeCalled);
    EXPECT_EQ(stub.unsubscribeParams.scenarioType, BusinessScenario::SCENARIO_NAVIGATION_COMMUTE);
    EXPECT_EQ(stub.unsubscribeParams.locationInfo.actionType, ActionType::SUBSCRIPTION);
    ASSERT_EQ(stub.unsubscribeParams.locationInfo.points.size(), 2u);
    EXPECT_EQ(stub.unsubscribeParams.locationInfo.points[0].labelType, LabelType::HOME);
    EXPECT_EQ(stub.unsubscribeParams.locationInfo.points[0].coordinateSystemType, CoordinateSystemType::WGS84);
    EXPECT_EQ(stub.unsubscribeParams.locationInfo.points[0].locationPoint.latitude, 31.2304);
    EXPECT_EQ(stub.unsubscribeParams.locationInfo.points[0].locationPoint.longitude, 121.4737);
    EXPECT_EQ(stub.unsubscribeParams.locationInfo.points[1].labelType, LabelType::COMPANY);
    EXPECT_EQ(stub.unsubscribeParams.locationInfo.points[1].coordinateSystemType, CoordinateSystemType::GCJ02);
    EXPECT_EQ(stub.unsubscribeParams.locationInfo.points[1].locationPoint.latitude, 31.2204);
    EXPECT_EQ(stub.unsubscribeParams.locationInfo.points[1].locationPoint.longitude, 121.4137);
    int32_t replyResult = 0;
    EXPECT_TRUE(reply.ReadInt32(replyResult));
    EXPECT_EQ(replyResult, RUN_OK);
}

/**
 * @tc.name: DataFabricAddressServiceStubTest012
 * @tc.desc: Test OnRemoteRequest subscribe is rejected when the caller is not a system application.
 * @tc.type: FUNC
 */
HWTEST_F(DataFabricAddressServiceStubTest, DataFabricAddressServiceStubTest012, TestSize.Level0)
{
    EXPECT_CALL(*DataFabricAddressServiceStubTest::accTokenMock, GetTokenTypeFlag(testing::_))
        .WillRepeatedly(testing::Return(ATokenTypeEnum::TOKEN_INVALID));
    TestDataFabricAddressServiceStub stub;
    DataFabricAddressParams params;
    params.scenarioType = BusinessScenario::SCENARIO_NAVIGATION_COMMUTE;
    params.locationInfo.actionType = ActionType::SUBSCRIPTION;
    params.locationInfo.points = {
        { LabelType::HOME, CoordinateSystemType::WGS84, { 31.2304, 121.4737 } },
        { LabelType::COMPANY, CoordinateSystemType::WGS84, { 31.2204, 121.4137 } },
    };
    MessageParcel data;
    BuildSubscribeParcel(data, params, 2);
    MessageParcel reply;
    int result = stub.OnRemoteRequest(CMD_SUBSCRIBE, data, reply);
    EXPECT_EQ(result, NOT_SYSTEM_CALL);
    EXPECT_FALSE(stub.subscribeCalled);
    int32_t replyResult = 0;
    EXPECT_TRUE(reply.ReadInt32(replyResult));
    EXPECT_EQ(replyResult, NOT_SYSTEM_CALL);
}

/**
 * @tc.name: DataFabricAddressServiceStubTest013
 * @tc.desc: Test OnRemoteRequest unsubscribe is rejected when the caller is not a system application.
 * @tc.type: FUNC
 */
HWTEST_F(DataFabricAddressServiceStubTest, DataFabricAddressServiceStubTest013, TestSize.Level0)
{
    EXPECT_CALL(*DataFabricAddressServiceStubTest::accTokenMock, GetTokenTypeFlag(testing::_))
        .WillRepeatedly(testing::Return(ATokenTypeEnum::TOKEN_INVALID));
    TestDataFabricAddressServiceStub stub;
    DataFabricAddressParams params;
    params.scenarioType = BusinessScenario::SCENARIO_NAVIGATION_COMMUTE;
    params.locationInfo.actionType = ActionType::SUBSCRIPTION;
    MessageParcel data;
    MessageParcel reply;
    data.WriteInterfaceToken(TestDataFabricAddressServiceStub::GetDescriptor());
    data.WriteInt32(static_cast<int32_t>(params.scenarioType));
    data.WriteInt32(static_cast<int32_t>(params.locationInfo.actionType));
    data.WriteInt32(0);
    int result = stub.OnRemoteRequest(CMD_UNSUBSCRIBE, data, reply);
    EXPECT_EQ(result, NOT_SYSTEM_CALL);
    EXPECT_FALSE(stub.unsubscribeCalled);
    int32_t replyResult = 0;
    EXPECT_TRUE(reply.ReadInt32(replyResult));
    EXPECT_EQ(replyResult, NOT_SYSTEM_CALL);
}

/**
 * @tc.name: DataFabricAddressServiceStubTest014
 * @tc.desc: Test OnRemoteRequest subscribe is rejected when the location permission is not granted.
 * @tc.type: FUNC
 */
HWTEST_F(DataFabricAddressServiceStubTest, DataFabricAddressServiceStubTest014, TestSize.Level0)
{
    ExpectSystemNativeCall();
    EXPECT_CALL(*DataFabricAddressServiceStubTest::accTokenMock,
        VerifyAccessToken(testing::_, "ohos.permission.APPROXIMATELY_LOCATION"))
        .WillRepeatedly(testing::Return(static_cast<int32_t>(PermissionState::PERMISSION_DENIED)));
    TestDataFabricAddressServiceStub stub;
    DataFabricAddressParams params;
    params.scenarioType = BusinessScenario::SCENARIO_NAVIGATION_COMMUTE;
    params.locationInfo.actionType = ActionType::SUBSCRIPTION;
    params.locationInfo.points = {
        { LabelType::HOME, CoordinateSystemType::WGS84, { 31.2304, 121.4737 } },
        { LabelType::COMPANY, CoordinateSystemType::WGS84, { 31.2204, 121.4137 } },
    };
    MessageParcel data;
    BuildSubscribeParcel(data, params, 2);
    MessageParcel reply;
    int result = stub.OnRemoteRequest(CMD_SUBSCRIBE, data, reply);
    EXPECT_EQ(result, PERMISSION_EXCEPTION);
    EXPECT_FALSE(stub.subscribeCalled);
    int32_t replyResult = 0;
    EXPECT_TRUE(reply.ReadInt32(replyResult));
    EXPECT_EQ(replyResult, PERMISSION_EXCEPTION);
}

/**
 * @tc.name: DataFabricAddressServiceStubTest015
 * @tc.desc: Test OnRemoteRequest unsubscribe is rejected when the location permission is not granted.
 * @tc.type: FUNC
 */
HWTEST_F(DataFabricAddressServiceStubTest, DataFabricAddressServiceStubTest015, TestSize.Level0)
{
    ExpectSystemNativeCall();
    EXPECT_CALL(*DataFabricAddressServiceStubTest::accTokenMock,
        VerifyAccessToken(testing::_, "ohos.permission.APPROXIMATELY_LOCATION"))
        .WillRepeatedly(testing::Return(static_cast<int32_t>(PermissionState::PERMISSION_DENIED)));
    TestDataFabricAddressServiceStub stub;
    DataFabricAddressParams params;
    params.scenarioType = BusinessScenario::SCENARIO_NAVIGATION_COMMUTE;
    params.locationInfo.actionType = ActionType::SUBSCRIPTION;
    MessageParcel data;
    MessageParcel reply;
    data.WriteInterfaceToken(TestDataFabricAddressServiceStub::GetDescriptor());
    data.WriteInt32(static_cast<int32_t>(params.scenarioType));
    data.WriteInt32(static_cast<int32_t>(params.locationInfo.actionType));
    data.WriteInt32(0);
    int result = stub.OnRemoteRequest(CMD_UNSUBSCRIBE, data, reply);
    EXPECT_EQ(result, PERMISSION_EXCEPTION);
    EXPECT_FALSE(stub.unsubscribeCalled);
    int32_t replyResult = 0;
    EXPECT_TRUE(reply.ReadInt32(replyResult));
    EXPECT_EQ(replyResult, PERMISSION_EXCEPTION);
}

/**
 * @tc.name: DataFabricAddressServiceStubTest016
 * @tc.desc: Test IsSystemApp when the token type is native.
 * @tc.type: FUNC
 */
HWTEST_F(DataFabricAddressServiceStubTest, DataFabricAddressServiceStubTest016, TestSize.Level0)
{
    EXPECT_CALL(*DataFabricAddressServiceStubTest::accTokenMock, GetTokenTypeFlag(testing::_))
        .WillRepeatedly(testing::Return(ATokenTypeEnum::TOKEN_NATIVE));
    TestDataFabricAddressServiceStub stub;
    EXPECT_TRUE(stub.IsSystemApp());
}

/**
 * @tc.name: DataFabricAddressServiceStubTest017
 * @tc.desc: Test IsSystemApp when the token type is shell.
 * @tc.type: FUNC
 */
HWTEST_F(DataFabricAddressServiceStubTest, DataFabricAddressServiceStubTest017, TestSize.Level0)
{
    EXPECT_CALL(*DataFabricAddressServiceStubTest::accTokenMock, GetTokenTypeFlag(testing::_))
        .WillRepeatedly(testing::Return(ATokenTypeEnum::TOKEN_SHELL));
    TestDataFabricAddressServiceStub stub;
    EXPECT_TRUE(stub.IsSystemApp());
}

/**
 * @tc.name: DataFabricAddressServiceStubTest018
 * @tc.desc: Test IsSystemApp when the token type is hap and it is a system app.
 * @tc.type: FUNC
 */
HWTEST_F(DataFabricAddressServiceStubTest, DataFabricAddressServiceStubTest018, TestSize.Level0)
{
    EXPECT_CALL(*DataFabricAddressServiceStubTest::accTokenMock, GetTokenTypeFlag(testing::_))
        .WillRepeatedly(testing::Return(ATokenTypeEnum::TOKEN_HAP));
    EXPECT_CALL(*DataFabricAddressServiceStubTest::tokenIdMock, IsSystemAppByFullTokenID(testing::_))
        .WillRepeatedly(testing::Return(true));
    TestDataFabricAddressServiceStub stub;
    EXPECT_TRUE(stub.IsSystemApp());
}

/**
 * @tc.name: DataFabricAddressServiceStubTest019
 * @tc.desc: Test IsSystemApp when the token type is hap and it is not a system app.
 * @tc.type: FUNC
 */
HWTEST_F(DataFabricAddressServiceStubTest, DataFabricAddressServiceStubTest019, TestSize.Level0)
{
    EXPECT_CALL(*DataFabricAddressServiceStubTest::accTokenMock, GetTokenTypeFlag(testing::_))
        .WillRepeatedly(testing::Return(ATokenTypeEnum::TOKEN_HAP));
    EXPECT_CALL(*DataFabricAddressServiceStubTest::tokenIdMock, IsSystemAppByFullTokenID(testing::_))
        .WillRepeatedly(testing::Return(false));
    TestDataFabricAddressServiceStub stub;
    EXPECT_FALSE(stub.IsSystemApp());
}

/**
 * @tc.name: DataFabricAddressServiceStubTest020
 * @tc.desc: Test IsSystemApp when the token type is invalid.
 * @tc.type: FUNC
 */
HWTEST_F(DataFabricAddressServiceStubTest, DataFabricAddressServiceStubTest020, TestSize.Level0)
{
    EXPECT_CALL(*DataFabricAddressServiceStubTest::accTokenMock, GetTokenTypeFlag(testing::_))
        .WillRepeatedly(testing::Return(ATokenTypeEnum::TOKEN_INVALID));
    TestDataFabricAddressServiceStub stub;
    EXPECT_FALSE(stub.IsSystemApp());
}

/**
 * @tc.name: DataFabricAddressServiceStubTest021
 * @tc.desc: Test CheckPermission when the approximately location permission is denied.
 * @tc.type: FUNC
 */
HWTEST_F(DataFabricAddressServiceStubTest, DataFabricAddressServiceStubTest021, TestSize.Level0)
{
    EXPECT_CALL(*DataFabricAddressServiceStubTest::accTokenMock,
        VerifyAccessToken(testing::_, "ohos.permission.APPROXIMATELY_LOCATION"))
        .WillRepeatedly(testing::Return(static_cast<int32_t>(PermissionState::PERMISSION_DENIED)));
    TestDataFabricAddressServiceStub stub;
    EXPECT_FALSE(stub.CheckPermission());
}

/**
 * @tc.name: DataFabricAddressServiceStubTest022
 * @tc.desc: Test CheckPermission when the location permission is denied.
 * @tc.type: FUNC
 */
HWTEST_F(DataFabricAddressServiceStubTest, DataFabricAddressServiceStubTest022, TestSize.Level0)
{
    EXPECT_CALL(*DataFabricAddressServiceStubTest::accTokenMock,
        VerifyAccessToken(testing::_, "ohos.permission.APPROXIMATELY_LOCATION"))
        .WillRepeatedly(testing::Return(static_cast<int32_t>(PermissionState::PERMISSION_GRANTED)));
    EXPECT_CALL(*DataFabricAddressServiceStubTest::accTokenMock,
        VerifyAccessToken(testing::_, "ohos.permission.LOCATION"))
        .WillRepeatedly(testing::Return(static_cast<int32_t>(PermissionState::PERMISSION_DENIED)));
    TestDataFabricAddressServiceStub stub;
    EXPECT_FALSE(stub.CheckPermission());
}

/**
 * @tc.name: DataFabricAddressServiceStubTest023
 * @tc.desc: Test CheckPermission when the background location permission is denied.
 * @tc.type: FUNC
 */
HWTEST_F(DataFabricAddressServiceStubTest, DataFabricAddressServiceStubTest023, TestSize.Level0)
{
    EXPECT_CALL(*DataFabricAddressServiceStubTest::accTokenMock,
        VerifyAccessToken(testing::_, "ohos.permission.APPROXIMATELY_LOCATION"))
        .WillRepeatedly(testing::Return(static_cast<int32_t>(PermissionState::PERMISSION_GRANTED)));
    EXPECT_CALL(*DataFabricAddressServiceStubTest::accTokenMock,
        VerifyAccessToken(testing::_, "ohos.permission.LOCATION"))
        .WillRepeatedly(testing::Return(static_cast<int32_t>(PermissionState::PERMISSION_GRANTED)));
    EXPECT_CALL(*DataFabricAddressServiceStubTest::accTokenMock,
        VerifyAccessToken(testing::_, "ohos.permission.LOCATION_IN_BACKGROUND"))
        .WillRepeatedly(testing::Return(static_cast<int32_t>(PermissionState::PERMISSION_DENIED)));
    TestDataFabricAddressServiceStub stub;
    EXPECT_FALSE(stub.CheckPermission());
}

/**
 * @tc.name: DataFabricAddressServiceStubTest024
 * @tc.desc: Test CheckPermission when all location permission is granted.
 * @tc.type: FUNC
 */
HWTEST_F(DataFabricAddressServiceStubTest, DataFabricAddressServiceStubTest024, TestSize.Level0)
{
    ExpectAllPermissionGranted();
    TestDataFabricAddressServiceStub stub;
    EXPECT_TRUE(stub.CheckPermission());
}

/**
 * @tc.name: DataFabricAddressServiceStubTest025
 * @tc.desc: Test CheckValidCall when the caller is not a system application.
 * @tc.type: FUNC
 */
HWTEST_F(DataFabricAddressServiceStubTest, DataFabricAddressServiceStubTest025, TestSize.Level0)
{
    EXPECT_CALL(*DataFabricAddressServiceStubTest::accTokenMock, GetTokenTypeFlag(testing::_))
        .WillRepeatedly(testing::Return(ATokenTypeEnum::TOKEN_INVALID));
    TestDataFabricAddressServiceStub stub;
    EXPECT_EQ(stub.CheckValidCall(), NOT_SYSTEM_CALL);
}

/**
 * @tc.name: DataFabricAddressServiceStubTest026
 * @tc.desc: Test CheckValidCall when the permissions are not granted.
 * @tc.type: FUNC
 */
HWTEST_F(DataFabricAddressServiceStubTest, DataFabricAddressServiceStubTest026, TestSize.Level0)
{
    ExpectSystemNativeCall();
    EXPECT_CALL(*DataFabricAddressServiceStubTest::accTokenMock,
        VerifyAccessToken(testing::_, "ohos.permission.APPROXIMATELY_LOCATION"))
        .WillRepeatedly(testing::Return(static_cast<int32_t>(PermissionState::PERMISSION_DENIED)));
    TestDataFabricAddressServiceStub stub;
    EXPECT_EQ(stub.CheckValidCall(), PERMISSION_EXCEPTION);
}

/**
 * @tc.name: DataFabricAddressServiceStubTest027
 * @tc.desc: Test CheckValidCall result depends on the target device type.
 * @tc.type: FUNC
 */
HWTEST_F(DataFabricAddressServiceStubTest, DataFabricAddressServiceStubTest027, TestSize.Level0)
{
    ExpectSystemNativeCall();
    ExpectAllPermissionGranted();
    TestDataFabricAddressServiceStub stub;
    bool deviceTypeOk = stub.IsTargetsDeviceTypes();
    int32_t result = stub.CheckValidCall();
    EXPECT_EQ(result, deviceTypeOk ? RUN_OK : DEVICE_EXCEPTION);
}

/**
 * @tc.name: DataFabricAddressServiceStubTest028
 * @tc.desc: Test IsTargetsDeviceTypes returns whether the device type is phone.
 * @tc.type: FUNC
 */
HWTEST_F(DataFabricAddressServiceStubTest, DataFabricAddressServiceStubTest028, TestSize.Level0)
{
    TestDataFabricAddressServiceStub stub;
    std::string deviceType = OHOS::system::GetParameter("const.product.devicetype", "");
    EXPECT_EQ(stub.IsTargetsDeviceTypes(), deviceType == "phone");
}