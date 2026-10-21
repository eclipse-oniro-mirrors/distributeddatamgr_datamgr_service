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

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "data_fabric_address_errors.h"
#include "data_fabric_address_service_impl.h"
#include "data_fabric_address_test_utils.h"
#include "fakes/navigation_mock.h"
#include "system_ability_definition.h"

using namespace OHOS;
using namespace OHOS::DataFabricAddress;
using namespace NativePreferences;
using namespace testing;
using namespace testing::ext;
using DataFabricAddressTest::TestDataFabricAddressCallbackStub;

namespace {
constexpr int32_t TEST_LOCATION_LOCATOR_SA_ID = LOCATION_LOCATOR_SA_ID;
constexpr int32_t TEST_UNRELATED_SA_ID = 9000;

class DataFabricAddressServiceImplTest : public testing::Test {
public:
    void SetUp() override
    {
        ResetFactoryToUninit();
        DataFabricAddressTest::ResetNavigationManagerMock();
        DataFabricAddressTest::ResetNavigationCommonUtilsMock();
    }

    void TearDown() override
    {
        ResetFactoryToUninit();
    }

    static void InitFactory()
    {
        auto &factory = DataFabricAddressServiceImpl::factory_;
        factory.staticActs_->OnSystemAbilityAdded(TEST_LOCATION_LOCATOR_SA_ID, "");
    }

    static void ResetFactoryToUninit()
    {
        auto &factory = DataFabricAddressServiceImpl::factory_;
        factory.staticActs_->OnSystemAbilityRemoved(TEST_LOCATION_LOCATOR_SA_ID, "");
    }

    static bool IsFactoryInited()
    {
        return DataFabricAddressServiceImpl::factory_.IsInited();
    }
};

} // namespace

/**
 * @tc.name: DataFabricAddressServiceImplTest001
 * @tc.desc: Test factory init status when the location ability is added and an unrelated ability is ignored.
 * @tc.type: FUNC
 */
HWTEST_F(DataFabricAddressServiceImplTest, DataFabricAddressServiceImplTest001, TestSize.Level0)
{
    EXPECT_FALSE(IsFactoryInited());
    auto &factory = DataFabricAddressServiceImpl::factory_;
    factory.staticActs_->OnSystemAbilityAdded(TEST_UNRELATED_SA_ID, "");
    EXPECT_FALSE(IsFactoryInited());
    factory.staticActs_->OnSystemAbilityAdded(TEST_LOCATION_LOCATOR_SA_ID, "");
    EXPECT_TRUE(IsFactoryInited());
}

/**
 * @tc.name: DataFabricAddressServiceImplTest002
 * @tc.desc: Test factory init status when the location ability is removed after init.
 * @tc.type: FUNC
 */
HWTEST_F(DataFabricAddressServiceImplTest, DataFabricAddressServiceImplTest002, TestSize.Level0)
{
    InitFactory();
    EXPECT_TRUE(IsFactoryInited());
    auto &factory = DataFabricAddressServiceImpl::factory_;
    factory.staticActs_->OnSystemAbilityAdded(TEST_LOCATION_LOCATOR_SA_ID, "");
    EXPECT_TRUE(IsFactoryInited());
    factory.staticActs_->OnSystemAbilityRemoved(TEST_LOCATION_LOCATOR_SA_ID, "");
    EXPECT_FALSE(IsFactoryInited());
    factory.staticActs_->OnSystemAbilityAdded(TEST_LOCATION_LOCATOR_SA_ID, "");
    EXPECT_TRUE(IsFactoryInited());
}

/**
 * @tc.name: DataFabricAddressServiceImplTest003
 * @tc.desc: Test factory init status when an unrelated system ability is removed after init.
 * @tc.type: FUNC
 */
HWTEST_F(DataFabricAddressServiceImplTest, DataFabricAddressServiceImplTest003, TestSize.Level0)
{
    InitFactory();
    EXPECT_TRUE(IsFactoryInited());
    auto &factory = DataFabricAddressServiceImpl::factory_;
    factory.staticActs_->OnSystemAbilityRemoved(TEST_UNRELATED_SA_ID, "");
    EXPECT_TRUE(IsFactoryInited());
}

/**
 * @tc.name: DataFabricAddressServiceImplTest004
 * @tc.desc: Test Subscribe when the system ability has not been initialized.
 * @tc.type: FUNC
 */
HWTEST_F(DataFabricAddressServiceImplTest, DataFabricAddressServiceImplTest004, TestSize.Level0)
{
    DataFabricAddressServiceImpl service;
    sptr<IDataFabricAddressCallback> callback = new TestDataFabricAddressCallbackStub();
    NativePreferences::DataFabricAddressParams params =
        DataFabricAddressTest::MakeCommuteSubscriptionParams(DataFabricAddressTest::MakeWgs84HomePoint(),
            DataFabricAddressTest::MakeWgs84CompanyPoint());
    int32_t result = service.Subscribe(params, callback);
    EXPECT_EQ(result, INTERNAL_EXCEPTION);
}

/**
 * @tc.name: DataFabricAddressServiceImplTest005
 * @tc.desc: Test Unsubscribe when the system ability has not been initialized.
 * @tc.type: FUNC
 */
HWTEST_F(DataFabricAddressServiceImplTest, DataFabricAddressServiceImplTest005, TestSize.Level0)
{
    DataFabricAddressServiceImpl service;
    NativePreferences::DataFabricAddressParams params =
        DataFabricAddressTest::MakeCommuteSubscriptionParams(DataFabricAddressTest::MakeWgs84HomePoint(),
            DataFabricAddressTest::MakeWgs84CompanyPoint());
    int32_t result = service.Unsubscribe(params);
    EXPECT_EQ(result, INTERNAL_EXCEPTION);
}

/**
 * @tc.name: DataFabricAddressServiceImplTest006
 * @tc.desc: Test Subscribe succeeds when the system ability is initialized and the params are valid.
 * @tc.type: FUNC
 */
HWTEST_F(DataFabricAddressServiceImplTest, DataFabricAddressServiceImplTest006, TestSize.Level0)
{
    InitFactory();
    DataFabricAddressTest::SetGetDistanceResult(true, 5000.0);
    DataFabricAddressServiceImpl service;
    sptr<IDataFabricAddressCallback> callback = new TestDataFabricAddressCallbackStub();
    NativePreferences::DataFabricAddressParams params =
        DataFabricAddressTest::MakeCommuteSubscriptionParams(DataFabricAddressTest::MakeWgs84HomePoint(),
            DataFabricAddressTest::MakeWgs84CompanyPoint());
    int32_t result = service.Subscribe(params, callback);
    EXPECT_EQ(result, RUN_OK);
}

/**
 * @tc.name: DataFabricAddressServiceImplTest007
 * @tc.desc: Test Unsubscribe succeeds when the system ability is initialized.
 * @tc.type: FUNC
 */
HWTEST_F(DataFabricAddressServiceImplTest, DataFabricAddressServiceImplTest007, TestSize.Level0)
{
    InitFactory();
    DataFabricAddressServiceImpl service;
    NativePreferences::DataFabricAddressParams params =
        DataFabricAddressTest::MakeCommuteSubscriptionParams(DataFabricAddressTest::MakeWgs84HomePoint(),
            DataFabricAddressTest::MakeWgs84CompanyPoint());
    int32_t result = service.Unsubscribe(params);
    EXPECT_EQ(result, RUN_OK);
}

/**
 * @tc.name: DataFabricAddressServiceImplTest008
 * @tc.desc: Test ValidateParams when the scenario type is not navigation commute.
 * @tc.type: FUNC
 */
HWTEST_F(DataFabricAddressServiceImplTest, DataFabricAddressServiceImplTest008, TestSize.Level0)
{
    DataFabricAddressServiceImpl service;
    NativePreferences::DataFabricAddressParams params =
        DataFabricAddressTest::MakeCommuteSubscriptionParams(DataFabricAddressTest::MakeWgs84HomePoint(),
            DataFabricAddressTest::MakeWgs84CompanyPoint());
    params.scenarioType = BusinessScenario::OTHERS;
    NativePreferences::LocationPoint homePoint;
    NativePreferences::LocationPoint companyPoint;
    int32_t result = service.ValidateParams(params, homePoint, companyPoint);
    EXPECT_EQ(result, ABNORMAL_OPERATION_EXCEPTION);
}

/**
 * @tc.name: DataFabricAddressServiceImplTest009
 * @tc.desc: Test ValidateParams when there is only one reference point.
 * @tc.type: FUNC
 */
HWTEST_F(DataFabricAddressServiceImplTest, DataFabricAddressServiceImplTest009, TestSize.Level0)
{
    DataFabricAddressServiceImpl service;
    NativePreferences::DataFabricAddressParams params;
    params.scenarioType = BusinessScenario::SCENARIO_NAVIGATION_COMMUTE;
    params.locationInfo.actionType = ActionType::SUBSCRIPTION;
    params.locationInfo.points = {
        { LabelType::HOME, CoordinateSystemType::WGS84, DataFabricAddressTest::MakeWgs84HomePoint() },
    };
    NativePreferences::LocationPoint homePoint;
    NativePreferences::LocationPoint companyPoint;
    int32_t result = service.ValidateParams(params, homePoint, companyPoint);
    EXPECT_EQ(result, PARAMETER_EXCEPTION);
}

/**
 * @tc.name: DataFabricAddressServiceImplTest010
 * @tc.desc: Test ValidateParams when both reference points are company points.
 * @tc.type: FUNC
 */
HWTEST_F(DataFabricAddressServiceImplTest, DataFabricAddressServiceImplTest010, TestSize.Level0)
{
    DataFabricAddressServiceImpl service;
    NativePreferences::DataFabricAddressParams params;
    params.scenarioType = BusinessScenario::SCENARIO_NAVIGATION_COMMUTE;
    params.locationInfo.actionType = ActionType::SUBSCRIPTION;
    params.locationInfo.points = {
        { LabelType::COMPANY, CoordinateSystemType::WGS84, DataFabricAddressTest::MakeWgs84HomePoint() },
        { LabelType::COMPANY, CoordinateSystemType::WGS84, DataFabricAddressTest::MakeWgs84CompanyPoint() },
    };
    NativePreferences::LocationPoint homePoint;
    NativePreferences::LocationPoint companyPoint;
    int32_t result = service.ValidateParams(params, homePoint, companyPoint);
    EXPECT_EQ(result, INTERNAL_EXCEPTION);
}

/**
 * @tc.name: DataFabricAddressServiceImplTest011
 * @tc.desc: Test ValidateParams when both reference points are home points.
 * @tc.type: FUNC
 */
HWTEST_F(DataFabricAddressServiceImplTest, DataFabricAddressServiceImplTest011, TestSize.Level0)
{
    DataFabricAddressServiceImpl service;
    NativePreferences::DataFabricAddressParams params;
    params.scenarioType = BusinessScenario::SCENARIO_NAVIGATION_COMMUTE;
    params.locationInfo.actionType = ActionType::SUBSCRIPTION;
    params.locationInfo.points = {
        { LabelType::HOME, CoordinateSystemType::WGS84, DataFabricAddressTest::MakeWgs84HomePoint() },
        { LabelType::HOME, CoordinateSystemType::WGS84, DataFabricAddressTest::MakeWgs84CompanyPoint() },
    };
    NativePreferences::LocationPoint homePoint;
    NativePreferences::LocationPoint companyPoint;
    int32_t result = service.ValidateParams(params, homePoint, companyPoint);
    EXPECT_EQ(result, INTERNAL_EXCEPTION);
}

/**
 * @tc.name: DataFabricAddressServiceImplTest012
 * @tc.desc: Test ValidateParams when home and company commute distance is supported.
 * @tc.type: FUNC
 */
HWTEST_F(DataFabricAddressServiceImplTest, DataFabricAddressServiceImplTest012, TestSize.Level0)
{
    DataFabricAddressTest::SetGetDistanceResult(true, 5000.0);
    DataFabricAddressServiceImpl service;
    NativePreferences::DataFabricAddressParams params =
        DataFabricAddressTest::MakeCommuteSubscriptionParams(DataFabricAddressTest::MakeWgs84HomePoint(),
            DataFabricAddressTest::MakeWgs84CompanyPoint());
    NativePreferences::LocationPoint homePoint;
    NativePreferences::LocationPoint companyPoint;
    int32_t result = service.ValidateParams(params, homePoint, companyPoint);
    EXPECT_EQ(result, RUN_OK);
    EXPECT_EQ(homePoint.latitude, DataFabricAddressTest::MakeWgs84HomePoint().latitude);
    EXPECT_EQ(companyPoint.latitude, DataFabricAddressTest::MakeWgs84CompanyPoint().latitude);
}

/**
 * @tc.name: DataFabricAddressServiceImplTest013
 * @tc.desc: Test ValidateParams when the distance between home and company cannot be obtained.
 * @tc.type: FUNC
 */
HWTEST_F(DataFabricAddressServiceImplTest, DataFabricAddressServiceImplTest013, TestSize.Level0)
{
    DataFabricAddressTest::SetGetDistanceResult(false, 0.0);
    DataFabricAddressServiceImpl service;
    NativePreferences::DataFabricAddressParams params =
        DataFabricAddressTest::MakeCommuteSubscriptionParams(DataFabricAddressTest::MakeWgs84HomePoint(),
            DataFabricAddressTest::MakeWgs84CompanyPoint());
    NativePreferences::LocationPoint homePoint;
    NativePreferences::LocationPoint companyPoint;
    int32_t result = service.ValidateParams(params, homePoint, companyPoint);
    EXPECT_EQ(result, INTERNAL_EXCEPTION);
}

/**
 * @tc.name: DataFabricAddressServiceImplTest014
 * @tc.desc: Test ValidateParams when the commute distance is too short.
 * @tc.type: FUNC
 */
HWTEST_F(DataFabricAddressServiceImplTest, DataFabricAddressServiceImplTest014, TestSize.Level0)
{
    DataFabricAddressTest::SetGetDistanceResult(true, 500.0);
    DataFabricAddressServiceImpl service;
    NativePreferences::DataFabricAddressParams params =
        DataFabricAddressTest::MakeCommuteSubscriptionParams(DataFabricAddressTest::MakeWgs84HomePoint(),
            DataFabricAddressTest::MakeWgs84CompanyPoint());
    NativePreferences::LocationPoint homePoint;
    NativePreferences::LocationPoint companyPoint;
    int32_t result = service.ValidateParams(params, homePoint, companyPoint);
    EXPECT_EQ(result, ABNORMAL_OPERATION_EXCEPTION);
}

/**
 * @tc.name: DataFabricAddressServiceImplTest015
 * @tc.desc: Test ValidateParams when the home GCJ02 coordinate conversion fails.
 * @tc.type: FUNC
 */
HWTEST_F(DataFabricAddressServiceImplTest, DataFabricAddressServiceImplTest015, TestSize.Level0)
{
    DataFabricAddressTest::SetGcj02ToWgs84Result(false);
    DataFabricAddressServiceImpl service;
    NativePreferences::DataFabricAddressParams params;
    params.scenarioType = BusinessScenario::SCENARIO_NAVIGATION_COMMUTE;
    params.locationInfo.actionType = ActionType::SUBSCRIPTION;
    params.locationInfo.points = {
        { LabelType::HOME, CoordinateSystemType::GCJ02, DataFabricAddressTest::MakeWgs84HomePoint() },
        { LabelType::COMPANY, CoordinateSystemType::WGS84, DataFabricAddressTest::MakeWgs84CompanyPoint() },
    };
    NativePreferences::LocationPoint homePoint;
    NativePreferences::LocationPoint companyPoint;
    int32_t result = service.ValidateParams(params, homePoint, companyPoint);
    EXPECT_EQ(result, INTERNAL_EXCEPTION);
}

/**
 * @tc.name: DataFabricAddressServiceImplTest016
 * @tc.desc: Test ValidateParams when the company GCJ02 coordinate conversion fails.
 * @tc.type: FUNC
 */
HWTEST_F(DataFabricAddressServiceImplTest, DataFabricAddressServiceImplTest016, TestSize.Level0)
{
    DataFabricAddressTest::SetGcj02ToWgs84Result(false);
    DataFabricAddressServiceImpl service;
    NativePreferences::DataFabricAddressParams params;
    params.scenarioType = BusinessScenario::SCENARIO_NAVIGATION_COMMUTE;
    params.locationInfo.actionType = ActionType::SUBSCRIPTION;
    params.locationInfo.points = {
        { LabelType::HOME, CoordinateSystemType::WGS84, DataFabricAddressTest::MakeWgs84HomePoint() },
        { LabelType::COMPANY, CoordinateSystemType::GCJ02, DataFabricAddressTest::MakeWgs84CompanyPoint() },
    };
    NativePreferences::LocationPoint homePoint;
    NativePreferences::LocationPoint companyPoint;
    int32_t result = service.ValidateParams(params, homePoint, companyPoint);
    EXPECT_EQ(result, INTERNAL_EXCEPTION);
}

/**
 * @tc.name: DataFabricAddressServiceImplTest017
 * @tc.desc: Test ObtainWgs84ReferencePoints with no reference point.
 * @tc.type: FUNC
 */
HWTEST_F(DataFabricAddressServiceImplTest, DataFabricAddressServiceImplTest017, TestSize.Level0)
{
    DataFabricAddressServiceImpl service;
    NativePreferences::ReferenceLocationInfo referenceInfo;
    referenceInfo.actionType = ActionType::SUBSCRIPTION;
    NativePreferences::LocationPoint homePoint;
    NativePreferences::LocationPoint companyPoint;
    EXPECT_FALSE(service.ObtainWgs84ReferencePoints(referenceInfo, homePoint, companyPoint));
}

/**
 * @tc.name: DataFabricAddressServiceImplTest018
 * @tc.desc: Test ObtainWgs84ReferencePoints with no reference point.
 * @tc.type: FUNC
 */
HWTEST_F(DataFabricAddressServiceImplTest, DataFabricAddressServiceImplTest018, TestSize.Level0)
{
    DataFabricAddressServiceImpl service;
    NativePreferences::ReferenceLocationInfo referenceInfo;
    referenceInfo.actionType = ActionType::SUBSCRIPTION;
    referenceInfo.points = {
        { LabelType::HOME, CoordinateSystemType::WGS84, DataFabricAddressTest::MakeWgs84HomePoint() },
        { LabelType::COMPANY, CoordinateSystemType::WGS84, DataFabricAddressTest::MakeWgs84CompanyPoint() },
    };
    NativePreferences::LocationPoint homePoint;
    NativePreferences::LocationPoint companyPoint;
    EXPECT_TRUE(service.ObtainWgs84ReferencePoints(referenceInfo, homePoint, companyPoint));
    EXPECT_EQ(homePoint.latitude, DataFabricAddressTest::MakeWgs84HomePoint().latitude);
    EXPECT_EQ(companyPoint.latitude, DataFabricAddressTest::MakeWgs84CompanyPoint().latitude);
}

/**
 * @tc.name: DataFabricAddressServiceImplTest019
 * @tc.desc: Test ObtainWgs84ReferencePoints with two gcj02 points converted successfully.
 * @tc.type: FUNC
 */
HWTEST_F(DataFabricAddressServiceImplTest, DataFabricAddressServiceImplTest019, TestSize.Level0)
{
    DataFabricAddressTest::SetGcj02ToWgs84Result(true);
    DataFabricAddressServiceImpl service;
    NativePreferences::ReferenceLocationInfo referenceInfo;
    referenceInfo.actionType = ActionType::SUBSCRIPTION;
    referenceInfo.points = {
        { LabelType::HOME, CoordinateSystemType::GCJ02, DataFabricAddressTest::MakeWgs84HomePoint() },
        { LabelType::COMPANY, CoordinateSystemType::GCJ02, DataFabricAddressTest::MakeWgs84CompanyPoint() },
    };
    NativePreferences::LocationPoint homePoint;
    NativePreferences::LocationPoint companyPoint;
    EXPECT_TRUE(service.ObtainWgs84ReferencePoints(referenceInfo, homePoint, companyPoint));
    EXPECT_EQ(homePoint.latitude, DataFabricAddressTest::MakeWgs84HomePoint().latitude - 0.001);
    EXPECT_EQ(companyPoint.latitude, DataFabricAddressTest::MakeWgs84CompanyPoint().latitude - 0.001);
}

/**
 * @tc.name: DataFabricAddressServiceImplTest020
 * @tc.desc: Test ObtainWgs84ReferencePoints when gcj02 conversion fails.
 * @tc.type: FUNC
 */
HWTEST_F(DataFabricAddressServiceImplTest, DataFabricAddressServiceImplTest020, TestSize.Level0)
{
    DataFabricAddressTest::SetGcj02ToWgs84Result(false);
    DataFabricAddressServiceImpl service;
    NativePreferences::ReferenceLocationInfo referenceInfo;
    referenceInfo.actionType = ActionType::SUBSCRIPTION;
    referenceInfo.points = {
        { LabelType::HOME, CoordinateSystemType::GCJ02, DataFabricAddressTest::MakeWgs84HomePoint() },
        { LabelType::COMPANY, CoordinateSystemType::WGS84, DataFabricAddressTest::MakeWgs84CompanyPoint() },
    };
    NativePreferences::LocationPoint homePoint;
    NativePreferences::LocationPoint companyPoint;
    EXPECT_FALSE(service.ObtainWgs84ReferencePoints(referenceInfo, homePoint, companyPoint));
}

/**
 * @tc.name: DataFabricAddressServiceImplTest021
 * @tc.desc: Test IsSupportedCommuteDistance when distance cannot be obtained.
 * @tc.type: FUNC
 */
HWTEST_F(DataFabricAddressServiceImplTest, DataFabricAddressServiceImplTest021, TestSize.Level0)
{
    DataFabricAddressTest::SetGetDistanceResult(false, 0.0);
    DataFabricAddressServiceImpl service;
    NativePreferences::LocationPoint homePoint = DataFabricAddressTest::MakeWgs84HomePoint();
    NativePreferences::LocationPoint companyPoint = DataFabricAddressTest::MakeWgs84CompanyPoint();
    int32_t result = service.IsSupportedCommuteDistance(homePoint, companyPoint);
    EXPECT_EQ(result, INTERNAL_EXCEPTION);
}

/**
 * @tc.name: DataFabricAddressServiceImplTest022
 * @tc.desc: Test IsSupportedCommuteDistance when the distance meets the minimum requirement.
 * @tc.type: FUNC
 */
HWTEST_F(DataFabricAddressServiceImplTest, DataFabricAddressServiceImplTest022, TestSize.Level0)
{
    DataFabricAddressTest::SetGetDistanceResult(true, 10000.0);
    DataFabricAddressServiceImpl service;
    NativePreferences::LocationPoint homePoint = DataFabricAddressTest::MakeWgs84HomePoint();
    NativePreferences::LocationPoint companyPoint = DataFabricAddressTest::MakeWgs84CompanyPoint();
    int32_t result = service.IsSupportedCommuteDistance(homePoint, companyPoint);
    EXPECT_EQ(result, RUN_OK);
}

/**
 * @tc.name: DataFabricAddressServiceImplTest023
 * @tc.desc: Test IsSupportedCommuteDistance when the distance is too short.
 * @tc.type: FUNC
 */
HWTEST_F(DataFabricAddressServiceImplTest, DataFabricAddressServiceImplTest023, TestSize.Level0)
{
    DataFabricAddressTest::SetGetDistanceResult(true, 100.0);
    DataFabricAddressServiceImpl service;
    NativePreferences::LocationPoint homePoint = DataFabricAddressTest::MakeWgs84HomePoint();
    NativePreferences::LocationPoint companyPoint = DataFabricAddressTest::MakeWgs84CompanyPoint();
    int32_t result = service.IsSupportedCommuteDistance(homePoint, companyPoint);
    EXPECT_EQ(result, ABNORMAL_OPERATION_EXCEPTION);
}

/**
 * @tc.name: DataFabricAddressServiceImplTest024
 * @tc.desc: Test AddCallback when the action type is update, no callback is cached.
 * @tc.type: FUNC
 */
HWTEST_F(DataFabricAddressServiceImplTest, DataFabricAddressServiceImplTest024, TestSize.Level0)
{
    auto service = std::make_shared<DataFabricAddressServiceImpl>();
    sptr<IDataFabricAddressCallback> callback = new TestDataFabricAddressCallbackStub();
    NativePreferences::DataFabricAddressParams params =
        DataFabricAddressTest::MakeCommuteUpdateParams(DataFabricAddressTest::MakeWgs84HomePoint(),
            DataFabricAddressTest::MakeWgs84CompanyPoint());
    EXPECT_TRUE(service->AddCallback(params, callback));
    EXPECT_TRUE(service->subscribeCacheMap_.empty());
}

/**
 * @tc.name: DataFabricAddressServiceImplTest025
 * @tc.desc: Test AddCallback with subscription action caches the callback.
 * @tc.type: FUNC
 */
HWTEST_F(DataFabricAddressServiceImplTest, DataFabricAddressServiceImplTest025, TestSize.Level0)
{
    auto service = std::make_shared<DataFabricAddressServiceImpl>();
    sptr<IDataFabricAddressCallback> callback = new TestDataFabricAddressCallbackStub();
    NativePreferences::DataFabricAddressParams params =
        DataFabricAddressTest::MakeCommuteSubscriptionParams(DataFabricAddressTest::MakeWgs84HomePoint(),
            DataFabricAddressTest::MakeWgs84CompanyPoint());
    EXPECT_TRUE(service->AddCallback(params, callback));
    ASSERT_EQ(service->subscribeCacheMap_.size(), 1u);
    EXPECT_TRUE(service->subscribeCacheMap_[params].callback_ != nullptr);
    EXPECT_TRUE(service->subscribeCacheMap_[params].cbDeathRecipient_ != nullptr);
}

/**
 * @tc.name: DataFabricAddressServiceImplTest026
 * @tc.desc: Test RemoveCallback when the params are not cached.
 * @tc.type: FUNC
 */
HWTEST_F(DataFabricAddressServiceImplTest, DataFabricAddressServiceImplTest026, TestSize.Level0)
{
    auto service = std::make_shared<DataFabricAddressServiceImpl>();
    NativePreferences::DataFabricAddressParams params =
        DataFabricAddressTest::MakeCommuteSubscriptionParams(DataFabricAddressTest::MakeWgs84HomePoint(),
            DataFabricAddressTest::MakeWgs84CompanyPoint());
    EXPECT_TRUE(service->RemoveCallback(params));
}

/**
 * @tc.name: DataFabricAddressServiceImplTest027
 * @tc.desc: Test RemoveCallback removes the cached callback.
 * @tc.type: FUNC
 */
HWTEST_F(DataFabricAddressServiceImplTest, DataFabricAddressServiceImplTest027, TestSize.Level0)
{
    auto service = std::make_shared<DataFabricAddressServiceImpl>();
    sptr<IDataFabricAddressCallback> callback = new TestDataFabricAddressCallbackStub();
    NativePreferences::DataFabricAddressParams params =
        DataFabricAddressTest::MakeCommuteSubscriptionParams(DataFabricAddressTest::MakeWgs84HomePoint(),
            DataFabricAddressTest::MakeWgs84CompanyPoint());
    ASSERT_TRUE(service->AddCallback(params, callback));
    ASSERT_EQ(service->subscribeCacheMap_.size(), 1u);
    EXPECT_TRUE(service->RemoveCallback(params));
    EXPECT_TRUE(service->subscribeCacheMap_.empty());
}

/**
 * @tc.name: DataFabricAddressServiceImplTest028
 * @tc.desc: Test RemoveCallback only removes the matching cached entry.
 * @tc.type: FUNC
 */
HWTEST_F(DataFabricAddressServiceImplTest, DataFabricAddressServiceImplTest028, TestSize.Level0)
{
    auto service = std::make_shared<DataFabricAddressServiceImpl>();
    NativePreferences::DataFabricAddressParams params1 =
        DataFabricAddressTest::MakeCommuteSubscriptionParams({ 30.0, 120.0 }, { 30.5, 120.5 });
    NativePreferences::DataFabricAddressParams params2 =
        DataFabricAddressTest::MakeCommuteSubscriptionParams({ 31.0, 121.0 }, { 31.5, 121.5 });
    EXPECT_TRUE(service->AddCallback(params1, new TestDataFabricAddressCallbackStub()));
    EXPECT_TRUE(service->AddCallback(params2, new TestDataFabricAddressCallbackStub()));
    ASSERT_EQ(service->subscribeCacheMap_.size(), 2u);
    EXPECT_TRUE(service->RemoveCallback(params1));
    ASSERT_EQ(service->subscribeCacheMap_.size(), 1u);
    EXPECT_TRUE(service->subscribeCacheMap_.find(params2) != service->subscribeCacheMap_.end());
}

/**
 * @tc.name: DataFabricAddressServiceImplTest029
 * @tc.desc: Test OnRemoteDied when the service has been destroyed.
 * @tc.type: FUNC
 */
HWTEST_F(DataFabricAddressServiceImplTest, DataFabricAddressServiceImplTest029, TestSize.Level0)
{
    std::weak_ptr<DataFabricAddressServiceImpl> emptyService;
    EXPECT_TRUE(emptyService.expired());
    DataFabricAddressServiceImpl::DeathRecipientListener listener(emptyService);
    sptr<IRemoteObject> remote = new TestDataFabricAddressCallbackStub();
    wptr<IRemoteObject> diedRemote(remote.GetRefPtr());
    EXPECT_NO_FATAL_FAILURE(listener.OnRemoteDied(diedRemote));
}

/**
 * @tc.name: DataFabricAddressServiceImplTest030
 * @tc.desc: Test OnRemoteDied when the died remote object is null.
 * @tc.type: FUNC
 */
HWTEST_F(DataFabricAddressServiceImplTest, DataFabricAddressServiceImplTest030, TestSize.Level0)
{
    auto service = std::make_shared<DataFabricAddressServiceImpl>();
    sptr<IDataFabricAddressCallback> callback = new TestDataFabricAddressCallbackStub();
    NativePreferences::DataFabricAddressParams params =
        DataFabricAddressTest::MakeCommuteSubscriptionParams(DataFabricAddressTest::MakeWgs84HomePoint(),
            DataFabricAddressTest::MakeWgs84CompanyPoint());
    ASSERT_TRUE(service->AddCallback(params, callback));
    ASSERT_EQ(service->subscribeCacheMap_.size(), 1u);
    std::weak_ptr<DataFabricAddressServiceImpl> weakService = service;
    DataFabricAddressServiceImpl::DeathRecipientListener listener(weakService);
    wptr<IRemoteObject> remote;
    EXPECT_NO_FATAL_FAILURE(listener.OnRemoteDied(remote));
    EXPECT_EQ(service->subscribeCacheMap_.size(), 1u);
}

/**
 * @tc.name: DataFabricAddressServiceImplTest031
 * @tc.desc: Test OnRemoteDied removes the matching callback from the cache.
 * @tc.type: FUNC
 */
HWTEST_F(DataFabricAddressServiceImplTest, DataFabricAddressServiceImplTest031, TestSize.Level0)
{
    auto service = std::make_shared<DataFabricAddressServiceImpl>();
    sptr<IDataFabricAddressCallback> callback = new TestDataFabricAddressCallbackStub();
    NativePreferences::DataFabricAddressParams params =
        DataFabricAddressTest::MakeCommuteSubscriptionParams(DataFabricAddressTest::MakeWgs84HomePoint(),
            DataFabricAddressTest::MakeWgs84CompanyPoint());
    ASSERT_TRUE(service->AddCallback(params, callback));
    ASSERT_EQ(service->subscribeCacheMap_.size(), 1u);
    std::weak_ptr<DataFabricAddressServiceImpl> weakService = service;
    DataFabricAddressServiceImpl::DeathRecipientListener listener(weakService);
    wptr<IRemoteObject> remote(callback->AsObject().GetRefPtr());
    listener.OnRemoteDied(remote);
    EXPECT_TRUE(service->subscribeCacheMap_.empty());
}

/**
 * @tc.name: DataFabricAddressServiceImplTest032
 * @tc.desc: Test OnRemoteDied removes cache entries with null callback or death recipient.
 * @tc.type: FUNC
 */
HWTEST_F(DataFabricAddressServiceImplTest, DataFabricAddressServiceImplTest032, TestSize.Level0)
{
    auto service = std::make_shared<DataFabricAddressServiceImpl>();
    NativePreferences::DataFabricAddressParams params =
        DataFabricAddressTest::MakeCommuteSubscriptionParams(DataFabricAddressTest::MakeWgs84HomePoint(),
            DataFabricAddressTest::MakeWgs84CompanyPoint());
    service->subscribeCacheMap_[params] = DataFabricAddressServiceImpl::SubscribeCacheData{ nullptr, nullptr };
    ASSERT_EQ(service->subscribeCacheMap_.size(), 1u);
    sptr<IDataFabricAddressCallback> callback = new TestDataFabricAddressCallbackStub();
    std::weak_ptr<DataFabricAddressServiceImpl> weakService = service;
    DataFabricAddressServiceImpl::DeathRecipientListener listener(weakService);
    wptr<IRemoteObject> remote(callback->AsObject().GetRefPtr());
    listener.OnRemoteDied(remote);
    EXPECT_TRUE(service->subscribeCacheMap_.empty());
}

/**
 * @tc.name: DataFabricAddressServiceImplTest033
 * @tc.desc: Test OnRemoteDied only removes the matching callback and keeps others.
 * @tc.type: FUNC
 */
HWTEST_F(DataFabricAddressServiceImplTest, DataFabricAddressServiceImplTest033, TestSize.Level0)
{
    auto service = std::make_shared<DataFabricAddressServiceImpl>();
    NativePreferences::DataFabricAddressParams params1 =
        DataFabricAddressTest::MakeCommuteSubscriptionParams({ 30.0, 120.0 }, { 30.5, 120.5 });
    NativePreferences::DataFabricAddressParams params2 =
        DataFabricAddressTest::MakeCommuteSubscriptionParams({ 31.0, 121.0 }, { 31.5, 121.5 });
    NativePreferences::DataFabricAddressParams params3 =
        DataFabricAddressTest::MakeCommuteSubscriptionParams({ 32.0, 122.0 }, { 32.5, 122.5 });
    sptr<IDataFabricAddressCallback> callback1 = new TestDataFabricAddressCallbackStub();
    sptr<IDataFabricAddressCallback> callback2 = new TestDataFabricAddressCallbackStub();
    sptr<IDataFabricAddressCallback> callback3 = new TestDataFabricAddressCallbackStub();
    EXPECT_TRUE(service->AddCallback(params1, callback1));
    EXPECT_TRUE(service->AddCallback(params2, callback2));
    EXPECT_TRUE(service->AddCallback(params3, callback3));
    ASSERT_EQ(service->subscribeCacheMap_.size(), 3u);
    std::weak_ptr<DataFabricAddressServiceImpl> weakService = service;
    DataFabricAddressServiceImpl::DeathRecipientListener listener(weakService);
    wptr<IRemoteObject> remote(callback2->AsObject().GetRefPtr());
    listener.OnRemoteDied(remote);
    ASSERT_EQ(service->subscribeCacheMap_.size(), 2u);
    EXPECT_TRUE(service->subscribeCacheMap_.find(params1) != service->subscribeCacheMap_.end());
    EXPECT_TRUE(service->subscribeCacheMap_.find(params3) != service->subscribeCacheMap_.end());
}