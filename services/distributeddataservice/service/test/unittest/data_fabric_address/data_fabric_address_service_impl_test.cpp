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
#include "navigation_common_utils.h"
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
 * @tc.desc: Test Unsubscribe succeeds when the params are not subscribed.
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
    // Scenario type outside the valid range of BusinessScenario.
    params.scenarioType = static_cast<BusinessScenario>(1);
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
    EXPECT_EQ(result, PARAMETER_EXCEPTION);
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
    EXPECT_EQ(result, PARAMETER_EXCEPTION);
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
    DataFabricAddressTest::SetGetDistanceResult(true, 499.0);
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
    EXPECT_EQ(PARAMETER_EXCEPTION, service.ObtainWgs84ReferencePoints(referenceInfo, homePoint, companyPoint));
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
    EXPECT_EQ(RUN_OK, service.ObtainWgs84ReferencePoints(referenceInfo, homePoint, companyPoint));
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
    EXPECT_EQ(RUN_OK, service.ObtainWgs84ReferencePoints(referenceInfo, homePoint, companyPoint));
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
    EXPECT_EQ(INTERNAL_EXCEPTION, service.ObtainWgs84ReferencePoints(referenceInfo, homePoint, companyPoint));
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
    EXPECT_TRUE(service->subscribeCacheMap_[params].callback != nullptr);
    EXPECT_TRUE(service->subscribeCacheMap_[params].cbDeathRecipient != nullptr);
}

/**
 * @tc.name: DataFabricAddressServiceImplTest026
 * @tc.desc: Test RemoveCallback treats the params as already unsubscribed when they are not cached.
 * @tc.type: FUNC
 */
HWTEST_F(DataFabricAddressServiceImplTest, DataFabricAddressServiceImplTest026, TestSize.Level0)
{
    auto service = std::make_shared<DataFabricAddressServiceImpl>();
    NativePreferences::DataFabricAddressParams params =
        DataFabricAddressTest::MakeCommuteSubscriptionParams(DataFabricAddressTest::MakeWgs84HomePoint(),
            DataFabricAddressTest::MakeWgs84CompanyPoint());
    sptr<IRemoteObject> callbackObject { nullptr };
    sptr<IRemoteObject::DeathRecipient> deathRecipient { nullptr };
    // Simulate that another caller owns the last cached subscription.
    service->lastSubscribedToken_ = 0xFFFF8888FFFF6666ULL;
    bool removed = true;
    int32_t result = service->RemoveCallback(params, callbackObject, deathRecipient, removed);
    EXPECT_EQ(result, RUN_OK);
    // The caller does not own the subscription, so it must not tear the navigation manager down.
    EXPECT_FALSE(removed);
    EXPECT_TRUE(callbackObject == nullptr);
    EXPECT_TRUE(deathRecipient == nullptr);
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
    sptr<IRemoteObject> callbackObject { nullptr };
    sptr<IRemoteObject::DeathRecipient> deathRecipient { nullptr };
    bool removed = false;
    int32_t result = service->RemoveCallback(params, callbackObject, deathRecipient, removed);
    EXPECT_EQ(result, RUN_OK);
    EXPECT_TRUE(removed);
    EXPECT_TRUE(callbackObject != nullptr);
    EXPECT_TRUE(deathRecipient != nullptr);
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
    sptr<IRemoteObject> callbackObject { nullptr };
    sptr<IRemoteObject::DeathRecipient> deathRecipient { nullptr };
    bool removed = false;
    int32_t result = service->RemoveCallback(params1, callbackObject, deathRecipient, removed);
    EXPECT_EQ(result, RUN_OK);
    EXPECT_TRUE(removed);
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

/**
 * @tc.name: DataFabricAddressServiceImplTest034
 * @tc.desc: Test Unsubscribe when the caller is not the origin subscriber, the cached entry is kept.
 * @tc.type: FUNC
 */
HWTEST_F(DataFabricAddressServiceImplTest, DataFabricAddressServiceImplTest034, TestSize.Level0)
{
    auto service = std::make_shared<DataFabricAddressServiceImpl>();
    sptr<IDataFabricAddressCallback> callback = new TestDataFabricAddressCallbackStub();
    NativePreferences::DataFabricAddressParams params =
        DataFabricAddressTest::MakeCommuteSubscriptionParams(DataFabricAddressTest::MakeWgs84HomePoint(),
            DataFabricAddressTest::MakeWgs84CompanyPoint());
    ASSERT_TRUE(service->AddCallback(params, callback));
    // Simulate that the entry was registered by a different caller.
    service->subscribeCacheMap_[params].callerFullTokenId = 0xFFFF8888FFFF6666ULL;
    InitFactory();
    DataFabricAddressTest::SetUnsubscribeNavigationManagerResult(ABNORMAL_OPERATION_EXCEPTION);
    int32_t result = service->Unsubscribe(params);
    EXPECT_EQ(result, UNSUBSCRIBE_EXCEPTION);
    ASSERT_EQ(service->subscribeCacheMap_.size(), 1u);
    EXPECT_TRUE(service->subscribeCacheMap_[params].callback == callback);
}

/**
 * @tc.name: DataFabricAddressServiceImplTest035
 * @tc.desc: Test Unsubscribe of the origin subscriber still triggers the navigation unsubscribe.
 * @tc.type: FUNC
 */
HWTEST_F(DataFabricAddressServiceImplTest, DataFabricAddressServiceImplTest035, TestSize.Level0)
{
    auto service = std::make_shared<DataFabricAddressServiceImpl>();
    sptr<IDataFabricAddressCallback> callback = new TestDataFabricAddressCallbackStub();
    NativePreferences::DataFabricAddressParams params =
        DataFabricAddressTest::MakeCommuteSubscriptionParams(DataFabricAddressTest::MakeWgs84HomePoint(),
            DataFabricAddressTest::MakeWgs84CompanyPoint());
    ASSERT_TRUE(service->AddCallback(params, callback));
    InitFactory();
    DataFabricAddressTest::SetUnsubscribeNavigationManagerResult(ABNORMAL_OPERATION_EXCEPTION);
    int32_t result = service->Unsubscribe(params);
    EXPECT_EQ(result, ABNORMAL_OPERATION_EXCEPTION);
    EXPECT_TRUE(service->subscribeCacheMap_.empty());
}

/**
 * @tc.name: DataFabricAddressServiceImplTest036
 * @tc.desc: Test Subscribe with the update action re-subscribes the navigation manager before the update.
 * @tc.type: FUNC
 */
HWTEST_F(DataFabricAddressServiceImplTest, DataFabricAddressServiceImplTest036, TestSize.Level0)
{
    InitFactory();
    DataFabricAddressTest::SetGetDistanceResult(true, 5000.0);
    DataFabricAddressServiceImpl service;
    sptr<IDataFabricAddressCallback> callback = new TestDataFabricAddressCallbackStub();
    NativePreferences::DataFabricAddressParams params =
        DataFabricAddressTest::MakeCommuteUpdateParams(DataFabricAddressTest::MakeWgs84HomePoint(),
            DataFabricAddressTest::MakeWgs84CompanyPoint());
    int32_t result = service.Subscribe(params, callback);
    EXPECT_EQ(result, RUN_OK);
    EXPECT_EQ(DataFabricAddressTest::GetSubscribeActionCount(), 2);
    EXPECT_EQ(DataFabricAddressTest::GetLastSubscribeAction(),
        static_cast<int32_t>(NativePreferences::ActionType::UPDATE));
}

/**
 * @tc.name: DataFabricAddressServiceImplTest037
 * @tc.desc: Test IsSupportedCommuteDistance accepts the distance equal to the minimum supported distance.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(DataFabricAddressServiceImplTest, DataFabricAddressServiceImplTest037, TestSize.Level0)
{
    DataFabricAddressTest::SetGetDistanceResult(true, DEFAULT_MIN_SUPPORTED_COMMUTE_DISTANCE);
    DataFabricAddressServiceImpl service;
    NativePreferences::LocationPoint homePoint = DataFabricAddressTest::MakeWgs84HomePoint();
    NativePreferences::LocationPoint companyPoint = DataFabricAddressTest::MakeWgs84CompanyPoint();
    int32_t result = service.IsSupportedCommuteDistance(homePoint, companyPoint);
    EXPECT_EQ(result, RUN_OK);
}

/**
 * @tc.name: DataFabricAddressServiceImplTest038
 * @tc.desc: Test IsSupportedCommuteDistance rejects the distance less than the minimum supported distance.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(DataFabricAddressServiceImplTest, DataFabricAddressServiceImplTest038, TestSize.Level0)
{
    DataFabricAddressTest::SetGetDistanceResult(true, DEFAULT_MIN_SUPPORTED_COMMUTE_DISTANCE - 1.0);
    DataFabricAddressServiceImpl service;
    NativePreferences::LocationPoint homePoint = DataFabricAddressTest::MakeWgs84HomePoint();
    NativePreferences::LocationPoint companyPoint = DataFabricAddressTest::MakeWgs84CompanyPoint();
    int32_t result = service.IsSupportedCommuteDistance(homePoint, companyPoint);
    EXPECT_EQ(result, ABNORMAL_OPERATION_EXCEPTION);
}

/**
 * @tc.name: DataFabricAddressServiceImplTest039
 * @tc.desc: Test ValidateParams accepts the commute distance of 750 m which was rejected by the old 1000 m threshold.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(DataFabricAddressServiceImplTest, DataFabricAddressServiceImplTest039, TestSize.Level0)
{
    DataFabricAddressTest::SetGetDistanceResult(true, 750.0);
    DataFabricAddressServiceImpl service;
    NativePreferences::DataFabricAddressParams params =
        DataFabricAddressTest::MakeCommuteSubscriptionParams(DataFabricAddressTest::MakeWgs84HomePoint(),
            DataFabricAddressTest::MakeWgs84CompanyPoint());
    NativePreferences::LocationPoint homePoint;
    NativePreferences::LocationPoint companyPoint;
    int32_t result = service.ValidateParams(params, homePoint, companyPoint);
    EXPECT_EQ(result, RUN_OK);
}

/**
 * @tc.name: DataFabricAddressServiceImplTest040
 * @tc.desc: Test Subscribe with the update action fails when the subscription state cannot be re-established.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(DataFabricAddressServiceImplTest, DataFabricAddressServiceImplTest040, TestSize.Level0)
{
    InitFactory();
    DataFabricAddressTest::SetGetDistanceResult(true, 5000.0);
    DataFabricAddressTest::SetSubscribeNavigationManagerResult(INTERNAL_EXCEPTION);
    DataFabricAddressServiceImpl service;
    sptr<IDataFabricAddressCallback> callback = new TestDataFabricAddressCallbackStub();
    NativePreferences::DataFabricAddressParams params =
        DataFabricAddressTest::MakeCommuteUpdateParams(DataFabricAddressTest::MakeWgs84HomePoint(),
            DataFabricAddressTest::MakeWgs84CompanyPoint());
    int32_t result = service.Subscribe(params, callback);
    EXPECT_EQ(result, INTERNAL_EXCEPTION);
    // The update action must not be sent when the re-subscription failed.
    EXPECT_EQ(DataFabricAddressTest::GetSubscribeActionCount(), 1);
    EXPECT_EQ(DataFabricAddressTest::GetLastSubscribeAction(),
        static_cast<int32_t>(NativePreferences::ActionType::SUBSCRIPTION));
}

/**
 * @tc.name: DataFabricAddressServiceImplTest041
 * @tc.desc: Test RemoveCallback erases a cached entry whose callback has been released.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(DataFabricAddressServiceImplTest, DataFabricAddressServiceImplTest041, TestSize.Level0)
{
    InitFactory();
    auto service = std::make_shared<DataFabricAddressServiceImpl>();
    sptr<IDataFabricAddressCallback> callback = new TestDataFabricAddressCallbackStub();
    NativePreferences::DataFabricAddressParams params =
        DataFabricAddressTest::MakeCommuteSubscriptionParams(DataFabricAddressTest::MakeWgs84HomePoint(),
            DataFabricAddressTest::MakeWgs84CompanyPoint());
    ASSERT_TRUE(service->AddCallback(params, callback));
    service->subscribeCacheMap_[params].callback = nullptr;
    int32_t result = service->Unsubscribe(params);
    EXPECT_EQ(result, RUN_OK);
    EXPECT_TRUE(service->subscribeCacheMap_.empty());
}

/**
 * @tc.name: DataFabricAddressServiceImplTest042
 * @tc.desc: Test RemoveCallback erases a cached entry whose death recipient has been released.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(DataFabricAddressServiceImplTest, DataFabricAddressServiceImplTest042, TestSize.Level0)
{
    InitFactory();
    auto service = std::make_shared<DataFabricAddressServiceImpl>();
    sptr<IDataFabricAddressCallback> callback = new TestDataFabricAddressCallbackStub();
    NativePreferences::DataFabricAddressParams params =
        DataFabricAddressTest::MakeCommuteSubscriptionParams(DataFabricAddressTest::MakeWgs84HomePoint(),
            DataFabricAddressTest::MakeWgs84CompanyPoint());
    ASSERT_TRUE(service->AddCallback(params, callback));
    service->subscribeCacheMap_[params].cbDeathRecipient = nullptr;
    int32_t result = service->Unsubscribe(params);
    EXPECT_EQ(result, RUN_OK);
    EXPECT_TRUE(service->subscribeCacheMap_.empty());
}

/**
 * @tc.name: DataFabricAddressServiceImplTest043
 * @tc.desc: Test OnRemoteDied erases a cached entry whose death recipient has been released.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(DataFabricAddressServiceImplTest, DataFabricAddressServiceImplTest043, TestSize.Level0)
{
    auto service = std::make_shared<DataFabricAddressServiceImpl>();
    sptr<IDataFabricAddressCallback> callback = new TestDataFabricAddressCallbackStub();
    NativePreferences::DataFabricAddressParams params =
        DataFabricAddressTest::MakeCommuteSubscriptionParams(DataFabricAddressTest::MakeWgs84HomePoint(),
            DataFabricAddressTest::MakeWgs84CompanyPoint());
    ASSERT_TRUE(service->AddCallback(params, callback));
    service->subscribeCacheMap_[params].cbDeathRecipient = nullptr;
    std::weak_ptr<DataFabricAddressServiceImpl> weakService = service;
    DataFabricAddressServiceImpl::DeathRecipientListener listener(weakService);
    wptr<IRemoteObject> remote(callback->AsObject().GetRefPtr());
    listener.OnRemoteDied(remote);
    EXPECT_TRUE(service->subscribeCacheMap_.empty());
}

/**
 * @tc.name: DataFabricAddressServiceImplTest044
 * @tc.desc: Test Subscribe rejects a second caller when another caller already owns the subscription.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(DataFabricAddressServiceImplTest, DataFabricAddressServiceImplTest044, TestSize.Level0)
{
    InitFactory();
    DataFabricAddressTest::SetGetDistanceResult(true, 5000.0);
    auto service = std::make_shared<DataFabricAddressServiceImpl>();
    sptr<IDataFabricAddressCallback> ownerCallback = new TestDataFabricAddressCallbackStub();
    sptr<IDataFabricAddressCallback> otherCallback = new TestDataFabricAddressCallbackStub();
    NativePreferences::DataFabricAddressParams ownerParams =
        DataFabricAddressTest::MakeCommuteSubscriptionParams(DataFabricAddressTest::MakeWgs84HomePoint(),
            DataFabricAddressTest::MakeWgs84CompanyPoint());
    NativePreferences::DataFabricAddressParams otherParams =
        DataFabricAddressTest::MakeCommuteSubscriptionParams({ 31.5, 121.5 }, { 32.0, 122.0 });
    ASSERT_TRUE(service->AddCallback(ownerParams, ownerCallback));
    // Simulate that the cached subscription was registered by another caller.
    service->subscribeCacheMap_[ownerParams].callerFullTokenId = 0xFFFF8888FFFF6666ULL;

    int32_t result = service->Subscribe(otherParams, otherCallback);

    EXPECT_EQ(result, SUBSCRIBE_EXCEPTION);
    ASSERT_EQ(service->subscribeCacheMap_.size(), 1u);
    EXPECT_TRUE(service->subscribeCacheMap_.find(otherParams) == service->subscribeCacheMap_.end());
    EXPECT_TRUE(service->subscribeCacheMap_[ownerParams].callback == ownerCallback);
    // The rejected caller must not reach the navigation manager.
    EXPECT_EQ(DataFabricAddressTest::GetSubscribeActionCount(), 0);
}

/**
 * @tc.name: DataFabricAddressServiceImplTest045
 * @tc.desc: Test a repeated subscription of the same caller keeps one cache entry and one death recipient.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(DataFabricAddressServiceImplTest, DataFabricAddressServiceImplTest045, TestSize.Level0)
{
    InitFactory();
    DataFabricAddressTest::SetGetDistanceResult(true, 5000.0);
    auto service = std::make_shared<DataFabricAddressServiceImpl>();
    sptr<IDataFabricAddressCallback> firstCallback = new TestDataFabricAddressCallbackStub();
    sptr<IDataFabricAddressCallback> secondCallback = new TestDataFabricAddressCallbackStub();
    NativePreferences::DataFabricAddressParams params =
        DataFabricAddressTest::MakeCommuteSubscriptionParams(DataFabricAddressTest::MakeWgs84HomePoint(),
            DataFabricAddressTest::MakeWgs84CompanyPoint());
    ASSERT_TRUE(service->AddCallback(params, firstCallback));
    sptr<IRemoteObject::DeathRecipient> firstDeathRecipient =
        service->subscribeCacheMap_[params].cbDeathRecipient;

    int32_t result = service->Subscribe(params, secondCallback);

    EXPECT_EQ(result, RUN_OK);
    ASSERT_EQ(service->subscribeCacheMap_.size(), 1u);
    EXPECT_TRUE(service->subscribeCacheMap_[params].callback == firstCallback);
    EXPECT_TRUE(service->subscribeCacheMap_[params].cbDeathRecipient == firstDeathRecipient);
    EXPECT_EQ(DataFabricAddressTest::GetSubscribeActionCount(), 1);
}

/**
 * @tc.name: DataFabricAddressServiceImplTest046
 * @tc.desc: Test Subscribe of the origin caller with different params is rejected because only one
 *           subscription exists, the reference points can only be changed by an update action.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(DataFabricAddressServiceImplTest, DataFabricAddressServiceImplTest046, TestSize.Level0)
{
    InitFactory();
    DataFabricAddressTest::SetGetDistanceResult(true, 5000.0);
    auto service = std::make_shared<DataFabricAddressServiceImpl>();
    sptr<IDataFabricAddressCallback> callback = new TestDataFabricAddressCallbackStub();
    NativePreferences::DataFabricAddressParams ownerParams =
        DataFabricAddressTest::MakeCommuteSubscriptionParams(DataFabricAddressTest::MakeWgs84HomePoint(),
            DataFabricAddressTest::MakeWgs84CompanyPoint());
    NativePreferences::DataFabricAddressParams otherParams =
        DataFabricAddressTest::MakeCommuteSubscriptionParams({ 31.5, 121.5 }, { 32.0, 122.0 });
    ASSERT_TRUE(service->AddCallback(ownerParams, callback));

    int32_t result = service->Subscribe(otherParams, callback);

    EXPECT_EQ(result, SUBSCRIBE_EXCEPTION);
    ASSERT_EQ(service->subscribeCacheMap_.size(), 1u);
    EXPECT_TRUE(service->subscribeCacheMap_.find(otherParams) == service->subscribeCacheMap_.end());
    EXPECT_TRUE(service->subscribeCacheMap_[ownerParams].callback == callback);
    EXPECT_EQ(DataFabricAddressTest::GetSubscribeActionCount(), 0);
}

/**
 * @tc.name: DataFabricAddressServiceImplTest047
 * @tc.desc: Test Subscribe with the update action of the origin caller with new reference points reaches
 *           the navigation manager and keeps the cached callback.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(DataFabricAddressServiceImplTest, DataFabricAddressServiceImplTest047, TestSize.Level0)
{
    InitFactory();
    DataFabricAddressTest::SetGetDistanceResult(true, 5000.0);
    auto service = std::make_shared<DataFabricAddressServiceImpl>();
    sptr<IDataFabricAddressCallback> ownerCallback = new TestDataFabricAddressCallbackStub();
    sptr<IDataFabricAddressCallback> updateCallback = new TestDataFabricAddressCallbackStub();
    NativePreferences::DataFabricAddressParams ownerParams =
        DataFabricAddressTest::MakeCommuteSubscriptionParams(DataFabricAddressTest::MakeWgs84HomePoint(),
            DataFabricAddressTest::MakeWgs84CompanyPoint());
    NativePreferences::DataFabricAddressParams updateParams =
        DataFabricAddressTest::MakeCommuteUpdateParams({ 31.5, 121.5 }, { 32.0, 122.0 });
    ASSERT_TRUE(service->AddCallback(ownerParams, ownerCallback));

    int32_t result = service->Subscribe(updateParams, updateCallback);

    EXPECT_EQ(result, RUN_OK);
    ASSERT_EQ(service->subscribeCacheMap_.size(), 1u);
    EXPECT_TRUE(service->subscribeCacheMap_[ownerParams].callback == ownerCallback);
    EXPECT_EQ(DataFabricAddressTest::GetSubscribeActionCount(), 2);
    EXPECT_EQ(DataFabricAddressTest::GetLastSubscribeAction(),
        static_cast<int32_t>(NativePreferences::ActionType::UPDATE));
}

/**
 * @tc.name: DataFabricAddressServiceImplTest048
 * @tc.desc: Test a failed subscription rolls back the cache so that another caller can subscribe.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(DataFabricAddressServiceImplTest, DataFabricAddressServiceImplTest048, TestSize.Level0)
{
    InitFactory();
    DataFabricAddressTest::SetGetDistanceResult(true, 5000.0);
    DataFabricAddressTest::SetSubscribeNavigationManagerResult(INTERNAL_EXCEPTION);
    auto service = std::make_shared<DataFabricAddressServiceImpl>();
    sptr<IDataFabricAddressCallback> firstCallback = new TestDataFabricAddressCallbackStub();
    sptr<IDataFabricAddressCallback> secondCallback = new TestDataFabricAddressCallbackStub();
    NativePreferences::DataFabricAddressParams firstParams =
        DataFabricAddressTest::MakeCommuteSubscriptionParams(DataFabricAddressTest::MakeWgs84HomePoint(),
            DataFabricAddressTest::MakeWgs84CompanyPoint());
    NativePreferences::DataFabricAddressParams secondParams =
        DataFabricAddressTest::MakeCommuteSubscriptionParams({ 31.5, 121.5 }, { 32.0, 122.0 });

    EXPECT_EQ(service->Subscribe(firstParams, firstCallback), INTERNAL_EXCEPTION);
    EXPECT_TRUE(service->subscribeCacheMap_.empty());

    // The failed subscription must not keep the single subscriber slot occupied.
    DataFabricAddressTest::SetSubscribeNavigationManagerResult(RUN_OK);
    EXPECT_EQ(service->Subscribe(secondParams, secondCallback), RUN_OK);
    ASSERT_EQ(service->subscribeCacheMap_.size(), 1u);
    EXPECT_TRUE(service->subscribeCacheMap_[secondParams].callback == secondCallback);
}

/**
 * @tc.name: DataFabricAddressServiceImplTest049
 * @tc.desc: Test the subscription cache lock is free while the navigation manager is called, and the
 *           cache slot has been reserved before the call so that the single subscriber check still holds.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(DataFabricAddressServiceImplTest, DataFabricAddressServiceImplTest049, TestSize.Level0)
{
    InitFactory();
    DataFabricAddressTest::SetGetDistanceResult(true, 5000.0);
    auto service = std::make_shared<DataFabricAddressServiceImpl>();
    sptr<IDataFabricAddressCallback> callback = new TestDataFabricAddressCallbackStub();
    NativePreferences::DataFabricAddressParams params =
        DataFabricAddressTest::MakeCommuteSubscriptionParams(DataFabricAddressTest::MakeWgs84HomePoint(),
            DataFabricAddressTest::MakeWgs84CompanyPoint());
    bool cacheLockAvailable = false;
    size_t cachedCount = 0;
    DataFabricAddressTest::SetSubscribeNavigationManagerHook([&service, &cacheLockAvailable, &cachedCount]() {
        cacheLockAvailable = service->subscribersMutex_.try_lock();
        if (cacheLockAvailable) {
            cachedCount = service->subscribeCacheMap_.size();
            service->subscribersMutex_.unlock();
        }
    });

    int32_t result = service->Subscribe(params, callback);

    EXPECT_EQ(result, RUN_OK);
    // The navigation manager calls the geofence and locator services synchronously, the cache lock must
    // not be held during it, otherwise a concurrent subscription or a client death is blocked.
    EXPECT_TRUE(cacheLockAvailable);
    // The subscription slot is reserved before the call, a concurrent second subscription is rejected.
    EXPECT_EQ(cachedCount, 1u);
    EXPECT_EQ(DataFabricAddressTest::GetSubscribeActionCount(), 1);
}
/**
 * @tc.name: DataFabricAddressServiceImplTest050
 * @tc.desc: Test Unsubscribe of a caller which does not own the subscription neither removes the cached
 *           entry nor tears the navigation manager down.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(DataFabricAddressServiceImplTest, DataFabricAddressServiceImplTest050, TestSize.Level0)
{
    InitFactory();
    auto service = std::make_shared<DataFabricAddressServiceImpl>();
    sptr<IDataFabricAddressCallback> ownerCallback = new TestDataFabricAddressCallbackStub();
    NativePreferences::DataFabricAddressParams ownerParams =
        DataFabricAddressTest::MakeCommuteSubscriptionParams(DataFabricAddressTest::MakeWgs84HomePoint(),
            DataFabricAddressTest::MakeWgs84CompanyPoint());
    NativePreferences::DataFabricAddressParams otherParams =
        DataFabricAddressTest::MakeCommuteSubscriptionParams({ 31.5, 121.5 }, { 32.0, 122.0 });
    ASSERT_TRUE(service->AddCallback(ownerParams, ownerCallback));
    // Simulate that the cached subscription was registered by another caller.
    service->subscribeCacheMap_[ownerParams].callerFullTokenId = 0xFFFF8888FFFF6666ULL;
    service->lastSubscribedToken_ = 0xFFFF8888FFFF6666ULL;

    int32_t result = service->Unsubscribe(otherParams);

    // The caller is treated as already unsubscribed, the collection of the owner keeps running.
    EXPECT_EQ(result, RUN_OK);
    EXPECT_EQ(DataFabricAddressTest::GetUnsubscribeManagerCallCount(), 0);
    ASSERT_EQ(service->subscribeCacheMap_.size(), 1u);
    EXPECT_TRUE(service->subscribeCacheMap_[ownerParams].callback == ownerCallback);
}

/**
 * @tc.name: DataFabricAddressServiceImplTest051
 * @tc.desc: Test the owner retries Unsubscribe after its cache entry has been removed, the navigation
 *           manager tear down is retried so that a partial tear down failure can be recovered.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(DataFabricAddressServiceImplTest, DataFabricAddressServiceImplTest051, TestSize.Level0)
{
    InitFactory();
    auto service = std::make_shared<DataFabricAddressServiceImpl>();
    sptr<IDataFabricAddressCallback> callback = new TestDataFabricAddressCallbackStub();
    NativePreferences::DataFabricAddressParams params =
        DataFabricAddressTest::MakeCommuteSubscriptionParams(DataFabricAddressTest::MakeWgs84HomePoint(),
            DataFabricAddressTest::MakeWgs84CompanyPoint());
    ASSERT_TRUE(service->AddCallback(params, callback));
    ASSERT_EQ(service->Unsubscribe(params), RUN_OK);
    ASSERT_EQ(DataFabricAddressTest::GetUnsubscribeManagerCallCount(), 1);
    ASSERT_TRUE(service->subscribeCacheMap_.empty());

    // The cache entry is already removed, the second call only retries the navigation manager tear down.
    EXPECT_EQ(service->Unsubscribe(params), RUN_OK);
    EXPECT_EQ(DataFabricAddressTest::GetUnsubscribeManagerCallCount(), 2);
}

/**
 * @tc.name: DataFabricAddressServiceImplTest052
 * @tc.desc: Test the death of the only subscriber tears the navigation manager down, so that the
 *           collection does not outlive the subscriber which can never receive the reports.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(DataFabricAddressServiceImplTest, DataFabricAddressServiceImplTest052, TestSize.Level0)
{
    auto service = std::make_shared<DataFabricAddressServiceImpl>();
    sptr<IDataFabricAddressCallback> callback = new TestDataFabricAddressCallbackStub();
    NativePreferences::DataFabricAddressParams params =
        DataFabricAddressTest::MakeCommuteSubscriptionParams(DataFabricAddressTest::MakeWgs84HomePoint(),
            DataFabricAddressTest::MakeWgs84CompanyPoint());
    ASSERT_TRUE(service->AddCallback(params, callback));
    std::weak_ptr<DataFabricAddressServiceImpl> weakService = service;
    DataFabricAddressServiceImpl::DeathRecipientListener listener(weakService);
    wptr<IRemoteObject> remote(callback->AsObject().GetRefPtr());

    listener.OnRemoteDied(remote);

    EXPECT_TRUE(service->subscribeCacheMap_.empty());
    EXPECT_EQ(DataFabricAddressTest::GetUnsubscribeManagerCallCount(), 1);
}

/**
 * @tc.name: DataFabricAddressServiceImplTest053
 * @tc.desc: Test the death of a client which does not own the subscription neither removes the cached
 *           entry nor tears the navigation manager down.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(DataFabricAddressServiceImplTest, DataFabricAddressServiceImplTest053, TestSize.Level0)
{
    auto service = std::make_shared<DataFabricAddressServiceImpl>();
    sptr<IDataFabricAddressCallback> ownerCallback = new TestDataFabricAddressCallbackStub();
    sptr<IDataFabricAddressCallback> otherCallback = new TestDataFabricAddressCallbackStub();
    NativePreferences::DataFabricAddressParams params =
        DataFabricAddressTest::MakeCommuteSubscriptionParams(DataFabricAddressTest::MakeWgs84HomePoint(),
            DataFabricAddressTest::MakeWgs84CompanyPoint());
    ASSERT_TRUE(service->AddCallback(params, ownerCallback));
    std::weak_ptr<DataFabricAddressServiceImpl> weakService = service;
    DataFabricAddressServiceImpl::DeathRecipientListener listener(weakService);
    wptr<IRemoteObject> remote(otherCallback->AsObject().GetRefPtr());

    listener.OnRemoteDied(remote);

    ASSERT_EQ(service->subscribeCacheMap_.size(), 1u);
    EXPECT_TRUE(service->subscribeCacheMap_[params].callback == ownerCallback);
    EXPECT_EQ(DataFabricAddressTest::GetUnsubscribeManagerCallCount(), 0);
}

/**
 * @tc.name: DataFabricAddressServiceImplTest054
 * @tc.desc: Test the death of one subscriber keeps the collection running when another subscription is
 *           still cached.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(DataFabricAddressServiceImplTest, DataFabricAddressServiceImplTest054, TestSize.Level0)
{
    auto service = std::make_shared<DataFabricAddressServiceImpl>();
    sptr<IDataFabricAddressCallback> deadCallback = new TestDataFabricAddressCallbackStub();
    sptr<IDataFabricAddressCallback> aliveCallback = new TestDataFabricAddressCallbackStub();
    NativePreferences::DataFabricAddressParams deadParams =
        DataFabricAddressTest::MakeCommuteSubscriptionParams({ 30.0, 120.0 }, { 30.5, 120.5 });
    NativePreferences::DataFabricAddressParams aliveParams =
        DataFabricAddressTest::MakeCommuteSubscriptionParams({ 31.0, 121.0 }, { 31.5, 121.5 });
    ASSERT_TRUE(service->AddCallback(deadParams, deadCallback));
    ASSERT_TRUE(service->AddCallback(aliveParams, aliveCallback));
    std::weak_ptr<DataFabricAddressServiceImpl> weakService = service;
    DataFabricAddressServiceImpl::DeathRecipientListener listener(weakService);
    wptr<IRemoteObject> remote(deadCallback->AsObject().GetRefPtr());

    listener.OnRemoteDied(remote);

    ASSERT_EQ(service->subscribeCacheMap_.size(), 1u);
    EXPECT_TRUE(service->subscribeCacheMap_.find(deadParams) == service->subscribeCacheMap_.end());
    EXPECT_TRUE(service->subscribeCacheMap_[aliveParams].callback == aliveCallback);
    EXPECT_EQ(DataFabricAddressTest::GetUnsubscribeManagerCallCount(), 0);
}
