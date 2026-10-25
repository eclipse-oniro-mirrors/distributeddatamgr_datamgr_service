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

#include <cmath>
#include <gtest/gtest.h>

#include "data_fabric_address_errors.h"
#include "data_fabric_address_test_utils.h"
#include "navigation_common_utils.h"
#include "navigation_manager.h"

using namespace OHOS;
using namespace OHOS::DataFabricAddress;
using namespace NativePreferences;
using namespace testing;
using namespace testing::ext;
using DataFabricAddressTest::TestDataFabricAddressCallbackStub;

class DataFabricAddressNavigationManagerTest : public testing::Test {
public:
    void SetUp() override
    {
        auto &manager = NavigationManager::GetInstance();
        manager.isSubscribed_ = false;
    }

    void TearDown() override
    {
        auto &manager = NavigationManager::GetInstance();
        manager.isSubscribed_ = false;
    }
};

/**
 * @tc.name: DataFabricAddressNavigationManagerTest001
 * @tc.desc: Test subscribe action returns ok when the manager has been subscribed.
 * @tc.type: FUNC
 */
HWTEST_F(DataFabricAddressNavigationManagerTest, DataFabricAddressNavigationManagerTest001, TestSize.Level0)
{
    auto &manager = NavigationManager::GetInstance();
    manager.isSubscribed_ = true;
    NativePreferences::LocationPoint homePoint = DataFabricAddressTest::MakeWgs84HomePoint();
    NativePreferences::LocationPoint companyPoint = DataFabricAddressTest::MakeWgs84CompanyPoint();
    sptr<NativePreferences::IDataFabricAddressCallback> callback = new TestDataFabricAddressCallbackStub();
    int32_t result = manager.SubscribeNavigationManager(ActionType::SUBSCRIPTION, homePoint, companyPoint, callback);
    EXPECT_EQ(result, RUN_OK);
}

/**
 * @tc.name: DataFabricAddressNavigationManagerTest002
 * @tc.desc: Test subscribe action with a null callback returns internal error.
 * @tc.type: FUNC
 */
HWTEST_F(DataFabricAddressNavigationManagerTest, DataFabricAddressNavigationManagerTest002, TestSize.Level0)
{
    auto &manager = NavigationManager::GetInstance();
    NativePreferences::LocationPoint homePoint = DataFabricAddressTest::MakeWgs84HomePoint();
    NativePreferences::LocationPoint companyPoint = DataFabricAddressTest::MakeWgs84CompanyPoint();
    int32_t result = manager.SubscribeNavigationManager(ActionType::SUBSCRIPTION, homePoint, companyPoint, nullptr);
    EXPECT_EQ(result, INTERNAL_EXCEPTION);
}

/**
 * @tc.name: DataFabricAddressNavigationManagerTest003
 * @tc.desc: Test update action returns abnormal when the manager has not been subscribed.
 * @tc.type: FUNC
 */
HWTEST_F(DataFabricAddressNavigationManagerTest, DataFabricAddressNavigationManagerTest003, TestSize.Level0)
{
    auto &manager = NavigationManager::GetInstance();
    NativePreferences::LocationPoint homePoint = DataFabricAddressTest::MakeWgs84HomePoint();
    NativePreferences::LocationPoint companyPoint = DataFabricAddressTest::MakeWgs84CompanyPoint();
    int32_t result = manager.SubscribeNavigationManager(ActionType::UPDATE, homePoint, companyPoint, nullptr);
    EXPECT_EQ(result, ABNORMAL_OPERATION_EXCEPTION);
}

/**
 * @tc.name: DataFabricAddressNavigationManagerTest004
 * @tc.desc: Test update action updates the reference points when subscribed.
 * @tc.type: FUNC
 */
HWTEST_F(DataFabricAddressNavigationManagerTest, DataFabricAddressNavigationManagerTest004, TestSize.Level0)
{
    auto &manager = NavigationManager::GetInstance();
    manager.isSubscribed_ = true;
    NativePreferences::LocationPoint homePoint = DataFabricAddressTest::MakeWgs84HomePoint();
    NativePreferences::LocationPoint companyPoint = DataFabricAddressTest::MakeWgs84CompanyPoint();
    int32_t result = manager.SubscribeNavigationManager(ActionType::UPDATE, homePoint, companyPoint, nullptr);
    EXPECT_EQ(result, RUN_OK);
}

/**
 * @tc.name: DataFabricAddressNavigationManagerTest005
 * @tc.desc: Test subscribe action with an invalid action type returns parameter error.
 * @tc.type: FUNC
 */
HWTEST_F(DataFabricAddressNavigationManagerTest, DataFabricAddressNavigationManagerTest005, TestSize.Level0)
{
    auto &manager = NavigationManager::GetInstance();
    NativePreferences::LocationPoint homePoint = DataFabricAddressTest::MakeWgs84HomePoint();
    NativePreferences::LocationPoint companyPoint = DataFabricAddressTest::MakeWgs84CompanyPoint();
    int32_t result = manager.SubscribeNavigationManager(static_cast<ActionType>(100),
        homePoint, companyPoint, nullptr);
    EXPECT_EQ(result, PARAMETER_EXCEPTION);
}

/**
 * @tc.name: DataFabricAddressNavigationManagerTest006
 * @tc.desc: Test unsubscribe returns ok when the manager has not been subscribed.
 * @tc.type: FUNC
 */
HWTEST_F(DataFabricAddressNavigationManagerTest, DataFabricAddressNavigationManagerTest006, TestSize.Level0)
{
    auto &manager = NavigationManager::GetInstance();
    int32_t result = manager.UnsubscribeNavigationManager();
    EXPECT_EQ(result, RUN_OK);
}

/**
 * @tc.name: DataFabricAddressNavigationManagerTest007
 * @tc.desc: Test unsubscribe resets the subscribed state.
 * @tc.type: FUNC
 */
HWTEST_F(DataFabricAddressNavigationManagerTest, DataFabricAddressNavigationManagerTest007, TestSize.Level0)
{
    auto &manager = NavigationManager::GetInstance();
    manager.isSubscribed_ = true;
    int32_t result = manager.UnsubscribeNavigationManager();
    EXPECT_EQ(result, NativePreferences::RUN_OK);
    EXPECT_FALSE(manager.isSubscribed_);
}

class DataFabricAddressNavigationCommonUtilTest : public testing::Test {
public:
    void SetUp() override {}
    void TearDown() override {}
};

/**
 * @tc.name: DataFabricAddressNavigationCommonUtilTest001
 * @tc.desc: Test GetDistance with an invalid source latitude.
 * @tc.type: FUNC
 */
HWTEST_F(DataFabricAddressNavigationCommonUtilTest, DataFabricAddressNavigationCommonUtilTest001, TestSize.Level0)
{
    NativePreferences::LocationPoint invalidPoint { 91.0, 121.0 };
    NativePreferences::LocationPoint validPoint = DataFabricAddressTest::MakeWgs84HomePoint();
    double distance = 0.0;
    EXPECT_FALSE(NavigationCommonUtil::GetDistance(invalidPoint, validPoint, distance));
}

/**
 * @tc.name: DataFabricAddressNavigationCommonUtilTest002
 * @tc.desc: Test GetDistance with an invalid target longitude.
 * @tc.type: FUNC
 */
HWTEST_F(DataFabricAddressNavigationCommonUtilTest, DataFabricAddressNavigationCommonUtilTest002, TestSize.Level0)
{
    NativePreferences::LocationPoint validPoint = DataFabricAddressTest::MakeWgs84HomePoint();
    NativePreferences::LocationPoint invalidPoint { 31.0, 181.0 };
    double distance = 0.0;
    EXPECT_FALSE(NavigationCommonUtil::GetDistance(validPoint, invalidPoint, distance));
}

/**
 * @tc.name: DataFabricAddressNavigationCommonUtilTest003
 * @tc.desc: Test Gcj02ToWgs84 with an invalid input coordinate.
 * @tc.type: FUNC
 */
HWTEST_F(DataFabricAddressNavigationCommonUtilTest, DataFabricAddressNavigationCommonUtilTest003, TestSize.Level0)
{
    NativePreferences::LocationPoint invalidPoint { 100.0, 121.0 };
    NativePreferences::LocationPoint outputPoint;
    EXPECT_FALSE(NavigationCommonUtil::Gcj02ToWgs84(invalidPoint, outputPoint));
}

/**
 * @tc.name: DataFabricAddressNavigationCommonUtilTest004
 * @tc.desc: Test Gcj02ToWgs84 with a valid input coordinate.
 * @tc.type: FUNC
 */
HWTEST_F(DataFabricAddressNavigationCommonUtilTest, DataFabricAddressNavigationCommonUtilTest004, TestSize.Level0)
{
    NativePreferences::LocationPoint gcj02Point = DataFabricAddressTest::MakeWgs84HomePoint();
    NativePreferences::LocationPoint wgs84Point;
    EXPECT_TRUE(NavigationCommonUtil::Gcj02ToWgs84(gcj02Point, wgs84Point));
    EXPECT_TRUE(std::isfinite(wgs84Point.latitude));
    EXPECT_TRUE(std::isfinite(wgs84Point.longitude));
    EXPECT_GT(std::abs(wgs84Point.latitude - gcj02Point.latitude), 1e-6);
    EXPECT_NE(wgs84Point.longitude, gcj02Point.longitude);
}

/**
 * @tc.name: DataFabricAddressNavigationCommonUtilTest005
 * @tc.desc: Test TransformLat returns a finite offset value.
 * @tc.type: FUNC
 */
HWTEST_F(DataFabricAddressNavigationCommonUtilTest, DataFabricAddressNavigationCommonUtilTest005, TestSize.Level0)
{
    double offset = NavigationCommonUtil::TransformLat(121.4737, 31.2304);
    double originOffset = NavigationCommonUtil::TransformLat(0.0, 0.0);
    EXPECT_TRUE(std::isfinite(offset));
    EXPECT_TRUE(std::isfinite(originOffset));
    EXPECT_NE(offset, originOffset);
    EXPECT_GT(std::abs(offset), std::abs(originOffset));
}

/**
 * @tc.name: DataFabricAddressNavigationCommonUtilTest006
 * @tc.desc: Test TransformLng returns a finite offset value.
 * @tc.type: FUNC
 */
HWTEST_F(DataFabricAddressNavigationCommonUtilTest, DataFabricAddressNavigationCommonUtilTest006, TestSize.Level0)
{
    double offset = NavigationCommonUtil::TransformLng(121.4737, 31.2304);
    double originOffset = NavigationCommonUtil::TransformLng(0.0, 0.0);
    EXPECT_TRUE(std::isfinite(offset));
    EXPECT_TRUE(std::isfinite(originOffset));
    EXPECT_NE(offset, originOffset);
    EXPECT_GT(std::abs(offset), std::abs(originOffset));
}

/**
 * @tc.name: DataFabricAddressNavigationCommonUtilTest007
 * @tc.desc: Test CalculateGcj02Delta produces a non-zero finite delta.
 * @tc.type: FUNC
 */
HWTEST_F(DataFabricAddressNavigationCommonUtilTest, DataFabricAddressNavigationCommonUtilTest007, TestSize.Level0)
{
    double dlng = 0.0;
    double dlat = 0.0;
    NavigationCommonUtil::CalculateGcj02Delta(121.4737, 31.2304, dlng, dlat);
    EXPECT_TRUE(std::isfinite(dlng));
    EXPECT_TRUE(std::isfinite(dlat));
    EXPECT_NE(dlng, 0.0);
    EXPECT_NE(dlat, 0.0);
}
