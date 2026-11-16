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

#include "location_mock.h"
#include "navigation_common_utils.h"

using namespace OHOS;
using namespace OHOS::DataFabricAddress;
using namespace NativePreferences;
using namespace testing;
using namespace testing::ext;

namespace {
constexpr int32_t LOCATOR_ERROR_CODE = 1;
constexpr double TEST_DISTANCE = 1234.5;
} // namespace

/*
 * The location SDK is shadowed by the "mocks/location" headers in this test
 * binary, so the distance calculation of the navigation common utils can be
 * controlled by the test.
 */
class DataFabricAddressNavigationDistanceTest : public testing::Test {
public:
    void SetUp() override
    {
        DataFabricAddressTest::ResetLocationMock();
    }

    void TearDown() override
    {
        DataFabricAddressTest::ResetLocationMock();
    }
};

/**
 * @tc.name: DataFabricAddressNavigationDistanceTest001
 * @tc.desc: Test GetDistance returns the distance reported by the locator when both points are valid.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(DataFabricAddressNavigationDistanceTest, DataFabricAddressNavigationDistanceTest001, TestSize.Level0)
{
    LocationPoint startPoint { 31.2304, 121.4737 };
    LocationPoint endPoint { 31.2204, 121.4137 };
    DataFabricAddressTest::SetDistanceBetweenLocationsResult(0, TEST_DISTANCE);
    double distance = 0.0;
    EXPECT_TRUE(NavigationCommonUtil::GetDistance(startPoint, endPoint, distance));
    EXPECT_DOUBLE_EQ(distance, TEST_DISTANCE);
    EXPECT_EQ(DataFabricAddressTest::GetDistanceBetweenLocationsCount(), 1);
}

/**
 * @tc.name: DataFabricAddressNavigationDistanceTest002
 * @tc.desc: Test GetDistance fails and keeps the output untouched when the locator reports an error.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(DataFabricAddressNavigationDistanceTest, DataFabricAddressNavigationDistanceTest002, TestSize.Level0)
{
    LocationPoint startPoint { 31.2304, 121.4737 };
    LocationPoint endPoint { 31.2204, 121.4137 };
    DataFabricAddressTest::SetDistanceBetweenLocationsResult(LOCATOR_ERROR_CODE, TEST_DISTANCE);
    double distance = 0.0;
    EXPECT_FALSE(NavigationCommonUtil::GetDistance(startPoint, endPoint, distance));
    EXPECT_DOUBLE_EQ(distance, 0.0);
    EXPECT_EQ(DataFabricAddressTest::GetDistanceBetweenLocationsCount(), 1);
}

/**
 * @tc.name: DataFabricAddressNavigationDistanceTest003
 * @tc.desc: Test GetDistance does not query the locator when an input point is invalid.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(DataFabricAddressNavigationDistanceTest, DataFabricAddressNavigationDistanceTest003, TestSize.Level0)
{
    LocationPoint invalidPoint { 91.0, 121.0 };
    LocationPoint validPoint { 31.2204, 121.4137 };
    double distance = 0.0;
    EXPECT_FALSE(NavigationCommonUtil::GetDistance(invalidPoint, validPoint, distance));
    EXPECT_EQ(DataFabricAddressTest::GetDistanceBetweenLocationsCount(), 0);
}

/**
 * @tc.name: DataFabricAddressNavigationDistanceTest004
 * @tc.desc: Test IsDistanceLessThan returns true when the locator distance is below the threshold.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(DataFabricAddressNavigationDistanceTest, DataFabricAddressNavigationDistanceTest004, TestSize.Level0)
{
    LocationPoint startPoint { 31.2304, 121.4737 };
    LocationPoint endPoint { 31.2204, 121.4137 };
    DataFabricAddressTest::SetDistanceBetweenLocationsResult(0, 300.0);
    EXPECT_TRUE(NavigationCommonUtil::IsDistanceLessThan(startPoint, endPoint, 500.0));
    EXPECT_EQ(DataFabricAddressTest::GetDistanceBetweenLocationsCount(), 1);
}

/**
 * @tc.name: DataFabricAddressNavigationDistanceTest005
 * @tc.desc: Test IsDistanceLessThan returns true just below the threshold.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(DataFabricAddressNavigationDistanceTest, DataFabricAddressNavigationDistanceTest005, TestSize.Level0)
{
    LocationPoint startPoint { 31.2304, 121.4737 };
    LocationPoint endPoint { 31.2204, 121.4137 };
    DataFabricAddressTest::SetDistanceBetweenLocationsResult(0, 499.9);
    EXPECT_TRUE(NavigationCommonUtil::IsDistanceLessThan(startPoint, endPoint, 500.0));
}

/**
 * @tc.name: DataFabricAddressNavigationDistanceTest006
 * @tc.desc: Test IsDistanceLessThan returns false when the locator distance equals the threshold.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(DataFabricAddressNavigationDistanceTest, DataFabricAddressNavigationDistanceTest006, TestSize.Level0)
{
    LocationPoint startPoint { 31.2304, 121.4737 };
    LocationPoint endPoint { 31.2204, 121.4137 };
    DataFabricAddressTest::SetDistanceBetweenLocationsResult(0, 500.0);
    EXPECT_FALSE(NavigationCommonUtil::IsDistanceLessThan(startPoint, endPoint, 500.0));
}

/**
 * @tc.name: DataFabricAddressNavigationDistanceTest007
 * @tc.desc: Test IsDistanceLessThan returns false when the locator fails to calculate the distance.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(DataFabricAddressNavigationDistanceTest, DataFabricAddressNavigationDistanceTest007, TestSize.Level0)
{
    LocationPoint startPoint { 31.2304, 121.4737 };
    LocationPoint endPoint { 31.2204, 121.4137 };
    DataFabricAddressTest::SetDistanceBetweenLocationsResult(LOCATOR_ERROR_CODE, TEST_DISTANCE);
    EXPECT_FALSE(NavigationCommonUtil::IsDistanceLessThan(startPoint, endPoint, 500.0));
    EXPECT_EQ(DataFabricAddressTest::GetDistanceBetweenLocationsCount(), 1);
}
