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

#include "navigation_mock.h"

#include "navigation_common_utils.h"

namespace {
constexpr double DEFAULT_DISTANCE_VALUE = 5000.0;
constexpr double GCJ02_TO_WGS84_OFFSET = 0.001;
constexpr int64_t DEFAULT_NOW_SECOND_TIMESTAMP = 1000;
bool g_getDistanceResults[2] = { true, true };
double g_distanceValues[2] = { DEFAULT_DISTANCE_VALUE, DEFAULT_DISTANCE_VALUE };
int32_t g_getDistanceCallCount = 0;
bool g_shortDistanceResult = false;
int32_t g_distanceLessThanCallCount = 0;
double g_lastDistanceThreshold = 0.0;
bool g_gcj02ToWgs84Result = true;
int64_t g_nowSecondTimestamp = DEFAULT_NOW_SECOND_TIMESTAMP;
} // namespace

namespace OHOS {
namespace DataFabricAddress {

bool NavigationCommonUtil::GetDistance(const NativePreferences::LocationPoint& startPoint,
    const NativePreferences::LocationPoint& endPoint, double& distance)
{
    // The first call is used for the home point, the following calls are used for the company point.
    const int32_t index = (g_getDistanceCallCount == 0) ? 0 : 1;
    const bool result = g_getDistanceResults[index];
    const double distanceValue = g_distanceValues[index];
    g_getDistanceCallCount++;
    if (!result) {
        return false;
    }
    distance = distanceValue;
    return true;
}

bool NavigationCommonUtil::IsDistanceLessThan(const NativePreferences::LocationPoint& startPoint,
    const NativePreferences::LocationPoint& endPoint, double threshold)
{
    (void)startPoint;
    (void)endPoint;
    g_distanceLessThanCallCount++;
    g_lastDistanceThreshold = threshold;
    return g_shortDistanceResult;
}

bool NavigationCommonUtil::Gcj02ToWgs84(const NativePreferences::LocationPoint& gcj02Point,
    NativePreferences::LocationPoint& wgs84Point)
{
    if (!g_gcj02ToWgs84Result) {
        return false;
    }
    wgs84Point.latitude = gcj02Point.latitude - GCJ02_TO_WGS84_OFFSET;
    wgs84Point.longitude = gcj02Point.longitude - GCJ02_TO_WGS84_OFFSET;
    return true;
}

int64_t NavigationCommonUtil::GetNowSecondTimestamp()
{
    return g_nowSecondTimestamp;
}
} // End of namespace DataFabricAddress

namespace DataFabricAddressTest {

void ResetNavigationCommonUtilsMock()
{
    g_getDistanceResults[0] = true;
    g_getDistanceResults[1] = true;
    g_distanceValues[0] = DEFAULT_DISTANCE_VALUE;
    g_distanceValues[1] = DEFAULT_DISTANCE_VALUE;
    g_getDistanceCallCount = 0;
    g_shortDistanceResult = false;
    g_distanceLessThanCallCount = 0;
    g_lastDistanceThreshold = 0.0;
    g_gcj02ToWgs84Result = true;
    g_nowSecondTimestamp = DEFAULT_NOW_SECOND_TIMESTAMP;
}

void SetGetDistanceResult(bool result, double distance)
{
    SetGetDistanceResults(result, distance, distance);
}

void SetGetDistanceResults(bool result, double firstDistance, double secondDistance)
{
    g_getDistanceResults[0] = result;
    g_getDistanceResults[1] = result;
    g_distanceValues[0] = firstDistance;
    g_distanceValues[1] = secondDistance;
    g_getDistanceCallCount = 0;
}

void SetGetDistanceCallResults(bool firstResult, bool secondResult)
{
    g_getDistanceResults[0] = firstResult;
    g_getDistanceResults[1] = secondResult;
    g_distanceValues[0] = DEFAULT_DISTANCE_VALUE;
    g_distanceValues[1] = DEFAULT_DISTANCE_VALUE;
    g_getDistanceCallCount = 0;
}

void SetShortDistanceResult(bool result)
{
    g_shortDistanceResult = result;
}

void SetGcj02ToWgs84Result(bool result)
{
    g_gcj02ToWgs84Result = result;
}

void SetNowSecondTimestamp(int64_t timestamp)
{
    g_nowSecondTimestamp = timestamp;
}

int32_t GetGetDistanceCallCount()
{
    return g_getDistanceCallCount;
}

int32_t GetIsDistanceLessThanCallCount()
{
    return g_distanceLessThanCallCount;
}

double GetLastDistanceThreshold()
{
    return g_lastDistanceThreshold;
}
} // End of namespace DataFabricAddressTest
} // End of namespace OHOS
