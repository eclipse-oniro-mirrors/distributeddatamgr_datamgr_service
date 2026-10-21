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
bool g_getDistanceResult = true;
double g_distanceValue = DEFAULT_DISTANCE_VALUE;
bool g_gcj02ToWgs84Result = true;
} // namespace

namespace OHOS {
namespace DataFabricAddress {

bool NavigationCommonUtil::GetDistance(const NativePreferences::LocationPoint& startPoint,
    const NativePreferences::LocationPoint& endPoint, double& distance)
{
    if (!g_getDistanceResult) {
        return false;
    }
    distance = g_distanceValue;
    return true;
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
} // End of namespace DataFabricAddress

namespace DataFabricAddressTest {

void ResetNavigationCommonUtilsMock()
{
    g_getDistanceResult = true;
    g_distanceValue = DEFAULT_DISTANCE_VALUE;
    g_gcj02ToWgs84Result = true;
}

void SetGetDistanceResult(bool result, double distance)
{
    g_getDistanceResult = result;
    g_distanceValue = distance;
}

void SetGcj02ToWgs84Result(bool result)
{
    g_gcj02ToWgs84Result = result;
}
} // End of namespace DataFabricAddressTest
} // End of namespace OHOS