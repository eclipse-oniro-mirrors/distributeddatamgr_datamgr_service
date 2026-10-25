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

#ifndef NAVIGATION_COMMON_UTILS_H
#define NAVIGATION_COMMON_UTILS_H

#include "data_fabric_address_types.h"

namespace OHOS {
namespace DataFabricAddress {

class NavigationCommonUtil {
public:
    static bool GetDistance(const NativePreferences::LocationPoint& startPoint,
        const NativePreferences::LocationPoint& endPoint, double& distance);
    // Convert the GCJ02 coordinate system to the WGS84 coordinate system
    static bool Gcj02ToWgs84(const NativePreferences::LocationPoint& gcj02Point,
        NativePreferences::LocationPoint& wgs84Point);
private:
    static double TransformLat(double lng, double lat);
    static double TransformLng(double lng, double lat);
    static bool CalculateGcj02Delta(double lng, double lat, double& dlng, double& dlat);
};
} // End of namespace DataFabricAddress
} // End of namespace OHOS
#endif // NAVIGATION_COMMON_UTILS_H
