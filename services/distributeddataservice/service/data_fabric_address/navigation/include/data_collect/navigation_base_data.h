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

#ifndef NAVIGATION_BASE_DATA_H
#define NAVIGATION_BASE_DATA_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>
#include <sstream>

#include "data_fabric_address_types.h"

namespace OHOS {
namespace DataFabricAddress {

struct Waypoint {
    int64_t timestamp = 0;
    double latitude = 0.0;
    double longitude = 0.0;

    NativePreferences::LocationPoint ToLocationPoint() const
    {
        return { latitude, longitude };
    }

    static Waypoint FromLocationPoint(const NativePreferences::LocationPoint &point, int64_t timestamp = 0)
    {
        return { timestamp, point.latitude, point.longitude };
    }

    std::string ToString() const
    {
        std::ostringstream oss;
        oss << "{\"timestamp\":" << timestamp << ",\"latitude\":" << latitude << ",\"longitude\":" << longitude << "}";
        return oss.str();
    }
};

struct NavigationResult {
    int64_t startTimestamp = 0;
    int64_t endTimestamp = 0;
    double startLatitude = 0.0;
    double startLongitude = 0.0;
    double endLatitude = 0.0;
    double endLongitude = 0.0;
    std::string bundleName;
    std::vector<Waypoint> waypoints;

    std::string ToString() const
    {
        std::ostringstream oss;
        oss << "{\"navigationInfo\":{";
        oss << "\"startTimestamp\":" << startTimestamp << ",\"endTimestamp\":" << endTimestamp << ",";
        oss << "\"startLatitude\":" << startLatitude << ",\"startLongitude\":" << startLongitude << ",";
        oss << "\"endLatitude\":" << endLatitude << ",\"endLongitude\":" << endLongitude << ",";
        oss << "\"bundleName\":\"" << bundleName << "\"},";
        oss << "\"waypoints\":[";
        size_t size = waypoints.size();
        for (size_t i = 0; i < size; i++) {
            oss << waypoints[i].ToString();
            if (i != size - 1) {
                oss << ",";
            }
        }
        oss << "]}";
        return oss.str();
    }
};
} // End of namespace DataFabricAddress
} // End of namespace OHOS
#endif // NAVIGATION_BASE_DATA_H
