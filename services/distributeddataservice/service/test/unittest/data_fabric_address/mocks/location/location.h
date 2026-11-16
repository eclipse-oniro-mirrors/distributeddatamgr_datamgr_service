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

// Unit test shadow of the location SDK "location.h" header. It only provides
// the minimal API surface used by the data fabric address navigation code.

#ifndef LOCATION_MOCK_LOCATION_H
#define LOCATION_MOCK_LOCATION_H

#include <memory>

#include "message_parcel.h"

namespace OHOS {
namespace Location {

enum LocationErrCode {
    ERRCODE_SUCCESS = 0,
    ERRCODE_ERROR = 1,
};

class Location {
public:
    Location() = default;
    Location(double latitude, double longitude) : latitude_(latitude), longitude_(longitude) {}
    ~Location() = default;

    static std::unique_ptr<Location> UnmarshallingMakeUnique(MessageParcel &data);

    double GetLatitude() const
    {
        return latitude_;
    }

    double GetLongitude() const
    {
        return longitude_;
    }

    void SetLatitude(double latitude)
    {
        latitude_ = latitude;
    }

    void SetLongitude(double longitude)
    {
        longitude_ = longitude;
    }

private:
    double latitude_ = 0.0;
    double longitude_ = 0.0;
};
} // namespace Location
} // namespace OHOS
#endif // LOCATION_MOCK_LOCATION_H
