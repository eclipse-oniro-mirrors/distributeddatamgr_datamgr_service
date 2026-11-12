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

// Unit test shadow of the location SDK "locator_impl.h" header.

#ifndef LOCATION_MOCK_LOCATOR_IMPL_H
#define LOCATION_MOCK_LOCATOR_IMPL_H

#include <cstdint>
#include <memory>

#include "i_locator_callback.h"

namespace OHOS {
namespace Location {

enum Scenario {
    SCENE_UNSET = 0,
    SCENE_NO_POWER = 1,
    SCENE_NAVIGATION = 2,
};

class RequestConfig {
public:
    RequestConfig() = default;
    ~RequestConfig() = default;

    void SetScenario(const Scenario &scenario);
    void SetTimeInterval(int32_t timeInterval);
    void SetDistanceInterval(int32_t distanceInterval);
};

class LocatorImpl {
public:
    static LocatorImpl *GetInstance();

    LocationErrCode StartLocatingV9(std::unique_ptr<RequestConfig> &requestConfig,
        sptr<ILocatorCallback> &callback);
    LocationErrCode StopLocatingV9(const sptr<ILocatorCallback> &callback);

    LocationErrCode GetDistanceBetweenLocations(const Location &source, const Location &target, double &distance);
};
} // namespace Location
} // namespace OHOS
#endif // LOCATION_MOCK_LOCATOR_IMPL_H
