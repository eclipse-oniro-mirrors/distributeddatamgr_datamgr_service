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

#ifndef NAVIGATION_PASSIVE_LOCATION_HANDLER_H
#define NAVIGATION_PASSIVE_LOCATION_HANDLER_H

#include <memory>
#include <vector>

#include <i_locator_callback.h>
#include <iremote_stub.h>
#include "navigation_base_data.h"

namespace OHOS {
namespace DataFabricAddress {
class PassiveLocatingCallback final : public IRemoteStub<Location::ILocatorCallback> {
public:
    PassiveLocatingCallback() = default;
    ~PassiveLocatingCallback() = default;

    int32_t OnRemoteRequest(
        uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override;
    void OnLocatingStatusChange(const int status) override;
    void OnLocationReport(const std::unique_ptr<Location::Location> &location) override;
    void OnErrorReport(const int errorCode) override;
private:
    void HandlePassiveLocation(const NativePreferences::LocationPoint &point);
};

class NavigationPassiveLocationHandler {
public:
    static NavigationPassiveLocationHandler &GetInstance();
    int32_t SubscribePassiveLocation();
    int32_t UnsubscribePassiveLocation();
    void AddWaypoints(const Waypoint &waypoint);
    void ReadWaypoints(std::vector<Waypoint> &waypoints);
    void ClearWaypoints();
private:
    NavigationPassiveLocationHandler() = default;
    ~NavigationPassiveLocationHandler() = default;

    // Called without mutex_ held: StartLocatingV9/StopLocatingV9 call the locator service synchronously, the
    // lock only protects the state and is re-acquired after them. The navigation manager serializes the calls.
    int32_t DoSubscribePassiveLocation();
    int32_t DoUnsubscribePassiveLocation(sptr<Location::ILocatorCallback> &callback);

    std::mutex mutex_;
    std::mutex waypointsMutex_;
    std::atomic<bool> isSubscribed_ { false };
    std::vector<Waypoint> waypoints_;
    sptr<Location::ILocatorCallback> passiveCallback_ { nullptr };
};
} // End of namespace DataFabricAddress
} // End of namespace OHOS
#endif // NAVIGATION_PASSIVE_LOCATION_HANDLER_H
