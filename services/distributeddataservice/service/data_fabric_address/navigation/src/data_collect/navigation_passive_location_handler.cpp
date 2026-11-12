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

#include "navigation_passive_location_handler.h"

#include "data_fabric_address_errors.h"
#include "data_fabric_address_event_dfx.h"
#include "locator_impl.h"
#include "log_print.h"
#include "navigation_base_data.h"
#include "navigation_common_utils.h"
#include "navigation_live_view_monitor.h"

#undef LOG_TAG
#define LOG_TAG "NavigationPassiveLocationHandler"

namespace OHOS {
namespace DataFabricAddress {
using namespace DistributedData;
const int32_t ON_REMOTE_OBJECT_FAILED_CODE = -1;
const int32_t LOCATION_NO_POWER_TIME_INTERVAL = 1;
const int32_t LOCATION_NO_POWER_DISTANCE_INTERVAL = 10;

NavigationPassiveLocationHandler &NavigationPassiveLocationHandler::GetInstance()
{
    static NavigationPassiveLocationHandler instance;
    return instance;
}

int32_t NavigationPassiveLocationHandler::SubscribePassiveLocation()
{
    ZLOGI("SubscribePassiveLocation enter.");
    std::lock_guard<std::mutex> lock(mutex_);
    if (isSubscribed_.load()) {
        ZLOGI("Passive location has been subscribed.");
        return NativePreferences::RUN_OK;
    }

    auto locator = Location::LocatorImpl::GetInstance();
    if (locator == nullptr) {
        ZLOGE("Failed to get location instance.");
        RADAR_REPORT(CLIENT_REQUEST, PSAAIVE_LOCATION_SUBSCRIBE, RES_FAILED, "ERRIR_CODE",
            PASSIVE_LOCATION_SUBSCRIBE_FAILED);
        return NativePreferences::INTERNAL_EXCEPTION;
    }

    sptr<Location::ILocatorCallback> callback =
        sptr<PassiveLocatingCallback>(new (std::nothrow) PassiveLocatingCallback());
    if (callback == nullptr) {
        ZLOGE("Failed to create location callback.");
        RADAR_REPORT(CLIENT_REQUEST, PSAAIVE_LOCATION_SUBSCRIBE, RES_FAILED, "ERRIR_CODE",
            PASSIVE_LOCATION_SUBSCRIBE_FAILED);
        return NativePreferences::INTERNAL_EXCEPTION;
    }

    auto requestConfig = std::make_unique<Location::RequestConfig>();
    requestConfig->SetScenario(Location::SCENE_NO_POWER);
    requestConfig->SetTimeInterval(LOCATION_NO_POWER_TIME_INTERVAL);
    requestConfig->SetDistanceInterval(LOCATION_NO_POWER_DISTANCE_INTERVAL);
    int32_t ret = locator->StartLocatingV9(requestConfig, callback);
    if (ret != Location::LocationErrCode::ERRCODE_SUCCESS) {
        ZLOGE("Failed to start passive locating, ret:%{public}d", ret);
        RADAR_REPORT(CLIENT_REQUEST, PSAAIVE_LOCATION_SUBSCRIBE, RES_FAILED, "ERRIR_CODE",
            PASSIVE_LOCATION_SUBSCRIBE_FAILED);
        return NativePreferences::INTERNAL_EXCEPTION;
    }

    passiveCallback_ = callback;
    isSubscribed_.store(true);
    RADAR_REPORT(CLIENT_REQUEST, PSAAIVE_LOCATION_SUBSCRIBE, RES_SUCCESS);
    ZLOGI("SubscribePassiveLocation exit.");
    return NativePreferences::RUN_OK;
}

int32_t NavigationPassiveLocationHandler::UnsubscribePassiveLocation()
{
    ZLOGI("UnsubscribePassiveLocation enter.");
    std::lock_guard<std::mutex> lock(mutex_);
    if (!isSubscribed_.load()) {
        ZLOGI("Passive location has not been subscribed.");
        return NativePreferences::RUN_OK;
    }

    if (passiveCallback_ == nullptr) {
        isSubscribed_.store(false);
        ZLOGI("The callback is null, does't need to unsubscribed.");
        return NativePreferences::RUN_OK;
    }

    auto locator = Location::LocatorImpl::GetInstance();
    if (locator == nullptr) {
        ZLOGE("Failed to get location instance.");
        RADAR_REPORT(CLIENT_REQUEST, LIVE_VIEW_SUBSCRIBE, RES_FAILED, "ERRIR_CODE",
            PASSIVE_LOCATION_UNSUBSCRIBE_FAILED);
        return NativePreferences::INTERNAL_EXCEPTION;
    }

    int32_t ret = locator->StopLocatingV9(passiveCallback_);
    if (ret != Location::LocationErrCode::ERRCODE_SUCCESS) {
        ZLOGE("Failed to stop passive locating, ret:%{public}d", ret);
        RADAR_REPORT(CLIENT_REQUEST, LIVE_VIEW_SUBSCRIBE, RES_FAILED, "ERRIR_CODE",
            PASSIVE_LOCATION_UNSUBSCRIBE_FAILED);
        return NativePreferences::INTERNAL_EXCEPTION;
    }

    passiveCallback_ = nullptr;
    isSubscribed_.store(false);
    RADAR_REPORT(CLIENT_REQUEST, LIVE_VIEW_UNSUBSCRIBE, RES_SUCCESS);
    ZLOGI("UnsubscribePassiveLocation exit.");
    return NativePreferences::RUN_OK;
}

void NavigationPassiveLocationHandler::AddWaypoints(const Waypoint &waypoint)
{
    std::lock_guard<std::mutex> lock(waypointsMutex_);
    waypoints_.push_back(waypoint);
    ZLOGI("AddWaypoints current size:%{public}zu", waypoints_.size());
}

void NavigationPassiveLocationHandler::ReadWaypoints(std::vector<Waypoint> &waypoints)
{
    std::lock_guard<std::mutex> lock(waypointsMutex_);
    waypoints = waypoints_;
}

void NavigationPassiveLocationHandler::ClearWaypoints()
{
    ZLOGI("ClearWaypoints enter.");
    std::lock_guard<std::mutex> lock(waypointsMutex_);
    waypoints_.clear();
}

int32_t PassiveLocatingCallback::OnRemoteRequest(
    uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    ZLOGI("OnRemoteRequest enter.");
    if (data.ReadInterfaceToken() != GetDescriptor()) {
        ZLOGE("PassiveLocatingCallback invalid token.");
        return ON_REMOTE_OBJECT_FAILED_CODE;
    }

    switch (code) {
        case Location::ILocatorCallback::RECEIVE_LOCATION_INFO_EVENT:
            std::unique_ptr<Location::Location> location =
                Location::Location::UnmarshallingMakeUnique(data);
            OnLocationReport(location);
            break;
        case Location::ILocatorCallback::RECEIVE_ERROR_INFO_EVENT:
            int32_t errorCode = data.ReadInt32();
            OnErrorReport(errorCode);
            break;
        case Location::ILocatorCallback::RECEIVE_LOCATION_STATUS_EVENT:
            int32_t status = data.ReadInt32();
            OnLocatingStatusChange(status);
            break;
        default:
            break;
    }
    return 0;
}

void PassiveLocatingCallback::OnLocatingStatusChange(const int status)
{
    ZLOGI("PassiveLocatingCallback locating status changed, current status: %{public}d", status);
}

void PassiveLocatingCallback::OnLocationReport(const std::unique_ptr<Location::Location> &location)
{
    ZLOGI("OnLocationReport enter.");
    if (location == nullptr) {
        ZLOGE("The location report location is null.");
        return;
    }

    double latitude = location->GetLatitude();
    double longitude = location->GetLongitude();
    HandlePassiveLocation(latitude, longitude);
}

void PassiveLocatingCallback::OnErrorReport(const int errorCode)
{
    ZLOGW("PassiveLocatingCallback report error, errorCode: %{public}d", errorCode);
}

void PassiveLocatingCallback::HandlePassiveLocation(double latitude, double longitude)
{
    ZLOGI("HandlePassiveLocation enter.");
    NativePreferences::LocationPoint currentPoint = { latitude, longitude };
    double distanceFromHome = 0.0;
    double distanceFromCompany = 0.0;
    if (!NavigationCommonUtil::GetDistance(currentPoint, NavigationLiveViewMonitor::GetInstance().GetHomePoint(),
        distanceFromHome) || !NavigationCommonUtil::GetDistance(currentPoint,
        NavigationLiveViewMonitor::GetInstance().GetCompanyPoint(), distanceFromCompany)) {
        ZLOGE("Failed to get the distance from current location to home or company.");
        return;
    }
    if (distanceFromHome >= DEFAULT_MAX_WAYPOINT_COLLECT_DISTANCE &&
        distanceFromCompany >= DEFAULT_MAX_WAYPOINT_COLLECT_DISTANCE) {
        ZLOGE("The distance from current location to home and company all are greater than %{public}zu, "
            "the location data is invalid.", DEFAULT_MAX_WAYPOINT_COLLECT_DISTANCE);
        return;
    }
    int64_t timestamp = NavigationCommonUtil::GetNowSecondTimestamp();
    Waypoint waypoint = { timestamp, latitude, longitude };
    NavigationPassiveLocationHandler::GetInstance().AddWaypoints(waypoint);
}
} // End of namespace DataFabricAddress
} // End of namespace OHOS
