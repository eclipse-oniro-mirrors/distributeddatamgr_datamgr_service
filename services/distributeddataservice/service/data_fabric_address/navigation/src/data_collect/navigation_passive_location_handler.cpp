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
// The report keeps the first and the last waypoint plus at most 64 middle waypoints, so collecting
// twice that number is enough and bounds the buffer of a navigation which never receives an end event.
constexpr size_t MAX_COLLECTED_WAYPOINT_COUNT = 128;

NavigationPassiveLocationHandler &NavigationPassiveLocationHandler::GetInstance()
{
    static NavigationPassiveLocationHandler instance;
    return instance;
}

int32_t NavigationPassiveLocationHandler::SubscribePassiveLocation()
{
    ZLOGI("SubscribePassiveLocation enter.");
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (isSubscribed_.load()) {
            ZLOGI("Passive location has been subscribed.");
            return NativePreferences::RUN_OK;
        }
    }
    // StartLocatingV9 calls the locator service synchronously, start it without the handler lock.
    int32_t ret = DoSubscribePassiveLocation();
    // The event is reported outside the handler lock, the write may block.
    if (ret != NativePreferences::RUN_OK) {
        RADAR_REPORT(CLIENT_REQUEST, PASSIVE_LOCATION_SUBSCRIBE, RES_FAILED, "ERROR_CODE",
            PASSIVE_LOCATION_SUBSCRIBE_FAILED);
        return ret;
    }
    ZLOGI("SubscribePassiveLocation exit.");
    return NativePreferences::RUN_OK;
}

int32_t NavigationPassiveLocationHandler::DoSubscribePassiveLocation()
{
    auto locator = Location::LocatorImpl::GetInstance();
    if (locator == nullptr) {
        ZLOGE("Failed to get location instance.");
        return NativePreferences::INTERNAL_EXCEPTION;
    }

    sptr<Location::ILocatorCallback> callback =
        sptr<PassiveLocatingCallback>(new (std::nothrow) PassiveLocatingCallback());
    if (callback == nullptr) {
        ZLOGE("Failed to create location callback.");
        return NativePreferences::INTERNAL_EXCEPTION;
    }

    auto requestConfig = std::make_unique<Location::RequestConfig>();
    requestConfig->SetScenario(Location::SCENE_NO_POWER);
    requestConfig->SetTimeInterval(LOCATION_NO_POWER_TIME_INTERVAL);
    requestConfig->SetDistanceInterval(LOCATION_NO_POWER_DISTANCE_INTERVAL);
    int32_t ret = locator->StartLocatingV9(requestConfig, callback);
    if (ret != Location::LocationErrCode::ERRCODE_SUCCESS) {
        ZLOGE("Failed to start passive locating, ret:%{public}d", ret);
        return NativePreferences::INTERNAL_EXCEPTION;
    }

    // The state is installed only after the locator has been started.
    std::lock_guard<std::mutex> lock(mutex_);
    passiveCallback_ = callback;
    isSubscribed_.store(true);
    return NativePreferences::RUN_OK;
}

int32_t NavigationPassiveLocationHandler::UnsubscribePassiveLocation()
{
    ZLOGI("UnsubscribePassiveLocation enter.");
    sptr<Location::ILocatorCallback> callback { nullptr };
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!isSubscribed_.load()) {
            ZLOGI("Passive location has not been subscribed.");
            return NativePreferences::RUN_OK;
        }
        callback = passiveCallback_;
        if (callback == nullptr) {
            isSubscribed_.store(false);
            ZLOGI("The callback is null, does't need to unsubscribed.");
            return NativePreferences::RUN_OK;
        }
    }
    // StopLocatingV9 calls the locator service synchronously, stop it without the handler lock. The state
    // is kept until it returns so that a failure keeps the passive location subscribed.
    int32_t ret = DoUnsubscribePassiveLocation(callback);
    // The event is reported outside the handler lock, the write may block.
    if (ret != NativePreferences::RUN_OK) {
        RADAR_REPORT(CLIENT_REQUEST, PASSIVE_LOCATION_UNSUBSCRIBE, RES_FAILED, "ERROR_CODE",
            PASSIVE_LOCATION_UNSUBSCRIBE_FAILED);
        return ret;
    }
    {
        std::lock_guard<std::mutex> lock(mutex_);
        passiveCallback_ = nullptr;
        isSubscribed_.store(false);
    }
    ZLOGI("UnsubscribePassiveLocation exit.");
    return NativePreferences::RUN_OK;
}

int32_t NavigationPassiveLocationHandler::DoUnsubscribePassiveLocation(
    sptr<Location::ILocatorCallback> &callback)
{
    auto locator = Location::LocatorImpl::GetInstance();
    if (locator == nullptr) {
        ZLOGE("Failed to get location instance.");
        return NativePreferences::INTERNAL_EXCEPTION;
    }

    int32_t ret = locator->StopLocatingV9(callback);
    if (ret != Location::LocationErrCode::ERRCODE_SUCCESS) {
        ZLOGE("Failed to stop passive locating, ret:%{public}d", ret);
        return NativePreferences::INTERNAL_EXCEPTION;
    }
    return NativePreferences::RUN_OK;
}

void NavigationPassiveLocationHandler::AddWaypoints(const Waypoint &waypoint)
{
    std::lock_guard<std::mutex> lock(waypointsMutex_);
    waypoints_.push_back(waypoint);
    if (waypoints_.size() > MAX_COLLECTED_WAYPOINT_COUNT) {
        // The first waypoint is the trip start and the last one is the trip end, so only the oldest
        // middle waypoint is dropped.
        waypoints_.erase(waypoints_.begin() + 1);
        ZLOGW("The collected waypoints exceed %{public}zu, drop the oldest middle waypoint.",
            MAX_COLLECTED_WAYPOINT_COUNT);
    }
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
        case Location::ILocatorCallback::RECEIVE_LOCATION_INFO_EVENT: {
            std::unique_ptr<Location::Location> location =
                Location::Location::UnmarshallingMakeUnique(data);
            OnLocationReport(location);
            break;
        }
        case Location::ILocatorCallback::RECEIVE_ERROR_INFO_EVENT: {
            int32_t errorCode = data.ReadInt32();
            OnErrorReport(errorCode);
            break;
        }
        case Location::ILocatorCallback::RECEIVE_LOCATION_STATUS_EVENT: {
            int32_t status = data.ReadInt32();
            OnLocatingStatusChange(status);
            break;
        }
        default: {
            break;
        }
    }
    return NativePreferences::RUN_OK;
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

    NativePreferences::LocationPoint reportedPoint = { location->GetLatitude(), location->GetLongitude() };
    HandlePassiveLocation(reportedPoint);
}

void PassiveLocatingCallback::OnErrorReport(const int errorCode)
{
    ZLOGW("PassiveLocatingCallback report error, errorCode: %{public}d", errorCode);
}

void PassiveLocatingCallback::HandlePassiveLocation(const NativePreferences::LocationPoint &point)
{
    ZLOGI("HandlePassiveLocation enter.");
    if (!NavigationLiveViewMonitor::GetInstance().HasActiveNavigation()) {
        ZLOGD("There is no navigation in progress, ignore the passive location.");
        return;
    }
    double distanceFromHome = 0.0;
    double distanceFromCompany = 0.0;
    if (!NavigationCommonUtil::GetDistance(point, NavigationLiveViewMonitor::GetInstance().GetHomePoint(),
        distanceFromHome) || !NavigationCommonUtil::GetDistance(point,
        NavigationLiveViewMonitor::GetInstance().GetCompanyPoint(), distanceFromCompany)) {
        ZLOGE("Failed to get the distance from current location to home or company.");
        return;
    }
    if (distanceFromHome >= DEFAULT_MAX_WAYPOINT_COLLECT_DISTANCE &&
        distanceFromCompany >= DEFAULT_MAX_WAYPOINT_COLLECT_DISTANCE) {
        ZLOGE("The distance from current location to home and company all are greater than %{public}f, "
            "the location data is invalid.", DEFAULT_MAX_WAYPOINT_COLLECT_DISTANCE);
        return;
    }
    int64_t timestamp = NavigationCommonUtil::GetNowSecondTimestamp();
    NavigationPassiveLocationHandler::GetInstance().AddWaypoints(Waypoint::FromLocationPoint(point, timestamp));
}
} // End of namespace DataFabricAddress
} // End of namespace OHOS
