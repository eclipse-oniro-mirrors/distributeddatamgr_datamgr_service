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

#include "navigation_live_view_monitor.h"

#include <dlfcn.h>

#include "data_fabric_address_errors.h"
#include "data_fabric_address_event_dfx.h"
#include "log_print.h"
#include "navigation_common_utils.h"
#include "navigation_passive_location_handler.h"

#undef LOG_TAG
#define LOG_TAG "NavigationLiveViewMonitor"

namespace OHOS {
namespace DataFabricAddress {
using namespace DistributedData;
const size_t WAYPOINT_MIN_SIZE = 2;
const size_t WAYPOINT_MAX_SIZE = 64;
const size_t REPORT_MAX_SIZE = 10240;
constexpr double DEFAULT_INVALID_LAT_VALUE = 100.0;
constexpr double DEFAULT_INVALID_LNG_VALUE = 200.0;

namespace {
constexpr const char *GEOFENCE_CLIENT_SO_PATH = "/system/lib64/platformsdk/libgeofence_client.z.so";
constexpr const char *SUBSCRIBE_LIVE_VIEW_FUNC_NAME = "CSubscribeLiveView";
constexpr const char *UNSUBSCRIBE_LIVE_VIEW_FUNC_NAME = "CUnsubscribeLiveView";

using SubscribeLiveViewFunc = int32_t (*)(const sptr<IRemoteObject> &);
using UnsubscribeLiveViewFunc = int32_t (*)();

std::mutex g_dlopenMutex;
void *g_geofenceHandle = nullptr;
SubscribeLiveViewFunc g_subscribeLiveViewFunc = nullptr;
UnsubscribeLiveViewFunc g_unsubscribeLiveViewFunc = nullptr;

int32_t LoadGeofenceLiveViewApi()
{
    std::lock_guard<std::mutex> lock(g_dlopenMutex);
    if (g_geofenceHandle != nullptr) {
        return NativePreferences::RUN_OK;
    }
    g_geofenceHandle = dlopen(GEOFENCE_CLIENT_SO_PATH, RTLD_LAZY);
    if (g_geofenceHandle == nullptr) {
        ZLOGE("dlopen geofence client failed, error:%{public}s", dlerror());
        return NativePreferences::INTERNAL_EXCEPTION;
    }
    g_subscribeLiveViewFunc = reinterpret_cast<SubscribeLiveViewFunc>(
        dlsym(g_geofenceHandle, SUBSCRIBE_LIVE_VIEW_FUNC_NAME));
    g_unsubscribeLiveViewFunc = reinterpret_cast<UnsubscribeLiveViewFunc>(
        dlsym(g_geofenceHandle, UNSUBSCRIBE_LIVE_VIEW_FUNC_NAME));
    if (g_subscribeLiveViewFunc == nullptr || g_unsubscribeLiveViewFunc == nullptr) {
        ZLOGE("dlsym live view api failed, error:%{public}s", dlerror());
        return NativePreferences::INTERNAL_EXCEPTION;
    }
    return NativePreferences::RUN_OK;
}
} // namespace

NavigationLiveViewMonitor &NavigationLiveViewMonitor::GetInstance()
{
    static NavigationLiveViewMonitor instance;
    return instance;
}

int32_t NavigationLiveViewMonitor::SubscribeNavigationLiveView(
    const NativePreferences::LocationPoint &homePoint,
    const NativePreferences::LocationPoint &companyPoint,
    const sptr<NativePreferences::IDataFabricAddressCallback>& callback)
{
    ZLOGI("Enter");
    std::lock_guard<std::mutex> lock(mutex_);
    if (isSubscribed_.load()) {
        ZLOGI("Navigation live view monitor has been subscribed.");
        return NativePreferences::RUN_OK;
    }

    if (callback == nullptr) {
        ZLOGE("The input callback is null.");
        RADAR_REPORT(CLIENT_REQUEST, LIVE_VIEW_SUBSCRIBE, RES_FAILED, "ERROR_CODE", ADD_CALLBACK_FAILED);
        return NativePreferences::INTERNAL_EXCEPTION;
    }

    int32_t ret = LoadGeofenceLiveViewApi();
    if (ret != NativePreferences::RUN_OK) {
        ZLOGE("Load geofence live view api failed, ret:%{public}d", ret);
        RADAR_REPORT(CLIENT_REQUEST, LIVE_VIEW_SUBSCRIBE, RES_FAILED, "ERROR_CODE", LIVE_VIEW_SUBSCRIBE_FAILED);
        return ret;
    }
    observer_ = sptr<LiveViewObserverImpl>(new (std::nothrow) LiveViewObserverImpl());
    if (observer_ == nullptr) {
        ZLOGE("Create live view observer failed.");
        RADAR_REPORT(CLIENT_REQUEST, LIVE_VIEW_SUBSCRIBE, RES_FAILED, "ERROR_CODE", LIVE_VIEW_SUBSCRIBE_FAILED);
        return NativePreferences::INTERNAL_EXCEPTION;
    }

    ret = g_subscribeLiveViewFunc(observer_);
    if (ret != NativePreferences::RUN_OK) {
        ZLOGE("Subscribe live view failed, ret:%{public}d", ret);
        RADAR_REPORT(CLIENT_REQUEST, LIVE_VIEW_SUBSCRIBE, RES_FAILED, "ERROR_CODE", LIVE_VIEW_SUBSCRIBE_FAILED);
        observer_ = nullptr;
        return NativePreferences::INTERNAL_EXCEPTION;
    }

    homePoint_ = homePoint;
    companyPoint_ = companyPoint;
    callback_ = callback;
    isSubscribed_.store(true);
    RADAR_REPORT(CLIENT_REQUEST, LIVE_VIEW_SUBSCRIBE, RES_SUCCESS);
    ZLOGI("SubscribeNavigationLiveView exit.");
    return NativePreferences::RUN_OK;
}

void NavigationLiveViewMonitor::UpdateReferenceLocation(
    const NativePreferences::LocationPoint &homePoint,
    const NativePreferences::LocationPoint &companyPoint)
{
    ZLOGI("Enter");
    std::lock_guard<std::mutex> lock(mutex_);
    homePoint_ = homePoint;
    companyPoint_ = companyPoint;
}

int32_t NavigationLiveViewMonitor::UnsubscribeNavigationLiveView()
{
    ZLOGI("Enter.");
    std::lock_guard<std::mutex> lock(mutex_);
    if (!isSubscribed_.load()) {
        ZLOGI("Navigation live view monitor has not been subscribed.");
        return NativePreferences::RUN_OK;
    }

    if (observer_ == nullptr) {
        isSubscribed_.store(false);
        ZLOGI("The observer_ is null, does't need to unsubscribed.");
        return NativePreferences::RUN_OK;
    }

    int32_t ret = g_unsubscribeLiveViewFunc();
    if (ret != NativePreferences::RUN_OK) {
        ZLOGE("Unsubscribe live view failed, ret:%{public}d", ret);
        RADAR_REPORT(CLIENT_REQUEST, LIVE_VIEW_UNSUBSCRIBE, RES_FAILED, "ERROR_CODE",
            LIVE_VIEW_UNSUBSCRIBE_FAILED);
        return ret;
    }

    homePoint_ = { DEFAULT_INVALID_LAT_VALUE, DEFAULT_INVALID_LNG_VALUE };
    companyPoint_ = { DEFAULT_INVALID_LAT_VALUE, DEFAULT_INVALID_LNG_VALUE };
    observer_ = nullptr;
    callback_ = nullptr;
    isSubscribed_.store(false);
    RADAR_REPORT(CLIENT_REQUEST, LIVE_VIEW_UNSUBSCRIBE, RES_SUCCESS);
    ZLOGI("Exit");
    return NativePreferences::RUN_OK;
}

void NavigationLiveViewMonitor::ReportNavigationData(NativePreferences::StatusCode code, const std::string &result)
{
    ZLOGI("Enter, report code:%{public}d, result:%{public}s", static_cast<int32_t>(code), result.c_str());
    sptr<NativePreferences::IDataFabricAddressCallback> callback = nullptr;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!isSubscribed_.load() || callback_ == nullptr) {
            ZLOGE("Navigation manager has not been subscribed or the callback_ is null.");
            return;
        }
        callback = callback_;
    }
    callback->OnDataFabricAddressChanged({code, result});
    ZLOGI("Exit");
}

NativePreferences::LocationPoint NavigationLiveViewMonitor::GetHomePoint()
{
    std::lock_guard<std::mutex> lock(mutex_);
    return homePoint_;
}

NativePreferences::LocationPoint NavigationLiveViewMonitor::GetCompanyPoint()
{
    std::lock_guard<std::mutex> lock(mutex_);
    return companyPoint_;
}

int LiveViewObserverImpl::OnRemoteRequest(uint32_t code, MessageParcel &data,
    MessageParcel &reply, MessageOption &option)
{
    (void)option;
    ZLOGI("OnRemoteRequest enter, code:%{public}u", code);
    std::u16string remoteDescriptor = data.ReadInterfaceToken();
    if (remoteDescriptor != ILiveViewCallback::GetDescriptor()) {
        ZLOGE("OnRemoteRequest failed, the descriptor is not matched.");
        reply.WriteInt32(ERR_INVALID_STATE);
        return ERR_INVALID_STATE;
    }

    if (code != static<uint32_t>(ILiveViewCallback::CMD_ON_LIVE_VIEW_CHANGED)) {
        ZLOGE("OnRemoteRequest unknown code:%{public}u", code);
        reply.WriteInt32(ERR_UNKNOWN_TRANSACTION);
        return ERR_UNKNOWN_TRANSACTION;
    }

    int32_t validity = 0;
    if (!data.ReadInt32(validity) || validity != 1) {
        ZLOGE("OnRemoteRequest read parcelable flag failed.");
        reply.WriteInt32(ERR_INVALID_DATA);
        return ERR_INVALID_DATA;
    }

    LiveViewEvent event;
    int32_t eventType = 0;
    if (!data.ReadInt32(eventType) || !data.ReadString(event.bundleName) ||
        !data.ReadInt32(event.notificationId) || !data.ReadInt64(event.timestamp)) {
        ZLOGE("OnRemoteRequest read live view event failed.");
        reply.WriteInt32(ERR_INVALID_DATA);
        return ERR_INVALID_DATA;
    }
    event.eventType = static_cast<LiveViewEventType>(eventType);
    OnLiveViewChanged(event);
    reply.WriteInt32(ERR_NONE);
    return ERR_NONE;
}

void LiveViewObserverImpl::OnLiveViewChanged(const LiveViewEvent &event)
{
    ZLOGI("Enter");
    if (!IsTargetNavigationEvent(event)) {
        ZLOGD("OnLiveViewChanged, the event is not target navigation event, notificationId=%{public}d, "
            "bundleName=%{public}s", event.notificationId, event.bundleName.c_str());
        return;
    }
    if (event.eventType == LiveViewEventType::LIVE_VIEW_START) {
        HandleLiveViewStart(event);
    } else {
        HandleLiveViewEnd(event);
    }
    ZLOGI("Exit");
}

bool LiveViewObserverImpl::IsTargetNavigationEvent(const LiveViewEvent &event)
{
    const auto &defaultNavigationBundleNameMap = GetDefaultNavigationBundleNameMap();
    if (defaultNavigationBundleNameMap.find(event.bundleName) == defaultNavigationBundleNameMap.end()) {
        ZLOGI("The event bundle name %{public}s does't match the tartet apps.", event.bundleName.c_str());
        return false;
    }
    return true;
}

void LiveViewObserverImpl::HandleLiveViewStart(const LiveViewEvent &event)
{
    ZLOGI("HandleLiveViewStart enter.");
    std::lock_guard<std::mutex> lock(mutex_);
    std::string recordKey = BuildRecordKey(event.bundleName, event.notificationId);
    if (activeRecords_.find(recordKey) != activeRecords_.end()) {
        ZLOGI("Live view %{public}s has been record.", recordKey.c_str());
        return;
    }

    int64_t timestamp = NavigationCommonUtil::GetNowSecondTimestamp();
    activeRecords_.emplace(recordKey, timestamp);
    ZLOGI("Navigation start, key:%{public}s", recordKey.c_str());
    NavigationPassiveLocationHandler::GetInstance().ClearWaypoints();
}

void LiveViewObserverImpl::HandleLiveViewEnd(const LiveViewEvent &event)
{
    ZLOGI("HandleLiveViewEnd enter.");
    int64_t startTimestamp = 0;
    const std::string recordKey = BuildRecordKey(event.bundleName, event.notificationId);
    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = activeRecords_.find(recordKey);
        if (it == activeRecords_.end()) {
            ZLOGW("Live view %{public}s has not been record.", recordKey.c_str());
            return;
        }
        startTimestamp = it->second;
        activeRecords_.erase(it);
    }

    std::string result;
    if (!ConstructReportResult(startTimestamp, event.bundleName, result)) {
        NavigationLiveViewMonitor::GetInstance().ReportNavigationData(NativePreferences::StatusCode::FAILURE, "");
        RADAR_REPORT(NOTIFICATION_EVENT, NAVIGATION_DATA_REPORT, RES_FAILED, "ERROR_CODE",
            REPORT_NAVIGATION_DATA_FAILED);
        NavigationPassiveLocationHandler::GetInstance().ClearWaypoints();
        return;
    }

    NavigationLiveViewMonitor::GetInstance.ReportNavigationData(NativePreferences::StatusCode::FAILURE, "");
    RADAR_REPORT(NOTIFICATION_EVENT, NAVIGATION_DATA_REPORT, RES_SUCCESS);
    NavigationPassiveLocationHandler::GetInstance().ClearWaypoints();
    ZLOGI("HandleLiveViewEnd exit.");
}

std::string LiveViewObserverImpl::BuildRecordKey(const std::string &bundleName, int32_t notificationId) const
{
    return bundleName + "#" + std::to_string(notificationId);
}

bool LiveViewObserverImpl::ConstructReportResult(int64_t startTimestamp, const std::string &bundleName,
    std::string &result)
{
    int64_t endTimestamp = NavigationCommonUtil::GetNowSecondTimestamp();
    std::vector<Waypoint> allWaypoints;
    NavigationPassiveLocationHandler::GetInstance().ReadWaypoints(allWaypoints);
    if (allWaypoints.size() < WAYPOINT_MIN_SIZE) {
        ZLOGE("The waypoints count can not less than %{public}zu.", WAYPOINT_MIN_SIZE);
        return false;
    }
    Waypoint navigationStartPoint = allWaypoints.front();
    Waypoint navigationEndPoint = allWaypoints.back();

    NativePreferences::LocationPoint endPoint = { navigationEndPoint.latitude, navigationEndPoint.longitude };
    double distanceFromHome = 0.0;
    double distanceFromCompany = 0.0;
    if (!NavigationCommonUtil::GetDistance(endPoint, NavigationLiveViewMonitor::GetInstance().GetHomePoint(),
        distanceFromHome) || !NavigationCommonUtil::GetDistance(endPoint,
        NavigationLiveViewMonitor::GetInstance().GetCompanyPoint(), distanceFromCompany)) {
        ZLOGE("Failed to get the distance from navigation end point to home or company.");
        return false;
    }
    if (distanceFromHome >= DEFAULT_MAX_NAVIGATION_END_DISTANCE &&
        distanceFromCompany >= DEFAULT_MAX_NAVIGATION_END_DISTANCE) {
        ZLOGE("The distance from navigation end point to home and company all are greater than %{public}zu, "
            "the navigation data is invalid.", DEFAULT_MAX_NAVIGATION_END_DISTANCE);
        return false;
    }

    std::vector<Waypoint> waypoints(allWaypoints.begin() + 1, allWaypoints.end() - 1);
    ZLOGI("The source waypoint count=%{public}zu", waypoints.size());
    if (waypoints.size() > WAYPOINT_MAX_SIZE) {
        size_t eraseCount = waypoints.size() - WAYPOINT_MAX_SIZE;
        waypoints.erase(waypoints.begin(), waypoints.begin() + eraseCount);
        ZLOGW("The waypoints count exceeds %{public}zu, the final waypoint count=%{public}zu", WAYPOINT_MAX_SIZE,
            waypoints.size());
    }
    NavigationResult navigationResult = {
        .startTimestamp = startTimestamp,
        .endTimestamp = endTimestamp,
        .startLatitude = navigationStartPoint.latitude,
        .startLongitude = navigationStartPoint.longitude,
        .endLatitude = navigationEndPoint.latitude,
        .endLongitude = navigationEndPoint.longitude,
        .bundleName = bundleName,
        .waypoints = waypoints
    };
    result = navigationResult.ToString();
    if (result.size() > REPORT_MAX_SIZE) {
        ZLOGE("The length of the report data  exceeds the threshold %{public}zu", REPORT_MAX_SIZE);
        return false;
    }
    return true;
}
} // End of namespace DataFabricAddress
} // End of namespace OHOS
