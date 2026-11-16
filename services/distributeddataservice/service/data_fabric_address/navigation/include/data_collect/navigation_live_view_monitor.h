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

#ifndef NAVIGATION_LIVE_VIEW_MONITOR_H
#define NAVIGATION_LIVE_VIEW_MONITOR_H

#include <atomic>
#include <cstdint>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include "data_fabric_address_callback.h"
#include "iremote_stub.h"
#include "message_option.h"
#include "message_parcel.h"
#include "navigation_base_data.h"

namespace OHOS {
namespace DataFabricAddress {
enum class LiveViewEventType : int32_t {
    LIVE_VIEW_START = 0,
    LIVE_VIEW_END,
};

struct LiveViewEvent {
    LiveViewEventType eventType = LiveViewEventType::LIVE_VIEW_START;
    std::string bundleName;
    int32_t notificationId = 0;
    int64_t timestamp;
};

class ILiveViewCallback : public IRemoteBroker {
public:
    enum {
        CMD_ON_LIVE_VIEW_CHANGED = 0,
    };

    virtual void OnLiveViewChanged(const LiveViewEvent &event) = 0;

    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.msdp.ILiveViewCallback");
};

class LiveViewObserverImpl final : public IRemoteStub<ILiveViewCallback> {
public:
    explicit LiveViewObserverImpl() = default;
    ~LiveViewObserverImpl() override = default;

    int OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override;
    void OnLiveViewChanged(const LiveViewEvent &event) override;
    bool HasActiveNavigation();

private:
    void HandleLiveViewStart(const LiveViewEvent &event);
    void HandleLiveViewEnd(const LiveViewEvent &event);
    std::string BuildRecordKey(const std::string &bundleName, int32_t notificationId) const;
    bool ConstructReportResult(int64_t startTimestamp, const std::string &bundleName, std::string &result);
    bool IsReportableTrip(const std::vector<Waypoint> &allWaypoints);
    bool BuildNavigationResult(int64_t startTimestamp, int64_t endTimestamp, const std::string &bundleName,
        const std::vector<Waypoint> &allWaypoints, std::string &result);

    std::mutex mutex_;
    std::map<std::string, int64_t> activeRecords_;
};

class NavigationLiveViewMonitor {
public:
    static NavigationLiveViewMonitor &GetInstance();
    int32_t SubscribeNavigationLiveView(const NativePreferences::LocationPoint &homePoint,
        const NativePreferences::LocationPoint &companyPoint,
        const sptr<NativePreferences::IDataFabricAddressCallback>& callback);
    void UpdateReferenceLocation(const NativePreferences::LocationPoint &homePoint,
        const NativePreferences::LocationPoint &companyPoint);
    int32_t UnsubscribeNavigationLiveView();
    bool HasActiveNavigation();
    void ReportNavigationData(NativePreferences::StatusCode code, const std::string &result);
    NativePreferences::LocationPoint GetHomePoint();
    NativePreferences::LocationPoint GetCompanyPoint();
private:
    NavigationLiveViewMonitor() = default;
    ~NavigationLiveViewMonitor() = default;

    // Called without mutex_ held: the geofence api load and calls may block, the lock only protects the state
    // and is re-acquired after them. The navigation manager serializes the calls, which never report events.
    int32_t DoSubscribeNavigationLiveView(const NativePreferences::LocationPoint &homePoint,
        const NativePreferences::LocationPoint &companyPoint,
        const sptr<NativePreferences::IDataFabricAddressCallback>& callback, int32_t &errorCode);
    int32_t DoUnsubscribeNavigationLiveView();

    std::mutex mutex_;
    std::atomic<bool> isSubscribed_ { false };
    // Set while the geofence unsubscription is in flight, the reports arriving meanwhile are dropped.
    std::atomic<bool> isUnsubscribing_ { false };
    NativePreferences::LocationPoint homePoint_;
    NativePreferences::LocationPoint companyPoint_;
    sptr<LiveViewObserverImpl> observer_ { nullptr };
    sptr<NativePreferences::IDataFabricAddressCallback> callback_ { nullptr };
};
} // End of namespace DataFabricAddress
} // End of namespace OHOS
#endif // NAVIGATION_LIVE_VIEW_MONITOR_H
