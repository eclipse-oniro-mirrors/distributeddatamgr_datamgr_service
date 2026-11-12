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

#ifndef DATA_FABRIC_ADDRESS_EVENT_DFX_H
#define DATA_FABRIC_ADDRESS_EVENT_DFX_H

#include <cstdint>

#include "hisysevent.h"

namespace OHOS {
namespace DataFabricAddress {
constexpr int32_t DATA_FABRIC_ADDRESS_BIZ_SCENE = 1;

enum TriggerMode : int32_t {
    CLIENT_REQUEST = 1,
    NOTIFICATION_EVENT,
};

enum DataFabricAddressBizStage : int32_t {
    DATA_FABRIC_ADDRESS_SUBSCRIBE = 1,
    DATA_FABRIC_ADDRESS_UNSUBSCRIBE,
    NAVIGATION_SUBSCRIBE,
    NAVIGATION_UNSUBSCRIBE,
    LIVE_VIEW_SUBSCRIBE,
    LIVE_VIEW_UNSUBSCRIBE,
    PASSIVE_LOCATION_SUBSCRIBE,
    PASSIVE_LOCATION_UNSUBSCRIBE,
    NAVIGATION_DATA_REPORT,
    NAVIGATION_DISTANCE_CALCULATE,
};

enum StageRes : int32_t {
    RES_IDLE = 0,
    RES_SUCCESS,
    RES_FAILED,
    RES_PROACTIVECANCELLATION,
    RES_TIMEOUT,
};

enum DataFabricAddressErrorCode : uint16_t {
    COMMUTE_DISTANCE_TOO_SHORT = 1,
    INVALID_SCENARIO_TYPE,
    INVALID_REFERENCE_POINTS_COUNT,
    OBTAIN_REFERENCE_POINTS_FAILED,
    GET_DISTANCE_FAILED,
    SYSTEM_ABILITY_NOT_INITED,
    ADD_CALLBACK_FAILED,
    REMOVE_CALLBACK_FAILED,
    NAVIGATION_SUBSCRIBE_FAILED,
    NAVIGATION_UNSUBSCRIBE_FAILED,
    LIVE_VIEW_SUBSCRIBE_FAILED,
    LIVE_VIEW_UNSUBSCRIBE_FAILED,
    PASSIVE_LOCATION_SUBSCRIBE_FAILED,
    PASSIVE_LOCATION_UNSUBSCRIBE_FAILED,
    REPORT_NAVIGATION_DATA_FAILED,
};

inline constexpr char DOMAIN_NAME[] = "DISTDATAMGR";
constexpr char const *EVENT_NAME { "DATA_FABRIC_ADDRESS_BEHAVIOR" };
constexpr char const *ORGPKGNAME { "distributeddata" };

#define RADAR_REPORT(triMode, bizStage, stageRes, ...) \
    HiSysEventWrite(DOMAIN_NAME, EVENT_NAME, HiviewDFX::HiSysEvent::BEHAVIOR, "ORG_PKG", ORGPKGNAME, \
        "FUNC", __FUNCTION__, "BIZ_SCENE", DATA_FABRIC_ADDRESS_BIZ_SCENE, "BIZ_STAGE", bizStage, "STAGE_RES", \
        stageRes, "TRIGGER_MODE", triMode, ##__VA_ARGS__)
} // End of namespace DataFabricAddress
} // End of namespace OHOS
#endif // DATA_FABRIC_ADDRESS_EVENT_DFX_H
