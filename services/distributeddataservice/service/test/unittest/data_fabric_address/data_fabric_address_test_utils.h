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

#ifndef DATA_FABRIC_ADDRESS_TEST_UTILS_H
#define DATA_FABRIC_ADDRESS_TEST_UTILS_H

#include <string>

#include "data_fabric_address_callback.h"
#include "iremote_stub.h"

namespace OHOS {
namespace DataFabricAddressTest {

class TestDataFabricAddressCallbackStub : public IRemoteStub<NativePreferences::IDataFabricAddressCallback> {
public:
    TestDataFabricAddressCallbackStub()
        : stableObject_(new IPCObjectStub(NativePreferences::IDataFabricAddressCallback::GetDescriptor()))
    {
    }

    void OnDataFabricAddressChanged(const NativePreferences::DataProcessingResponse &response) override
    {
        lastCode = response.code;
        lastResult = response.result;
    }

    sptr<IRemoteObject> AsObject() override
    {
        return stableObject_;
    }

    NativePreferences::StatusCode lastCode = NativePreferences::StatusCode::FAILURE;
    std::string lastResult;

private:
    sptr<IRemoteObject> stableObject_;
};

inline NativePreferences::DataFabricAddressParams MakeCommuteSubscriptionParams(
    const NativePreferences::LocationPoint &homePoint, const NativePreferences::LocationPoint &companyPoint)
{
    NativePreferences::DataFabricAddressParams params;
    params.scenarioType = NativePreferences::BusinessScenario::SCENARIO_NAVIGATION_COMMUTE;
    params.locationInfo.actionType = NativePreferences::ActionType::SUBSCRIPTION;
    params.locationInfo.points = {
        { NativePreferences::LabelType::HOME, NativePreferences::CoordinateSystemType::WGS84, homePoint },
        { NativePreferences::LabelType::COMPANY, NativePreferences::CoordinateSystemType::WGS84, companyPoint },
    };
    return params;
}

inline NativePreferences::DataFabricAddressParams MakeCommuteUpdateParams(
    const NativePreferences::LocationPoint &homePoint, const NativePreferences::LocationPoint &companyPoint)
{
    NativePreferences::DataFabricAddressParams params;
    params.scenarioType = NativePreferences::BusinessScenario::SCENARIO_NAVIGATION_COMMUTE;
    params.locationInfo.actionType = NativePreferences::ActionType::UPDATE;
    params.locationInfo.points = {
        { NativePreferences::LabelType::HOME, NativePreferences::CoordinateSystemType::WGS84, homePoint },
        { NativePreferences::LabelType::COMPANY, NativePreferences::CoordinateSystemType::WGS84, companyPoint },
    };
    return params;
}

inline NativePreferences::LocationPoint MakeWgs84HomePoint()
{
    return { 31.2304, 121.4737 };
}

inline NativePreferences::LocationPoint MakeWgs84CompanyPoint()
{
    return { 31.2204, 121.4137 };
}
} // End of namespace DataFabricAddressTest
} // End of namespace OHOS
#endif // DATA_FABRIC_ADDRESS_TEST_UTILS_H
