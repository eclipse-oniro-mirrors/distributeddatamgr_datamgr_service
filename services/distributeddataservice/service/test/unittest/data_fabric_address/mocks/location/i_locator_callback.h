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

// Unit test shadow of the location SDK "i_locator_callback.h" header.

#ifndef LOCATION_MOCK_I_LOCATOR_CALLBACK_H
#define LOCATION_MOCK_I_LOCATOR_CALLBACK_H

#include <memory>

#include "iremote_broker.h"
#include "location.h"

namespace OHOS {
namespace Location {

class ILocatorCallback : public IRemoteBroker {
public:
    enum {
        RECEIVE_LOCATION_INFO_EVENT = 0,
        RECEIVE_ERROR_INFO_EVENT,
        RECEIVE_LOCATION_STATUS_EVENT,
    };

    virtual void OnLocatingStatusChange(const int status) = 0;
    virtual void OnLocationReport(const std::unique_ptr<Location> &location) = 0;
    virtual void OnErrorReport(const int errorCode) = 0;

    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.location.ILocatorCallback");
};
} // namespace Location
} // namespace OHOS
#endif // LOCATION_MOCK_I_LOCATOR_CALLBACK_H
