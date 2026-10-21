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

#ifndef DATA_FABRIC_ADDRESS_CALLBACK_PROXY_H
#define DATA_FABRIC_ADDRESS_CALLBACK_PROXY_H

#include "data_fabric_address_callback.h"
#include "data_fabric_address_types.h"
#include "iremote_proxy.h"
#include <nocopyable.h>

namespace OHOS {
namespace DataFabricAddress {

class DataFabricAddressCallbackProxy : public IRemoteProxy<NativePreferences::IDataFabricAddressCallback> {
public:
    explicit DataFabricAddressCallbackProxy(const sptr<IRemoteObject>& impl)
        : IRemoteProxy<NativePreferences::IDataFabricAddressCallback>(impl) {}
    ~DataFabricAddressCallbackProxy() = default;
    DISALLOW_COPY_AND_MOVE(DataFabricAddressCallbackProxy);

    void OnDataFabricAddressChanged(const NativePreferences::DataProcessingResponse& response) override;
private:
    static inline BrokerDelegator<DataFabricAddressCallbackProxy> delegator_;
};
} // End of namespace DataFabricAddress
} // End of namespace OHOS
#endif // DATA_FABRIC_ADDRESS_CALLBACK_PROXY_H
