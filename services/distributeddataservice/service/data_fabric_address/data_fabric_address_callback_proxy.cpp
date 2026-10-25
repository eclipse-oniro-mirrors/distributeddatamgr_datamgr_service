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

#include "data_fabric_address_callback_proxy.h"

#include "data_fabric_address_errors.h"
#include <ipc_types.h>
#include "log_print.h"
#include <message_parcel.h>

#undef LOG_TAG
#define LOG_TAG "DataFabricAddressCallbackProxy"

namespace OHOS {
namespace DataFabricAddress {
using namespace DistributedData;

void DataFabricAddressCallbackProxy::OnDataFabricAddressChanged(
    const NativePreferences::DataProcessingResponse& response)
{
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        ZLOGE("Failed to create remote object.");
        return;
    }

    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!data.WriteInterfaceToken(DataFabricAddressCallbackProxy::GetDescriptor())) {
        ZLOGE("Write descriptor failed.");
        return;
    }
    if (!data.WriteInt32(static_cast<int32_t>(response.code))) {
        ZLOGE("Write reponse code failed.");
        return;
    }
    if (!data.WriteString(response.result)) {
        ZLOGE("Write reponse result failed.");
        return;
    }
    int ret = remote->SendRequest(static_cast<int>(IDataFabricAddressCallback::CMD_DATA_CHANGED),
        data, reply, option);
    if (ret != NativePreferences::RUN_OK) {
        ZLOGE("Send ipc request failed, ret=%{public}d", ret);
        return;
    }
}
} // End of namespace DataFabricAddress
} // End of namespace OHOS