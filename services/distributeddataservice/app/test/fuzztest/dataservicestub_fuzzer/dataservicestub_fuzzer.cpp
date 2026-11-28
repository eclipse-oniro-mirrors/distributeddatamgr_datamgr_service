/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <fuzzer/FuzzedDataProvider.h>

#include "dataservicestub_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <utility>

#include "ipc_object_stub.h"
#include "kvstore_data_service_stub.h"
#include "message_parcel.h"
#include "securec.h"

using namespace OHOS::DistributedKv;

namespace OHOS {
const std::u16string INTERFACE_TOKEN = u"OHOS.DistributedKv.IKvStoreDataService";
const uint32_t CODE_MIN = 0;
const uint32_t CODE_MAX = 10;

namespace {
/* Minimal stub: verify IPC parcel parsing and isolate the listeners of the real SA. */
class FuzzDataServiceStub : public KvStoreDataServiceStub {
public:
    sptr<IRemoteObject> GetFeatureInterface(const std::string &name) override
    {
        if (name == "FuzzLocalFeature") {
            return sptr<IRemoteObject>(new IPCObjectStub(u"FuzzLocalFeature"));
        }
        return nullptr;
    }

    Status RegisterClientDeathObserver(const AppId &appId, sptr<IRemoteObject> observer,
        const std::string &featureName) override
    {
        return Status::SUCCESS;
    }

    int32_t ClearAppStorage(const std::string &bundleName, int32_t userId, int32_t appIndex,
        int32_t tokenId) override
    {
        return 0;
    }

    int32_t Exit(const std::string &featureName) override
    {
        return 0;
    }

    std::pair<int32_t, std::string> GetSelfBundleName() override
    {
        return { 0, "" };
    }
};
} // namespace

bool OnRemoteRequestFuzz(FuzzedDataProvider &provider)
{
    uint32_t code = provider.ConsumeIntegralInRange<uint32_t>(CODE_MIN, CODE_MAX);
    MessageParcel request;
    request.WriteInterfaceToken(INTERFACE_TOKEN);
    std::vector<uint8_t> remainingData = provider.ConsumeRemainingBytes<uint8_t>();
    request.WriteBuffer(static_cast<void *>(remainingData.data()), remainingData.size());
    request.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    std::shared_ptr<KvStoreDataServiceStub> kvStoreDataServiceStub = std::make_shared<FuzzDataServiceStub>();
    kvStoreDataServiceStub->OnRemoteRequest(code, request, reply, option);
    return true;
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider provider(data, size);
    OHOS::OnRemoteRequestFuzz(provider);
    return 0;
}