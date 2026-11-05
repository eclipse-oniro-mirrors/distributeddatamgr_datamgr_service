/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "udmfservicevirtualentryconcurrent_fuzzer.h"

#include "accesstoken_kit.h"
#include "distributeddata_udmf_ipc_interface_code.h"
#include "ipc_object_stub.h"
#include "itypes_util.h"
#include "ipc_skeleton.h"
#include "message_parcel.h"
#include "token_setproc.h"
#include "udmf_service_impl.h"
#include "udmf_types_util.h"
#include "unified_key.h"
#include "virtual_entry.h"

using namespace OHOS::UDMF;

namespace OHOS {
const std::u16string INTERFACE_TOKEN = u"OHOS.UDMF.UdmfService";
constexpr size_t NUM_MIN = 5;
constexpr size_t NUM_MAX = 12;
static constexpr int ID_LEN = 32;
static constexpr int MINIMUM = 48;
static constexpr int MAXIMUM = 121;
static constexpr int USERID = 100;
static constexpr int INSTINDEX = 0;
static constexpr const char *BUNDLENAME = "com.test.demo";
static constexpr uint32_t FUZZ_MAX_DEPTH = 4;
static constexpr uint32_t FUZZ_MAX_CHILDREN = 3;
static std::shared_ptr<UdmfServiceImpl> g_udmfServiceImpl = nullptr;

std::string GenerateFuzzVirtualKey(FuzzedDataProvider &provider)
{
    if (provider.ConsumeBool()) {
        std::vector<uint8_t> groupId(ID_LEN, '0');
        for (size_t i = 0; i < groupId.size(); ++i) {
            groupId[i] = provider.ConsumeIntegralInRange<uint8_t>(MINIMUM, MAXIMUM);
        }
        std::string groupIdStr(groupId.begin(), groupId.end());
        UnifiedKey udKey = UnifiedKey("drag", "com.test.demo", groupIdStr);
        return udKey.GetUnifiedKey();
    }
    return provider.ConsumeRandomLengthString();
}

void WriteFuzzEntryTree(MessageParcel &parcel, FuzzedDataProvider &provider, uint32_t depth)
{
    if (depth >= FUZZ_MAX_DEPTH) {
        return;
    }
    parcel.WriteString(provider.ConsumeRandomLengthString()); // id
    parcel.WriteString(provider.ConsumeRandomLengthString()); // name
    parcel.WriteInt32(provider.ConsumeIntegralInRange<int32_t>(-2, 3)); // type, spans valid bounds
    parcel.WriteInt64(provider.ConsumeIntegral<int64_t>()); // modifyTime
    parcel.WriteInt64(provider.ConsumeIntegral<int64_t>()); // size
    uint32_t childCount = provider.ConsumeIntegralInRange<uint32_t>(0, FUZZ_MAX_CHILDREN);
    parcel.WriteUint32(childCount);
    for (uint32_t index = 0; index < childCount; ++index) {
        WriteFuzzEntryTree(parcel, provider, depth + 1);
    }
}

// Structured IPC fuzz dispatched against the long-lived shared service so the
// REGISTER_VIRTUAL_ENTRY transaction is exercised under concurrent pressure.
void RegisterVirtualEntryRequestFuzz(FuzzedDataProvider &provider)
{
    std::shared_ptr<UdmfServiceStub> udmfServiceStub = g_udmfServiceImpl;
    if (udmfServiceStub == nullptr) {
        return;
    }
    MessageParcel request;
    request.WriteInterfaceToken(INTERFACE_TOKEN);
    request.WriteString(GenerateFuzzVirtualKey(provider));
    request.WriteUint32(provider.ConsumeIntegral<uint32_t>()); // recordIndex
    WriteFuzzEntryTree(request, provider, 0);
    if (provider.ConsumeBool()) {
        sptr<IRemoteObject> providerObj = new IPCObjectStub(u"VirtualEntryFuzzProvider");
        request.WriteRemoteObject(providerObj);
    }
    MessageParcel reply;
    udmfServiceStub->OnRemoteRequest(static_cast<uint32_t>(UdmfServiceInterfaceCode::REGISTER_VIRTUAL_ENTRY),
        request, reply);
}

// Raw IPC fuzz against the shared service to stress ReadVirtualEntry decoding
// with arbitrary truncated payloads under concurrent dispatch.
void RegisterVirtualEntryRawFuzz(FuzzedDataProvider &provider)
{
    std::shared_ptr<UdmfServiceStub> udmfServiceStub = g_udmfServiceImpl;
    if (udmfServiceStub == nullptr) {
        return;
    }
    MessageParcel request;
    request.WriteInterfaceToken(INTERFACE_TOKEN);
    auto raw = provider.ConsumeRemainingBytes<uint8_t>();
    if (!raw.empty()) {
        request.WriteBuffer(raw.data(), raw.size());
    }
    MessageParcel reply;
    udmfServiceStub->OnRemoteRequest(static_cast<uint32_t>(UdmfServiceInterfaceCode::REGISTER_VIRTUAL_ENTRY),
        request, reply);
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    OHOS::g_udmfServiceImpl = std::make_shared<UdmfServiceImpl>();
    OHOS::Security::AccessToken::AccessTokenID tokenId =
        OHOS::Security::AccessToken::AccessTokenKit::GetHapTokenID(OHOS::USERID, OHOS::BUNDLENAME, OHOS::INSTINDEX);
    SetSelfTokenID(tokenId);
    std::shared_ptr<OHOS::ExecutorPool> executor = std::make_shared<OHOS::ExecutorPool>(OHOS::NUM_MAX, OHOS::NUM_MIN);
    OHOS::g_udmfServiceImpl->OnBind(
        { "UdmfServiceVirtualEntryConcurrentFuzzTest", static_cast<uint32_t>(OHOS::IPCSkeleton::GetSelfTokenID()),
        std::move(executor) });
    return 0;
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    FuzzedDataProvider provider(data, size);
    OHOS::RegisterVirtualEntryRequestFuzz(provider);
    OHOS::RegisterVirtualEntryRawFuzz(provider);
    return 0;
}
