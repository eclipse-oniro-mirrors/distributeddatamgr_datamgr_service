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

#include "udmfservicevirtualentry_fuzzer.h"
#include "accesstoken_kit.h"
#include "distributeddata_udmf_ipc_interface_code.h"
#include "ipc_object_stub.h"
#include "itypes_util.h"
#include "ipc_skeleton.h"
#include "message_parcel.h"
#include "securec.h"
#include "token_setproc.h"
#include "udmf_service_impl.h"
#include "udmf_types_util.h"
#include "bootstrap.h"
#include "observer_factory.h"
#include "drag_observer.h"
#include "data_handler.h"
#include "delay_data_acquire_container.h"
#include "device_manager_adapter.h"
#include "kvstore_meta_manager.h"
#include "lifecycle_manager.h"
#include "log_print.h"
#include "nativetoken_kit.h"
#include "udmf_notifier_proxy.h"
#include "udmf_service_impl.h"
#include "unified_data_helper.h"
#include "virtual_entry.h"

using namespace OHOS::UDMF;
using namespace OHOS::Security::AccessToken;
using DmAdapter = OHOS::DistributedData::DeviceManagerAdapter;

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

static void GrantPermissionNative()
{
    const char *perms[3] = {
        "ohos.permission.DISTRIBUTED_DATASYNC",
        "ohos.permission.ACCESS_SERVICE_DM",
        "ohos.permission.MONITOR_DEVICE_NETWORK_STATE" // perms[2] is a permission parameter
    };
    TokenInfoParams infoInstance = {
        .dcapsNum = 0,
        .permsNum = 3,
        .aclsNum = 0,
        .dcaps = nullptr,
        .perms = perms,
        .acls = nullptr,
        .processName = "distributed_data_test",
        .aplStr = "system_basic",
    };
    uint64_t tokenId = GetAccessTokenId(&infoInstance);
    SetSelfTokenID(tokenId);
    AccessTokenKit::ReloadNativeTokenInfo();
}

static void SetUpTestCase(void) {}
static void TearDownTestCase(void) {}
static void DeleteTestHapToken();
void SetUp() {}
void TearDown()
{
    DeleteTestHapToken();
}

void AllocTestHapToken()
{
    HapInfoParams info = {
        .userID = USERID,
        .bundleName = BUNDLENAME,
        .instIndex = INSTINDEX,
        .appIDDesc = "ohos.test.demo1"
    };

    HapPolicyParams policy = {
        .apl = APL_NORMAL,
        .domain = "test.domain",
        .permList = {
            {
                .permissionName = "ohos.permission.test",
                .bundleName = BUNDLENAME,
                .grantMode = 1,
                .availableLevel = APL_NORMAL,
                .label = "label",
                .labelId = 1,
                .description = "test1",
                .descriptionId = 1
            }
        },
        .permStateList = {
            {
                .permissionName = "ohos.permission.test",
                .isGeneral = true,
                .resDeviceID = { "local" },
                .grantStatus = { PermissionState::PERMISSION_GRANTED },
                .grantFlags = { 1 }
            }
        }
    };
    auto tokenID = AccessTokenKit::AllocHapToken(info, policy);
    SetSelfTokenID(tokenID.tokenIDEx);
}

std::shared_ptr<UdmfServiceImpl> InitializeEnvironment()
{
    GrantPermissionNative();
    DistributedData::Bootstrap::GetInstance().LoadComponents();
    DistributedData::Bootstrap::GetInstance().LoadDirectory();
    DistributedData::Bootstrap::GetInstance().LoadCheckers();
    auto executors = std::make_shared<OHOS::ExecutorPool>(NUM_MAX, NUM_MIN);
    DmAdapter::GetInstance().Init(executors);
    DistributedKv::KvStoreMetaManager::GetInstance().BindExecutor(executors);
    DistributedKv::KvStoreMetaManager::GetInstance().InitMetaParameter();
    DistributedKv::KvStoreMetaManager::GetInstance().InitMetaListener();
    AllocTestHapToken();
    std::shared_ptr<UdmfServiceImpl> udmfServiceImpl = std::make_shared<UdmfServiceImpl>();
    return udmfServiceImpl;
}

void DeleteTestHapToken()
{
    auto tokenId = AccessTokenKit::GetHapTokenID(USERID, BUNDLENAME, INSTINDEX);
    AccessTokenKit::DeleteToken(tokenId);
}

// Build a fuzzed drag-scenario key. Half the time it is a well-formed drag
// udKey so the request can reach the implementation, the rest is arbitrary to
// exercise the stub NormalizeQueryOption/key validation branches.
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

// Mirror UdmfServiceStub::ReadVirtualEntry parcel layout so the fuzzer can
// generate inputs that cross the IPC boundary and reach the implementation.
void WriteFuzzEntryTree(MessageParcel &parcel, FuzzedDataProvider &provider, uint32_t depth)
{
    if (depth >= FUZZ_MAX_DEPTH) {
        return;
    }
    parcel.WriteString(provider.ConsumeRandomLengthString()); // id
    parcel.WriteString(provider.ConsumeRandomLengthString()); // name
    // Span below and above the valid FILE/DIRECTORY enum to hit rejection paths.
    parcel.WriteInt32(provider.ConsumeIntegralInRange<int32_t>(-2, 3));
    parcel.WriteInt64(provider.ConsumeIntegral<int64_t>()); // modifyTime
    parcel.WriteInt64(provider.ConsumeIntegral<int64_t>()); // size, sometimes negative
    uint32_t childCount = provider.ConsumeIntegralInRange<uint32_t>(0, FUZZ_MAX_CHILDREN);
    parcel.WriteUint32(childCount);
    for (uint32_t index = 0; index < childCount; ++index) {
        WriteFuzzEntryTree(parcel, provider, depth + 1);
    }
}

// Structured IPC fuzz: build the exact OnRegisterVirtualEntry parcel payload
// from fuzz data and dispatch through OnRemoteRequest.
void RegisterVirtualEntryRequestFuzz(FuzzedDataProvider &provider)
{
    std::shared_ptr<UdmfServiceImpl> udmfServiceImpl = InitializeEnvironment();
    std::shared_ptr<ExecutorPool> executor = std::make_shared<ExecutorPool>(NUM_MAX, NUM_MIN);
    udmfServiceImpl->OnBind(
        { "UdmfServiceVirtualEntryFuzzTest", static_cast<uint32_t>(IPCSkeleton::GetSelfTokenID()),
        std::move(executor) });
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
    udmfServiceImpl->OnRemoteRequest(static_cast<uint32_t>(UdmfServiceInterfaceCode::REGISTER_VIRTUAL_ENTRY),
        request, reply);
    udmfServiceImpl->OnBind(
        { "UdmfServiceVirtualEntryFuzzTest", static_cast<uint32_t>(IPCSkeleton::GetSelfTokenID()), nullptr });
    executor = nullptr;
}

// Raw IPC fuzz: feed arbitrary bytes after the interface token to stress the
// stub ReadVirtualEntry/ReadRemoteObject decoding against truncated payloads.
void RegisterVirtualEntryRawFuzz(FuzzedDataProvider &provider)
{
    std::shared_ptr<UdmfServiceImpl> udmfServiceImpl = std::make_shared<UdmfServiceImpl>();
    MessageParcel request;
    request.WriteInterfaceToken(INTERFACE_TOKEN);
    auto raw = provider.ConsumeRemainingBytes<uint8_t>();
    if (!raw.empty()) {
        request.WriteBuffer(raw.data(), raw.size());
    }
    MessageParcel reply;
    udmfServiceImpl->OnRemoteRequest(static_cast<uint32_t>(UdmfServiceInterfaceCode::REGISTER_VIRTUAL_ENTRY),
        request, reply);
}

// Direct implementation fuzz: bypass the stub to exercise RegisterVirtualEntry
// with arbitrary trees and provider handles.
void RegisterVirtualEntryImplFuzz(FuzzedDataProvider &provider)
{
    std::shared_ptr<UdmfServiceImpl> udmfServiceImpl = std::make_shared<UdmfServiceImpl>();
    VirtualEntry entry;
    entry.id = provider.ConsumeRandomLengthString();
    entry.name = provider.ConsumeRandomLengthString();
    int32_t type = provider.ConsumeIntegralInRange<int32_t>(-1, 2);
    entry.type = static_cast<VirtualEntryType>(type);
    entry.modifyTime = provider.ConsumeIntegral<int64_t>();
    entry.size = provider.ConsumeIntegral<int64_t>();
    sptr<IRemoteObject> providerObj = provider.ConsumeBool()
        ? sptr<IRemoteObject>(new IPCObjectStub(u"VirtualEntryFuzzProvider"))
        : nullptr;
    udmfServiceImpl->RegisterVirtualEntry(GenerateFuzzVirtualKey(provider),
        provider.ConsumeIntegral<uint32_t>(), entry, providerObj);
}

// Exercise the virtual-entry retrieve path through RetrieveData so the FUSE
// drag data flow is covered together with the registration IPC.
void RetrieveDataVirtualFuzz(FuzzedDataProvider &provider)
{
    std::shared_ptr<UdmfServiceImpl> udmfServiceImpl = InitializeEnvironment();
    std::vector<uint8_t> groupId(ID_LEN, '0');
    for (size_t i = 0; i < groupId.size(); ++i) {
        groupId[i] = provider.ConsumeIntegralInRange<uint8_t>(MINIMUM, MAXIMUM);
    }
    std::string groupIdStr(groupId.begin(), groupId.end());
    UnifiedKey udKey = UnifiedKey("drag", "com.test.demo", groupIdStr);
    QueryOption query;
    query.key = udKey.GetUnifiedKey();
    query.intention = Intention::UD_INTENTION_DRAG;
    query.tokenId = provider.ConsumeIntegral<uint32_t>();
    UnifiedData unifiedData;
    udmfServiceImpl->RetrieveData(query, unifiedData);
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    OHOS::Security::AccessToken::AccessTokenID tokenId =
        OHOS::Security::AccessToken::AccessTokenKit::GetHapTokenID(OHOS::USERID, OHOS::BUNDLENAME, OHOS::INSTINDEX);
    SetSelfTokenID(tokenId);
    return 0;
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    FuzzedDataProvider provider(data, size);
    OHOS::SetUpTestCase();
    OHOS::RegisterVirtualEntryRequestFuzz(provider);
    OHOS::RegisterVirtualEntryRawFuzz(provider);
    OHOS::RegisterVirtualEntryImplFuzz(provider);
    OHOS::RetrieveDataVirtualFuzz(provider);
    OHOS::TearDownTestCase();
    return 0;
}
