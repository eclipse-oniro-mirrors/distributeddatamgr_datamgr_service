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

#include "datashareserviceimpl_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <map>
#include <string>
#include <vector>

#include "data_share_service_impl.h"

using namespace OHOS::DataShare;

namespace OHOS {
// Upper bound of consumed random-length strings, keeps a single input cheap.
constexpr size_t MAX_TEXT_LENGTH = 64;
// AccountStatus enum value count, spans all OnUserChange switch cases.
constexpr uint8_t ACCOUNT_STATUS_COUNT = 8;
// Bundle name pool size used by the app lifecycle interfaces.
constexpr size_t BUNDLE_NAME_POOL_SIZE = 2;
// Value count of the dump params map.
constexpr size_t DUMP_PARAM_COUNT = 2;

// Semantic bundle name pool: the settings bundle exercises the
// settingsDataTokenIdCache_ erase/lookup branch of OnAppUninstall, the
// generic bundle covers the plain path.
constexpr const char *BUNDLE_NAME_POOL[] = {
    "com.ohos.settingsdata",
    "com.example.app",
};

// Dispatch targets of the entry switch, indexed by the first consumed byte.
// OnBind is intentionally not fuzzed here: it initializes KvDBDelegate in the
// distributeddata service data directory, which aborts in a fuzz process that
// lacks the SA process context and directory permission.
enum FuzzTarget : uint8_t {
    FUZZ_ON_USER_CHANGE = 0,
    FUZZ_ON_INITIALIZE,
    FUZZ_ON_APP_UNINSTALL,
    FUZZ_ON_APP_UPDATE,
    FUZZ_ON_APP_EXIT,
    FUZZ_GET_CONNECTION_INTERFACE_INFO,
    FUZZ_DUMP_DATA_SHARE_SERVICE_INFO,
    FUZZ_STATIC_ON_APP_UNINSTALL,
    FUZZ_STATIC_ON_APP_UPDATE,
    FUZZ_STATIC_ON_CLEAR_APP_STORAGE,
};

// Target interface count of this fuzzer, used by the entry switch.
constexpr size_t TARGET_SIZE = 10;

std::string ConsumeBundleNameFromPool(FuzzedDataProvider &fdp)
{
    return BUNDLE_NAME_POOL[fdp.ConsumeIntegral<uint8_t>() % BUNDLE_NAME_POOL_SIZE];
}

// code spans the whole AccountStatus enum (uint8_t), covering the
// DEVICE_ACCOUNT_DELETE / DEVICE_ACCOUNT_STOPPING / DEVICE_ACCOUNT_STOPPED
// cases and the default case of OnUserChange.
void OnUserChangeFuzz(FuzzedDataProvider &fdp)
{
    std::shared_ptr<DataShareServiceImpl> dataShareServiceImpl = std::make_shared<DataShareServiceImpl>();
    uint32_t code = fdp.ConsumeIntegral<uint8_t>() % ACCOUNT_STATUS_COUNT;
    std::string user = fdp.ConsumeRandomLengthString(MAX_TEXT_LENGTH);
    std::string account = fdp.ConsumeRandomLengthString(MAX_TEXT_LENGTH);
    dataShareServiceImpl->OnUserChange(code, user, account);
}

// OnInitialize drives RegisterDataShareServiceInfo and RegisterHandler.
// UpdateLaunchInfo is a static interface of the same lifecycle domain and
// OnConnectDone is the follow-up notification of the bind lifecycle; both are
// driven by dedicated input bytes.
void OnInitializeFuzz(FuzzedDataProvider &fdp)
{
    std::shared_ptr<DataShareServiceImpl> dataShareServiceImpl = std::make_shared<DataShareServiceImpl>();
    dataShareServiceImpl->OnInitialize();
    if (fdp.ConsumeBool()) {
        DataShareServiceImpl::UpdateLaunchInfo();
    }
    if (fdp.ConsumeBool()) {
        dataShareServiceImpl->OnConnectDone();
    }
}

void OnAppUninstallFuzz(FuzzedDataProvider &fdp)
{
    std::shared_ptr<DataShareServiceImpl> dataShareServiceImpl = std::make_shared<DataShareServiceImpl>();
    std::string bundleName = ConsumeBundleNameFromPool(fdp);
    int32_t user = fdp.ConsumeIntegral<int32_t>();
    int32_t index = fdp.ConsumeIntegral<int32_t>();
    dataShareServiceImpl->OnAppUninstall(bundleName, user, index);
}

void OnAppUpdateFuzz(FuzzedDataProvider &fdp)
{
    std::shared_ptr<DataShareServiceImpl> dataShareServiceImpl = std::make_shared<DataShareServiceImpl>();
    std::string bundleName = ConsumeBundleNameFromPool(fdp);
    int32_t user = fdp.ConsumeIntegral<int32_t>();
    int32_t index = fdp.ConsumeIntegral<int32_t>();
    dataShareServiceImpl->OnAppUpdate(bundleName, user, index);
}

void OnAppExitFuzz(FuzzedDataProvider &fdp)
{
    std::shared_ptr<DataShareServiceImpl> dataShareServiceImpl = std::make_shared<DataShareServiceImpl>();
    pid_t uid = fdp.ConsumeIntegral<int32_t>();
    pid_t pid = fdp.ConsumeIntegral<int32_t>();
    uint32_t tokenId = fdp.ConsumeIntegral<uint32_t>();
    std::string bundleName = ConsumeBundleNameFromPool(fdp);
    dataShareServiceImpl->OnAppExit(uid, pid, tokenId, bundleName);
}

void GetConnectionInterfaceInfoFuzz(FuzzedDataProvider &fdp)
{
    std::shared_ptr<DataShareServiceImpl> dataShareServiceImpl = std::make_shared<DataShareServiceImpl>();
    int32_t saId = fdp.ConsumeIntegral<int32_t>();
    uint32_t waitTime = fdp.ConsumeIntegral<uint32_t>();
    dataShareServiceImpl->GetConnectionInterfaceInfo(saId, waitTime);
}

void DumpDataShareServiceInfoFuzz(FuzzedDataProvider &fdp)
{
    int fd = fdp.ConsumeIntegral<int>();
    std::map<std::string, std::vector<std::string>> params;
    for (size_t i = 0; i < DUMP_PARAM_COUNT; i++) {
        std::string key = fdp.ConsumeRandomLengthString(MAX_TEXT_LENGTH);
        std::vector<std::string> values;
        values.push_back(fdp.ConsumeRandomLengthString(MAX_TEXT_LENGTH));
        params[key] = values;
    }
    DataShareServiceImpl::DumpDataShareServiceInfo(fd, params);
}

// DataShareStatic is the StaticActs callback set of the data_share feature.
void DataShareStaticOnAppUninstallFuzz(FuzzedDataProvider &fdp)
{
    DataShareServiceImpl::DataShareStatic dataShareStatic;
    std::string bundleName = ConsumeBundleNameFromPool(fdp);
    int32_t user = fdp.ConsumeIntegral<int32_t>();
    int32_t index = fdp.ConsumeIntegral<int32_t>();
    dataShareStatic.OnAppUninstall(bundleName, user, index);
}

void DataShareStaticOnAppUpdateFuzz(FuzzedDataProvider &fdp)
{
    DataShareServiceImpl::DataShareStatic dataShareStatic;
    std::string bundleName = ConsumeBundleNameFromPool(fdp);
    int32_t user = fdp.ConsumeIntegral<int32_t>();
    int32_t index = fdp.ConsumeIntegral<int32_t>();
    dataShareStatic.OnAppUpdate(bundleName, user, index);
}

void DataShareStaticOnClearAppStorageFuzz(FuzzedDataProvider &fdp)
{
    DataShareServiceImpl::DataShareStatic dataShareStatic;
    std::string bundleName = ConsumeBundleNameFromPool(fdp);
    int32_t user = fdp.ConsumeIntegral<int32_t>();
    int32_t index = fdp.ConsumeIntegral<int32_t>();
    uint32_t tokenId = fdp.ConsumeIntegral<uint32_t>();
    dataShareStatic.OnClearAppStorage(bundleName, user, index, tokenId);
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (data == nullptr) {
        return 0;
    }
    FuzzedDataProvider fdp(data, size);
    uint8_t target = fdp.ConsumeIntegral<uint8_t>() % OHOS::TARGET_SIZE;
    switch (target) {
        case OHOS::FUZZ_ON_USER_CHANGE:
            OHOS::OnUserChangeFuzz(fdp);
            break;
        case OHOS::FUZZ_ON_INITIALIZE:
            OHOS::OnInitializeFuzz(fdp);
            break;
        case OHOS::FUZZ_ON_APP_UNINSTALL:
            OHOS::OnAppUninstallFuzz(fdp);
            break;
        case OHOS::FUZZ_ON_APP_UPDATE:
            OHOS::OnAppUpdateFuzz(fdp);
            break;
        case OHOS::FUZZ_ON_APP_EXIT:
            OHOS::OnAppExitFuzz(fdp);
            break;
        case OHOS::FUZZ_GET_CONNECTION_INTERFACE_INFO:
            OHOS::GetConnectionInterfaceInfoFuzz(fdp);
            break;
        case OHOS::FUZZ_DUMP_DATA_SHARE_SERVICE_INFO:
            OHOS::DumpDataShareServiceInfoFuzz(fdp);
            break;
        case OHOS::FUZZ_STATIC_ON_APP_UNINSTALL:
            OHOS::DataShareStaticOnAppUninstallFuzz(fdp);
            break;
        case OHOS::FUZZ_STATIC_ON_APP_UPDATE:
            OHOS::DataShareStaticOnAppUpdateFuzz(fdp);
            break;
        default:
            OHOS::DataShareStaticOnClearAppStorageFuzz(fdp);
            break;
    }
    return 0;
}
