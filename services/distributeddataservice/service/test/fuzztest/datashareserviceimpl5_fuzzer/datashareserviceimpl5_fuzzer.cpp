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

#include "datashareserviceimpl5_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <string>

#include "data_share_service_impl.h"
#include "ipc_skeleton.h"

using namespace OHOS::DataShare;

namespace OHOS {
// Executor pool size for DataShareServiceImpl::OnBind, aligned with the
// existing datashareservicestub fuzzers.
constexpr size_t EXECUTOR_NUM_MAX = 12;
constexpr size_t EXECUTOR_NUM_MIN = 5;

// Target interface count of this fuzzer, used by the entry switch.
constexpr size_t TARGET_SIZE = 3;

// code spans the whole AccountStatus enum (uint8_t), covering the
// DEVICE_ACCOUNT_DELETE / DEVICE_ACCOUNT_STOPPING / DEVICE_ACCOUNT_STOPPED
// cases and the default case of OnUserChange.
void OnUserChangeFuzz(FuzzedDataProvider &fdp)
{
    std::shared_ptr<DataShareServiceImpl> dataShareServiceImpl = std::make_shared<DataShareServiceImpl>();
    uint32_t code = fdp.ConsumeIntegral<uint8_t>() % 8; // AccountStatus has 8 values
    std::string user = fdp.ConsumeRandomLengthString(64);
    std::string account = fdp.ConsumeRandomLengthString(64);
    dataShareServiceImpl->OnUserChange(code, user, account);
}

// OnBind initializes the static binderInfo_ (executors) and drives the
// subscription/registration chain: SubscribeCommonEvent, SubscribeTimeChanged,
// SubscribeChange, SubscribeListen and SetCriticalTask. OnConnectDone is the
// natural follow-up notification of the bind lifecycle.
void OnBindFuzz(FuzzedDataProvider &fdp)
{
    std::shared_ptr<DataShareServiceImpl> dataShareServiceImpl = std::make_shared<DataShareServiceImpl>();
    std::shared_ptr<ExecutorPool> executor = std::make_shared<ExecutorPool>(EXECUTOR_NUM_MAX, EXECUTOR_NUM_MIN);
    DataShareServiceImpl::BindInfo bindInfo = { "datashareserviceimpl5_fuzzer",
        static_cast<uint32_t>(IPCSkeleton::GetSelfTokenID()), std::move(executor) };
    dataShareServiceImpl->OnBind(bindInfo);
    if (fdp.ConsumeBool()) {
        dataShareServiceImpl->OnConnectDone();
    }
}

// OnInitialize drives RegisterDataShareServiceInfo and RegisterHandler.
// UpdateLaunchInfo is a static interface of the same lifecycle domain and is
// driven by a dedicated input byte.
void OnInitializeFuzz(FuzzedDataProvider &fdp)
{
    std::shared_ptr<DataShareServiceImpl> dataShareServiceImpl = std::make_shared<DataShareServiceImpl>();
    dataShareServiceImpl->OnInitialize();
    if (fdp.ConsumeBool()) {
        DataShareServiceImpl::UpdateLaunchInfo();
    }
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
        case 0:
            OHOS::OnUserChangeFuzz(fdp);
            break;
        case 1:
            OHOS::OnBindFuzz(fdp);
            break;
        default:
            OHOS::OnInitializeFuzz(fdp);
            break;
    }
    return 0;
}
