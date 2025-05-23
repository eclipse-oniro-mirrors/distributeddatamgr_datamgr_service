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
#include "feature/static_acts.h"
namespace OHOS::DistributedData {
StaticActs::~StaticActs()
{
}

int32_t StaticActs::OnAppUninstall(const std::string &bundleName, int32_t user, int32_t index)
{
    return E_OK;
}

int32_t StaticActs::OnAppUpdate(const std::string &bundleName, int32_t user, int32_t index)
{
    return E_OK;
}

int32_t StaticActs::OnAppInstall(const std::string &bundleName, int32_t user, int32_t index)
{
    return E_OK;
}

int32_t StaticActs::OnClearAppStorage(const std::string &bundleName, int32_t user, int32_t index, int32_t tokenId)
{
    return E_OK;
}

void StaticActs::SetThreadPool(std::shared_ptr<ExecutorPool> executors)
{
    executors_ = executors;
}

void StaticActs::Execute(Task task)
{
    auto executor = executors_;
    if (executor == nullptr) {
        return;
    }
    executor->Execute(std::move(task));
}
}
