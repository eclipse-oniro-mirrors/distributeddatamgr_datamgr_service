/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "device_manager/device_manager_delegate.h"

namespace OHOS {
namespace DistributedData {
DeviceManagerDelegate *DeviceManagerDelegate::instance_ = nullptr;

bool DeviceManagerDelegate::RegisterInstance(DeviceManagerDelegate *instance)
{
    if (instance_ != nullptr) {
        return false;
    }
    instance_ = instance;
    return true;
}

DeviceManagerDelegate *DeviceManagerDelegate::GetInstance()
{
    return instance_;
}
} // namespace DistributedData
} // namespace OHOS