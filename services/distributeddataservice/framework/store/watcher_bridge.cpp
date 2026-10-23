/**
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

#include "store/watcher_bridge.h"

#include <utility>

#include "error/general_error.h"

namespace OHOS::DistributedData {
WatcherBridge::WatcherBridge(Getter getter) : getter_(std::move(getter))
{
}

int32_t WatcherBridge::OnChange(const Origin &origin, const PRIFields &fields, ChangeInfo &&values)
{
    auto watchers = getter_ ? getter_() : Watchers{};
    watchers.erase(nullptr);
    size_t remain = watchers.size();
    for (const auto &watcher : watchers) {
        --remain;
        watcher->OnChange(origin, fields, remain != 0 ? ChangeInfo(values) : std::move(values));
    }
    return GeneralError::E_OK;
}

int32_t WatcherBridge::OnChange(const Origin &origin, const Fields &fields, ChangeData &&values)
{
    auto watchers = getter_ ? getter_() : Watchers{};
    watchers.erase(nullptr);
    size_t remain = watchers.size();
    for (const auto &watcher : watchers) {
        --remain;
        watcher->OnChange(origin, fields, remain != 0 ? ChangeData(values) : std::move(values));
    }
    return GeneralError::E_OK;
}
} // namespace OHOS::DistributedData
