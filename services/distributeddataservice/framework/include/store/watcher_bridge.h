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

#ifndef OHOS_DISTRIBUTED_DATA_SERVICES_FRAMEWORK_STORE_WATCHER_BRIDGE_H
#define OHOS_DISTRIBUTED_DATA_SERVICES_FRAMEWORK_STORE_WATCHER_BRIDGE_H

#include <functional>
#include <memory>
#include <set>

#include "store/general_watcher.h"

namespace OHOS::DistributedData {
class API_EXPORT WatcherBridge final : public GeneralWatcher {
public:
    using Watchers = std::set<std::shared_ptr<GeneralWatcher>>;
    using Getter = std::function<Watchers()>;

    // Getter returns a client watcher snapshot with all registry locks released.
    // It must not return this bridge or another forwarding bridge.
    explicit WatcherBridge(Getter getter);
    WatcherBridge(const WatcherBridge &) = delete;
    WatcherBridge &operator=(const WatcherBridge &) = delete;
    WatcherBridge(WatcherBridge &&) = delete;
    WatcherBridge &operator=(WatcherBridge &&) = delete;

    int32_t OnChange(const Origin &origin, const PRIFields &fields, ChangeInfo &&values) override;
    int32_t OnChange(const Origin &origin, const Fields &fields, ChangeData &&values) override;

private:
    const Getter getter_;
};
} // namespace OHOS::DistributedData
#endif // OHOS_DISTRIBUTED_DATA_SERVICES_FRAMEWORK_STORE_WATCHER_BRIDGE_H
