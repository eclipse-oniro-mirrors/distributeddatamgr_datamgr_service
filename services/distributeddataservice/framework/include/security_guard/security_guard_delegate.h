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

#ifndef DISTRIBUTEDDATAMGR_SECURITY_GUARD_DELEGATE_H
#define DISTRIBUTEDDATAMGR_SECURITY_GUARD_DELEGATE_H

#include <chrono>
#include <cstdint>
#include <functional>
#include <map>
#include <string>
#include <vector>

#include "visibility.h"

namespace OHOS {
namespace DistributedData {
class SecurityGuardDelegate {
public:
    enum class Strategy { ALLOW, DENY, TIMEOUT, ERROR };
    enum class Status { READY, UNAVAILABLE };
    enum class DispatchStatus { DISPATCHED, UNAVAILABLE, REJECTED, BUSY };

    struct Event {
        int64_t eventId = 0;
        std::string version;
        std::string jsonContent;
        std::vector<std::string> degradedClients{};
        std::chrono::steady_clock::time_point deadline = std::chrono::steady_clock::time_point::max();
    };
    struct ClientPolicy {
        Strategy strategy = Strategy::DENY;
        int64_t timeoutMs = 0;
        std::string clientId{};
        // Changes when the subscription is recreated or its timeout policy changes.
        uint64_t generation = 0;
    };
    struct ClientSnapshot {
        bool initialized = false;
        uint64_t version = 0;
        std::map<int64_t, std::vector<ClientPolicy>> policies;
        API_EXPORT bool HasSubscribers(int64_t eventId) const;
    };
    struct ClientResult {
        std::string clientId{};
        Strategy strategy = Strategy::ERROR;
    };
    struct Result {
        Strategy mergedStrategy = Strategy::ERROR;
        std::vector<ClientResult> clients{};
        DispatchStatus dispatchStatus = DispatchStatus::DISPATCHED;
    };
    using Completion = std::function<void(const Result &)>;
    using TaskDispatcher = std::function<bool(std::function<void()>)>;

    API_EXPORT virtual ~SecurityGuardDelegate() = default;
    API_EXPORT virtual Status Start() = 0;
    API_EXPORT virtual void BindTaskDispatcher(TaskDispatcher)
    {
    }
    API_EXPORT virtual void OnServiceAvailable()
    {
    }
    API_EXPORT virtual void OnServiceUnavailable()
    {
    }
    API_EXPORT virtual bool IsReady() const = 0;
    API_EXPORT virtual DispatchStatus Request(const Event &event, Completion completion) = 0;
    API_EXPORT virtual ClientSnapshot GetClientSnapshot() const = 0;
    API_EXPORT virtual void Stop() = 0;
    API_EXPORT static SecurityGuardDelegate *GetInstance();
    // Register the selected adapter during process initialization, before service binding.
    API_EXPORT static bool RegisterSecurityGuardInstance(SecurityGuardDelegate *instance);

private:
    static SecurityGuardDelegate *instance_;
};
} // namespace DistributedData
} // namespace OHOS
#endif // DISTRIBUTEDDATAMGR_SECURITY_GUARD_DELEGATE_H
