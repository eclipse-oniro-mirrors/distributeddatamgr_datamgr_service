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

#ifndef DISTRIBUTEDDATAMGR_SECURITY_GUARD_DELEGATE_IMPL_H
#define DISTRIBUTEDDATAMGR_SECURITY_GUARD_DELEGATE_IMPL_H

#include <atomic>
#include <memory>
#include <mutex>

#include "security_guard/security_guard_delegate.h"

namespace OHOS {
namespace DistributedData {
class SecurityGuardDelegateImpl : public SecurityGuardDelegate {
public:
    struct Subscriber {
        std::vector<int64_t> subscribedEvents;
        Strategy timeoutStrategy = Strategy::DENY;
        int64_t timeoutMs = 0;
        std::string clientId{};
    };
    using ClientStatusCallback = std::function<void(const std::vector<Subscriber> &)>;
    class Provider {
    public:
        virtual ~Provider() = default;
        virtual DispatchStatus Request(const Event &event, Completion completion) = 0;
        virtual void Stop() = 0;
    };
    using ProviderFactory =
        std::function<int32_t(ClientStatusCallback, const std::string &, std::shared_ptr<Provider> &)>;

    explicit SecurityGuardDelegateImpl(ProviderFactory factory, TaskDispatcher dispatcher = {});
    void BindTaskDispatcher(TaskDispatcher dispatcher) override;
    void OnServiceAvailable() override;
    void OnServiceUnavailable() override;
    ~SecurityGuardDelegateImpl() override;
    Status Start() override;
    bool IsReady() const override;
    DispatchStatus Request(const Event &event, Completion completion) override;
    ClientSnapshot GetClientSnapshot() const override;
    void Stop() override;

private:
    enum class State { INITIAL, STARTING, READY, STOPPED, FAILED };
    struct PolicyStore {
        std::mutex mutex;
        bool stopped = false;
        ClientSnapshot snapshot;
    };
    Status FinishStart(const std::shared_ptr<PolicyStore> &store, std::shared_ptr<Provider> created, int32_t status);
    static void UpdateSnapshot(const std::weak_ptr<PolicyStore> &weakStore, const std::vector<Subscriber> &clients);
    ProviderFactory factory_;
    TaskDispatcher dispatcher_;
    std::shared_ptr<std::atomic<uint32_t>> dispatchCount_ = std::make_shared<std::atomic<uint32_t>>(0);
    mutable std::mutex mutex_;
    State state_ = State::INITIAL;
    bool serviceAvailable_ = true;
    std::shared_ptr<PolicyStore> policyStore_ = std::make_shared<PolicyStore>();
    std::shared_ptr<Provider> provider_;
};
} // namespace DistributedData
} // namespace OHOS
#endif // DISTRIBUTEDDATAMGR_SECURITY_GUARD_DELEGATE_IMPL_H
