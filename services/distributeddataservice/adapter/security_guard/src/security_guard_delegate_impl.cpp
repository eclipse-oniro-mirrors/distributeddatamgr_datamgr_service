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

#define LOG_TAG "SecurityGuardDelegate"
#include "security_guard_delegate_impl.h"

#include <optional>
#include <utility>

#include "log_print.h"
#include "security_guard_log_limiter.h"

namespace OHOS {
namespace DistributedData {
namespace {
SecurityGuardLogLimiter g_logLimiter;
// SDK IPC may remain blocked after the receiver watchdog. Keep its workers bounded.
constexpr uint32_t MAX_ACTIVE_DISPATCHES = 2;

class DispatchCompletion {
public:
    explicit DispatchCompletion(SecurityGuardDelegate::Completion completion) : completion_(std::move(completion))
    {
    }
    void Receive(const SecurityGuardDelegate::Result &result)
    {
        SecurityGuardDelegate::Completion completion;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (completed_ || buffered_) {
                return;
            }
            if (!accepted_) {
                buffered_ = result;
                return;
            }
            completed_ = true;
            completion = std::move(completion_);
        }
        completion(result);
    }
    void Accepted(SecurityGuardDelegate::DispatchStatus status)
    {
        SecurityGuardDelegate::Completion completion;
        SecurityGuardDelegate::Result result;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            accepted_ = true;
            if (status == SecurityGuardDelegate::DispatchStatus::DISPATCHED && !buffered_) {
                return;
            }
            result = buffered_.value_or(SecurityGuardDelegate::Result{});
            result.dispatchStatus = status;
            completed_ = true;
            completion = std::move(completion_);
        }
        completion(result);
    }

private:
    std::mutex mutex_;
    bool accepted_ = false;
    bool completed_ = false;
    std::optional<SecurityGuardDelegate::Result> buffered_;
    SecurityGuardDelegate::Completion completion_;
};

uint64_t FindGeneration(const SecurityGuardDelegate::ClientSnapshot &previous, int64_t eventId,
    const SecurityGuardDelegateImpl::Subscriber &subscriber)
{
    uint64_t generation = 0;
    size_t matches = 0;
    auto it = previous.policies.find(eventId);
    if (it != previous.policies.end() && !subscriber.clientId.empty()) {
        for (const auto &client : it->second) {
            if (client.clientId != subscriber.clientId) {
                continue;
            }
            ++matches;
            if (client.timeoutMs == subscriber.timeoutMs && client.strategy == subscriber.timeoutStrategy) {
                generation = client.generation;
            }
        }
    }
    return matches == 1 && generation != 0 ? generation : previous.version + 1;
}
} // namespace

SecurityGuardDelegateImpl::SecurityGuardDelegateImpl(ProviderFactory factory, TaskDispatcher dispatcher)
    : factory_(std::move(factory)), dispatcher_(std::move(dispatcher))
{
}

SecurityGuardDelegateImpl::~SecurityGuardDelegateImpl()
{
    SecurityGuardDelegateImpl::Stop();
}

void SecurityGuardDelegateImpl::UpdateSnapshot(
    const std::weak_ptr<PolicyStore> &weakStore, const std::vector<Subscriber> &clients)
{
    auto store = weakStore.lock();
    if (!store) {
        return;
    }
    uint64_t version = 0;
    size_t eventCount = 0;
    {
        std::lock_guard<std::mutex> lock(store->mutex);
        if (store->stopped) {
            return;
        }
        ClientSnapshot snapshot;
        snapshot.initialized = true;
        snapshot.version = store->snapshot.version + 1;
        for (const auto &client : clients) {
            for (auto eventId : client.subscribedEvents) {
                snapshot.policies[eventId].push_back({ client.timeoutStrategy, client.timeoutMs, client.clientId,
                    FindGeneration(store->snapshot, eventId, client) });
            }
        }
        version = snapshot.version;
        eventCount = snapshot.policies.size();
        store->snapshot = std::move(snapshot);
    }
    if (auto skipped = g_logLimiter.Take(SecurityGuardLogLimiter::Event::SNAPSHOT)) {
        ZLOGI("subscriptions updated version=%{public}llu clients=%{public}zu events=%{public}zu "
              "suppressed=%{public}llu",
            static_cast<unsigned long long>(version), clients.size(), eventCount,
            static_cast<unsigned long long>(*skipped));
    }
}

SecurityGuardDelegate::Status SecurityGuardDelegateImpl::Start()
{
    auto store = std::make_shared<PolicyStore>();
    std::shared_ptr<Provider> previous;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!serviceAvailable_) {
            return Status::UNAVAILABLE;
        }
        if (state_ != State::INITIAL && state_ != State::FAILED) {
            return state_ == State::READY ? Status::READY : Status::UNAVAILABLE;
        }
        state_ = State::STARTING;
        previous = std::move(provider_);
        {
            std::lock_guard<std::mutex> statusLock(policyStore_->mutex);
            policyStore_->stopped = true;
            store->snapshot.version = policyStore_->snapshot.version + 1;
        }
        policyStore_ = store;
    }
    if (previous) {
        previous->Stop();
    }
    auto onStatus = [weakStore = std::weak_ptr<PolicyStore>(store)](
                        const std::vector<Subscriber> &clients) { UpdateSnapshot(weakStore, clients); };
    std::shared_ptr<Provider> created;
    auto status = factory_ ? factory_(std::move(onStatus), "distributeddata", created) : -1;
    return FinishStart(store, std::move(created), status);
}

SecurityGuardDelegate::Status SecurityGuardDelegateImpl::FinishStart(
    const std::shared_ptr<PolicyStore> &store, std::shared_ptr<Provider> created, int32_t status)
{
    bool ready = false;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (state_ == State::STARTING && policyStore_ == store) {
            ready = status == 0 && created != nullptr;
            state_ = ready ? State::READY : State::FAILED;
            if (ready) {
                provider_ = std::move(created);
            }
        }
    }
    if (ready) {
        if (auto skipped = g_logLimiter.Take(SecurityGuardLogLimiter::Event::PROVIDER_READY)) {
            ZLOGI("provider registered service=distributeddata suppressed=%{public}llu",
                static_cast<unsigned long long>(*skipped));
        }
        return Status::READY;
    }
    {
        std::lock_guard<std::mutex> lock(store->mutex);
        store->stopped = true;
        store->snapshot.initialized = false;
        store->snapshot.policies.clear();
    }
    if (created) {
        created->Stop();
    }
    if (auto skipped = g_logLimiter.Take(SecurityGuardLogLimiter::Event::PROVIDER_FAILED)) {
        ZLOGW("provider registration failed sdkStatus=%{public}d suppressed=%{public}llu", status,
            static_cast<unsigned long long>(*skipped));
    }
    return Status::UNAVAILABLE;
}

bool SecurityGuardDelegateImpl::IsReady() const
{
    std::lock_guard<std::mutex> lock(mutex_);
    return state_ == State::READY;
}

void SecurityGuardDelegateImpl::BindTaskDispatcher(TaskDispatcher dispatcher)
{
    std::lock_guard<std::mutex> lock(mutex_);
    dispatcher_ = std::move(dispatcher);
}

void SecurityGuardDelegateImpl::OnServiceAvailable()
{
    std::lock_guard<std::mutex> lock(mutex_);
    serviceAvailable_ = true;
}

void SecurityGuardDelegateImpl::OnServiceUnavailable()
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (state_ == State::STOPPED) {
        return;
    }
    serviceAvailable_ = false;
    state_ = State::FAILED;
    std::lock_guard<std::mutex> statusLock(policyStore_->mutex);
    policyStore_->stopped = true;
    policyStore_->snapshot.initialized = false;
    policyStore_->snapshot.policies.clear();
    ++policyStore_->snapshot.version;
}

SecurityGuardDelegate::DispatchStatus SecurityGuardDelegateImpl::Request(const Event &event, Completion completion)
{
    if (!completion) {
        return DispatchStatus::REJECTED;
    }
    std::unique_lock<std::mutex> lock(mutex_);
    if (state_ != State::READY || !dispatcher_) {
        return DispatchStatus::UNAVAILABLE;
    }
    if (dispatchCount_->load() >= MAX_ACTIVE_DISPATCHES) {
        return DispatchStatus::BUSY;
    }
    dispatchCount_->fetch_add(1);
    auto permit = std::shared_ptr<void>(nullptr, [count = dispatchCount_](void *) { count->fetch_sub(1); });
    auto guarded = [weak = std::weak_ptr<PolicyStore>(policyStore_), completion](const Result &result) {
        auto store = weak.lock();
        if (!store) {
            return;
        }
        {
            std::lock_guard<std::mutex> statusLock(store->mutex);
            if (store->stopped) {
                return;
            }
        }
        completion(result);
    };
    auto response = std::make_shared<DispatchCompletion>(std::move(guarded));
    auto dispatcher = dispatcher_;
    auto task = [provider = provider_, weak = std::weak_ptr<PolicyStore>(policyStore_), event, response, permit]() {
        auto store = weak.lock();
        if (!store || std::chrono::steady_clock::now() >= event.deadline) {
            return;
        }
        {
            std::lock_guard<std::mutex> statusLock(store->mutex);
            if (store->stopped) {
                return;
            }
        }
        auto status = provider->Request(event, [response](const Result &result) { response->Receive(result); });
        response->Accepted(status);
    };
    lock.unlock();
    return dispatcher(std::move(task)) ? DispatchStatus::DISPATCHED : DispatchStatus::UNAVAILABLE;
}

SecurityGuardDelegate::ClientSnapshot SecurityGuardDelegateImpl::GetClientSnapshot() const
{
    std::shared_ptr<PolicyStore> store;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        store = policyStore_;
    }
    std::lock_guard<std::mutex> lock(store->mutex);
    return store->snapshot;
}

void SecurityGuardDelegateImpl::Stop()
{
    std::shared_ptr<Provider> provider;
    std::shared_ptr<PolicyStore> store;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        store = policyStore_;
        state_ = State::STOPPED;
        provider = std::move(provider_);
    }
    {
        std::lock_guard<std::mutex> lock(store->mutex);
        store->stopped = true;
    }
    if (provider) {
        provider->Stop();
        ZLOGI("provider stopped");
    }
}
} // namespace DistributedData
} // namespace OHOS
