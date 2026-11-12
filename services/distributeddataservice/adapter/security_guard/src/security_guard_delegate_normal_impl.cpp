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

#define LOG_TAG "SecurityGuardProvider"
#include "security_guard_delegate_normal_impl.h"

#include <utility>

#include "auth_provider_subscribe_client.h"
#include "log_print.h"
#include "security_guard_log_limiter.h"

namespace OHOS {
namespace DistributedData {
namespace {
namespace SG = OHOS::Security::SecurityGuard;
using Strategy = SecurityGuardDelegate::Strategy;
SecurityGuardLogLimiter g_logLimiter;

Strategy MapStrategy(SG::AuthStrategy strategy)
{
    switch (strategy) {
        case SG::ALLOW:
            return Strategy::ALLOW;
        case SG::DENY:
            return Strategy::DENY;
        case SG::TIMEOUT:
            return Strategy::TIMEOUT;
        default:
            return Strategy::ERROR;
    }
}

class SecurityGuardProvider final : public SecurityGuardDelegateImpl::Provider {
public:
    explicit SecurityGuardProvider(std::shared_ptr<SG::AuthProviderSubscribeClient> provider)
        : provider_(std::move(provider))
    {
    }
    ~SecurityGuardProvider() override
    {
        SecurityGuardProvider::Stop();
    }
    SecurityGuardDelegate::DispatchStatus Request(
        const SecurityGuardDelegate::Event &input, SecurityGuardDelegate::Completion completion) override
    {
        std::shared_ptr<SG::AuthProviderSubscribeClient> provider;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            provider = provider_;
        }
        if (!provider) {
            return SecurityGuardDelegate::DispatchStatus::UNAVAILABLE;
        }
        SG::AuthEventInfo event(input.eventId, input.version, input.jsonContent);
        std::vector<SG::AuthClientStatus> clientStatus;
        clientStatus.reserve(input.degradedClients.size());
        for (const auto &clientId : input.degradedClients) {
            clientStatus.emplace_back(clientId, true);
        }
        event.SetClientStatus(clientStatus);
        auto status = provider->RequestAuthResult(event, [completion = std::move(completion)](const auto &result) {
            SecurityGuardDelegate::Result response;
            response.mergedStrategy = MapStrategy(result.GetMergedAuthStrategy());
            for (const auto &client : result.GetClientAuthResult()) {
                response.clients.push_back({ client.GetClientId(), MapStrategy(client.GetAuthStrategy()) });
            }
            completion(response);
        });
        if (status != 0) {
            if (auto skipped = g_logLimiter.Take(SecurityGuardLogLimiter::Event::REQUEST_REJECTED)) {
                ZLOGW("request rejected sdkStatus=%{public}d event=%{public}lld bytes=%{public}zu "
                      "degraded=%{public}zu suppressed=%{public}llu",
                    status, static_cast<long long>(input.eventId), input.jsonContent.size(),
                    input.degradedClients.size(), static_cast<unsigned long long>(*skipped));
            }
        }
        return status == 0 ? SecurityGuardDelegate::DispatchStatus::DISPATCHED
                           : SecurityGuardDelegate::DispatchStatus::REJECTED;
    }
    void Stop() override
    {
        std::shared_ptr<SG::AuthProviderSubscribeClient> provider;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            provider = std::move(provider_);
        }
        if (provider) {
            provider->DeleteProvider();
        }
    }

private:
    std::mutex mutex_;
    std::shared_ptr<SG::AuthProviderSubscribeClient> provider_;
};

int32_t CreateSecurityGuardProvider(SecurityGuardDelegateImpl::ClientStatusCallback callback,
    const std::string &serviceId, std::shared_ptr<SecurityGuardDelegateImpl::Provider> &provider)
{
    std::shared_ptr<SG::AuthProviderSubscribeClient> client;
    auto status = SG::AuthProviderSubscribeClient::CreateProvider(
        [callback = std::move(callback)](const auto &clients) {
            std::vector<SecurityGuardDelegateImpl::Subscriber> subscribers;
            subscribers.reserve(clients.size());
            for (const auto &item : clients) {
                subscribers.push_back({ item.GetSubscribedEvents(), MapStrategy(item.GetDefaultTimeoutStrategy()),
                    item.GetDefaultTimeoutMs(), item.GetClientId() });
            }
            callback(subscribers);
        },
        serviceId, client);
    if (status != 0 || !client) {
        if (client) {
            client->DeleteProvider();
        }
        return status != 0 ? status : -1;
    }
    provider = std::make_shared<SecurityGuardProvider>(std::move(client));
    return 0;
}
} // namespace

__attribute__((used)) static bool g_isInit = SecurityGuardDelegateNormalImpl::Init();

SecurityGuardDelegateNormalImpl::SecurityGuardDelegateNormalImpl(TaskDispatcher dispatcher)
    : SecurityGuardDelegateImpl(CreateSecurityGuardProvider, std::move(dispatcher))
{
}

bool SecurityGuardDelegateNormalImpl::Init()
{
    static SecurityGuardDelegateNormalImpl instance;
    static std::once_flag onceFlag;
    std::call_once(onceFlag, [&]() { SecurityGuardDelegate::RegisterSecurityGuardInstance(&instance); });
    return true;
}
} // namespace DistributedData
} // namespace OHOS
