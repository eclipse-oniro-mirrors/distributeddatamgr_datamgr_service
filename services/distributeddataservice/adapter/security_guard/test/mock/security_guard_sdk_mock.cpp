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

#include "security_guard_sdk_mock.h"

namespace OHOS::DistributedData {
SecurityGuardSdkMock *SecurityGuardSdkMock::instance = nullptr;
}

namespace OHOS::Security::SecurityGuard {
using OHOS::DistributedData::SecurityGuardSdkMock;
// This fixture mocks SDK sessions and never serializes their DTOs.
// Define the Parcelable key methods locally so SDK symbol trimming cannot break
// the test link. Reject any accidental attempt to use this mock for transport.
bool AuthClientInfo::Marshalling(Parcel &) const
{
    return false;
}

bool AuthClientStatus::Marshalling(Parcel &) const
{
    return false;
}

bool AuthResult::Marshalling(Parcel &) const
{
    return false;
}

bool ClientAuthResult::Marshalling(Parcel &) const
{
    return false;
}

AuthProviderSubscribeClient::AuthProviderSubscribeClient(ConstructTag)
{
}
AuthProviderSubscribeClient::~AuthProviderSubscribeClient() = default;

int32_t AuthProviderSubscribeClient::CreateProvider(AuthProviderCallback callback, const std::string &serviceId,
    std::shared_ptr<AuthProviderSubscribeClient> &provider)
{
    auto &mock = *SecurityGuardSdkMock::instance;
    if (!mock.returnNull) {
        provider = std::make_shared<AuthProviderSubscribeClient>(ConstructTag{});
    }
    return mock.Create(std::move(callback), serviceId);
}

int32_t AuthProviderSubscribeClient::RequestAuthResult(const AuthEventInfo &event, AuthResultCallback callback)
{
    return SecurityGuardSdkMock::instance->Request(event, std::move(callback));
}

void AuthProviderSubscribeClient::DeleteProvider()
{
    SecurityGuardSdkMock::instance->Delete();
}
} // namespace OHOS::Security::SecurityGuard
