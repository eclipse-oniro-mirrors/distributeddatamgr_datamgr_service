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

#ifndef SECURITY_GUARD_SDK_MOCK_H
#define SECURITY_GUARD_SDK_MOCK_H

#include <gmock/gmock.h>

#include "auth_provider_subscribe_client.h"

namespace OHOS::DistributedData {
namespace SG = OHOS::Security::SecurityGuard;
class SecurityGuardSdkMock {
public:
    static SecurityGuardSdkMock *instance;
    bool returnNull = false;
    MOCK_METHOD(int32_t, Create, (SG::AuthProviderCallback, const std::string &));
    MOCK_METHOD(int32_t, Request, (const SG::AuthEventInfo &, SG::AuthResultCallback));
    MOCK_METHOD(void, Delete, ());
};
} // namespace OHOS::DistributedData
#endif
