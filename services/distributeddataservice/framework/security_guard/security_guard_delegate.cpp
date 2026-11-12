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

#include "security_guard/security_guard_delegate.h"

namespace OHOS {
namespace DistributedData {
SecurityGuardDelegate *SecurityGuardDelegate::instance_ = nullptr;

SecurityGuardDelegate *SecurityGuardDelegate::GetInstance()
{
    return instance_;
}

bool SecurityGuardDelegate::RegisterSecurityGuardInstance(SecurityGuardDelegate *instance)
{
    if (instance == nullptr || instance_ != nullptr) {
        return false;
    }
    instance_ = instance;
    return true;
}

bool SecurityGuardDelegate::ClientSnapshot::HasSubscribers(int64_t eventId) const
{
    auto it = policies.find(eventId);
    return !initialized || (it != policies.end() && !it->second.empty());
}
} // namespace DistributedData
} // namespace OHOS
