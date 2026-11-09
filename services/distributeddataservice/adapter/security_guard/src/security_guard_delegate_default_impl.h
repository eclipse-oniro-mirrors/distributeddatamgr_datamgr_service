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

#ifndef DISTRIBUTEDDATAMGR_SECURITY_GUARD_DELEGATE_DEFAULT_IMPL_H
#define DISTRIBUTEDDATAMGR_SECURITY_GUARD_DELEGATE_DEFAULT_IMPL_H

#include "security_guard/security_guard_delegate.h"

namespace OHOS {
namespace DistributedData {
class SecurityGuardDelegateDefaultImpl final : public SecurityGuardDelegate {
public:
    Status Start() override;
    bool IsReady() const override;
    DispatchStatus Request(const Event &event, Completion completion) override;
    ClientSnapshot GetClientSnapshot() const override;
    void Stop() override;
    static bool Init();
};
} // namespace DistributedData
} // namespace OHOS
#endif // DISTRIBUTEDDATAMGR_SECURITY_GUARD_DELEGATE_DEFAULT_IMPL_H
