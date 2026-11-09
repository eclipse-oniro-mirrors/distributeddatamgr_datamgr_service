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

#include "security_guard_delegate_mock.h"

#include "ipc_skeleton.h"
namespace OHOS::DistributedData {
SecurityGuardDelegate *SecurityGuardTestRegistry::instance = nullptr;
SecurityGuardDelegate *SecurityGuardDelegate::GetInstance()
{
    return SecurityGuardTestRegistry::instance;
}
} // namespace OHOS::DistributedData

namespace OHOS {
// Unit-test IPC identity; the real IPC library remains used by the parcel/stub suite.
uint32_t IPCSkeleton::GetCallingTokenID()
{
    return 19;
}
} // namespace OHOS
