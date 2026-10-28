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

#include "udmf_fuse_mount_adapter.h"

#include <cerrno>

namespace OHOS::UDMF {
int32_t UdmfFuseMountAdapter::Mount(int32_t userId, const std::string &mountPoint, int &fuseFd)
{
    (void)userId;
    (void)mountPoint;
    fuseFd = -1;
    return -ENOSYS;
}

int32_t UdmfFuseMountAdapter::Unmount(int32_t userId, const std::string &mountPoint)
{
    (void)userId;
    (void)mountPoint;
    return 0;
}
} // namespace OHOS::UDMF
