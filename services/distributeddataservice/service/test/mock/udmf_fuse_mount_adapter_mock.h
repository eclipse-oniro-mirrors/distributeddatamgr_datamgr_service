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

#ifndef UDMF_FUSE_MOUNT_ADAPTER_MOCK_H
#define UDMF_FUSE_MOUNT_ADAPTER_MOCK_H

#include <cerrno>
#include <cstdint>
#include <string>

namespace OHOS::UDMF {
struct UdmfFuseMountAdapterMock {
    static void Reset()
    {
        mountStatus = -ENOSYS;
        unmountStatus = 0;
        mounts = 0;
        unmounts = 0;
        lastMountPoint.clear();
        lastUnmountPoint.clear();
    }

    inline static int32_t mountStatus = -ENOSYS;
    inline static int32_t unmountStatus = 0;
    inline static uint32_t mounts = 0;
    inline static uint32_t unmounts = 0;
    inline static std::string lastMountPoint;
    inline static std::string lastUnmountPoint;
};
} // namespace OHOS::UDMF
#endif // UDMF_FUSE_MOUNT_ADAPTER_MOCK_H
