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

#ifndef OHOS_DISTRIBUTED_DATA_EVENT_CENTER_RUNTIME_MOCK_H
#define OHOS_DISTRIBUTED_DATA_EVENT_CENTER_RUNTIME_MOCK_H

#include <cstddef>
#include <cstdint>
#include <new>

namespace OHOS::DistributedData {
class EventCenterRuntimeMock final {
public:
    static void Reset();
    static void SetLegacyMode(bool enabled);
    static int32_t GetLegacyDepth();
    static int32_t GetMinimumDepth();
    static int32_t GetAllocationDepth();
    static int32_t GetFailedAllocations();
    static void FailNextAllocation();
    static bool OnAllocation();
};
} // namespace OHOS::DistributedData

// Linker --wrap entry points are confined to this test executable and still
// call real FFRT. Assembler labels keep linker names separate from C++ names.
extern "C" void RealSetLegacyMode(bool enabled) asm("__real_ffrt_this_task_set_legacy_mode");
extern "C" void WrapSetLegacyMode(bool enabled) asm("__wrap_ffrt_this_task_set_legacy_mode");
#if defined(__LP64__)
extern "C" void *RealNothrowNew(size_t size, const std::nothrow_t &tag) noexcept asm("__real__ZnwmRKSt9nothrow_t");
extern "C" void *WrapNothrowNew(size_t size, const std::nothrow_t &tag) noexcept asm("__wrap__ZnwmRKSt9nothrow_t");
#else
extern "C" void *RealNothrowNew(size_t size, const std::nothrow_t &tag) noexcept asm("__real__ZnwjRKSt9nothrow_t");
extern "C" void *WrapNothrowNew(size_t size, const std::nothrow_t &tag) noexcept asm("__wrap__ZnwjRKSt9nothrow_t");
#endif
#endif // OHOS_DISTRIBUTED_DATA_EVENT_CENTER_RUNTIME_MOCK_H
