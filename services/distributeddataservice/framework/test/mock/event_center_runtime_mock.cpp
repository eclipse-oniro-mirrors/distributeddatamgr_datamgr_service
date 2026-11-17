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

#include "event_center_runtime_mock.h"

#include <algorithm>

namespace OHOS::DistributedData {
namespace {
thread_local int32_t g_legacyDepth = 0;
thread_local int32_t g_minimumDepth = 0;
thread_local int32_t g_allocationDepth = 0;
thread_local int32_t g_failedAllocations = 0;
thread_local bool g_failNextAllocation = false;
} // namespace

void EventCenterRuntimeMock::Reset()
{
    g_legacyDepth = 0;
    g_minimumDepth = 0;
    g_allocationDepth = 0;
    g_failedAllocations = 0;
    g_failNextAllocation = false;
}

void EventCenterRuntimeMock::SetLegacyMode(bool enabled)
{
    g_legacyDepth += enabled ? 1 : -1;
    g_minimumDepth = std::min(g_minimumDepth, g_legacyDepth);
}

int32_t EventCenterRuntimeMock::GetLegacyDepth()
{
    return g_legacyDepth;
}

int32_t EventCenterRuntimeMock::GetMinimumDepth()
{
    return g_minimumDepth;
}

int32_t EventCenterRuntimeMock::GetAllocationDepth()
{
    return g_allocationDepth;
}

int32_t EventCenterRuntimeMock::GetFailedAllocations()
{
    return g_failedAllocations;
}

void EventCenterRuntimeMock::FailNextAllocation()
{
    g_failNextAllocation = true;
}

bool EventCenterRuntimeMock::OnAllocation()
{
    g_allocationDepth = g_legacyDepth;
    bool fail = g_failNextAllocation;
    g_failedAllocations += fail ? 1 : 0;
    g_failNextAllocation = false;
    return fail;
}
} // namespace OHOS::DistributedData

using OHOS::DistributedData::EventCenterRuntimeMock;

extern "C" void WrapSetLegacyMode(bool enabled)
{
    EventCenterRuntimeMock::SetLegacyMode(enabled);
    RealSetLegacyMode(enabled);
}

extern "C" void *WrapNothrowNew(size_t size, const std::nothrow_t &tag) noexcept
{
    return EventCenterRuntimeMock::OnAllocation() ? nullptr : RealNothrowNew(size, tag);
}
