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

#include <gtest/gtest.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <chrono>
#include <memory>
#include <vector>

#include "c/ffrt_ipc.h"
#include "eventcenter/event_center.h"
#include "ffrt.h"
#include "mock/event_center_runtime_mock.h"

using namespace testing::ext;
using namespace OHOS::DistributedData;

namespace {
constexpr int32_t FIRST_EVENT = Event::EVT_CUSTOM + 221;
constexpr int32_t SECOND_EVENT = FIRST_EVENT + 1;
constexpr int32_t ROUNDS = 200;
constexpr int32_t WAIT_MICROSECONDS = 100;

struct Trace {
    std::vector<int32_t> callbacks;
    std::vector<int32_t> eventDestruction;
    std::vector<int32_t> handlerDestruction;
    int32_t result = EventCenter::CODE_INVALID_ARGS;
};

class TrackedEvent final : public Event {
public:
    explicit TrackedEvent(std::shared_ptr<Trace> trace) : Event(SECOND_EVENT), trace_(std::move(trace))
    {
    }
    ~TrackedEvent() override
    {
        trace_->eventDestruction.push_back(EventCenterRuntimeMock::GetLegacyDepth());
    }

private:
    std::shared_ptr<Trace> trace_;
};

class HandlerLifetime final {
public:
    explicit HandlerLifetime(std::shared_ptr<Trace> trace) : trace_(std::move(trace))
    {
    }
    ~HandlerLifetime()
    {
        trace_->handlerDestruction.push_back(EventCenterRuntimeMock::GetLegacyDepth());
    }

private:
    std::shared_ptr<Trace> trace_;
};

struct FfrtResult {
    int32_t callbacks = 0;
    int32_t wrongResults = 0;
    int32_t migrations = 0;
    int32_t unprotectedWaits = 0;
    int32_t unbalancedScopes = 0;
    uint64_t taskId = 0;
};

void WaitInScope(const std::shared_ptr<FfrtResult> &result)
{
    auto before = syscall(SYS_gettid);
    result->unprotectedWaits += EventCenterRuntimeMock::GetLegacyDepth() <= 0;
    ffrt::this_task::sleep_for(std::chrono::microseconds(WAIT_MICROSECONDS));
    result->migrations += before != syscall(SYS_gettid);
}

void PostEvents(const std::shared_ptr<FfrtResult> &result)
{
    EventCenterRuntimeMock::Reset();
    result->taskId = ffrt::this_task::get_id();
    for (int32_t round = 0; round < ROUNDS; ++round) {
        result->wrongResults += EventCenter::GetInstance().PostEvent(std::make_unique<Event>(FIRST_EVENT)) !=
                                EventCenter::CODE_SYNC;
        {
            EventCenter::Defer outer;
            {
                EventCenter::Defer inner;
                result->wrongResults += EventCenter::GetInstance().PostEvent(std::make_unique<Event>(FIRST_EVENT)) !=
                                        EventCenter::CODE_ASYNC;
            }
            WaitInScope(result);
        }
        result->unbalancedScopes += EventCenterRuntimeMock::GetLegacyDepth() != 0;
        ffrt_this_task_set_legacy_mode(true);
        {
            EventCenter::Defer nested;
            WaitInScope(result);
        }
        result->unbalancedScopes += EventCenterRuntimeMock::GetLegacyDepth() != 1;
        WaitInScope(result);
        ffrt_this_task_set_legacy_mode(false);
        result->unbalancedScopes += EventCenterRuntimeMock::GetLegacyDepth() != 0;
    }
}
} // namespace

class EventCenterLegacyTest : public testing::TestWithParam<int32_t> {
public:
    void SetUp() override
    {
        EventCenterRuntimeMock::Reset();
    }
    void TearDown() override
    {
        EventCenter::GetInstance().Unsubscribe(FIRST_EVENT);
        EventCenter::GetInstance().Unsubscribe(SECOND_EVENT);
    }
};

/**
 * @tc.name: Defer_EmptyScope_BalancesLegacyMode
 * @tc.desc: Protection starts before queue allocation and ends when an empty scope is destroyed.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(EventCenterLegacyTest, Defer_EmptyScope_BalancesLegacyMode, TestSize.Level1)
{
    {
        EventCenter::Defer defer;
        EXPECT_EQ(EventCenterRuntimeMock::GetLegacyDepth(), 1);
        EXPECT_EQ(EventCenterRuntimeMock::GetAllocationDepth(), 1);
    }
    EXPECT_EQ(EventCenterRuntimeMock::GetLegacyDepth(), 0);
    EXPECT_EQ(EventCenterRuntimeMock::GetMinimumDepth(), 0);
}

/**
 * @tc.name: Defer_NestedScopes_PreserveExistingLegacyMode
 * @tc.desc: An EventCenter scope must not clear protection established by its caller or outer scope.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(EventCenterLegacyTest, Defer_NestedScopes_PreserveExistingLegacyMode, TestSize.Level1)
{
    ffrt_this_task_set_legacy_mode(true);
    {
        EventCenter::Defer outer;
        {
            EventCenter::Defer inner;
            EXPECT_EQ(EventCenterRuntimeMock::GetLegacyDepth(), 3);
        }
        EXPECT_EQ(EventCenterRuntimeMock::GetLegacyDepth(), 2);
    }
    EXPECT_EQ(EventCenterRuntimeMock::GetLegacyDepth(), 1);
    ffrt_this_task_set_legacy_mode(false);
    EXPECT_EQ(EventCenterRuntimeMock::GetLegacyDepth(), 0);
    EXPECT_EQ(EventCenterRuntimeMock::GetMinimumDepth(), 0);
}

/**
 * @tc.name: Defer_AllocationFailure_RestoresLegacyMode
 * @tc.desc: A failed nothrow queue allocation still releases its matching protection on destruction.
 * @tc.type: RELI
 * @tc.author: agent
 */
HWTEST_F(EventCenterLegacyTest, Defer_AllocationFailure_RestoresLegacyMode, TestSize.Level1)
{
    EventCenterRuntimeMock::FailNextAllocation();
    {
        EventCenter::Defer defer;
        EXPECT_EQ(EventCenterRuntimeMock::GetFailedAllocations(), 1);
        EXPECT_EQ(EventCenterRuntimeMock::GetAllocationDepth(), 1);
        EXPECT_EQ(EventCenterRuntimeMock::GetLegacyDepth(), 1);
    }
    EXPECT_EQ(EventCenterRuntimeMock::GetLegacyDepth(), 0);
    EXPECT_EQ(EventCenterRuntimeMock::GetMinimumDepth(), 0);
    EXPECT_EQ(EventCenter::GetInstance().PostEvent(std::make_unique<Event>(FIRST_EVENT)), EventCenter::CODE_SYNC);
    EXPECT_EQ(EventCenterRuntimeMock::GetLegacyDepth(), 0);
}

/**
 * @tc.name: PostEvent_ReentrantCallback_ProtectsDispatchAndCleanup
 * @tc.desc: Direct dispatch, deferred callbacks, event and temporary-handler destruction stay protected.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(EventCenterLegacyTest, PostEvent_ReentrantCallback_ProtectsDispatchAndCleanup, TestSize.Level1)
{
    auto trace = std::make_shared<Trace>();
    ASSERT_TRUE(EventCenter::GetInstance().Subscribe(FIRST_EVENT, [trace](const Event &) {
        trace->callbacks.push_back(EventCenterRuntimeMock::GetLegacyDepth());
        EventCenter::Defer nested(
            [trace, lifetime = std::make_shared<HandlerLifetime>(trace)](
                const Event &) { trace->callbacks.push_back(EventCenterRuntimeMock::GetLegacyDepth()); },
            SECOND_EVENT);
        trace->result = EventCenter::GetInstance().PostEvent(std::make_unique<TrackedEvent>(trace));
    }));
    ASSERT_TRUE(EventCenter::GetInstance().Subscribe(SECOND_EVENT,
        [trace](const Event &) { trace->callbacks.push_back(EventCenterRuntimeMock::GetLegacyDepth()); }));
    EXPECT_EQ(EventCenter::GetInstance().PostEvent(std::make_unique<Event>(FIRST_EVENT)), EventCenter::CODE_SYNC);
    EXPECT_EQ(trace->result, EventCenter::CODE_ASYNC);
    EXPECT_EQ(trace->callbacks, (std::vector<int32_t>{ 1, 1, 1 }));
    EXPECT_EQ(trace->eventDestruction, (std::vector<int32_t>{ 1 }));
    EXPECT_EQ(trace->handlerDestruction, (std::vector<int32_t>{ 1 }));
    EXPECT_EQ(EventCenterRuntimeMock::GetLegacyDepth(), 0);
    EXPECT_EQ(EventCenterRuntimeMock::GetMinimumDepth(), 0);
}

class EventCenterFfrtLegacyTest : public EventCenterLegacyTest {};

/**
 * @tc.name: PostEvent_FfrtWaits_PreservesThreadAndRestoresMode
 * @tc.desc: Real normal tasks, coroutine queues and thread-mode queues keep nested EventCenter waits on one worker.
 * @tc.type: RELI
 * @tc.author: agent
 */
HWTEST_P(EventCenterFfrtLegacyTest, PostEvent_FfrtWaits_PreservesThreadAndRestoresMode, TestSize.Level2)
{
    auto result = std::make_shared<FfrtResult>();
    ASSERT_TRUE(EventCenter::GetInstance().Subscribe(FIRST_EVENT, [result](const Event &) {
        ++result->callbacks;
        WaitInScope(result);
        result->wrongResults += EventCenter::GetInstance().PostEvent(std::make_unique<Event>(SECOND_EVENT)) !=
                                EventCenter::CODE_ASYNC;
    }));
    ASSERT_TRUE(EventCenter::GetInstance().Subscribe(SECOND_EVENT, [result](const Event &) {
        ++result->callbacks;
        WaitInScope(result);
    }));
    if (GetParam() == 0) {
        auto handle = ffrt::submit_h([result]() { PostEvents(result); });
        ffrt::wait({ handle });
    } else {
        ffrt::queue_attr attr;
        attr.thread_mode(GetParam() == 2);
        ffrt::queue queue("event_center_legacy_test", attr);
        auto handle = queue.submit_h([result]() { PostEvents(result); });
        queue.wait(handle);
    }
    EXPECT_NE(result->taskId, 0u);
    EXPECT_EQ(result->callbacks, ROUNDS * 4);
    EXPECT_EQ(result->wrongResults, 0);
    EXPECT_EQ(result->migrations, 0);
    EXPECT_EQ(result->unprotectedWaits, 0);
    EXPECT_EQ(result->unbalancedScopes, 0);
}

INSTANTIATE_TEST_SUITE_P(ExecutionModes, EventCenterFfrtLegacyTest, testing::Values(0, 1, 2));
