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

#include "security_guard_log_limiter.h"

#include <gtest/gtest.h>

#include <thread>
#include <vector>

using namespace testing::ext;
namespace OHOS::DistributedData {
using Event = SecurityGuardLogLimiter::Event;
using Clock = SecurityGuardLogLimiter::Clock;
class SecurityGuardLogLimiterTest : public testing::Test {};
/**
 * @tc.name: Take_FirstAtBootAndBoundary_LogsImmediatelyThenEveryFiveSeconds
 * @tc.desc: First failure must be visible even before five seconds of process uptime.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(SecurityGuardLogLimiterTest, Take_FirstAtBootAndBoundary_LogsImmediatelyThenEveryFiveSeconds, TestSize.Level1)
{
    SecurityGuardLogLimiter limiter;
    Clock::time_point start{};
    EXPECT_EQ(limiter.Take(Event::PROVIDER_FAILED, start), std::optional<uint64_t>(0));
    EXPECT_EQ(limiter.Take(Event::PROVIDER_FAILED, start + std::chrono::seconds(1)), std::nullopt);
    EXPECT_EQ(limiter.Take(Event::PROVIDER_FAILED, start + std::chrono::milliseconds(4999)), std::nullopt);
    EXPECT_EQ(limiter.Take(Event::PROVIDER_FAILED, start + std::chrono::seconds(5)), std::optional<uint64_t>(2));
    EXPECT_EQ(limiter.Take(Event::PROVIDER_FAILED, start + std::chrono::seconds(10)), std::optional<uint64_t>(0));
}
/**
 * @tc.name: Take_Burst_AggregatesSuppressedCount
 * @tc.desc: A burst of SDK failures produces one diagnostic per category and interval.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(SecurityGuardLogLimiterTest, Take_Burst_AggregatesSuppressedCount, TestSize.Level1)
{
    SecurityGuardLogLimiter limiter;
    Clock::time_point now{};
    EXPECT_TRUE(limiter.Take(Event::REQUEST_REJECTED, now).has_value());
    for (unsigned i = 0; i < 1000; ++i) {
        EXPECT_FALSE(limiter.Take(Event::REQUEST_REJECTED, now).has_value());
    }
    EXPECT_EQ(limiter.Take(Event::REQUEST_REJECTED, now + std::chrono::seconds(5)), std::optional<uint64_t>(1000));
}
/**
 * @tc.name: Take_RecoveryAndSnapshot_IndependentFromFailureThrottle
 * @tc.desc: A registration recovery remains visible immediately after a failed attempt.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(SecurityGuardLogLimiterTest, Take_RecoveryAndSnapshot_IndependentFromFailureThrottle, TestSize.Level1)
{
    SecurityGuardLogLimiter limiter;
    Clock::time_point now{};
    EXPECT_TRUE(limiter.Take(Event::PROVIDER_FAILED, now).has_value());
    EXPECT_TRUE(limiter.Take(Event::PROVIDER_READY, now).has_value());
    EXPECT_TRUE(limiter.Take(Event::SNAPSHOT, now).has_value());
    EXPECT_FALSE(limiter.Take(Event::PROVIDER_READY, now).has_value());
    EXPECT_FALSE(limiter.Take(Event::COUNT, now).has_value());
    EXPECT_FALSE(limiter.Take(static_cast<Event>(-1), now).has_value());
}
/**
 * @tc.name: Take_ConcurrentBurst_AdmitsExactlyOneLog
 * @tc.desc: Concurrent callbacks share the same bounded logging quota.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(SecurityGuardLogLimiterTest, Take_ConcurrentBurst_AdmitsExactlyOneLog, TestSize.Level1)
{
    SecurityGuardLogLimiter limiter;
    Clock::time_point now{};
    constexpr size_t CALLBACK_COUNT = 8;
    std::array<std::optional<uint64_t>, CALLBACK_COUNT> records;
    std::vector<std::thread> callbacks;
    for (size_t i = 0; i < CALLBACK_COUNT; ++i) {
        callbacks.emplace_back([&, i] { records[i] = limiter.Take(Event::SNAPSHOT, now); });
    }
    for (auto &callback : callbacks) {
        callback.join();
    }
    size_t admitted = 0;
    for (const auto &record : records) {
        admitted += record.has_value();
    }
    EXPECT_EQ(admitted, 1u);
    EXPECT_EQ(
        limiter.Take(Event::SNAPSHOT, now + std::chrono::seconds(5)), std::optional<uint64_t>(CALLBACK_COUNT - 1));
}
} // namespace OHOS::DistributedData
