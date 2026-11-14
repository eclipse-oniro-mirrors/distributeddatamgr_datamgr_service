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

#include "communicator_context.h"
#include "softbus_adapter.h"

namespace OHOS::AppDistributedKv {
namespace {
class CommunicationProviderEnvironment final : public testing::Environment {
public:
    void TearDown() override
    {
        // Release the adapter before its static callback dependencies are destroyed.
        DistributedData::CommunicatorContext::GetInstance().SetSessionListener({});
        SoftBusAdapter::instance_.reset();
    }
};

const bool REGISTER_COMMUNICATION_ENVIRONMENT = [] {
    testing::AddGlobalTestEnvironment(new CommunicationProviderEnvironment());
    return true;
}();
} // namespace
} // namespace OHOS::AppDistributedKv
