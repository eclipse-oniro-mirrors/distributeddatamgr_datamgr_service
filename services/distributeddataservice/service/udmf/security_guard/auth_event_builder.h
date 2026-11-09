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

#ifndef UDMF_AUTH_EVENT_BUILDER_H
#define UDMF_AUTH_EVENT_BUILDER_H
#include <memory>

#include "drag_auth_types.h"
#include "serializable/serializable.h"
namespace OHOS::UDMF {
class UnifiedData;
inline constexpr int64_t DRAG_AUTH_EVENT_ID = 0x0F810000;
inline constexpr size_t DRAG_AUTH_MAX_CONTENT_BYTES = 10 * 1024;
enum class AuthBuildStatus { SUCCESS, INVALID_DATA, TOO_LARGE, INVALID_ENCODING };
struct DragAuthContext {
    bool crossApplication = false;
    uint32_t sourceTokenId = 0;
    uint32_t targetTokenId = 0;
    std::shared_ptr<const UnifiedData> data;
};
struct AuthEventContract {
    int64_t eventId = DRAG_AUTH_EVENT_ID;
    std::string version = "1.0";
    size_t maxContentBytes = DRAG_AUTH_MAX_CONTENT_BYTES;
    std::function<AuthBuildStatus(const DragAuthContext &, DistributedData::Serializable::json &)> encode;
};
class AuthEventBuilder {
public:
    explicit AuthEventBuilder(AuthEventContract contract = {});
    bool IsReady() const;
    int64_t GetEventId() const;
    AuthBuildStatus Build(const DragAuthContext &context, DragAuthEvent &event) const;

private:
    const AuthEventContract contract_;
};
} // namespace OHOS::UDMF
#endif // UDMF_AUTH_EVENT_BUILDER_H
