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

#include "auth_event_builder.h"

#include <cmath>
#include <utility>
#include <vector>
namespace OHOS::UDMF {
namespace {
using Json = DistributedData::Serializable::json;
bool IsLosslessString(const std::string &value)
{
    auto encoded = Json(value).dump(-1, ' ', false, DistributedData::Serializable::error_handler_t::replace);
    auto decoded = Json::parse(encoded, nullptr, false);
    return decoded.is_string() && decoded.get_ref<const std::string &>() == value;
}

bool IsLosslessContent(const Json &content)
{
    std::vector<const Json *> pending{ &content };
    while (!pending.empty()) {
        const auto &node = *pending.back();
        pending.pop_back();
        if (node.is_string() && !IsLosslessString(node.get_ref<const std::string &>())) {
            return false;
        }
        if (node.is_number_float() && !std::isfinite(node.get<double>())) {
            return false;
        }
        if (!node.is_object() && !node.is_array()) {
            continue;
        }
        for (auto it = node.begin(); it != node.end(); ++it) {
            if (node.is_object() && !IsLosslessString(it.key())) {
                return false;
            }
            pending.push_back(&it.value());
        }
    }
    return true;
}
} // namespace
AuthEventBuilder::AuthEventBuilder(AuthEventContract contract) : contract_(std::move(contract))
{
}
bool AuthEventBuilder::IsReady() const
{
    return contract_.eventId > 0 && !contract_.version.empty() && contract_.maxContentBytes > 0 &&
           contract_.maxContentBytes <= DRAG_AUTH_MAX_CONTENT_BYTES && static_cast<bool>(contract_.encode);
}
int64_t AuthEventBuilder::GetEventId() const
{
    return contract_.eventId;
}
AuthBuildStatus AuthEventBuilder::Build(const DragAuthContext &context, DragAuthEvent &event) const
{
    if (!context.crossApplication || !IsReady()) {
        return AuthBuildStatus::INVALID_DATA;
    }
    DistributedData::Serializable::json content;
    auto status = contract_.encode(context, content);
    if (status != AuthBuildStatus::SUCCESS) {
        return status;
    }
    if (!content.is_object()) {
        return AuthBuildStatus::INVALID_DATA;
    }
    auto encoded = content.dump(-1, ' ', false, DistributedData::Serializable::error_handler_t::replace);
    if (encoded.size() > contract_.maxContentBytes) {
        return AuthBuildStatus::TOO_LARGE;
    }
    if (!IsLosslessContent(content)) {
        return AuthBuildStatus::INVALID_ENCODING;
    }
    event = { contract_.eventId, contract_.version, std::move(encoded) };
    return AuthBuildStatus::SUCCESS;
}
} // namespace OHOS::UDMF
