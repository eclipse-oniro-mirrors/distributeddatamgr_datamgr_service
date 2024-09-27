/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "cloud/cloud_report.h"

namespace OHOS::DistributedData {
CloudReport *CloudReport::instance_ = nullptr;

CloudReport *CloudReport::GetInstance()
{
    return instance_;
}

bool CloudReport::RegisterCloudReportInstance(CloudReport *instance)
{
    if (instance_ != nullptr) {
        return false;
    }
    instance_ = instance;
    return true;
}

std::string CloudReport::GetPrepareTraceId(int32_t userId, const std::string &bundleName)
{
    return "";
}

std::string CloudReport::GetRequestTraceId(int32_t userId, const std::string &bundleName)
{
    return "";
}

bool CloudReport::Report(const ReportParam &reportParam)
{
    return true;
}
} // namespace OHOS::DistributedData