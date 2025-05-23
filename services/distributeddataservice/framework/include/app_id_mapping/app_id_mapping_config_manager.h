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
#ifndef OHOS_DISTRIBUTED_DATA_SERVICES_FRAMEWORK_APP_ID_MAPPING_CONFIG_MANAGER_H
#define OHOS_DISTRIBUTED_DATA_SERVICES_FRAMEWORK_APP_ID_MAPPING_CONFIG_MANAGER_H
#include <string>
#include <vector>
#include <map>
#include "visibility.h"
namespace OHOS {
namespace DistributedData {
class AppIdMappingConfigManager {
public:
    struct AppMappingInfo {
        std::string srcAppId;
        std::string dstAppId;
    };
    API_EXPORT static AppIdMappingConfigManager &GetInstance();
    API_EXPORT void Initialize(const std::vector<AppMappingInfo> &mapper);
    API_EXPORT std::pair<std::string, std::string> Convert(const std::string &appId,
        const std::string &accountId);
    API_EXPORT std::string Convert(const std::string &appId);
private:
    std::map<std::string, std::string> toDstMapper_;
};

} // namespace DistributedData
} // namespace OHOS
#endif //OHOS_DISTRIBUTED_DATA_SERVICES_FRAMEWORK_APP_ID_MAPPING_CONFIG_MANAGER_H
