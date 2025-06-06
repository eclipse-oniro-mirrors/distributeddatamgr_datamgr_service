/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#ifndef OHOS_DISTRIBUTED_DATA_SERVICES_CONFIG_MODEL_GLOBAL_CONFIG_H
#define OHOS_DISTRIBUTED_DATA_SERVICES_CONFIG_MODEL_GLOBAL_CONFIG_H
#include "model/app_access_check_config.h"
#include "model/app_id_mapping_config.h"
#include "model/backup_config.h"
#include "model/checker_config.h"
#include "model/cloud_config.h"
#include "model/component_config.h"
#include "model/datashare_config.h"
#include "model/directory_config.h"
#include "model/network_config.h"
#include "model/thread_config.h"
#include "model/device_sync_app_white_list_config.h"
#include "serializable/serializable.h"
namespace OHOS {
namespace DistributedData {
class GlobalConfig final : public Serializable {
public:
    std::string processLabel;
    std::string metaData;
    std::string version;
    std::vector<std::string> features;
    std::vector<ComponentConfig> *components = nullptr;
    CheckerConfig *bundleChecker = nullptr;
    NetworkConfig *networks = nullptr;
    DirectoryConfig *directory = nullptr;
    BackupConfig *backup = nullptr;
    CloudConfig *cloud = nullptr;
    std::vector<AppIdMappingConfig> *appIdMapping = nullptr;
    ThreadConfig *thread = nullptr;
    DataShareConfig *dataShare = nullptr;
    DeviceSyncAppWhiteListConfig *deviceSyncAppWhiteList = nullptr;
    AppAccessCheckConfig *syncAppList = nullptr;
    ~GlobalConfig();
    bool Marshal(json &node) const override;
    bool Unmarshal(const json &node) override;
};
} // namespace DistributedData
} // namespace OHOS
#endif // OHOS_DISTRIBUTED_DATA_SERVICES_CONFIG_MODEL_GLOBAL_CONFIG_H