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

#ifndef DISTRIBUTEDDATAMGR_INSTALLER_H
#define DISTRIBUTEDDATAMGR_INSTALLER_H

#include <memory>
#include <mutex>

#include "visibility.h"
#include "executor_pool.h"
namespace OHOS::DistributedKv {
class KvStoreDataService;
enum Status : int32_t;
class Installer {
public:
    KVSTORE_API virtual Status Init(KvStoreDataService *kvStoreDataService,
        std::shared_ptr<ExecutorPool> executors) = 0;
    KVSTORE_API virtual void UnsubscribeEvent() = 0;
    KVSTORE_API virtual ~Installer() {}
    KVSTORE_API static Installer &GetInstance();
};
} // namespace OHOS::DistributedKv
#endif // DISTRIBUTEDDATAMGR_INSTALLER_H
