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

#ifndef OHOS_DISTRIBUTED_DATA_DATAMGR_SERVICE_COMMON_XCOLLIE_H
#define OHOS_DISTRIBUTED_DATA_DATAMGR_SERVICE_COMMON_XCOLLIE_H

#include <string>
#include "xcollie/xcollie.h"

namespace OHOS::DistributedData {
class XCollie {
public:
    enum FLAG {
        XCOLLIE_LOG = 0x1,
        XCOLLIE_RECOVERY = 0x2
    };
    XCollie(const std::string &tag, uint32_t flag, uint32_t timeoutSeconds = RESTART_TIME_THRESHOLD,
        std::function<void(void *)> func = nullptr, void *arg = nullptr);
    ~XCollie();

private:
    int32_t id_ = -1;
    static constexpr int32_t RESTART_TIME_THRESHOLD = 30;
};
} // namespace OHOS::DistributedData
#endif // OHOS_DISTRIBUTED_DATA_DATAMGR_SERVICE_COMMON_XCOLLIE_H