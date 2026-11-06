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
#ifndef DISTRIBUTEDDATAMGR_SERVICE_UDMF_AUDIT_I_AUDIT_HELPER_H
#define DISTRIBUTEDDATAMGR_SERVICE_UDMF_AUDIT_I_AUDIT_HELPER_H

#include <cstdint>
#include <memory>

#include "executor_pool.h"
#include "unified_data.h"

namespace OHOS {
namespace UDMF {

class IAuditHelper {
public:
    virtual ~IAuditHelper() = default;
    virtual void ReportDragAuditEvent(const UnifiedData &unifiedData, int32_t userId, uint32_t tokenId,
        const std::shared_ptr<ExecutorPool> &executors) = 0;
};

} // namespace UDMF
} // namespace OHOS
#endif // DISTRIBUTEDDATAMGR_SERVICE_UDMF_AUDIT_I_AUDIT_HELPER_H
