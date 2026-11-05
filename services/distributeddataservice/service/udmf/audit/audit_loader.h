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
#ifndef DISTRIBUTEDDATAMGR_SERVICE_UDMF_AUDIT_LOADER_H
#define DISTRIBUTEDDATAMGR_SERVICE_UDMF_AUDIT_LOADER_H

#include <memory>
#include <mutex>

#include "i_audit_helper.h"

namespace OHOS {
namespace UDMF {

class AuditLoader {
public:
    static AuditLoader &GetInstance();
    void ReportDragAuditEvent(const UnifiedData &unifiedData, int32_t userId, uint32_t tokenId);

private:
    AuditLoader() = default;
    ~AuditLoader() = default;
    AuditLoader(const AuditLoader &) = delete;
    AuditLoader &operator=(const AuditLoader &) = delete;

    std::shared_ptr<IAuditHelper> GetAuditHelper();
    bool IsEnterpriseDevice();

    std::mutex mutex_;
    std::shared_ptr<IAuditHelper> auditHelper_ = nullptr;
};

} // namespace UDMF
} // namespace OHOS
#endif // DISTRIBUTEDDATAMGR_SERVICE_UDMF_AUDIT_LOADER_H