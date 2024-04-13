/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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
#define LOG_TAG "SoftbusAdapterStandardTest"

#include "gtest/gtest.h"
#include "types.h"
#include "log_print.h"
#include <cstdint>
#include <vector>
#include <unistd.h>
#include <iostream>
#include "softbus_adapter.h"
#include "app_device_change_listener.h"

namespace {
using namespace testing::ext;
using namespace OHOS::AppDistributedKv;
using DeviceInfo = OHOS::AppDistributedKv::DeviceInfo;
class AppDataChangeListenerImpl : public AppDataChangeListener {
struct ServerSocketInfo {
        std::string name;      /**< Peer socket name */
        std::string networkId; /**< Peer network ID */
        std::string pkgName;   /**< Peer package name */
    };

    void OnMessage(const OHOS::AppDistributedKv::DeviceInfo &info, const uint8_t *ptr, const int size,
        const struct PipeInfo &id) const override;
};

    void AppDataChangeListenerImpl::OnMessage(const OHOS::AppDistributedKv::DeviceInfo &info,
        const uint8_t *ptr, const int size, const struct PipeInfo &id) const
    {
        ZLOGI("data  %{public}s  %s", info.deviceName.c_str(), ptr);
    }

class SoftbusAdapterStandardTest : public testing::Test {
public:
  static void SetUpTestCase(void)
    {
    }
    static void TearDownTestCase(void) {}
    void SetUp() {}
    void TearDown() {}

protected:
    static const std::string INVALID_DEVICE_ID;
    static const std::string EMPTY_DEVICE_ID;
    uint32_t DEFAULT_MTU_SIZE = 4096u;
    uint32_t DEFAULT_TIMEOUT = 30 * 1000;
};
const std::string SoftbusAdapterStandardTest::INVALID_DEVICE_ID = "1234567890";
const std::string SoftbusAdapterStandardTest::EMPTY_DEVICE_ID = "";

/**
* @tc.name: StartWatchDeviceChange
* @tc.desc: start watch data change
* @tc.type: FUNC
* @tc.require:
* @tc.author: nhj
 */
HWTEST_F(SoftbusAdapterStandardTest, StartWatchDeviceChange, TestSize.Level0)
{
    auto status = SoftBusAdapter::GetInstance()->StartWatchDataChange(nullptr, {});
    EXPECT_EQ(status, Status::INVALID_ARGUMENT);
}

/**
* @tc.name: StartWatchDeviceChange
* @tc.desc: start watch data change
* @tc.type: FUNC
* @tc.require:
* @tc.author: nhj
 */
HWTEST_F(SoftbusAdapterStandardTest, StartWatchDeviceChange01, TestSize.Level0)
{
    PipeInfo appId;
    appId.pipeId = "appId";
    appId.userId = "groupId";
    const AppDataChangeListenerImpl *dataListener = new AppDataChangeListenerImpl();
    auto status = SoftBusAdapter::GetInstance()->StartWatchDataChange(dataListener, appId);
    EXPECT_EQ(status, Status::SUCCESS);
}

/**
* @tc.name: StartWatchDeviceChange
* @tc.desc: start watch data change
* @tc.type: FUNC
* @tc.require:
* @tc.author: nhj
 */
HWTEST_F(SoftbusAdapterStandardTest, StartWatchDeviceChange02, TestSize.Level0)
{
    PipeInfo appId;
    appId.pipeId = "";
    appId.userId = "groupId";
    const AppDataChangeListenerImpl *dataListener = new AppDataChangeListenerImpl();
    auto status = SoftBusAdapter::GetInstance()->StartWatchDataChange(dataListener, appId);
    EXPECT_EQ(status, Status::SUCCESS);
}

/**
* @tc.name: StopWatchDataChange
* @tc.desc: stop watch data change
* @tc.type: FUNC
* @tc.require:
* @tc.author: nhj
 */
HWTEST_F(SoftbusAdapterStandardTest, StopWatchDataChange, TestSize.Level0)
{
    PipeInfo appId;
    appId.pipeId = "appId";
    appId.userId = "groupId";
    const AppDataChangeListenerImpl *dataListener = new AppDataChangeListenerImpl();
    auto status = SoftBusAdapter::GetInstance()->StopWatchDataChange(dataListener, appId);
    EXPECT_EQ(status, Status::SUCCESS);
}

/**
* @tc.name: StopWatchDataChange
* @tc.desc: stop watch data change
* @tc.type: FUNC
* @tc.require:
* @tc.author: nhj
 */
HWTEST_F(SoftbusAdapterStandardTest, StopWatchDataChange01, TestSize.Level0)
{
    PipeInfo appId;
    appId.pipeId = "";
    appId.userId = "groupId";
    const AppDataChangeListenerImpl *dataListener = new AppDataChangeListenerImpl();
    auto status = SoftBusAdapter::GetInstance()->StopWatchDataChange(dataListener, appId);
    EXPECT_EQ(status, Status::SUCCESS);
}

/**
* @tc.name: SendData
* @tc.desc: parse sent data
* @tc.type: FUNC
* @tc.author: nhj
*/
HWTEST_F(SoftbusAdapterStandardTest, SendData, TestSize.Level1)
{
    const AppDataChangeListenerImpl *dataListener = new AppDataChangeListenerImpl();
    PipeInfo id17;
    id17.pipeId = "appId";
    id17.userId = "groupId";
    auto secRegister = SoftBusAdapter::GetInstance()->StartWatchDataChange(dataListener, id17);
    EXPECT_EQ(Status::SUCCESS, secRegister);
    std::string content = "Helloworlds";
    const uint8_t *t = reinterpret_cast<const uint8_t*>(content.c_str());
    DeviceId di17 = {"127.0.0.2"};
    DataInfo data = { const_cast<uint8_t *>(t), static_cast<uint32_t>(content.length())};
    Status status = SoftBusAdapter::GetInstance()->SendData(id17, di17, data, 11, { MessageType::DEFAULT });
    EXPECT_NE(status, Status::SUCCESS);
    SoftBusAdapter::GetInstance()->StopWatchDataChange(dataListener, id17);
    delete dataListener;
    sleep(1); // avoid thread dnet thread died, then will have pthread;
}

/**
* @tc.name: GetMtuSize
* @tc.desc: get size
* @tc.type: FUNC
* @tc.author: nhj
*/
HWTEST_F(SoftbusAdapterStandardTest, GetMtuSize, TestSize.Level1)
{
    const AppDataChangeListenerImpl *dataListener = new AppDataChangeListenerImpl();
    PipeInfo id;
    id.pipeId = "appId";
    id.userId = "groupId";
    SoftBusAdapter::GetInstance()->StartWatchDataChange(dataListener, id);
    DeviceId di = {"127.0.0.2"};
    auto size = SoftBusAdapter::GetInstance()->GetMtuSize(di);
    EXPECT_EQ(size, 4096);
    SoftBusAdapter::GetInstance()->GetCloseSessionTask();
    SoftBusAdapter::GetInstance()->StopWatchDataChange(dataListener, id);
    delete dataListener;
    sleep(1); // avoid thread dnet thread died, then will have pthread;
}

/**
* @tc.name: GetTimeout
* @tc.desc: get timeout
* @tc.type: FUNC
* @tc.author: nhj
*/
HWTEST_F(SoftbusAdapterStandardTest, GetTimeout, TestSize.Level1)
{
    const AppDataChangeListenerImpl *dataListener = new AppDataChangeListenerImpl();
    PipeInfo id;
    id.pipeId = "appId01";
    id.userId = "groupId01";
    SoftBusAdapter::GetInstance()->StartWatchDataChange(dataListener, id);
    DeviceId di = {"127.0.0.2"};
    auto time = SoftBusAdapter::GetInstance()->GetTimeout(di);
    EXPECT_EQ(time, DEFAULT_TIMEOUT);
    SoftBusAdapter::GetInstance()->StopWatchDataChange(dataListener, id);
    delete dataListener;
    sleep(1); // avoid thread dnet thread died, then will have pthread;
}

/**
* @tc.name: IsSameStartedOnPeer
* @tc.desc: get size
* @tc.type: FUNC
* @tc.author: nhj
*/
HWTEST_F(SoftbusAdapterStandardTest, IsSameStartedOnPeer, TestSize.Level1)
{
    PipeInfo id;
    id.pipeId = "appId01";
    id.userId = "groupId01";
    DeviceId di = {"127.0.0.2"};
    SoftBusAdapter::GetInstance()->SetMessageTransFlag(id, true);
    auto status = SoftBusAdapter::GetInstance()->IsSameStartedOnPeer(id, di);
    EXPECT_EQ(status, true);
}

/**
* @tc.name: NotifyDataListeners
* @tc.desc: get size
* @tc.type: FUNC
* @tc.author: nhj
*/
HWTEST_F(SoftbusAdapterStandardTest, NotifyDataListeners, TestSize.Level1)
{
    std::string content = "Helloworlds";
    const uint8_t *t = reinterpret_cast<const uint8_t*>(content.c_str());
    PipeInfo id;
    id.pipeId = "appId01";
    id.userId = "groupId01";
    std::string deviceId = "1001";
    SoftBusAdapter::GetInstance()->NotifyDataListeners(const_cast<uint8_t *>(t), 10, deviceId, id);
}
}