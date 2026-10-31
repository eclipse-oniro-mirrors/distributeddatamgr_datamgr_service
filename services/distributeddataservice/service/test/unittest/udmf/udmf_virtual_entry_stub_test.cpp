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

#include <limits>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "ipc_object_stub.h"
#include "udmf_service_stub.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS::UDMF {
namespace {
constexpr uint32_t REGISTER_CODE = static_cast<uint32_t>(UdmfServiceInterfaceCode::REGISTER_VIRTUAL_ENTRY);
constexpr uint32_t NODE_LIMIT = 4096;
constexpr uint32_t DEPTH_LIMIT = 64;
constexpr uint32_t RECORD_INDEX = 3;
constexpr int64_t MODIFY_TIME = 123456;
constexpr const char *TEST_KEY = "udmf://drag/com.example.virtual/0123456789abcdef0123456789abcdef";

class VirtualEntryDispatchMock final : public UdmfServiceStub {
public:
    MOCK_METHOD(int32_t, SetData, (CustomOption &, UnifiedData &, Summary &, std::string &), (override));
    MOCK_METHOD(int32_t, GetData, (const QueryOption &, UnifiedData &), (override));
    MOCK_METHOD(int32_t, GetBatchData, (const QueryOption &, std::vector<UnifiedData> &), (override));
    MOCK_METHOD(int32_t, UpdateData, (const QueryOption &, UnifiedData &), (override));
    MOCK_METHOD(int32_t, DeleteData, (const QueryOption &, std::vector<UnifiedData> &), (override));
    MOCK_METHOD(int32_t, GetSummary, (const QueryOption &, Summary &), (override));
    MOCK_METHOD(int32_t, AddPrivilege, (const QueryOption &, Privilege &), (override));
    MOCK_METHOD(int32_t, Sync, (const QueryOption &, const std::vector<std::string> &), (override));
    MOCK_METHOD(int32_t, IsRemoteData, (const QueryOption &, bool &), (override));
    MOCK_METHOD(int32_t, SetAppShareOption, (const std::string &, int32_t), (override));
    MOCK_METHOD(int32_t, GetAppShareOption, (const std::string &, int32_t &), (override));
    MOCK_METHOD(int32_t, RemoveAppShareOption, (const std::string &), (override));
    MOCK_METHOD(int32_t, ObtainAsynProcess, (AsyncProcessInfo &), (override));
    MOCK_METHOD(int32_t, ClearAsynProcessByKey, (const std::string &), (override));
    MOCK_METHOD(int32_t, SetDelayInfo, (const DataLoadInfo &, sptr<IRemoteObject>, std::string &), (override));
    MOCK_METHOD(int32_t, PushDelayData, (const std::string &, UnifiedData &, Summary &), (override));
    MOCK_METHOD(int32_t, GetDataIfAvailable,
        (const std::string &, const DataLoadInfo &, sptr<IRemoteObject>, std::shared_ptr<UnifiedData>), (override));
    MOCK_METHOD(int32_t, RegisterVirtualEntry,
        (const std::string &, uint32_t, const VirtualEntry &, sptr<IRemoteObject>), (override));
};

class RejectParcelAllocator final : public Allocator {
public:
    void *Alloc(size_t size) override
    {
        return nullptr;
    }

    void *Realloc(void *data, size_t size) override
    {
        return nullptr;
    }

    void Dealloc(void *data) override {}
};

VirtualEntry MakeStubFile()
{
    VirtualEntry entry;
    entry.id = "file-id";
    entry.name = "example.bin";
    entry.type = VirtualEntryType::FILE;
    entry.modifyTime = MODIFY_TIME;
    entry.size = 7;
    return entry;
}

VirtualEntry MakeStubDirectory(uint32_t childCount)
{
    VirtualEntry entry;
    entry.name = "directory";
    entry.type = VirtualEntryType::DIRECTORY;
    for (uint32_t index = 0; index < childCount; ++index) {
        auto child = MakeStubFile();
        child.name = "file-" + std::to_string(index);
        entry.subItems.push_back(std::move(child));
    }
    return entry;
}

bool WriteEntryHeader(MessageParcel &parcel, const VirtualEntry &entry, uint32_t fields = 6)
{
    return (fields < 1 || parcel.WriteString(entry.id)) && (fields < 2 || parcel.WriteString(entry.name)) &&
        (fields < 3 || parcel.WriteInt32(static_cast<int32_t>(entry.type))) &&
        (fields < 4 || parcel.WriteInt64(entry.modifyTime)) && (fields < 5 || parcel.WriteInt64(entry.size)) &&
        (fields < 6 || parcel.WriteUint32(static_cast<uint32_t>(entry.subItems.size())));
}

bool WriteEntryTree(MessageParcel &parcel, const VirtualEntry &entry)
{
    if (!WriteEntryHeader(parcel, entry)) {
        return false;
    }
    for (const auto &child : entry.subItems) {
        if (!WriteEntryTree(parcel, child)) {
            return false;
        }
    }
    return true;
}

bool WriteRegisterPrefix(MessageParcel &parcel, const std::string &key = TEST_KEY)
{
    return parcel.WriteInterfaceToken(UdmfServiceStub::GetDescriptor()) && parcel.WriteString(key) &&
        parcel.WriteUint32(RECORD_INDEX);
}
} // namespace

class UdmfVirtualEntryStubTest : public testing::Test {
protected:
    StrictMock<VirtualEntryDispatchMock> service_;
    sptr<IRemoteObject> provider_ = new IPCObjectStub(u"VirtualEntryTestProvider");
};

/**
 * @tc.name: OnRemoteRequest_VirtualEntryWrongDescriptor_RejectWithoutDispatch
 * @tc.desc: The new transaction must preserve the interface-token boundary.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfVirtualEntryStubTest, OnRemoteRequest_VirtualEntryWrongDescriptor_RejectWithoutDispatch, TestSize.Level0)
{
    MessageParcel request;
    MessageParcel reply;
    ASSERT_TRUE(request.WriteInterfaceToken(u"wrong-descriptor"));
    EXPECT_CALL(service_, RegisterVirtualEntry(_, _, _, _)).Times(0);
    EXPECT_EQ(service_.OnRemoteRequest(REGISTER_CODE, request, reply), -1);
}

/**
 * @tc.name: OnRemoteRequest_CodeAfterVirtualEntry_RejectWithoutDispatch
 * @tc.desc: Adding the new transaction must not accept the upper code sentinel.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfVirtualEntryStubTest, OnRemoteRequest_CodeAfterVirtualEntry_RejectWithoutDispatch, TestSize.Level0)
{
    MessageParcel request;
    MessageParcel reply;
    ASSERT_TRUE(request.WriteInterfaceToken(UdmfServiceStub::GetDescriptor()));
    EXPECT_CALL(service_, RegisterVirtualEntry(_, _, _, _)).Times(0);
    EXPECT_EQ(service_.OnRemoteRequest(static_cast<uint32_t>(UdmfServiceInterfaceCode::CODE_BUTT), request, reply), -1);
}

/**
 * @tc.name: RegisterVirtualEntry_EmptyKey_RejectBeforeReadingTree
 * @tc.desc: An empty virtual-session key cannot reach the service implementation.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfVirtualEntryStubTest, RegisterVirtualEntry_EmptyKey_RejectBeforeReadingTree, TestSize.Level0)
{
    MessageParcel request;
    MessageParcel reply;
    ASSERT_TRUE(WriteRegisterPrefix(request, ""));
    EXPECT_CALL(service_, RegisterVirtualEntry(_, _, _, _)).Times(0);
    EXPECT_EQ(service_.OnRemoteRequest(REGISTER_CODE, request, reply), E_READ_PARCEL_ERROR);
}

/**
 * @tc.name: RegisterVirtualEntry_TruncatedMetadata_RejectEachMissingField
 * @tc.desc: Truncation before every numeric metadata field must fail decoding.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfVirtualEntryStubTest, RegisterVirtualEntry_TruncatedMetadata_RejectEachMissingField, TestSize.Level0)
{
    EXPECT_CALL(service_, RegisterVirtualEntry(_, _, _, _)).Times(0);
    for (uint32_t fields = 0; fields < 6; ++fields) {
        SCOPED_TRACE(fields);
        MessageParcel request;
        MessageParcel reply;
        ASSERT_TRUE(WriteRegisterPrefix(request));
        ASSERT_TRUE(WriteEntryHeader(request, MakeStubFile(), fields));
        EXPECT_EQ(service_.OnRemoteRequest(REGISTER_CODE, request, reply), E_READ_PARCEL_ERROR);
    }
}

/**
 * @tc.name: RegisterVirtualEntry_InvalidNodeType_RejectBothEnumBounds
 * @tc.desc: Values below FILE and above DIRECTORY cannot be decoded as nodes.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfVirtualEntryStubTest, RegisterVirtualEntry_InvalidNodeType_RejectBothEnumBounds, TestSize.Level0)
{
    EXPECT_CALL(service_, RegisterVirtualEntry(_, _, _, _)).Times(0);
    for (int32_t type : { -1, 2 }) {
        SCOPED_TRACE(type);
        auto entry = MakeStubFile();
        entry.type = static_cast<VirtualEntryType>(type);
        MessageParcel request;
        MessageParcel reply;
        ASSERT_TRUE(WriteRegisterPrefix(request));
        ASSERT_TRUE(WriteEntryHeader(request, entry));
        EXPECT_EQ(service_.OnRemoteRequest(REGISTER_CODE, request, reply), E_READ_PARCEL_ERROR);
    }
}

/**
 * @tc.name: RegisterVirtualEntry_NegativeFileSize_RejectUnknownAndInvalidSizes
 * @tc.desc: Neither unknown size nor other negative sizes may pass the IPC boundary.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfVirtualEntryStubTest, RegisterVirtualEntry_NegativeFileSize_RejectUnknownAndInvalidSizes, TestSize.Level0)
{
    EXPECT_CALL(service_, RegisterVirtualEntry(_, _, _, _)).Times(0);
    for (int64_t size : { int64_t(-1), std::numeric_limits<int64_t>::min() }) {
        SCOPED_TRACE(size);
        auto entry = MakeStubFile();
        entry.size = size;
        MessageParcel request;
        MessageParcel reply;
        ASSERT_TRUE(WriteRegisterPrefix(request));
        ASSERT_TRUE(WriteEntryHeader(request, entry));
        EXPECT_EQ(service_.OnRemoteRequest(REGISTER_CODE, request, reply), E_READ_PARCEL_ERROR);
    }
}

/**
 * @tc.name: RegisterVirtualEntry_ChildrenExceedRemainingBudget_RejectBeforeAllocation
 * @tc.desc: The child count must include the already consumed root node.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfVirtualEntryStubTest, RegisterVirtualEntry_ChildrenExceedRemainingBudget_RejectBeforeAllocation,
    TestSize.Level0)
{
    MessageParcel request;
    MessageParcel reply;
    auto entry = MakeStubDirectory(0);
    ASSERT_TRUE(WriteRegisterPrefix(request));
    ASSERT_TRUE(WriteEntryHeader(request, entry, 5));
    ASSERT_TRUE(request.WriteUint32(NODE_LIMIT));
    EXPECT_CALL(service_, RegisterVirtualEntry(_, _, _, _)).Times(0);
    EXPECT_EQ(service_.OnRemoteRequest(REGISTER_CODE, request, reply), E_READ_PARCEL_ERROR);
}

/**
 * @tc.name: RegisterVirtualEntry_TruncatedChild_RejectPartialDirectory
 * @tc.desc: A declared child without complete metadata must fail recursive decoding.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfVirtualEntryStubTest, RegisterVirtualEntry_TruncatedChild_RejectPartialDirectory, TestSize.Level0)
{
    MessageParcel request;
    MessageParcel reply;
    ASSERT_TRUE(WriteRegisterPrefix(request));
    ASSERT_TRUE(WriteEntryHeader(request, MakeStubDirectory(1)));
    ASSERT_TRUE(WriteEntryHeader(request, MakeStubFile(), 3));
    EXPECT_CALL(service_, RegisterVirtualEntry(_, _, _, _)).Times(0);
    EXPECT_EQ(service_.OnRemoteRequest(REGISTER_CODE, request, reply), E_READ_PARCEL_ERROR);
}

/**
 * @tc.name: RegisterVirtualEntry_MissingProvider_RejectDecodedTree
 * @tc.desc: Valid metadata alone cannot register a virtual file without a provider.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfVirtualEntryStubTest, RegisterVirtualEntry_MissingProvider_RejectDecodedTree, TestSize.Level0)
{
    MessageParcel request;
    MessageParcel reply;
    ASSERT_TRUE(WriteRegisterPrefix(request));
    ASSERT_TRUE(WriteEntryTree(request, MakeStubFile()));
    EXPECT_CALL(service_, RegisterVirtualEntry(_, _, _, _)).Times(0);
    EXPECT_EQ(service_.OnRemoteRequest(REGISTER_CODE, request, reply), E_READ_PARCEL_ERROR);
}

/**
 * @tc.name: RegisterVirtualEntry_ValidFile_PreserveMetadataAndBusinessStatus
 * @tc.desc: Dispatch all file fields and return the business error in the reply parcel.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfVirtualEntryStubTest, RegisterVirtualEntry_ValidFile_PreserveMetadataAndBusinessStatus, TestSize.Level0)
{
    MessageParcel request;
    MessageParcel reply;
    auto entry = MakeStubFile();
    VirtualEntry received;
    ASSERT_TRUE(WriteRegisterPrefix(request));
    ASSERT_TRUE(WriteEntryTree(request, entry));
    ASSERT_TRUE(request.WriteRemoteObject(provider_));
    EXPECT_CALL(service_, RegisterVirtualEntry(TEST_KEY, RECORD_INDEX, _, provider_))
        .WillOnce(DoAll(SaveArg<2>(&received), Return(E_NO_PERMISSION)));

    EXPECT_EQ(service_.OnRemoteRequest(REGISTER_CODE, request, reply), E_OK);
    int32_t status = E_OK;
    ASSERT_TRUE(reply.ReadInt32(status));
    EXPECT_EQ(status, E_NO_PERMISSION);
    EXPECT_EQ(received.id, entry.id);
    EXPECT_EQ(received.name, entry.name);
    EXPECT_EQ(received.type, entry.type);
    EXPECT_EQ(received.modifyTime, entry.modifyTime);
    EXPECT_EQ(received.size, entry.size);
    EXPECT_TRUE(received.subItems.empty());
}

/**
 * @tc.name: RegisterVirtualEntry_ZeroSizeAndEmptyDirectory_DispatchBothValidShapes
 * @tc.desc: A real empty file and an empty directory have different valid size representations.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfVirtualEntryStubTest, RegisterVirtualEntry_ZeroSizeAndEmptyDirectory_DispatchBothValidShapes,
    TestSize.Level0)
{
    auto file = MakeStubFile();
    file.size = 0;
    for (const auto &entry : { file, MakeStubDirectory(0) }) {
        MessageParcel request;
        MessageParcel reply;
        VirtualEntry received;
        ASSERT_TRUE(WriteRegisterPrefix(request));
        ASSERT_TRUE(WriteEntryTree(request, entry));
        ASSERT_TRUE(request.WriteRemoteObject(provider_));
        EXPECT_CALL(service_, RegisterVirtualEntry(_, _, _, _))
            .WillOnce(DoAll(SaveArg<2>(&received), Return(E_OK)));
        EXPECT_EQ(service_.OnRemoteRequest(REGISTER_CODE, request, reply), E_OK);
        EXPECT_EQ(received.type, entry.type);
        EXPECT_EQ(received.size, entry.size);
        EXPECT_TRUE(received.subItems.empty());
        EXPECT_EQ(reply.ReadInt32(), E_OK);
    }
}

/**
 * @tc.name: RegisterVirtualEntry_NestedDirectory_PreserveRecursiveChildren
 * @tc.desc: Decode nested directories with file and empty-directory siblings.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfVirtualEntryStubTest, RegisterVirtualEntry_NestedDirectory_PreserveRecursiveChildren, TestSize.Level0)
{
    auto entry = MakeStubDirectory(1);
    entry.subItems.push_back(MakeStubDirectory(2));
    MessageParcel request;
    MessageParcel reply;
    VirtualEntry received;
    ASSERT_TRUE(WriteRegisterPrefix(request));
    ASSERT_TRUE(WriteEntryTree(request, entry));
    ASSERT_TRUE(request.WriteRemoteObject(provider_));
    EXPECT_CALL(service_, RegisterVirtualEntry(_, _, _, _))
        .WillOnce(DoAll(SaveArg<2>(&received), Return(E_OK)));

    EXPECT_EQ(service_.OnRemoteRequest(REGISTER_CODE, request, reply), E_OK);
    ASSERT_EQ(received.subItems.size(), 2u);
    EXPECT_EQ(received.subItems[0].id, entry.subItems[0].id);
    EXPECT_EQ(received.subItems[1].type, VirtualEntryType::DIRECTORY);
    ASSERT_EQ(received.subItems[1].subItems.size(), 2u);
    EXPECT_EQ(received.subItems[1].subItems[1].name, "file-1");
}

/**
 * @tc.name: RegisterVirtualEntry_DepthBoundary_Accept64AndReject65
 * @tc.desc: The root is depth zero and recursive decoding rejects the first excessive level.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfVirtualEntryStubTest, RegisterVirtualEntry_DepthBoundary_Accept64AndReject65, TestSize.Level0)
{
    for (uint32_t depth : { DEPTH_LIMIT, DEPTH_LIMIT + 1 }) {
        SCOPED_TRACE(depth);
        auto root = MakeStubFile();
        for (uint32_t level = 0; level < depth; ++level) {
            auto parent = MakeStubDirectory(0);
            parent.subItems.push_back(std::move(root));
            root = std::move(parent);
        }
        MessageParcel request;
        MessageParcel reply;
        ASSERT_TRUE(WriteRegisterPrefix(request));
        ASSERT_TRUE(WriteEntryTree(request, root));
        ASSERT_TRUE(request.WriteRemoteObject(provider_));
        EXPECT_CALL(service_, RegisterVirtualEntry(_, _, _, _))
            .Times(depth == DEPTH_LIMIT ? 1 : 0).WillRepeatedly(Return(E_OK));
        EXPECT_EQ(service_.OnRemoteRequest(REGISTER_CODE, request, reply),
            depth == DEPTH_LIMIT ? E_OK : E_READ_PARCEL_ERROR);
    }
}

/**
 * @tc.name: RegisterVirtualEntry_NodeCountBoundary_Accept4096AndReject4097
 * @tc.desc: Nested siblings cannot exceed the global node budget after an earlier subtree consumes it.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfVirtualEntryStubTest, RegisterVirtualEntry_NodeCountBoundary_Accept4096AndReject4097, TestSize.Level0)
{
    for (bool oversized : { false, true }) {
        SCOPED_TRACE(oversized);
        auto root = MakeStubDirectory(0);
        root.subItems.push_back(MakeStubDirectory(NODE_LIMIT - 2));
        if (oversized) {
            root.subItems.push_back(MakeStubFile());
        }
        MessageParcel request;
        MessageParcel reply;
        ASSERT_TRUE(request.SetMaxCapacity(4 * 1024 * 1024));
        ASSERT_TRUE(WriteRegisterPrefix(request));
        ASSERT_TRUE(WriteEntryTree(request, root));
        ASSERT_TRUE(request.WriteRemoteObject(provider_));
        EXPECT_CALL(service_, RegisterVirtualEntry(_, _, _, _))
            .Times(oversized ? 0 : 1).WillRepeatedly(Return(E_OK));
        EXPECT_EQ(service_.OnRemoteRequest(REGISTER_CODE, request, reply),
            oversized ? E_READ_PARCEL_ERROR : E_OK);
    }
}

/**
 * @tc.name: RegisterVirtualEntry_ReplyAllocationFailed_ReturnWriteParcelError
 * @tc.desc: A successful registration must still report failure when its status cannot be serialized.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfVirtualEntryStubTest, RegisterVirtualEntry_ReplyAllocationFailed_ReturnWriteParcelError, TestSize.Level0)
{
    MessageParcel request;
    MessageParcel reply;
    ASSERT_TRUE(reply.SetAllocator(new RejectParcelAllocator()));
    ASSERT_TRUE(WriteRegisterPrefix(request));
    ASSERT_TRUE(WriteEntryTree(request, MakeStubFile()));
    ASSERT_TRUE(request.WriteRemoteObject(provider_));
    EXPECT_CALL(service_, RegisterVirtualEntry(_, _, _, _)).WillOnce(Return(E_OK));
    EXPECT_EQ(service_.OnRemoteRequest(REGISTER_CODE, request, reply), E_WRITE_PARCEL_ERROR);
}
} // namespace OHOS::UDMF
