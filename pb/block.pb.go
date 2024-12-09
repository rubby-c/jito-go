// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.35.2
// 	protoc        v3.21.12
// source: block.proto

package jito_pb

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

// Condensed block helpful for getting data around efficiently internal to our system.
type CondensedBlock struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Header                *Header  `protobuf:"bytes,1,opt,name=header,proto3" json:"header,omitempty"`
	PreviousBlockhash     string   `protobuf:"bytes,2,opt,name=previous_blockhash,json=previousBlockhash,proto3" json:"previous_blockhash,omitempty"`
	Blockhash             string   `protobuf:"bytes,3,opt,name=blockhash,proto3" json:"blockhash,omitempty"`
	ParentSlot            uint64   `protobuf:"varint,4,opt,name=parent_slot,json=parentSlot,proto3" json:"parent_slot,omitempty"`
	VersionedTransactions [][]byte `protobuf:"bytes,5,rep,name=versioned_transactions,json=versionedTransactions,proto3" json:"versioned_transactions,omitempty"`
	Slot                  uint64   `protobuf:"varint,6,opt,name=slot,proto3" json:"slot,omitempty"`
	Commitment            string   `protobuf:"bytes,7,opt,name=commitment,proto3" json:"commitment,omitempty"`
}

func (x *CondensedBlock) Reset() {
	*x = CondensedBlock{}
	mi := &file_block_proto_msgTypes[0]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *CondensedBlock) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*CondensedBlock) ProtoMessage() {}

func (x *CondensedBlock) ProtoReflect() protoreflect.Message {
	mi := &file_block_proto_msgTypes[0]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use CondensedBlock.ProtoReflect.Descriptor instead.
func (*CondensedBlock) Descriptor() ([]byte, []int) {
	return file_block_proto_rawDescGZIP(), []int{0}
}

func (x *CondensedBlock) GetHeader() *Header {
	if x != nil {
		return x.Header
	}
	return nil
}

func (x *CondensedBlock) GetPreviousBlockhash() string {
	if x != nil {
		return x.PreviousBlockhash
	}
	return ""
}

func (x *CondensedBlock) GetBlockhash() string {
	if x != nil {
		return x.Blockhash
	}
	return ""
}

func (x *CondensedBlock) GetParentSlot() uint64 {
	if x != nil {
		return x.ParentSlot
	}
	return 0
}

func (x *CondensedBlock) GetVersionedTransactions() [][]byte {
	if x != nil {
		return x.VersionedTransactions
	}
	return nil
}

func (x *CondensedBlock) GetSlot() uint64 {
	if x != nil {
		return x.Slot
	}
	return 0
}

func (x *CondensedBlock) GetCommitment() string {
	if x != nil {
		return x.Commitment
	}
	return ""
}

var File_block_proto protoreflect.FileDescriptor

var file_block_proto_rawDesc = []byte{
	0x0a, 0x0b, 0x62, 0x6c, 0x6f, 0x63, 0x6b, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x05, 0x62,
	0x6c, 0x6f, 0x63, 0x6b, 0x1a, 0x0c, 0x73, 0x68, 0x61, 0x72, 0x65, 0x64, 0x2e, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x22, 0x91, 0x02, 0x0a, 0x0e, 0x43, 0x6f, 0x6e, 0x64, 0x65, 0x6e, 0x73, 0x65, 0x64,
	0x42, 0x6c, 0x6f, 0x63, 0x6b, 0x12, 0x26, 0x0a, 0x06, 0x68, 0x65, 0x61, 0x64, 0x65, 0x72, 0x18,
	0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x0e, 0x2e, 0x73, 0x68, 0x61, 0x72, 0x65, 0x64, 0x2e, 0x48,
	0x65, 0x61, 0x64, 0x65, 0x72, 0x52, 0x06, 0x68, 0x65, 0x61, 0x64, 0x65, 0x72, 0x12, 0x2d, 0x0a,
	0x12, 0x70, 0x72, 0x65, 0x76, 0x69, 0x6f, 0x75, 0x73, 0x5f, 0x62, 0x6c, 0x6f, 0x63, 0x6b, 0x68,
	0x61, 0x73, 0x68, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x11, 0x70, 0x72, 0x65, 0x76, 0x69,
	0x6f, 0x75, 0x73, 0x42, 0x6c, 0x6f, 0x63, 0x6b, 0x68, 0x61, 0x73, 0x68, 0x12, 0x1c, 0x0a, 0x09,
	0x62, 0x6c, 0x6f, 0x63, 0x6b, 0x68, 0x61, 0x73, 0x68, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52,
	0x09, 0x62, 0x6c, 0x6f, 0x63, 0x6b, 0x68, 0x61, 0x73, 0x68, 0x12, 0x1f, 0x0a, 0x0b, 0x70, 0x61,
	0x72, 0x65, 0x6e, 0x74, 0x5f, 0x73, 0x6c, 0x6f, 0x74, 0x18, 0x04, 0x20, 0x01, 0x28, 0x04, 0x52,
	0x0a, 0x70, 0x61, 0x72, 0x65, 0x6e, 0x74, 0x53, 0x6c, 0x6f, 0x74, 0x12, 0x35, 0x0a, 0x16, 0x76,
	0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x65, 0x64, 0x5f, 0x74, 0x72, 0x61, 0x6e, 0x73, 0x61, 0x63,
	0x74, 0x69, 0x6f, 0x6e, 0x73, 0x18, 0x05, 0x20, 0x03, 0x28, 0x0c, 0x52, 0x15, 0x76, 0x65, 0x72,
	0x73, 0x69, 0x6f, 0x6e, 0x65, 0x64, 0x54, 0x72, 0x61, 0x6e, 0x73, 0x61, 0x63, 0x74, 0x69, 0x6f,
	0x6e, 0x73, 0x12, 0x12, 0x0a, 0x04, 0x73, 0x6c, 0x6f, 0x74, 0x18, 0x06, 0x20, 0x01, 0x28, 0x04,
	0x52, 0x04, 0x73, 0x6c, 0x6f, 0x74, 0x12, 0x1e, 0x0a, 0x0a, 0x63, 0x6f, 0x6d, 0x6d, 0x69, 0x74,
	0x6d, 0x65, 0x6e, 0x74, 0x18, 0x07, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0a, 0x63, 0x6f, 0x6d, 0x6d,
	0x69, 0x74, 0x6d, 0x65, 0x6e, 0x74, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_block_proto_rawDescOnce sync.Once
	file_block_proto_rawDescData = file_block_proto_rawDesc
)

func file_block_proto_rawDescGZIP() []byte {
	file_block_proto_rawDescOnce.Do(func() {
		file_block_proto_rawDescData = protoimpl.X.CompressGZIP(file_block_proto_rawDescData)
	})
	return file_block_proto_rawDescData
}

var file_block_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_block_proto_goTypes = []any{
	(*CondensedBlock)(nil), // 0: block.CondensedBlock
	(*Header)(nil),         // 1: shared.Header
}
var file_block_proto_depIdxs = []int32{
	1, // 0: block.CondensedBlock.header:type_name -> shared.Header
	1, // [1:1] is the sub-list for method output_type
	1, // [1:1] is the sub-list for method input_type
	1, // [1:1] is the sub-list for extension type_name
	1, // [1:1] is the sub-list for extension extendee
	0, // [0:1] is the sub-list for field type_name
}

func init() { file_block_proto_init() }
func file_block_proto_init() {
	if File_block_proto != nil {
		return
	}
	file_shared_proto_init()
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_block_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_block_proto_goTypes,
		DependencyIndexes: file_block_proto_depIdxs,
		MessageInfos:      file_block_proto_msgTypes,
	}.Build()
	File_block_proto = out.File
	file_block_proto_rawDesc = nil
	file_block_proto_goTypes = nil
	file_block_proto_depIdxs = nil
}
