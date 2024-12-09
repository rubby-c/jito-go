// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.35.2
// 	protoc        v3.21.12
// source: bundle.proto

package jitopb

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

type DroppedReason int32

const (
	DroppedReason_BlockhashExpired DroppedReason = 0
	// One or more transactions in the bundle landed on-chain, invalidating the bundle.
	DroppedReason_PartiallyProcessed DroppedReason = 1
	// This indicates bundle was processed but not finalized. This could occur during forks.
	DroppedReason_NotFinalized DroppedReason = 2
)

// Enum value maps for DroppedReason.
var (
	DroppedReason_name = map[int32]string{
		0: "BlockhashExpired",
		1: "PartiallyProcessed",
		2: "NotFinalized",
	}
	DroppedReason_value = map[string]int32{
		"BlockhashExpired":   0,
		"PartiallyProcessed": 1,
		"NotFinalized":       2,
	}
)

func (x DroppedReason) Enum() *DroppedReason {
	p := new(DroppedReason)
	*p = x
	return p
}

func (x DroppedReason) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (DroppedReason) Descriptor() protoreflect.EnumDescriptor {
	return file_bundle_proto_enumTypes[0].Descriptor()
}

func (DroppedReason) Type() protoreflect.EnumType {
	return &file_bundle_proto_enumTypes[0]
}

func (x DroppedReason) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use DroppedReason.Descriptor instead.
func (DroppedReason) EnumDescriptor() ([]byte, []int) {
	return file_bundle_proto_rawDescGZIP(), []int{0}
}

type Bundle struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Header  *Header   `protobuf:"bytes,2,opt,name=header,proto3" json:"header,omitempty"`
	Packets []*Packet `protobuf:"bytes,3,rep,name=packets,proto3" json:"packets,omitempty"`
}

func (x *Bundle) Reset() {
	*x = Bundle{}
	mi := &file_bundle_proto_msgTypes[0]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *Bundle) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Bundle) ProtoMessage() {}

func (x *Bundle) ProtoReflect() protoreflect.Message {
	mi := &file_bundle_proto_msgTypes[0]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Bundle.ProtoReflect.Descriptor instead.
func (*Bundle) Descriptor() ([]byte, []int) {
	return file_bundle_proto_rawDescGZIP(), []int{0}
}

func (x *Bundle) GetHeader() *Header {
	if x != nil {
		return x.Header
	}
	return nil
}

func (x *Bundle) GetPackets() []*Packet {
	if x != nil {
		return x.Packets
	}
	return nil
}

type BundleUuid struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Bundle *Bundle `protobuf:"bytes,1,opt,name=bundle,proto3" json:"bundle,omitempty"`
	Uuid   string  `protobuf:"bytes,2,opt,name=uuid,proto3" json:"uuid,omitempty"`
}

func (x *BundleUuid) Reset() {
	*x = BundleUuid{}
	mi := &file_bundle_proto_msgTypes[1]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *BundleUuid) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*BundleUuid) ProtoMessage() {}

func (x *BundleUuid) ProtoReflect() protoreflect.Message {
	mi := &file_bundle_proto_msgTypes[1]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use BundleUuid.ProtoReflect.Descriptor instead.
func (*BundleUuid) Descriptor() ([]byte, []int) {
	return file_bundle_proto_rawDescGZIP(), []int{1}
}

func (x *BundleUuid) GetBundle() *Bundle {
	if x != nil {
		return x.Bundle
	}
	return nil
}

func (x *BundleUuid) GetUuid() string {
	if x != nil {
		return x.Uuid
	}
	return ""
}

// Indicates the bundle was accepted and forwarded to a validator.
// NOTE: A single bundle may have multiple events emitted if forwarded to many validators.
type Accepted struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Slot at which bundle was forwarded.
	Slot uint64 `protobuf:"varint,1,opt,name=slot,proto3" json:"slot,omitempty"`
	// Validator identity bundle was forwarded to.
	ValidatorIdentity string `protobuf:"bytes,2,opt,name=validator_identity,json=validatorIdentity,proto3" json:"validator_identity,omitempty"`
}

func (x *Accepted) Reset() {
	*x = Accepted{}
	mi := &file_bundle_proto_msgTypes[2]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *Accepted) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Accepted) ProtoMessage() {}

func (x *Accepted) ProtoReflect() protoreflect.Message {
	mi := &file_bundle_proto_msgTypes[2]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Accepted.ProtoReflect.Descriptor instead.
func (*Accepted) Descriptor() ([]byte, []int) {
	return file_bundle_proto_rawDescGZIP(), []int{2}
}

func (x *Accepted) GetSlot() uint64 {
	if x != nil {
		return x.Slot
	}
	return 0
}

func (x *Accepted) GetValidatorIdentity() string {
	if x != nil {
		return x.ValidatorIdentity
	}
	return ""
}

// Indicates the bundle was dropped and therefore not forwarded to any validator.
type Rejected struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Types that are assignable to Reason:
	//
	//	*Rejected_StateAuctionBidRejected
	//	*Rejected_WinningBatchBidRejected
	//	*Rejected_SimulationFailure
	//	*Rejected_InternalError
	//	*Rejected_DroppedBundle
	Reason isRejected_Reason `protobuf_oneof:"reason"`
}

func (x *Rejected) Reset() {
	*x = Rejected{}
	mi := &file_bundle_proto_msgTypes[3]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *Rejected) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Rejected) ProtoMessage() {}

func (x *Rejected) ProtoReflect() protoreflect.Message {
	mi := &file_bundle_proto_msgTypes[3]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Rejected.ProtoReflect.Descriptor instead.
func (*Rejected) Descriptor() ([]byte, []int) {
	return file_bundle_proto_rawDescGZIP(), []int{3}
}

func (m *Rejected) GetReason() isRejected_Reason {
	if m != nil {
		return m.Reason
	}
	return nil
}

func (x *Rejected) GetStateAuctionBidRejected() *StateAuctionBidRejected {
	if x, ok := x.GetReason().(*Rejected_StateAuctionBidRejected); ok {
		return x.StateAuctionBidRejected
	}
	return nil
}

func (x *Rejected) GetWinningBatchBidRejected() *WinningBatchBidRejected {
	if x, ok := x.GetReason().(*Rejected_WinningBatchBidRejected); ok {
		return x.WinningBatchBidRejected
	}
	return nil
}

func (x *Rejected) GetSimulationFailure() *SimulationFailure {
	if x, ok := x.GetReason().(*Rejected_SimulationFailure); ok {
		return x.SimulationFailure
	}
	return nil
}

func (x *Rejected) GetInternalError() *InternalError {
	if x, ok := x.GetReason().(*Rejected_InternalError); ok {
		return x.InternalError
	}
	return nil
}

func (x *Rejected) GetDroppedBundle() *DroppedBundle {
	if x, ok := x.GetReason().(*Rejected_DroppedBundle); ok {
		return x.DroppedBundle
	}
	return nil
}

type isRejected_Reason interface {
	isRejected_Reason()
}

type Rejected_StateAuctionBidRejected struct {
	StateAuctionBidRejected *StateAuctionBidRejected `protobuf:"bytes,1,opt,name=state_auction_bid_rejected,json=stateAuctionBidRejected,proto3,oneof"`
}

type Rejected_WinningBatchBidRejected struct {
	WinningBatchBidRejected *WinningBatchBidRejected `protobuf:"bytes,2,opt,name=winning_batch_bid_rejected,json=winningBatchBidRejected,proto3,oneof"`
}

type Rejected_SimulationFailure struct {
	SimulationFailure *SimulationFailure `protobuf:"bytes,3,opt,name=simulation_failure,json=simulationFailure,proto3,oneof"`
}

type Rejected_InternalError struct {
	InternalError *InternalError `protobuf:"bytes,4,opt,name=internal_error,json=internalError,proto3,oneof"`
}

type Rejected_DroppedBundle struct {
	DroppedBundle *DroppedBundle `protobuf:"bytes,5,opt,name=dropped_bundle,json=droppedBundle,proto3,oneof"`
}

func (*Rejected_StateAuctionBidRejected) isRejected_Reason() {}

func (*Rejected_WinningBatchBidRejected) isRejected_Reason() {}

func (*Rejected_SimulationFailure) isRejected_Reason() {}

func (*Rejected_InternalError) isRejected_Reason() {}

func (*Rejected_DroppedBundle) isRejected_Reason() {}

// Indicates the bundle's bid was high enough to win its state auction.
// However, not high enough relative to other state auction winners and therefore excluded from being forwarded.
type WinningBatchBidRejected struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Auction's unique identifier.
	AuctionId string `protobuf:"bytes,1,opt,name=auction_id,json=auctionId,proto3" json:"auction_id,omitempty"`
	// Bundle's simulated bid.
	SimulatedBidLamports uint64  `protobuf:"varint,2,opt,name=simulated_bid_lamports,json=simulatedBidLamports,proto3" json:"simulated_bid_lamports,omitempty"`
	Msg                  *string `protobuf:"bytes,3,opt,name=msg,proto3,oneof" json:"msg,omitempty"`
}

func (x *WinningBatchBidRejected) Reset() {
	*x = WinningBatchBidRejected{}
	mi := &file_bundle_proto_msgTypes[4]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *WinningBatchBidRejected) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*WinningBatchBidRejected) ProtoMessage() {}

func (x *WinningBatchBidRejected) ProtoReflect() protoreflect.Message {
	mi := &file_bundle_proto_msgTypes[4]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use WinningBatchBidRejected.ProtoReflect.Descriptor instead.
func (*WinningBatchBidRejected) Descriptor() ([]byte, []int) {
	return file_bundle_proto_rawDescGZIP(), []int{4}
}

func (x *WinningBatchBidRejected) GetAuctionId() string {
	if x != nil {
		return x.AuctionId
	}
	return ""
}

func (x *WinningBatchBidRejected) GetSimulatedBidLamports() uint64 {
	if x != nil {
		return x.SimulatedBidLamports
	}
	return 0
}

func (x *WinningBatchBidRejected) GetMsg() string {
	if x != nil && x.Msg != nil {
		return *x.Msg
	}
	return ""
}

// Indicates the bundle's bid was __not__ high enough to be included in its state auction's set of winners.
type StateAuctionBidRejected struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Auction's unique identifier.
	AuctionId string `protobuf:"bytes,1,opt,name=auction_id,json=auctionId,proto3" json:"auction_id,omitempty"`
	// Bundle's simulated bid.
	SimulatedBidLamports uint64  `protobuf:"varint,2,opt,name=simulated_bid_lamports,json=simulatedBidLamports,proto3" json:"simulated_bid_lamports,omitempty"`
	Msg                  *string `protobuf:"bytes,3,opt,name=msg,proto3,oneof" json:"msg,omitempty"`
}

func (x *StateAuctionBidRejected) Reset() {
	*x = StateAuctionBidRejected{}
	mi := &file_bundle_proto_msgTypes[5]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *StateAuctionBidRejected) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*StateAuctionBidRejected) ProtoMessage() {}

func (x *StateAuctionBidRejected) ProtoReflect() protoreflect.Message {
	mi := &file_bundle_proto_msgTypes[5]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use StateAuctionBidRejected.ProtoReflect.Descriptor instead.
func (*StateAuctionBidRejected) Descriptor() ([]byte, []int) {
	return file_bundle_proto_rawDescGZIP(), []int{5}
}

func (x *StateAuctionBidRejected) GetAuctionId() string {
	if x != nil {
		return x.AuctionId
	}
	return ""
}

func (x *StateAuctionBidRejected) GetSimulatedBidLamports() uint64 {
	if x != nil {
		return x.SimulatedBidLamports
	}
	return 0
}

func (x *StateAuctionBidRejected) GetMsg() string {
	if x != nil && x.Msg != nil {
		return *x.Msg
	}
	return ""
}

// Bundle dropped due to simulation failure.
type SimulationFailure struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Signature of the offending transaction.
	TxSignature string  `protobuf:"bytes,1,opt,name=tx_signature,json=txSignature,proto3" json:"tx_signature,omitempty"`
	Msg         *string `protobuf:"bytes,2,opt,name=msg,proto3,oneof" json:"msg,omitempty"`
}

func (x *SimulationFailure) Reset() {
	*x = SimulationFailure{}
	mi := &file_bundle_proto_msgTypes[6]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *SimulationFailure) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SimulationFailure) ProtoMessage() {}

func (x *SimulationFailure) ProtoReflect() protoreflect.Message {
	mi := &file_bundle_proto_msgTypes[6]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SimulationFailure.ProtoReflect.Descriptor instead.
func (*SimulationFailure) Descriptor() ([]byte, []int) {
	return file_bundle_proto_rawDescGZIP(), []int{6}
}

func (x *SimulationFailure) GetTxSignature() string {
	if x != nil {
		return x.TxSignature
	}
	return ""
}

func (x *SimulationFailure) GetMsg() string {
	if x != nil && x.Msg != nil {
		return *x.Msg
	}
	return ""
}

// Bundle dropped due to an internal error.
type InternalError struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Msg string `protobuf:"bytes,1,opt,name=msg,proto3" json:"msg,omitempty"`
}

func (x *InternalError) Reset() {
	*x = InternalError{}
	mi := &file_bundle_proto_msgTypes[7]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *InternalError) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*InternalError) ProtoMessage() {}

func (x *InternalError) ProtoReflect() protoreflect.Message {
	mi := &file_bundle_proto_msgTypes[7]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use InternalError.ProtoReflect.Descriptor instead.
func (*InternalError) Descriptor() ([]byte, []int) {
	return file_bundle_proto_rawDescGZIP(), []int{7}
}

func (x *InternalError) GetMsg() string {
	if x != nil {
		return x.Msg
	}
	return ""
}

// Bundle dropped (e.g. because no leader upcoming)
type DroppedBundle struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Msg string `protobuf:"bytes,1,opt,name=msg,proto3" json:"msg,omitempty"`
}

func (x *DroppedBundle) Reset() {
	*x = DroppedBundle{}
	mi := &file_bundle_proto_msgTypes[8]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *DroppedBundle) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*DroppedBundle) ProtoMessage() {}

func (x *DroppedBundle) ProtoReflect() protoreflect.Message {
	mi := &file_bundle_proto_msgTypes[8]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use DroppedBundle.ProtoReflect.Descriptor instead.
func (*DroppedBundle) Descriptor() ([]byte, []int) {
	return file_bundle_proto_rawDescGZIP(), []int{8}
}

func (x *DroppedBundle) GetMsg() string {
	if x != nil {
		return x.Msg
	}
	return ""
}

type Finalized struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *Finalized) Reset() {
	*x = Finalized{}
	mi := &file_bundle_proto_msgTypes[9]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *Finalized) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Finalized) ProtoMessage() {}

func (x *Finalized) ProtoReflect() protoreflect.Message {
	mi := &file_bundle_proto_msgTypes[9]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Finalized.ProtoReflect.Descriptor instead.
func (*Finalized) Descriptor() ([]byte, []int) {
	return file_bundle_proto_rawDescGZIP(), []int{9}
}

type Processed struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	ValidatorIdentity string `protobuf:"bytes,1,opt,name=validator_identity,json=validatorIdentity,proto3" json:"validator_identity,omitempty"`
	Slot              uint64 `protobuf:"varint,2,opt,name=slot,proto3" json:"slot,omitempty"`
	// / Index within the block.
	BundleIndex uint64 `protobuf:"varint,3,opt,name=bundle_index,json=bundleIndex,proto3" json:"bundle_index,omitempty"`
}

func (x *Processed) Reset() {
	*x = Processed{}
	mi := &file_bundle_proto_msgTypes[10]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *Processed) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Processed) ProtoMessage() {}

func (x *Processed) ProtoReflect() protoreflect.Message {
	mi := &file_bundle_proto_msgTypes[10]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Processed.ProtoReflect.Descriptor instead.
func (*Processed) Descriptor() ([]byte, []int) {
	return file_bundle_proto_rawDescGZIP(), []int{10}
}

func (x *Processed) GetValidatorIdentity() string {
	if x != nil {
		return x.ValidatorIdentity
	}
	return ""
}

func (x *Processed) GetSlot() uint64 {
	if x != nil {
		return x.Slot
	}
	return 0
}

func (x *Processed) GetBundleIndex() uint64 {
	if x != nil {
		return x.BundleIndex
	}
	return 0
}

type Dropped struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Reason DroppedReason `protobuf:"varint,1,opt,name=reason,proto3,enum=bundle.DroppedReason" json:"reason,omitempty"`
}

func (x *Dropped) Reset() {
	*x = Dropped{}
	mi := &file_bundle_proto_msgTypes[11]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *Dropped) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Dropped) ProtoMessage() {}

func (x *Dropped) ProtoReflect() protoreflect.Message {
	mi := &file_bundle_proto_msgTypes[11]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Dropped.ProtoReflect.Descriptor instead.
func (*Dropped) Descriptor() ([]byte, []int) {
	return file_bundle_proto_rawDescGZIP(), []int{11}
}

func (x *Dropped) GetReason() DroppedReason {
	if x != nil {
		return x.Reason
	}
	return DroppedReason_BlockhashExpired
}

type BundleResult struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Bundle's Uuid.
	BundleId string `protobuf:"bytes,1,opt,name=bundle_id,json=bundleId,proto3" json:"bundle_id,omitempty"`
	// Types that are assignable to Result:
	//
	//	*BundleResult_Accepted
	//	*BundleResult_Rejected
	//	*BundleResult_Finalized
	//	*BundleResult_Processed
	//	*BundleResult_Dropped
	Result isBundleResult_Result `protobuf_oneof:"result"`
}

func (x *BundleResult) Reset() {
	*x = BundleResult{}
	mi := &file_bundle_proto_msgTypes[12]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *BundleResult) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*BundleResult) ProtoMessage() {}

func (x *BundleResult) ProtoReflect() protoreflect.Message {
	mi := &file_bundle_proto_msgTypes[12]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use BundleResult.ProtoReflect.Descriptor instead.
func (*BundleResult) Descriptor() ([]byte, []int) {
	return file_bundle_proto_rawDescGZIP(), []int{12}
}

func (x *BundleResult) GetBundleId() string {
	if x != nil {
		return x.BundleId
	}
	return ""
}

func (m *BundleResult) GetResult() isBundleResult_Result {
	if m != nil {
		return m.Result
	}
	return nil
}

func (x *BundleResult) GetAccepted() *Accepted {
	if x, ok := x.GetResult().(*BundleResult_Accepted); ok {
		return x.Accepted
	}
	return nil
}

func (x *BundleResult) GetRejected() *Rejected {
	if x, ok := x.GetResult().(*BundleResult_Rejected); ok {
		return x.Rejected
	}
	return nil
}

func (x *BundleResult) GetFinalized() *Finalized {
	if x, ok := x.GetResult().(*BundleResult_Finalized); ok {
		return x.Finalized
	}
	return nil
}

func (x *BundleResult) GetProcessed() *Processed {
	if x, ok := x.GetResult().(*BundleResult_Processed); ok {
		return x.Processed
	}
	return nil
}

func (x *BundleResult) GetDropped() *Dropped {
	if x, ok := x.GetResult().(*BundleResult_Dropped); ok {
		return x.Dropped
	}
	return nil
}

type isBundleResult_Result interface {
	isBundleResult_Result()
}

type BundleResult_Accepted struct {
	// Indicated accepted by the block-engine and forwarded to a jito-solana validator.
	Accepted *Accepted `protobuf:"bytes,2,opt,name=accepted,proto3,oneof"`
}

type BundleResult_Rejected struct {
	// Rejected by the block-engine.
	Rejected *Rejected `protobuf:"bytes,3,opt,name=rejected,proto3,oneof"`
}

type BundleResult_Finalized struct {
	// Reached finalized commitment level.
	Finalized *Finalized `protobuf:"bytes,4,opt,name=finalized,proto3,oneof"`
}

type BundleResult_Processed struct {
	// Reached a processed commitment level.
	Processed *Processed `protobuf:"bytes,5,opt,name=processed,proto3,oneof"`
}

type BundleResult_Dropped struct {
	// Was accepted and forwarded by the block-engine but never landed on-chain.
	Dropped *Dropped `protobuf:"bytes,6,opt,name=dropped,proto3,oneof"`
}

func (*BundleResult_Accepted) isBundleResult_Result() {}

func (*BundleResult_Rejected) isBundleResult_Result() {}

func (*BundleResult_Finalized) isBundleResult_Result() {}

func (*BundleResult_Processed) isBundleResult_Result() {}

func (*BundleResult_Dropped) isBundleResult_Result() {}

var File_bundle_proto protoreflect.FileDescriptor

var file_bundle_proto_rawDesc = []byte{
	0x0a, 0x0c, 0x62, 0x75, 0x6e, 0x64, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x06,
	0x62, 0x75, 0x6e, 0x64, 0x6c, 0x65, 0x1a, 0x0c, 0x70, 0x61, 0x63, 0x6b, 0x65, 0x74, 0x2e, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x0c, 0x73, 0x68, 0x61, 0x72, 0x65, 0x64, 0x2e, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x22, 0x5a, 0x0a, 0x06, 0x42, 0x75, 0x6e, 0x64, 0x6c, 0x65, 0x12, 0x26, 0x0a, 0x06,
	0x68, 0x65, 0x61, 0x64, 0x65, 0x72, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x0e, 0x2e, 0x73,
	0x68, 0x61, 0x72, 0x65, 0x64, 0x2e, 0x48, 0x65, 0x61, 0x64, 0x65, 0x72, 0x52, 0x06, 0x68, 0x65,
	0x61, 0x64, 0x65, 0x72, 0x12, 0x28, 0x0a, 0x07, 0x70, 0x61, 0x63, 0x6b, 0x65, 0x74, 0x73, 0x18,
	0x03, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x0e, 0x2e, 0x70, 0x61, 0x63, 0x6b, 0x65, 0x74, 0x2e, 0x50,
	0x61, 0x63, 0x6b, 0x65, 0x74, 0x52, 0x07, 0x70, 0x61, 0x63, 0x6b, 0x65, 0x74, 0x73, 0x22, 0x48,
	0x0a, 0x0a, 0x42, 0x75, 0x6e, 0x64, 0x6c, 0x65, 0x55, 0x75, 0x69, 0x64, 0x12, 0x26, 0x0a, 0x06,
	0x62, 0x75, 0x6e, 0x64, 0x6c, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x0e, 0x2e, 0x62,
	0x75, 0x6e, 0x64, 0x6c, 0x65, 0x2e, 0x42, 0x75, 0x6e, 0x64, 0x6c, 0x65, 0x52, 0x06, 0x62, 0x75,
	0x6e, 0x64, 0x6c, 0x65, 0x12, 0x12, 0x0a, 0x04, 0x75, 0x75, 0x69, 0x64, 0x18, 0x02, 0x20, 0x01,
	0x28, 0x09, 0x52, 0x04, 0x75, 0x75, 0x69, 0x64, 0x22, 0x4d, 0x0a, 0x08, 0x41, 0x63, 0x63, 0x65,
	0x70, 0x74, 0x65, 0x64, 0x12, 0x12, 0x0a, 0x04, 0x73, 0x6c, 0x6f, 0x74, 0x18, 0x01, 0x20, 0x01,
	0x28, 0x04, 0x52, 0x04, 0x73, 0x6c, 0x6f, 0x74, 0x12, 0x2d, 0x0a, 0x12, 0x76, 0x61, 0x6c, 0x69,
	0x64, 0x61, 0x74, 0x6f, 0x72, 0x5f, 0x69, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x74, 0x79, 0x18, 0x02,
	0x20, 0x01, 0x28, 0x09, 0x52, 0x11, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x61, 0x74, 0x6f, 0x72, 0x49,
	0x64, 0x65, 0x6e, 0x74, 0x69, 0x74, 0x79, 0x22, 0xa0, 0x03, 0x0a, 0x08, 0x52, 0x65, 0x6a, 0x65,
	0x63, 0x74, 0x65, 0x64, 0x12, 0x5e, 0x0a, 0x1a, 0x73, 0x74, 0x61, 0x74, 0x65, 0x5f, 0x61, 0x75,
	0x63, 0x74, 0x69, 0x6f, 0x6e, 0x5f, 0x62, 0x69, 0x64, 0x5f, 0x72, 0x65, 0x6a, 0x65, 0x63, 0x74,
	0x65, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1f, 0x2e, 0x62, 0x75, 0x6e, 0x64, 0x6c,
	0x65, 0x2e, 0x53, 0x74, 0x61, 0x74, 0x65, 0x41, 0x75, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x42, 0x69,
	0x64, 0x52, 0x65, 0x6a, 0x65, 0x63, 0x74, 0x65, 0x64, 0x48, 0x00, 0x52, 0x17, 0x73, 0x74, 0x61,
	0x74, 0x65, 0x41, 0x75, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x42, 0x69, 0x64, 0x52, 0x65, 0x6a, 0x65,
	0x63, 0x74, 0x65, 0x64, 0x12, 0x5e, 0x0a, 0x1a, 0x77, 0x69, 0x6e, 0x6e, 0x69, 0x6e, 0x67, 0x5f,
	0x62, 0x61, 0x74, 0x63, 0x68, 0x5f, 0x62, 0x69, 0x64, 0x5f, 0x72, 0x65, 0x6a, 0x65, 0x63, 0x74,
	0x65, 0x64, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1f, 0x2e, 0x62, 0x75, 0x6e, 0x64, 0x6c,
	0x65, 0x2e, 0x57, 0x69, 0x6e, 0x6e, 0x69, 0x6e, 0x67, 0x42, 0x61, 0x74, 0x63, 0x68, 0x42, 0x69,
	0x64, 0x52, 0x65, 0x6a, 0x65, 0x63, 0x74, 0x65, 0x64, 0x48, 0x00, 0x52, 0x17, 0x77, 0x69, 0x6e,
	0x6e, 0x69, 0x6e, 0x67, 0x42, 0x61, 0x74, 0x63, 0x68, 0x42, 0x69, 0x64, 0x52, 0x65, 0x6a, 0x65,
	0x63, 0x74, 0x65, 0x64, 0x12, 0x4a, 0x0a, 0x12, 0x73, 0x69, 0x6d, 0x75, 0x6c, 0x61, 0x74, 0x69,
	0x6f, 0x6e, 0x5f, 0x66, 0x61, 0x69, 0x6c, 0x75, 0x72, 0x65, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0b,
	0x32, 0x19, 0x2e, 0x62, 0x75, 0x6e, 0x64, 0x6c, 0x65, 0x2e, 0x53, 0x69, 0x6d, 0x75, 0x6c, 0x61,
	0x74, 0x69, 0x6f, 0x6e, 0x46, 0x61, 0x69, 0x6c, 0x75, 0x72, 0x65, 0x48, 0x00, 0x52, 0x11, 0x73,
	0x69, 0x6d, 0x75, 0x6c, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x46, 0x61, 0x69, 0x6c, 0x75, 0x72, 0x65,
	0x12, 0x3e, 0x0a, 0x0e, 0x69, 0x6e, 0x74, 0x65, 0x72, 0x6e, 0x61, 0x6c, 0x5f, 0x65, 0x72, 0x72,
	0x6f, 0x72, 0x18, 0x04, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x15, 0x2e, 0x62, 0x75, 0x6e, 0x64, 0x6c,
	0x65, 0x2e, 0x49, 0x6e, 0x74, 0x65, 0x72, 0x6e, 0x61, 0x6c, 0x45, 0x72, 0x72, 0x6f, 0x72, 0x48,
	0x00, 0x52, 0x0d, 0x69, 0x6e, 0x74, 0x65, 0x72, 0x6e, 0x61, 0x6c, 0x45, 0x72, 0x72, 0x6f, 0x72,
	0x12, 0x3e, 0x0a, 0x0e, 0x64, 0x72, 0x6f, 0x70, 0x70, 0x65, 0x64, 0x5f, 0x62, 0x75, 0x6e, 0x64,
	0x6c, 0x65, 0x18, 0x05, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x15, 0x2e, 0x62, 0x75, 0x6e, 0x64, 0x6c,
	0x65, 0x2e, 0x44, 0x72, 0x6f, 0x70, 0x70, 0x65, 0x64, 0x42, 0x75, 0x6e, 0x64, 0x6c, 0x65, 0x48,
	0x00, 0x52, 0x0d, 0x64, 0x72, 0x6f, 0x70, 0x70, 0x65, 0x64, 0x42, 0x75, 0x6e, 0x64, 0x6c, 0x65,
	0x42, 0x08, 0x0a, 0x06, 0x72, 0x65, 0x61, 0x73, 0x6f, 0x6e, 0x22, 0x8d, 0x01, 0x0a, 0x17, 0x57,
	0x69, 0x6e, 0x6e, 0x69, 0x6e, 0x67, 0x42, 0x61, 0x74, 0x63, 0x68, 0x42, 0x69, 0x64, 0x52, 0x65,
	0x6a, 0x65, 0x63, 0x74, 0x65, 0x64, 0x12, 0x1d, 0x0a, 0x0a, 0x61, 0x75, 0x63, 0x74, 0x69, 0x6f,
	0x6e, 0x5f, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x09, 0x61, 0x75, 0x63, 0x74,
	0x69, 0x6f, 0x6e, 0x49, 0x64, 0x12, 0x34, 0x0a, 0x16, 0x73, 0x69, 0x6d, 0x75, 0x6c, 0x61, 0x74,
	0x65, 0x64, 0x5f, 0x62, 0x69, 0x64, 0x5f, 0x6c, 0x61, 0x6d, 0x70, 0x6f, 0x72, 0x74, 0x73, 0x18,
	0x02, 0x20, 0x01, 0x28, 0x04, 0x52, 0x14, 0x73, 0x69, 0x6d, 0x75, 0x6c, 0x61, 0x74, 0x65, 0x64,
	0x42, 0x69, 0x64, 0x4c, 0x61, 0x6d, 0x70, 0x6f, 0x72, 0x74, 0x73, 0x12, 0x15, 0x0a, 0x03, 0x6d,
	0x73, 0x67, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x48, 0x00, 0x52, 0x03, 0x6d, 0x73, 0x67, 0x88,
	0x01, 0x01, 0x42, 0x06, 0x0a, 0x04, 0x5f, 0x6d, 0x73, 0x67, 0x22, 0x8d, 0x01, 0x0a, 0x17, 0x53,
	0x74, 0x61, 0x74, 0x65, 0x41, 0x75, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x42, 0x69, 0x64, 0x52, 0x65,
	0x6a, 0x65, 0x63, 0x74, 0x65, 0x64, 0x12, 0x1d, 0x0a, 0x0a, 0x61, 0x75, 0x63, 0x74, 0x69, 0x6f,
	0x6e, 0x5f, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x09, 0x61, 0x75, 0x63, 0x74,
	0x69, 0x6f, 0x6e, 0x49, 0x64, 0x12, 0x34, 0x0a, 0x16, 0x73, 0x69, 0x6d, 0x75, 0x6c, 0x61, 0x74,
	0x65, 0x64, 0x5f, 0x62, 0x69, 0x64, 0x5f, 0x6c, 0x61, 0x6d, 0x70, 0x6f, 0x72, 0x74, 0x73, 0x18,
	0x02, 0x20, 0x01, 0x28, 0x04, 0x52, 0x14, 0x73, 0x69, 0x6d, 0x75, 0x6c, 0x61, 0x74, 0x65, 0x64,
	0x42, 0x69, 0x64, 0x4c, 0x61, 0x6d, 0x70, 0x6f, 0x72, 0x74, 0x73, 0x12, 0x15, 0x0a, 0x03, 0x6d,
	0x73, 0x67, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x48, 0x00, 0x52, 0x03, 0x6d, 0x73, 0x67, 0x88,
	0x01, 0x01, 0x42, 0x06, 0x0a, 0x04, 0x5f, 0x6d, 0x73, 0x67, 0x22, 0x55, 0x0a, 0x11, 0x53, 0x69,
	0x6d, 0x75, 0x6c, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x46, 0x61, 0x69, 0x6c, 0x75, 0x72, 0x65, 0x12,
	0x21, 0x0a, 0x0c, 0x74, 0x78, 0x5f, 0x73, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x18,
	0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0b, 0x74, 0x78, 0x53, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75,
	0x72, 0x65, 0x12, 0x15, 0x0a, 0x03, 0x6d, 0x73, 0x67, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x48,
	0x00, 0x52, 0x03, 0x6d, 0x73, 0x67, 0x88, 0x01, 0x01, 0x42, 0x06, 0x0a, 0x04, 0x5f, 0x6d, 0x73,
	0x67, 0x22, 0x21, 0x0a, 0x0d, 0x49, 0x6e, 0x74, 0x65, 0x72, 0x6e, 0x61, 0x6c, 0x45, 0x72, 0x72,
	0x6f, 0x72, 0x12, 0x10, 0x0a, 0x03, 0x6d, 0x73, 0x67, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52,
	0x03, 0x6d, 0x73, 0x67, 0x22, 0x21, 0x0a, 0x0d, 0x44, 0x72, 0x6f, 0x70, 0x70, 0x65, 0x64, 0x42,
	0x75, 0x6e, 0x64, 0x6c, 0x65, 0x12, 0x10, 0x0a, 0x03, 0x6d, 0x73, 0x67, 0x18, 0x01, 0x20, 0x01,
	0x28, 0x09, 0x52, 0x03, 0x6d, 0x73, 0x67, 0x22, 0x0b, 0x0a, 0x09, 0x46, 0x69, 0x6e, 0x61, 0x6c,
	0x69, 0x7a, 0x65, 0x64, 0x22, 0x71, 0x0a, 0x09, 0x50, 0x72, 0x6f, 0x63, 0x65, 0x73, 0x73, 0x65,
	0x64, 0x12, 0x2d, 0x0a, 0x12, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x61, 0x74, 0x6f, 0x72, 0x5f, 0x69,
	0x64, 0x65, 0x6e, 0x74, 0x69, 0x74, 0x79, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x11, 0x76,
	0x61, 0x6c, 0x69, 0x64, 0x61, 0x74, 0x6f, 0x72, 0x49, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x74, 0x79,
	0x12, 0x12, 0x0a, 0x04, 0x73, 0x6c, 0x6f, 0x74, 0x18, 0x02, 0x20, 0x01, 0x28, 0x04, 0x52, 0x04,
	0x73, 0x6c, 0x6f, 0x74, 0x12, 0x21, 0x0a, 0x0c, 0x62, 0x75, 0x6e, 0x64, 0x6c, 0x65, 0x5f, 0x69,
	0x6e, 0x64, 0x65, 0x78, 0x18, 0x03, 0x20, 0x01, 0x28, 0x04, 0x52, 0x0b, 0x62, 0x75, 0x6e, 0x64,
	0x6c, 0x65, 0x49, 0x6e, 0x64, 0x65, 0x78, 0x22, 0x38, 0x0a, 0x07, 0x44, 0x72, 0x6f, 0x70, 0x70,
	0x65, 0x64, 0x12, 0x2d, 0x0a, 0x06, 0x72, 0x65, 0x61, 0x73, 0x6f, 0x6e, 0x18, 0x01, 0x20, 0x01,
	0x28, 0x0e, 0x32, 0x15, 0x2e, 0x62, 0x75, 0x6e, 0x64, 0x6c, 0x65, 0x2e, 0x44, 0x72, 0x6f, 0x70,
	0x70, 0x65, 0x64, 0x52, 0x65, 0x61, 0x73, 0x6f, 0x6e, 0x52, 0x06, 0x72, 0x65, 0x61, 0x73, 0x6f,
	0x6e, 0x22, 0xa8, 0x02, 0x0a, 0x0c, 0x42, 0x75, 0x6e, 0x64, 0x6c, 0x65, 0x52, 0x65, 0x73, 0x75,
	0x6c, 0x74, 0x12, 0x1b, 0x0a, 0x09, 0x62, 0x75, 0x6e, 0x64, 0x6c, 0x65, 0x5f, 0x69, 0x64, 0x18,
	0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x08, 0x62, 0x75, 0x6e, 0x64, 0x6c, 0x65, 0x49, 0x64, 0x12,
	0x2e, 0x0a, 0x08, 0x61, 0x63, 0x63, 0x65, 0x70, 0x74, 0x65, 0x64, 0x18, 0x02, 0x20, 0x01, 0x28,
	0x0b, 0x32, 0x10, 0x2e, 0x62, 0x75, 0x6e, 0x64, 0x6c, 0x65, 0x2e, 0x41, 0x63, 0x63, 0x65, 0x70,
	0x74, 0x65, 0x64, 0x48, 0x00, 0x52, 0x08, 0x61, 0x63, 0x63, 0x65, 0x70, 0x74, 0x65, 0x64, 0x12,
	0x2e, 0x0a, 0x08, 0x72, 0x65, 0x6a, 0x65, 0x63, 0x74, 0x65, 0x64, 0x18, 0x03, 0x20, 0x01, 0x28,
	0x0b, 0x32, 0x10, 0x2e, 0x62, 0x75, 0x6e, 0x64, 0x6c, 0x65, 0x2e, 0x52, 0x65, 0x6a, 0x65, 0x63,
	0x74, 0x65, 0x64, 0x48, 0x00, 0x52, 0x08, 0x72, 0x65, 0x6a, 0x65, 0x63, 0x74, 0x65, 0x64, 0x12,
	0x31, 0x0a, 0x09, 0x66, 0x69, 0x6e, 0x61, 0x6c, 0x69, 0x7a, 0x65, 0x64, 0x18, 0x04, 0x20, 0x01,
	0x28, 0x0b, 0x32, 0x11, 0x2e, 0x62, 0x75, 0x6e, 0x64, 0x6c, 0x65, 0x2e, 0x46, 0x69, 0x6e, 0x61,
	0x6c, 0x69, 0x7a, 0x65, 0x64, 0x48, 0x00, 0x52, 0x09, 0x66, 0x69, 0x6e, 0x61, 0x6c, 0x69, 0x7a,
	0x65, 0x64, 0x12, 0x31, 0x0a, 0x09, 0x70, 0x72, 0x6f, 0x63, 0x65, 0x73, 0x73, 0x65, 0x64, 0x18,
	0x05, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x11, 0x2e, 0x62, 0x75, 0x6e, 0x64, 0x6c, 0x65, 0x2e, 0x50,
	0x72, 0x6f, 0x63, 0x65, 0x73, 0x73, 0x65, 0x64, 0x48, 0x00, 0x52, 0x09, 0x70, 0x72, 0x6f, 0x63,
	0x65, 0x73, 0x73, 0x65, 0x64, 0x12, 0x2b, 0x0a, 0x07, 0x64, 0x72, 0x6f, 0x70, 0x70, 0x65, 0x64,
	0x18, 0x06, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x0f, 0x2e, 0x62, 0x75, 0x6e, 0x64, 0x6c, 0x65, 0x2e,
	0x44, 0x72, 0x6f, 0x70, 0x70, 0x65, 0x64, 0x48, 0x00, 0x52, 0x07, 0x64, 0x72, 0x6f, 0x70, 0x70,
	0x65, 0x64, 0x42, 0x08, 0x0a, 0x06, 0x72, 0x65, 0x73, 0x75, 0x6c, 0x74, 0x2a, 0x4f, 0x0a, 0x0d,
	0x44, 0x72, 0x6f, 0x70, 0x70, 0x65, 0x64, 0x52, 0x65, 0x61, 0x73, 0x6f, 0x6e, 0x12, 0x14, 0x0a,
	0x10, 0x42, 0x6c, 0x6f, 0x63, 0x6b, 0x68, 0x61, 0x73, 0x68, 0x45, 0x78, 0x70, 0x69, 0x72, 0x65,
	0x64, 0x10, 0x00, 0x12, 0x16, 0x0a, 0x12, 0x50, 0x61, 0x72, 0x74, 0x69, 0x61, 0x6c, 0x6c, 0x79,
	0x50, 0x72, 0x6f, 0x63, 0x65, 0x73, 0x73, 0x65, 0x64, 0x10, 0x01, 0x12, 0x10, 0x0a, 0x0c, 0x4e,
	0x6f, 0x74, 0x46, 0x69, 0x6e, 0x61, 0x6c, 0x69, 0x7a, 0x65, 0x64, 0x10, 0x02, 0x62, 0x06, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_bundle_proto_rawDescOnce sync.Once
	file_bundle_proto_rawDescData = file_bundle_proto_rawDesc
)

func file_bundle_proto_rawDescGZIP() []byte {
	file_bundle_proto_rawDescOnce.Do(func() {
		file_bundle_proto_rawDescData = protoimpl.X.CompressGZIP(file_bundle_proto_rawDescData)
	})
	return file_bundle_proto_rawDescData
}

var file_bundle_proto_enumTypes = make([]protoimpl.EnumInfo, 1)
var file_bundle_proto_msgTypes = make([]protoimpl.MessageInfo, 13)
var file_bundle_proto_goTypes = []any{
	(DroppedReason)(0),              // 0: bundle.DroppedReason
	(*Bundle)(nil),                  // 1: bundle.Bundle
	(*BundleUuid)(nil),              // 2: bundle.BundleUuid
	(*Accepted)(nil),                // 3: bundle.Accepted
	(*Rejected)(nil),                // 4: bundle.Rejected
	(*WinningBatchBidRejected)(nil), // 5: bundle.WinningBatchBidRejected
	(*StateAuctionBidRejected)(nil), // 6: bundle.StateAuctionBidRejected
	(*SimulationFailure)(nil),       // 7: bundle.SimulationFailure
	(*InternalError)(nil),           // 8: bundle.InternalError
	(*DroppedBundle)(nil),           // 9: bundle.DroppedBundle
	(*Finalized)(nil),               // 10: bundle.Finalized
	(*Processed)(nil),               // 11: bundle.Processed
	(*Dropped)(nil),                 // 12: bundle.Dropped
	(*BundleResult)(nil),            // 13: bundle.BundleResult
	(*Header)(nil),                  // 14: shared.Header
	(*Packet)(nil),                  // 15: packet.Packet
}
var file_bundle_proto_depIdxs = []int32{
	14, // 0: bundle.Bundle.header:type_name -> shared.Header
	15, // 1: bundle.Bundle.packets:type_name -> packet.Packet
	1,  // 2: bundle.BundleUuid.bundle:type_name -> bundle.Bundle
	6,  // 3: bundle.Rejected.state_auction_bid_rejected:type_name -> bundle.StateAuctionBidRejected
	5,  // 4: bundle.Rejected.winning_batch_bid_rejected:type_name -> bundle.WinningBatchBidRejected
	7,  // 5: bundle.Rejected.simulation_failure:type_name -> bundle.SimulationFailure
	8,  // 6: bundle.Rejected.internal_error:type_name -> bundle.InternalError
	9,  // 7: bundle.Rejected.dropped_bundle:type_name -> bundle.DroppedBundle
	0,  // 8: bundle.Dropped.reason:type_name -> bundle.DroppedReason
	3,  // 9: bundle.BundleResult.accepted:type_name -> bundle.Accepted
	4,  // 10: bundle.BundleResult.rejected:type_name -> bundle.Rejected
	10, // 11: bundle.BundleResult.finalized:type_name -> bundle.Finalized
	11, // 12: bundle.BundleResult.processed:type_name -> bundle.Processed
	12, // 13: bundle.BundleResult.dropped:type_name -> bundle.Dropped
	14, // [14:14] is the sub-list for method output_type
	14, // [14:14] is the sub-list for method input_type
	14, // [14:14] is the sub-list for extension type_name
	14, // [14:14] is the sub-list for extension extendee
	0,  // [0:14] is the sub-list for field type_name
}

func init() { file_bundle_proto_init() }
func file_bundle_proto_init() {
	if File_bundle_proto != nil {
		return
	}
	file_packet_proto_init()
	file_shared_proto_init()
	file_bundle_proto_msgTypes[3].OneofWrappers = []any{
		(*Rejected_StateAuctionBidRejected)(nil),
		(*Rejected_WinningBatchBidRejected)(nil),
		(*Rejected_SimulationFailure)(nil),
		(*Rejected_InternalError)(nil),
		(*Rejected_DroppedBundle)(nil),
	}
	file_bundle_proto_msgTypes[4].OneofWrappers = []any{}
	file_bundle_proto_msgTypes[5].OneofWrappers = []any{}
	file_bundle_proto_msgTypes[6].OneofWrappers = []any{}
	file_bundle_proto_msgTypes[12].OneofWrappers = []any{
		(*BundleResult_Accepted)(nil),
		(*BundleResult_Rejected)(nil),
		(*BundleResult_Finalized)(nil),
		(*BundleResult_Processed)(nil),
		(*BundleResult_Dropped)(nil),
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_bundle_proto_rawDesc,
			NumEnums:      1,
			NumMessages:   13,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_bundle_proto_goTypes,
		DependencyIndexes: file_bundle_proto_depIdxs,
		EnumInfos:         file_bundle_proto_enumTypes,
		MessageInfos:      file_bundle_proto_msgTypes,
	}.Build()
	File_bundle_proto = out.File
	file_bundle_proto_rawDesc = nil
	file_bundle_proto_goTypes = nil
	file_bundle_proto_depIdxs = nil
}
