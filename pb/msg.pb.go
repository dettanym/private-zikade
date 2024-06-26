// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.33.0
// 	protoc        v3.20.3
// source: msg.proto

package pb

import (
	pb "github.com/libp2p/go-libp2p-record/pb"
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

// MessageType represents the type of RPC being called. Based on the message
// type different fields of this message will be populated. The response
// of a message with a certain type will have the same type.
type Message_MessageType int32

const (
	Message_PUT_VALUE             Message_MessageType = 0
	Message_GET_VALUE             Message_MessageType = 1
	Message_ADD_PROVIDER          Message_MessageType = 2
	Message_GET_PROVIDERS         Message_MessageType = 3
	Message_FIND_NODE             Message_MessageType = 4
	Message_PING                  Message_MessageType = 5
	Message_PRIVATE_FIND_NODE     Message_MessageType = 32
	Message_PRIVATE_GET_PROVIDERS Message_MessageType = 33
)

// Enum value maps for Message_MessageType.
var (
	Message_MessageType_name = map[int32]string{
		0:  "PUT_VALUE",
		1:  "GET_VALUE",
		2:  "ADD_PROVIDER",
		3:  "GET_PROVIDERS",
		4:  "FIND_NODE",
		5:  "PING",
		32: "PRIVATE_FIND_NODE",
		33: "PRIVATE_GET_PROVIDERS",
	}
	Message_MessageType_value = map[string]int32{
		"PUT_VALUE":             0,
		"GET_VALUE":             1,
		"ADD_PROVIDER":          2,
		"GET_PROVIDERS":         3,
		"FIND_NODE":             4,
		"PING":                  5,
		"PRIVATE_FIND_NODE":     32,
		"PRIVATE_GET_PROVIDERS": 33,
	}
)

func (x Message_MessageType) Enum() *Message_MessageType {
	p := new(Message_MessageType)
	*p = x
	return p
}

func (x Message_MessageType) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (Message_MessageType) Descriptor() protoreflect.EnumDescriptor {
	return file_msg_proto_enumTypes[0].Descriptor()
}

func (Message_MessageType) Type() protoreflect.EnumType {
	return &file_msg_proto_enumTypes[0]
}

func (x Message_MessageType) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use Message_MessageType.Descriptor instead.
func (Message_MessageType) EnumDescriptor() ([]byte, []int) {
	return file_msg_proto_rawDescGZIP(), []int{0, 0}
}

type Message_ConnectionType int32

const (
	// sender does not have a connection to peer, and no extra information (default)
	Message_NOT_CONNECTED Message_ConnectionType = 0
	// sender has a live connection to peer
	Message_CONNECTED Message_ConnectionType = 1
	// sender recently connected to peer
	Message_CAN_CONNECT Message_ConnectionType = 2
	// sender recently tried to connect to peer repeatedly but failed to connect
	// ("try" here is loose, but this should signal "made strong effort, failed")
	Message_CANNOT_CONNECT Message_ConnectionType = 3
)

// Enum value maps for Message_ConnectionType.
var (
	Message_ConnectionType_name = map[int32]string{
		0: "NOT_CONNECTED",
		1: "CONNECTED",
		2: "CAN_CONNECT",
		3: "CANNOT_CONNECT",
	}
	Message_ConnectionType_value = map[string]int32{
		"NOT_CONNECTED":  0,
		"CONNECTED":      1,
		"CAN_CONNECT":    2,
		"CANNOT_CONNECT": 3,
	}
)

func (x Message_ConnectionType) Enum() *Message_ConnectionType {
	p := new(Message_ConnectionType)
	*p = x
	return p
}

func (x Message_ConnectionType) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (Message_ConnectionType) Descriptor() protoreflect.EnumDescriptor {
	return file_msg_proto_enumTypes[1].Descriptor()
}

func (Message_ConnectionType) Type() protoreflect.EnumType {
	return &file_msg_proto_enumTypes[1]
}

func (x Message_ConnectionType) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use Message_ConnectionType.Descriptor instead.
func (Message_ConnectionType) EnumDescriptor() ([]byte, []int) {
	return file_msg_proto_rawDescGZIP(), []int{0, 1}
}

// Message is the top-level envelope for exchanging
// information with the DHT protocol.
type Message struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Buckets []*Message_CIDToProviderMap `protobuf:"bytes,20,rep,name=buckets,proto3" json:"buckets,omitempty"`
	// defines what type of message it is.
	Type Message_MessageType `protobuf:"varint,1,opt,name=type,proto3,enum=dht.pb.Message_MessageType" json:"type,omitempty"`
	// defines what coral cluster level this query/response belongs to.
	// in case we want to implement coral's cluster rings in the future.
	//
	// Deprecated: Marked as deprecated in msg.proto.
	ClusterLevelRaw int32 `protobuf:"varint,10,opt,name=cluster_level_raw,json=clusterLevelRaw,proto3" json:"cluster_level_raw,omitempty"`
	// Used to specify the key associated with this message.
	// PUT_VALUE, GET_VALUE, ADD_PROVIDER, GET_PROVIDERS
	Key []byte `protobuf:"bytes,2,opt,name=key,proto3" json:"key,omitempty"`
	// Used to return a value
	// PUT_VALUE, GET_VALUE
	Record *pb.Record `protobuf:"bytes,3,opt,name=record,proto3" json:"record,omitempty"`
	// Used to return peers closer to a key in a query
	// GET_VALUE, GET_PROVIDERS, FIND_NODE
	CloserPeers []*Message_Peer `protobuf:"bytes,8,rep,name=closer_peers,json=closerPeers,proto3" json:"closer_peers,omitempty"`
	// Used to return Providers
	// GET_VALUE, ADD_PROVIDER, GET_PROVIDERS
	ProviderPeers []*Message_Peer `protobuf:"bytes,9,rep,name=provider_peers,json=providerPeers,proto3" json:"provider_peers,omitempty"`
	// PIR_Message_ID should just be a nonce. It is used as a request ID.
	// Does not correspond to any keys in the Kademlia ID or peer ID spaces.
	PIR_Message_ID        int64         `protobuf:"varint,30,opt,name=PIR_Message_ID,json=PIRMessageID,proto3" json:"PIR_Message_ID,omitempty"`
	CloserPeersRequest    *PIR_Request  `protobuf:"bytes,32,opt,name=closer_peers_request,json=closerPeersRequest,proto3" json:"closer_peers_request,omitempty"`
	ProviderPeersRequest  *PIR_Request  `protobuf:"bytes,33,opt,name=provider_peers_request,json=providerPeersRequest,proto3" json:"provider_peers_request,omitempty"`
	CloserPeersResponse   *PIR_Response `protobuf:"bytes,34,opt,name=closer_peers_response,json=closerPeersResponse,proto3" json:"closer_peers_response,omitempty"`
	ProviderPeersResponse *PIR_Response `protobuf:"bytes,35,opt,name=provider_peers_response,json=providerPeersResponse,proto3" json:"provider_peers_response,omitempty"`
}

func (x *Message) Reset() {
	*x = Message{}
	if protoimpl.UnsafeEnabled {
		mi := &file_msg_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Message) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Message) ProtoMessage() {}

func (x *Message) ProtoReflect() protoreflect.Message {
	mi := &file_msg_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Message.ProtoReflect.Descriptor instead.
func (*Message) Descriptor() ([]byte, []int) {
	return file_msg_proto_rawDescGZIP(), []int{0}
}

func (x *Message) GetBuckets() []*Message_CIDToProviderMap {
	if x != nil {
		return x.Buckets
	}
	return nil
}

func (x *Message) GetType() Message_MessageType {
	if x != nil {
		return x.Type
	}
	return Message_PUT_VALUE
}

// Deprecated: Marked as deprecated in msg.proto.
func (x *Message) GetClusterLevelRaw() int32 {
	if x != nil {
		return x.ClusterLevelRaw
	}
	return 0
}

func (x *Message) GetKey() []byte {
	if x != nil {
		return x.Key
	}
	return nil
}

func (x *Message) GetRecord() *pb.Record {
	if x != nil {
		return x.Record
	}
	return nil
}

func (x *Message) GetCloserPeers() []*Message_Peer {
	if x != nil {
		return x.CloserPeers
	}
	return nil
}

func (x *Message) GetProviderPeers() []*Message_Peer {
	if x != nil {
		return x.ProviderPeers
	}
	return nil
}

func (x *Message) GetPIR_Message_ID() int64 {
	if x != nil {
		return x.PIR_Message_ID
	}
	return 0
}

func (x *Message) GetCloserPeersRequest() *PIR_Request {
	if x != nil {
		return x.CloserPeersRequest
	}
	return nil
}

func (x *Message) GetProviderPeersRequest() *PIR_Request {
	if x != nil {
		return x.ProviderPeersRequest
	}
	return nil
}

func (x *Message) GetCloserPeersResponse() *PIR_Response {
	if x != nil {
		return x.CloserPeersResponse
	}
	return nil
}

func (x *Message) GetProviderPeersResponse() *PIR_Response {
	if x != nil {
		return x.ProviderPeersResponse
	}
	return nil
}

type PIR_Request struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Log2NumRows int64  `protobuf:"varint,1,opt,name=log2_num_rows,json=log2NumRows,proto3" json:"log2_num_rows,omitempty"`
	Parameters  []byte `protobuf:"bytes,2,opt,name=parameters,proto3" json:"parameters,omitempty"`
	// Types that are assignable to SchemeDependent:
	//
	//	*PIR_Request_RLWEEvaluationKeys
	//	*PIR_Request_Paillier_Public_Key
	//	*PIR_Request_OtherKeys
	SchemeDependent        isPIR_Request_SchemeDependent `protobuf_oneof:"SchemeDependent"`
	EncryptedQuery         []byte                        `protobuf:"bytes,3,opt,name=encrypted_query,json=encryptedQuery,proto3" json:"encrypted_query,omitempty"`
	EncryptedPaillierQuery [][]byte                      `protobuf:"bytes,4,rep,name=encrypted_paillier_query,json=encryptedPaillierQuery,proto3" json:"encrypted_paillier_query,omitempty"`
}

func (x *PIR_Request) Reset() {
	*x = PIR_Request{}
	if protoimpl.UnsafeEnabled {
		mi := &file_msg_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *PIR_Request) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*PIR_Request) ProtoMessage() {}

func (x *PIR_Request) ProtoReflect() protoreflect.Message {
	mi := &file_msg_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use PIR_Request.ProtoReflect.Descriptor instead.
func (*PIR_Request) Descriptor() ([]byte, []int) {
	return file_msg_proto_rawDescGZIP(), []int{1}
}

func (x *PIR_Request) GetLog2NumRows() int64 {
	if x != nil {
		return x.Log2NumRows
	}
	return 0
}

func (x *PIR_Request) GetParameters() []byte {
	if x != nil {
		return x.Parameters
	}
	return nil
}

func (m *PIR_Request) GetSchemeDependent() isPIR_Request_SchemeDependent {
	if m != nil {
		return m.SchemeDependent
	}
	return nil
}

func (x *PIR_Request) GetRLWEEvaluationKeys() []byte {
	if x, ok := x.GetSchemeDependent().(*PIR_Request_RLWEEvaluationKeys); ok {
		return x.RLWEEvaluationKeys
	}
	return nil
}

func (x *PIR_Request) GetPaillier_Public_Key() *Paillier_Public_Key {
	if x, ok := x.GetSchemeDependent().(*PIR_Request_Paillier_Public_Key); ok {
		return x.Paillier_Public_Key
	}
	return nil
}

func (x *PIR_Request) GetOtherKeys() []byte {
	if x, ok := x.GetSchemeDependent().(*PIR_Request_OtherKeys); ok {
		return x.OtherKeys
	}
	return nil
}

func (x *PIR_Request) GetEncryptedQuery() []byte {
	if x != nil {
		return x.EncryptedQuery
	}
	return nil
}

func (x *PIR_Request) GetEncryptedPaillierQuery() [][]byte {
	if x != nil {
		return x.EncryptedPaillierQuery
	}
	return nil
}

type isPIR_Request_SchemeDependent interface {
	isPIR_Request_SchemeDependent()
}

type PIR_Request_RLWEEvaluationKeys struct {
	RLWEEvaluationKeys []byte `protobuf:"bytes,10,opt,name=RLWE_evaluation_keys,json=RLWEEvaluationKeys,proto3,oneof"`
}

type PIR_Request_Paillier_Public_Key struct {
	Paillier_Public_Key *Paillier_Public_Key `protobuf:"bytes,11,opt,name=Paillier_Public_Key,json=PaillierPublicKey,proto3,oneof"`
}

type PIR_Request_OtherKeys struct {
	OtherKeys []byte `protobuf:"bytes,21,opt,name=other_keys,json=otherKeys,proto3,oneof"`
}

func (*PIR_Request_RLWEEvaluationKeys) isPIR_Request_SchemeDependent() {}

func (*PIR_Request_Paillier_Public_Key) isPIR_Request_SchemeDependent() {}

func (*PIR_Request_OtherKeys) isPIR_Request_SchemeDependent() {}

type PIR_Response struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Ciphertexts               []byte   `protobuf:"bytes,1,opt,name=ciphertexts,proto3" json:"ciphertexts,omitempty"`
	EncryptedPaillierResponse [][]byte `protobuf:"bytes,2,rep,name=encrypted_paillier_response,json=encryptedPaillierResponse,proto3" json:"encrypted_paillier_response,omitempty"`
}

func (x *PIR_Response) Reset() {
	*x = PIR_Response{}
	if protoimpl.UnsafeEnabled {
		mi := &file_msg_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *PIR_Response) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*PIR_Response) ProtoMessage() {}

func (x *PIR_Response) ProtoReflect() protoreflect.Message {
	mi := &file_msg_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use PIR_Response.ProtoReflect.Descriptor instead.
func (*PIR_Response) Descriptor() ([]byte, []int) {
	return file_msg_proto_rawDescGZIP(), []int{2}
}

func (x *PIR_Response) GetCiphertexts() []byte {
	if x != nil {
		return x.Ciphertexts
	}
	return nil
}

func (x *PIR_Response) GetEncryptedPaillierResponse() [][]byte {
	if x != nil {
		return x.EncryptedPaillierResponse
	}
	return nil
}

type Paillier_Public_Key struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	N      []byte `protobuf:"bytes,1,opt,name=n,proto3" json:"n,omitempty"`
	G      []byte `protobuf:"bytes,2,opt,name=g,proto3" json:"g,omitempty"`
	Length int64  `protobuf:"varint,3,opt,name=length,proto3" json:"length,omitempty"`
}

func (x *Paillier_Public_Key) Reset() {
	*x = Paillier_Public_Key{}
	if protoimpl.UnsafeEnabled {
		mi := &file_msg_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Paillier_Public_Key) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Paillier_Public_Key) ProtoMessage() {}

func (x *Paillier_Public_Key) ProtoReflect() protoreflect.Message {
	mi := &file_msg_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Paillier_Public_Key.ProtoReflect.Descriptor instead.
func (*Paillier_Public_Key) Descriptor() ([]byte, []int) {
	return file_msg_proto_rawDescGZIP(), []int{3}
}

func (x *Paillier_Public_Key) GetN() []byte {
	if x != nil {
		return x.N
	}
	return nil
}

func (x *Paillier_Public_Key) GetG() []byte {
	if x != nil {
		return x.G
	}
	return nil
}

func (x *Paillier_Public_Key) GetLength() int64 {
	if x != nil {
		return x.Length
	}
	return 0
}

type Message_Peer struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// ID of a given peer.
	Id []byte `protobuf:"bytes,1,opt,name=id,proto3" json:"id,omitempty"`
	// multiaddrs for a given peer
	Addrs [][]byte `protobuf:"bytes,2,rep,name=addrs,proto3" json:"addrs,omitempty"`
	// used to signal the sender's connection capabilities to the peer
	Connection Message_ConnectionType `protobuf:"varint,3,opt,name=connection,proto3,enum=dht.pb.Message_ConnectionType" json:"connection,omitempty"`
}

func (x *Message_Peer) Reset() {
	*x = Message_Peer{}
	if protoimpl.UnsafeEnabled {
		mi := &file_msg_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Message_Peer) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Message_Peer) ProtoMessage() {}

func (x *Message_Peer) ProtoReflect() protoreflect.Message {
	mi := &file_msg_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Message_Peer.ProtoReflect.Descriptor instead.
func (*Message_Peer) Descriptor() ([]byte, []int) {
	return file_msg_proto_rawDescGZIP(), []int{0, 0}
}

func (x *Message_Peer) GetId() []byte {
	if x != nil {
		return x.Id
	}
	return nil
}

func (x *Message_Peer) GetAddrs() [][]byte {
	if x != nil {
		return x.Addrs
	}
	return nil
}

func (x *Message_Peer) GetConnection() Message_ConnectionType {
	if x != nil {
		return x.Connection
	}
	return Message_NOT_CONNECTED
}

type Message_CIDToProviderMap struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Cid           []byte          `protobuf:"bytes,1,opt,name=cid,proto3" json:"cid,omitempty"`
	ProviderPeers []*Message_Peer `protobuf:"bytes,2,rep,name=provider_peers,json=providerPeers,proto3" json:"provider_peers,omitempty"`
}

func (x *Message_CIDToProviderMap) Reset() {
	*x = Message_CIDToProviderMap{}
	if protoimpl.UnsafeEnabled {
		mi := &file_msg_proto_msgTypes[5]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Message_CIDToProviderMap) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Message_CIDToProviderMap) ProtoMessage() {}

func (x *Message_CIDToProviderMap) ProtoReflect() protoreflect.Message {
	mi := &file_msg_proto_msgTypes[5]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Message_CIDToProviderMap.ProtoReflect.Descriptor instead.
func (*Message_CIDToProviderMap) Descriptor() ([]byte, []int) {
	return file_msg_proto_rawDescGZIP(), []int{0, 1}
}

func (x *Message_CIDToProviderMap) GetCid() []byte {
	if x != nil {
		return x.Cid
	}
	return nil
}

func (x *Message_CIDToProviderMap) GetProviderPeers() []*Message_Peer {
	if x != nil {
		return x.ProviderPeers
	}
	return nil
}

var File_msg_proto protoreflect.FileDescriptor

var file_msg_proto_rawDesc = []byte{
	0x0a, 0x09, 0x6d, 0x73, 0x67, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x06, 0x64, 0x68, 0x74,
	0x2e, 0x70, 0x62, 0x1a, 0x32, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f,
	0x6c, 0x69, 0x62, 0x70, 0x32, 0x70, 0x2f, 0x67, 0x6f, 0x2d, 0x6c, 0x69, 0x62, 0x70, 0x32, 0x70,
	0x2d, 0x72, 0x65, 0x63, 0x6f, 0x72, 0x64, 0x2f, 0x70, 0x62, 0x2f, 0x72, 0x65, 0x63, 0x6f, 0x72,
	0x64, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0xf1, 0x08, 0x0a, 0x07, 0x4d, 0x65, 0x73, 0x73,
	0x61, 0x67, 0x65, 0x12, 0x3a, 0x0a, 0x07, 0x62, 0x75, 0x63, 0x6b, 0x65, 0x74, 0x73, 0x18, 0x14,
	0x20, 0x03, 0x28, 0x0b, 0x32, 0x20, 0x2e, 0x64, 0x68, 0x74, 0x2e, 0x70, 0x62, 0x2e, 0x4d, 0x65,
	0x73, 0x73, 0x61, 0x67, 0x65, 0x2e, 0x43, 0x49, 0x44, 0x54, 0x6f, 0x50, 0x72, 0x6f, 0x76, 0x69,
	0x64, 0x65, 0x72, 0x4d, 0x61, 0x70, 0x52, 0x07, 0x62, 0x75, 0x63, 0x6b, 0x65, 0x74, 0x73, 0x12,
	0x2f, 0x0a, 0x04, 0x74, 0x79, 0x70, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0e, 0x32, 0x1b, 0x2e,
	0x64, 0x68, 0x74, 0x2e, 0x70, 0x62, 0x2e, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x2e, 0x4d,
	0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x54, 0x79, 0x70, 0x65, 0x52, 0x04, 0x74, 0x79, 0x70, 0x65,
	0x12, 0x2e, 0x0a, 0x11, 0x63, 0x6c, 0x75, 0x73, 0x74, 0x65, 0x72, 0x5f, 0x6c, 0x65, 0x76, 0x65,
	0x6c, 0x5f, 0x72, 0x61, 0x77, 0x18, 0x0a, 0x20, 0x01, 0x28, 0x05, 0x42, 0x02, 0x18, 0x01, 0x52,
	0x0f, 0x63, 0x6c, 0x75, 0x73, 0x74, 0x65, 0x72, 0x4c, 0x65, 0x76, 0x65, 0x6c, 0x52, 0x61, 0x77,
	0x12, 0x10, 0x0a, 0x03, 0x6b, 0x65, 0x79, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x03, 0x6b,
	0x65, 0x79, 0x12, 0x29, 0x0a, 0x06, 0x72, 0x65, 0x63, 0x6f, 0x72, 0x64, 0x18, 0x03, 0x20, 0x01,
	0x28, 0x0b, 0x32, 0x11, 0x2e, 0x72, 0x65, 0x63, 0x6f, 0x72, 0x64, 0x2e, 0x70, 0x62, 0x2e, 0x52,
	0x65, 0x63, 0x6f, 0x72, 0x64, 0x52, 0x06, 0x72, 0x65, 0x63, 0x6f, 0x72, 0x64, 0x12, 0x37, 0x0a,
	0x0c, 0x63, 0x6c, 0x6f, 0x73, 0x65, 0x72, 0x5f, 0x70, 0x65, 0x65, 0x72, 0x73, 0x18, 0x08, 0x20,
	0x03, 0x28, 0x0b, 0x32, 0x14, 0x2e, 0x64, 0x68, 0x74, 0x2e, 0x70, 0x62, 0x2e, 0x4d, 0x65, 0x73,
	0x73, 0x61, 0x67, 0x65, 0x2e, 0x50, 0x65, 0x65, 0x72, 0x52, 0x0b, 0x63, 0x6c, 0x6f, 0x73, 0x65,
	0x72, 0x50, 0x65, 0x65, 0x72, 0x73, 0x12, 0x3b, 0x0a, 0x0e, 0x70, 0x72, 0x6f, 0x76, 0x69, 0x64,
	0x65, 0x72, 0x5f, 0x70, 0x65, 0x65, 0x72, 0x73, 0x18, 0x09, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x14,
	0x2e, 0x64, 0x68, 0x74, 0x2e, 0x70, 0x62, 0x2e, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x2e,
	0x50, 0x65, 0x65, 0x72, 0x52, 0x0d, 0x70, 0x72, 0x6f, 0x76, 0x69, 0x64, 0x65, 0x72, 0x50, 0x65,
	0x65, 0x72, 0x73, 0x12, 0x24, 0x0a, 0x0e, 0x50, 0x49, 0x52, 0x5f, 0x4d, 0x65, 0x73, 0x73, 0x61,
	0x67, 0x65, 0x5f, 0x49, 0x44, 0x18, 0x1e, 0x20, 0x01, 0x28, 0x03, 0x52, 0x0c, 0x50, 0x49, 0x52,
	0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x49, 0x44, 0x12, 0x45, 0x0a, 0x14, 0x63, 0x6c, 0x6f,
	0x73, 0x65, 0x72, 0x5f, 0x70, 0x65, 0x65, 0x72, 0x73, 0x5f, 0x72, 0x65, 0x71, 0x75, 0x65, 0x73,
	0x74, 0x18, 0x20, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x13, 0x2e, 0x64, 0x68, 0x74, 0x2e, 0x70, 0x62,
	0x2e, 0x50, 0x49, 0x52, 0x5f, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x52, 0x12, 0x63, 0x6c,
	0x6f, 0x73, 0x65, 0x72, 0x50, 0x65, 0x65, 0x72, 0x73, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74,
	0x12, 0x49, 0x0a, 0x16, 0x70, 0x72, 0x6f, 0x76, 0x69, 0x64, 0x65, 0x72, 0x5f, 0x70, 0x65, 0x65,
	0x72, 0x73, 0x5f, 0x72, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x18, 0x21, 0x20, 0x01, 0x28, 0x0b,
	0x32, 0x13, 0x2e, 0x64, 0x68, 0x74, 0x2e, 0x70, 0x62, 0x2e, 0x50, 0x49, 0x52, 0x5f, 0x52, 0x65,
	0x71, 0x75, 0x65, 0x73, 0x74, 0x52, 0x14, 0x70, 0x72, 0x6f, 0x76, 0x69, 0x64, 0x65, 0x72, 0x50,
	0x65, 0x65, 0x72, 0x73, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x48, 0x0a, 0x15, 0x63,
	0x6c, 0x6f, 0x73, 0x65, 0x72, 0x5f, 0x70, 0x65, 0x65, 0x72, 0x73, 0x5f, 0x72, 0x65, 0x73, 0x70,
	0x6f, 0x6e, 0x73, 0x65, 0x18, 0x22, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x14, 0x2e, 0x64, 0x68, 0x74,
	0x2e, 0x70, 0x62, 0x2e, 0x50, 0x49, 0x52, 0x5f, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65,
	0x52, 0x13, 0x63, 0x6c, 0x6f, 0x73, 0x65, 0x72, 0x50, 0x65, 0x65, 0x72, 0x73, 0x52, 0x65, 0x73,
	0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x4c, 0x0a, 0x17, 0x70, 0x72, 0x6f, 0x76, 0x69, 0x64, 0x65,
	0x72, 0x5f, 0x70, 0x65, 0x65, 0x72, 0x73, 0x5f, 0x72, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65,
	0x18, 0x23, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x14, 0x2e, 0x64, 0x68, 0x74, 0x2e, 0x70, 0x62, 0x2e,
	0x50, 0x49, 0x52, 0x5f, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x52, 0x15, 0x70, 0x72,
	0x6f, 0x76, 0x69, 0x64, 0x65, 0x72, 0x50, 0x65, 0x65, 0x72, 0x73, 0x52, 0x65, 0x73, 0x70, 0x6f,
	0x6e, 0x73, 0x65, 0x1a, 0x6c, 0x0a, 0x04, 0x50, 0x65, 0x65, 0x72, 0x12, 0x0e, 0x0a, 0x02, 0x69,
	0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x02, 0x69, 0x64, 0x12, 0x14, 0x0a, 0x05, 0x61,
	0x64, 0x64, 0x72, 0x73, 0x18, 0x02, 0x20, 0x03, 0x28, 0x0c, 0x52, 0x05, 0x61, 0x64, 0x64, 0x72,
	0x73, 0x12, 0x3e, 0x0a, 0x0a, 0x63, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x18,
	0x03, 0x20, 0x01, 0x28, 0x0e, 0x32, 0x1e, 0x2e, 0x64, 0x68, 0x74, 0x2e, 0x70, 0x62, 0x2e, 0x4d,
	0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x2e, 0x43, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x69, 0x6f,
	0x6e, 0x54, 0x79, 0x70, 0x65, 0x52, 0x0a, 0x63, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x69, 0x6f,
	0x6e, 0x1a, 0x61, 0x0a, 0x10, 0x43, 0x49, 0x44, 0x54, 0x6f, 0x50, 0x72, 0x6f, 0x76, 0x69, 0x64,
	0x65, 0x72, 0x4d, 0x61, 0x70, 0x12, 0x10, 0x0a, 0x03, 0x63, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01,
	0x28, 0x0c, 0x52, 0x03, 0x63, 0x69, 0x64, 0x12, 0x3b, 0x0a, 0x0e, 0x70, 0x72, 0x6f, 0x76, 0x69,
	0x64, 0x65, 0x72, 0x5f, 0x70, 0x65, 0x65, 0x72, 0x73, 0x18, 0x02, 0x20, 0x03, 0x28, 0x0b, 0x32,
	0x14, 0x2e, 0x64, 0x68, 0x74, 0x2e, 0x70, 0x62, 0x2e, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65,
	0x2e, 0x50, 0x65, 0x65, 0x72, 0x52, 0x0d, 0x70, 0x72, 0x6f, 0x76, 0x69, 0x64, 0x65, 0x72, 0x50,
	0x65, 0x65, 0x72, 0x73, 0x22, 0x9b, 0x01, 0x0a, 0x0b, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65,
	0x54, 0x79, 0x70, 0x65, 0x12, 0x0d, 0x0a, 0x09, 0x50, 0x55, 0x54, 0x5f, 0x56, 0x41, 0x4c, 0x55,
	0x45, 0x10, 0x00, 0x12, 0x0d, 0x0a, 0x09, 0x47, 0x45, 0x54, 0x5f, 0x56, 0x41, 0x4c, 0x55, 0x45,
	0x10, 0x01, 0x12, 0x10, 0x0a, 0x0c, 0x41, 0x44, 0x44, 0x5f, 0x50, 0x52, 0x4f, 0x56, 0x49, 0x44,
	0x45, 0x52, 0x10, 0x02, 0x12, 0x11, 0x0a, 0x0d, 0x47, 0x45, 0x54, 0x5f, 0x50, 0x52, 0x4f, 0x56,
	0x49, 0x44, 0x45, 0x52, 0x53, 0x10, 0x03, 0x12, 0x0d, 0x0a, 0x09, 0x46, 0x49, 0x4e, 0x44, 0x5f,
	0x4e, 0x4f, 0x44, 0x45, 0x10, 0x04, 0x12, 0x08, 0x0a, 0x04, 0x50, 0x49, 0x4e, 0x47, 0x10, 0x05,
	0x12, 0x15, 0x0a, 0x11, 0x50, 0x52, 0x49, 0x56, 0x41, 0x54, 0x45, 0x5f, 0x46, 0x49, 0x4e, 0x44,
	0x5f, 0x4e, 0x4f, 0x44, 0x45, 0x10, 0x20, 0x12, 0x19, 0x0a, 0x15, 0x50, 0x52, 0x49, 0x56, 0x41,
	0x54, 0x45, 0x5f, 0x47, 0x45, 0x54, 0x5f, 0x50, 0x52, 0x4f, 0x56, 0x49, 0x44, 0x45, 0x52, 0x53,
	0x10, 0x21, 0x22, 0x57, 0x0a, 0x0e, 0x43, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e,
	0x54, 0x79, 0x70, 0x65, 0x12, 0x11, 0x0a, 0x0d, 0x4e, 0x4f, 0x54, 0x5f, 0x43, 0x4f, 0x4e, 0x4e,
	0x45, 0x43, 0x54, 0x45, 0x44, 0x10, 0x00, 0x12, 0x0d, 0x0a, 0x09, 0x43, 0x4f, 0x4e, 0x4e, 0x45,
	0x43, 0x54, 0x45, 0x44, 0x10, 0x01, 0x12, 0x0f, 0x0a, 0x0b, 0x43, 0x41, 0x4e, 0x5f, 0x43, 0x4f,
	0x4e, 0x4e, 0x45, 0x43, 0x54, 0x10, 0x02, 0x12, 0x12, 0x0a, 0x0e, 0x43, 0x41, 0x4e, 0x4e, 0x4f,
	0x54, 0x5f, 0x43, 0x4f, 0x4e, 0x4e, 0x45, 0x43, 0x54, 0x10, 0x03, 0x22, 0xeb, 0x02, 0x0a, 0x0b,
	0x50, 0x49, 0x52, 0x5f, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x22, 0x0a, 0x0d, 0x6c,
	0x6f, 0x67, 0x32, 0x5f, 0x6e, 0x75, 0x6d, 0x5f, 0x72, 0x6f, 0x77, 0x73, 0x18, 0x01, 0x20, 0x01,
	0x28, 0x03, 0x52, 0x0b, 0x6c, 0x6f, 0x67, 0x32, 0x4e, 0x75, 0x6d, 0x52, 0x6f, 0x77, 0x73, 0x12,
	0x1e, 0x0a, 0x0a, 0x70, 0x61, 0x72, 0x61, 0x6d, 0x65, 0x74, 0x65, 0x72, 0x73, 0x18, 0x02, 0x20,
	0x01, 0x28, 0x0c, 0x52, 0x0a, 0x70, 0x61, 0x72, 0x61, 0x6d, 0x65, 0x74, 0x65, 0x72, 0x73, 0x12,
	0x32, 0x0a, 0x14, 0x52, 0x4c, 0x57, 0x45, 0x5f, 0x65, 0x76, 0x61, 0x6c, 0x75, 0x61, 0x74, 0x69,
	0x6f, 0x6e, 0x5f, 0x6b, 0x65, 0x79, 0x73, 0x18, 0x0a, 0x20, 0x01, 0x28, 0x0c, 0x48, 0x00, 0x52,
	0x12, 0x52, 0x4c, 0x57, 0x45, 0x45, 0x76, 0x61, 0x6c, 0x75, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x4b,
	0x65, 0x79, 0x73, 0x12, 0x4d, 0x0a, 0x13, 0x50, 0x61, 0x69, 0x6c, 0x6c, 0x69, 0x65, 0x72, 0x5f,
	0x50, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x5f, 0x4b, 0x65, 0x79, 0x18, 0x0b, 0x20, 0x01, 0x28, 0x0b,
	0x32, 0x1b, 0x2e, 0x64, 0x68, 0x74, 0x2e, 0x70, 0x62, 0x2e, 0x50, 0x61, 0x69, 0x6c, 0x6c, 0x69,
	0x65, 0x72, 0x5f, 0x50, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x5f, 0x4b, 0x65, 0x79, 0x48, 0x00, 0x52,
	0x11, 0x50, 0x61, 0x69, 0x6c, 0x6c, 0x69, 0x65, 0x72, 0x50, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x4b,
	0x65, 0x79, 0x12, 0x1f, 0x0a, 0x0a, 0x6f, 0x74, 0x68, 0x65, 0x72, 0x5f, 0x6b, 0x65, 0x79, 0x73,
	0x18, 0x15, 0x20, 0x01, 0x28, 0x0c, 0x48, 0x00, 0x52, 0x09, 0x6f, 0x74, 0x68, 0x65, 0x72, 0x4b,
	0x65, 0x79, 0x73, 0x12, 0x27, 0x0a, 0x0f, 0x65, 0x6e, 0x63, 0x72, 0x79, 0x70, 0x74, 0x65, 0x64,
	0x5f, 0x71, 0x75, 0x65, 0x72, 0x79, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x0e, 0x65, 0x6e,
	0x63, 0x72, 0x79, 0x70, 0x74, 0x65, 0x64, 0x51, 0x75, 0x65, 0x72, 0x79, 0x12, 0x38, 0x0a, 0x18,
	0x65, 0x6e, 0x63, 0x72, 0x79, 0x70, 0x74, 0x65, 0x64, 0x5f, 0x70, 0x61, 0x69, 0x6c, 0x6c, 0x69,
	0x65, 0x72, 0x5f, 0x71, 0x75, 0x65, 0x72, 0x79, 0x18, 0x04, 0x20, 0x03, 0x28, 0x0c, 0x52, 0x16,
	0x65, 0x6e, 0x63, 0x72, 0x79, 0x70, 0x74, 0x65, 0x64, 0x50, 0x61, 0x69, 0x6c, 0x6c, 0x69, 0x65,
	0x72, 0x51, 0x75, 0x65, 0x72, 0x79, 0x42, 0x11, 0x0a, 0x0f, 0x53, 0x63, 0x68, 0x65, 0x6d, 0x65,
	0x44, 0x65, 0x70, 0x65, 0x6e, 0x64, 0x65, 0x6e, 0x74, 0x22, 0x70, 0x0a, 0x0c, 0x50, 0x49, 0x52,
	0x5f, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x20, 0x0a, 0x0b, 0x63, 0x69, 0x70,
	0x68, 0x65, 0x72, 0x74, 0x65, 0x78, 0x74, 0x73, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x0b,
	0x63, 0x69, 0x70, 0x68, 0x65, 0x72, 0x74, 0x65, 0x78, 0x74, 0x73, 0x12, 0x3e, 0x0a, 0x1b, 0x65,
	0x6e, 0x63, 0x72, 0x79, 0x70, 0x74, 0x65, 0x64, 0x5f, 0x70, 0x61, 0x69, 0x6c, 0x6c, 0x69, 0x65,
	0x72, 0x5f, 0x72, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x18, 0x02, 0x20, 0x03, 0x28, 0x0c,
	0x52, 0x19, 0x65, 0x6e, 0x63, 0x72, 0x79, 0x70, 0x74, 0x65, 0x64, 0x50, 0x61, 0x69, 0x6c, 0x6c,
	0x69, 0x65, 0x72, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x22, 0x49, 0x0a, 0x13, 0x50,
	0x61, 0x69, 0x6c, 0x6c, 0x69, 0x65, 0x72, 0x5f, 0x50, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x5f, 0x4b,
	0x65, 0x79, 0x12, 0x0c, 0x0a, 0x01, 0x6e, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x01, 0x6e,
	0x12, 0x0c, 0x0a, 0x01, 0x67, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x01, 0x67, 0x12, 0x16,
	0x0a, 0x06, 0x6c, 0x65, 0x6e, 0x67, 0x74, 0x68, 0x18, 0x03, 0x20, 0x01, 0x28, 0x03, 0x52, 0x06,
	0x6c, 0x65, 0x6e, 0x67, 0x74, 0x68, 0x42, 0x07, 0x5a, 0x05, 0x2e, 0x2f, 0x3b, 0x70, 0x62, 0x62,
	0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_msg_proto_rawDescOnce sync.Once
	file_msg_proto_rawDescData = file_msg_proto_rawDesc
)

func file_msg_proto_rawDescGZIP() []byte {
	file_msg_proto_rawDescOnce.Do(func() {
		file_msg_proto_rawDescData = protoimpl.X.CompressGZIP(file_msg_proto_rawDescData)
	})
	return file_msg_proto_rawDescData
}

var file_msg_proto_enumTypes = make([]protoimpl.EnumInfo, 2)
var file_msg_proto_msgTypes = make([]protoimpl.MessageInfo, 6)
var file_msg_proto_goTypes = []interface{}{
	(Message_MessageType)(0),         // 0: dht.pb.Message.MessageType
	(Message_ConnectionType)(0),      // 1: dht.pb.Message.ConnectionType
	(*Message)(nil),                  // 2: dht.pb.Message
	(*PIR_Request)(nil),              // 3: dht.pb.PIR_Request
	(*PIR_Response)(nil),             // 4: dht.pb.PIR_Response
	(*Paillier_Public_Key)(nil),      // 5: dht.pb.Paillier_Public_Key
	(*Message_Peer)(nil),             // 6: dht.pb.Message.Peer
	(*Message_CIDToProviderMap)(nil), // 7: dht.pb.Message.CIDToProviderMap
	(*pb.Record)(nil),                // 8: record.pb.Record
}
var file_msg_proto_depIdxs = []int32{
	7,  // 0: dht.pb.Message.buckets:type_name -> dht.pb.Message.CIDToProviderMap
	0,  // 1: dht.pb.Message.type:type_name -> dht.pb.Message.MessageType
	8,  // 2: dht.pb.Message.record:type_name -> record.pb.Record
	6,  // 3: dht.pb.Message.closer_peers:type_name -> dht.pb.Message.Peer
	6,  // 4: dht.pb.Message.provider_peers:type_name -> dht.pb.Message.Peer
	3,  // 5: dht.pb.Message.closer_peers_request:type_name -> dht.pb.PIR_Request
	3,  // 6: dht.pb.Message.provider_peers_request:type_name -> dht.pb.PIR_Request
	4,  // 7: dht.pb.Message.closer_peers_response:type_name -> dht.pb.PIR_Response
	4,  // 8: dht.pb.Message.provider_peers_response:type_name -> dht.pb.PIR_Response
	5,  // 9: dht.pb.PIR_Request.Paillier_Public_Key:type_name -> dht.pb.Paillier_Public_Key
	1,  // 10: dht.pb.Message.Peer.connection:type_name -> dht.pb.Message.ConnectionType
	6,  // 11: dht.pb.Message.CIDToProviderMap.provider_peers:type_name -> dht.pb.Message.Peer
	12, // [12:12] is the sub-list for method output_type
	12, // [12:12] is the sub-list for method input_type
	12, // [12:12] is the sub-list for extension type_name
	12, // [12:12] is the sub-list for extension extendee
	0,  // [0:12] is the sub-list for field type_name
}

func init() { file_msg_proto_init() }
func file_msg_proto_init() {
	if File_msg_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_msg_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Message); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_msg_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*PIR_Request); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_msg_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*PIR_Response); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_msg_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Paillier_Public_Key); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_msg_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Message_Peer); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_msg_proto_msgTypes[5].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Message_CIDToProviderMap); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	file_msg_proto_msgTypes[1].OneofWrappers = []interface{}{
		(*PIR_Request_RLWEEvaluationKeys)(nil),
		(*PIR_Request_Paillier_Public_Key)(nil),
		(*PIR_Request_OtherKeys)(nil),
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_msg_proto_rawDesc,
			NumEnums:      2,
			NumMessages:   6,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_msg_proto_goTypes,
		DependencyIndexes: file_msg_proto_depIdxs,
		EnumInfos:         file_msg_proto_enumTypes,
		MessageInfos:      file_msg_proto_msgTypes,
	}.Build()
	File_msg_proto = out.File
	file_msg_proto_rawDesc = nil
	file_msg_proto_goTypes = nil
	file_msg_proto_depIdxs = nil
}
