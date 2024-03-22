package private_routing

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"github.com/plprobelab/zikade/pb"
	"google.golang.org/protobuf/proto"
)

func UnmarshallPlaintextToPB(paddedMarshalledBucket []byte) (*pb.Message, error) {
	marshalledBucket, err := unpadMarshalledPBWithLength(paddedMarshalledBucket)
	if err != nil {
		return nil, err
	}
	resp := &pb.Message{}
	err = proto.Unmarshal(marshalledBucket, resp)
	if err != nil {
		return nil, fmt.Errorf("Could not marshal peers in RT. Err: %s ", err)
	}
	return resp, nil
}

func MarshallPBToPlaintext(mesg *pb.Message) ([]byte, error) {
	marshalledRoutingEntries, err := proto.Marshal(mesg)
	if err != nil {
		return nil, fmt.Errorf("Could not marshal peers in RT. Err: %s ", err)
	}
	padded, err := padMarshalledPBWithLength(marshalledRoutingEntries)
	if err != nil {
		return nil, err
	}
	return padded, nil
}

func padMarshalledPBWithLength(marshalledPB []byte) ([]byte, error) {
	buf := new(bytes.Buffer)
	var lenMarshalledRTEntries = uint64(len(marshalledPB))
	err := binary.Write(buf, binary.LittleEndian, lenMarshalledRTEntries)
	if err != nil {
		return nil, fmt.Errorf("couldn't write the length of the marshalled PB to a byte array %s", err)
	}
	// fmt.Printf("Bucket %d has %d bytes, expressed in bytes: %x\n", bid, lenMarshalledRTEntries, buf.Bytes())
	return append(buf.Bytes(), marshalledPB...), nil
}

func unpadMarshalledPBWithLength(paddedMarshalledBucket []byte) ([]byte, error) {
	buf := bytes.NewReader(paddedMarshalledBucket[0:8])
	var lenMarshalledRTEntries uint64
	err := binary.Read(buf, binary.LittleEndian, &lenMarshalledRTEntries)
	if err != nil {
		fmt.Printf("couldn't read the length of the RT entries to a byte array %s", err)
		return nil, err
	}
	fmt.Printf("marshalled bucket length %d\n", lenMarshalledRTEntries)

	return paddedMarshalledBucket[8 : 8+lenMarshalledRTEntries], nil
}
