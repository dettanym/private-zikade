package private_routing

import (
	"encoding/binary"
	"fmt"
	"log"
	"time"

	"github.com/plprobelab/zikade/pb"
	"github.com/tuneinsight/lattigo/v5/core/rlwe"
	"github.com/tuneinsight/lattigo/v5/he/heint"
)

type Query struct {
	parameters      heint.Parameters
	evaluation_keys rlwe.MemEvaluationKeySet
	encrypted_query rlwe.Ciphertext
}

func (q *Query) MarshalBinary() ([]byte, error) {
	params_bytes, err := q.parameters.MarshalBinary()
	if err != nil {
		return nil, err
	}
	evk_bytes, err := q.evaluation_keys.MarshalBinary()
	if err != nil {
		return nil, err
	}
	query_bytes, err := q.encrypted_query.MarshalBinary()
	if err != nil {
		return nil, err
	}

	// Calculate the total size: sum of all bytes plus 3 sizes (each 8 bytes)
	totalSize := len(params_bytes) + len(evk_bytes) + len(query_bytes) + 3*8

	// Allocate the byte slice
	result := make([]byte, 0, totalSize)

	// Helper function to append size and data
	appendData := func(data []byte) {
		size := uint64(len(data))
		sizeBytes := make([]byte, 8)
		binary.LittleEndian.PutUint64(sizeBytes, size)
		result = append(result, sizeBytes...)
		result = append(result, data...)
	}

	// Append data for each part
	appendData(params_bytes)
	appendData(evk_bytes)
	appendData(query_bytes)

	return result, nil
}

func (q *Query) UnmarshalBinary(data []byte) error {
	// Helper function to read next byte slice
	readNextBytes := func(data []byte) ([]byte, []byte, error) {
		if len(data) < 8 {
			return nil, nil, fmt.Errorf("data too short to contain size information")
		}
		size := binary.LittleEndian.Uint64(data[:8])
		if uint64(len(data)) < 8+size {
			return nil, nil, fmt.Errorf("data too short to contain expected byte slice")
		}
		return data[8 : 8+size], data[8+size:], nil
	}

	var err error

	// Read params_bytes
	params_bytes, data, err := readNextBytes(data)
	if err != nil {
		return err
	}

	// Read evk_bytes
	evk_bytes, data, err := readNextBytes(data)
	if err != nil {
		return err
	}

	// Read query_bytes
	query_bytes, _, err := readNextBytes(data)
	if err != nil {
		return err
	}

	// Assuming q.parameters, q.evaluation_keys, q.encrypted_query have
	// methods to unmarshal from byte slices
	if err := q.parameters.UnmarshalBinary(params_bytes); err != nil {
		return err
	}
	if err := q.evaluation_keys.UnmarshalBinary(evk_bytes); err != nil {
		return err
	}
	if err := q.encrypted_query.UnmarshalBinary(query_bytes); err != nil {
		return err
	}

	return nil
}

// // This function needs to fetch the 'index'th row from the database.
// // And return the data as a vector of N uint64, where each number if less than mod
// func encode_db_row_as_size_N_vector(index uint64, N uint64, mod uint64) []uint64 {
// 	// TODO: Make this function actually fetch the row from the database
// 	// Right now it's just generating a random row
// 	db_rows := make([]uint64, N)
// 	for i := uint64(0); i < N; i++ {
// 		db_rows[i] = uint64(((i*i)%mod + i) % mod)
// 	}
// 	return db_rows
// }

type PIR_Protocol interface {
	ProcessRequestAndReturnResponse(msg *pb.PIR_Message) (*pb.PIR_Message, error)
}

type PIR_Protocol_Simple_RLWE struct {
}

func (p *PIR_Protocol_Simple_RLWE) ProcessRequestAndReturnResponse(msg *pb.PIR_Protocol_Simple_RLWE_Request) (*pb.PIR_Protocol_Simple_RLWE_Response, error) {
	start := time.Now()

	// Set to the bytes of the query
	query_struct_bytes := msg.Query

	query := &Query{}
	err := query.UnmarshalBinary(query_struct_bytes)
	if err != nil {
		return nil, err
	}

	params := query.parameters
	evk := &query.evaluation_keys
	encrypted_data := &query.encrypted_query

	N := params.N()
	evaluator := heint.NewEvaluator(params, evk)
	encoder := heint.NewEncoder(params)

	ciphertexts, err := evaluator.Expand(encrypted_data, 8, 0)
	if err != nil {
		return nil, err
	}

	for i := 0; i < 256; i++ {

		// this part is encoding the content of row i in the coefficients of a polynomial
		// For now it's just random junk
		// TODO: change this to encode the bytes of row i in the routing table
		coeffs := make([]uint64, N)
		for j := 0; j < int(N); j++ {
			coeffs[j] = uint64((j * (i + 5) * i) % int(params.PlaintextModulus()))
		}
		poly_pt := heint.NewPlaintext(params, params.MaxLevel())
		poly_pt.MetaData.IsBatched = false
		encoder.Encode(coeffs, poly_pt)
		///

		if i == 0 {
			evaluator.Mul(ciphertexts[i], poly_pt, ciphertexts[i])
		} else {
			evaluator.MulThenAdd(ciphertexts[i], poly_pt, ciphertexts[0])
		}
	}

	var response_bytes []byte
	// println("Response:", ciphertexts[0].BinarySize()/1024, "KB")
	response_bytes, err = ciphertexts[0].MarshalBinary()
	if err != nil {
		return nil, err
	}
	elapsed := time.Since(start)
	log.Printf("elapsed time: %v", elapsed)

	return &pb.PIR_Protocol_Simple_RLWE_Response{
		Response: response_bytes,
	}, nil

}
