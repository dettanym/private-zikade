package private_routing

import (
	"encoding/binary"
	"fmt"
	"log"
	"math"
	"time"

	"github.com/plprobelab/zikade/pb"
	"github.com/tuneinsight/lattigo/v5/core/rlwe"
	"github.com/tuneinsight/lattigo/v5/he/heint"
	"github.com/tuneinsight/lattigo/v5/utils/structs"
)

type SimpleRLWEPIRQuery struct {
	parameters      heint.Parameters
	evaluation_keys rlwe.MemEvaluationKeySet
	encrypted_query rlwe.Ciphertext
}

func (q *SimpleRLWEPIRQuery) MarshalBinary() ([]byte, error) {
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

func (q *SimpleRLWEPIRQuery) UnmarshalBinary(data []byte) error {
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

type PIR_Protocol interface {
	ProcessRequestAndReturnResponse(msg *pb.PIR_Message, database [][]byte) (*pb.PIR_Message, error)
}

type PIR_Protocol_Simple_RLWE struct {
}

func (p *PIR_Protocol_Simple_RLWE) ProcessRequestAndReturnResponse(msg *pb.PIR_Protocol_Simple_RLWE_Request, database [][]byte) (*pb.PIR_Protocol_Simple_RLWE_Response, error) {

	start := time.Now()

	// Set to the bytes of the query
	query_bytes := msg.Query

	query := &SimpleRLWEPIRQuery{}
	err := query.UnmarshalBinary(query_bytes)
	if err != nil {
		return nil, err
	}

	log2_num_rows := 8
	params := query.parameters
	evaluation_keys := query.evaluation_keys
	encrypted_query := query.encrypted_query

	N := params.N()
	evaluator := heint.NewEvaluator(params, &evaluation_keys)
	encoder := heint.NewEncoder(params)

	indicator_bits, err := evaluator.Expand(&encrypted_query, log2_num_rows, 0)
	if err != nil {
		return nil, err
	}

	num_rows := 1 << log2_num_rows

	bytes_per_coefficient := int(math.Floor(math.Log2(float64(params.PlaintextModulus())))) / 8
	bytes_per_ciphertext := bytes_per_coefficient * int(N)
	number_of_response_ciphertexts := (len(database) + bytes_per_coefficient - 1) / bytes_per_coefficient

	response_ciphertexts := make([]rlwe.Ciphertext, number_of_response_ciphertexts)

	// WARNING: Inner loop is not paralleliable
	for k := 0; k < number_of_response_ciphertexts; k++ {
		for i := 0; i < num_rows; i++ {
			// this part is encoding the content of row i in the coefficients of a polynomial
			// TODO: change this to encode the bytes of row i in the routing table
			coeffs := make([]uint64, N)
			for j := 0; j < N; j++ {
				start_index := bytes_per_ciphertext*k + bytes_per_coefficient*j
				coeffs[j] = binary.LittleEndian.Uint64(database[i][start_index : start_index+bytes_per_coefficient])
			}
			row_data_plaintext := heint.NewPlaintext(params, params.MaxLevel())
			row_data_plaintext.IsBatched = false
			encoder.Encode(coeffs, row_data_plaintext)
			///

			// We accumulate the results in the first cipertext so we don't require the
			// public key to create a new ciphertext
			if i == 0 {
				tmp, err := evaluator.MulNew(indicator_bits[i], row_data_plaintext)
				if err != nil {
					panic(err)
				}
				response_ciphertexts[k] = *tmp
			} else {
				evaluator.MulThenAdd(indicator_bits[i], row_data_plaintext, &response_ciphertexts[k])
			}
		}
	}

	// println("Response:", ciphertexts[0].BinarySize()/1024, "KB")
	response_bytes, err := structs.Vector[rlwe.Ciphertext](response_ciphertexts).MarshalBinary()
	if err != nil {
		return nil, err
	}
	// return response_bytes
	elapsed := time.Since(start)
	log.Printf("elapsed time: %v", elapsed)

	return &pb.PIR_Protocol_Simple_RLWE_Response{
		Response: response_bytes,
	}, nil

}
