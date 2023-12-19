package pir

import (
	"encoding/binary"
	"fmt"
	"log"
	"math"
	"time"

	"github.com/plprobelab/zikade/pb"
	"github.com/tuneinsight/lattigo/v5/core/rlwe"
	"github.com/tuneinsight/lattigo/v5/he/heint"
)

type SimpleRLWEPIR struct {
	parameters      heint.Parameters
	evaluation_keys rlwe.MemEvaluationKeySet
	encrypted_query rlwe.Ciphertext
}

// TODO: The marshalling, unmarshalling functions don't need to be public.
//
//	make them private, while being able to test them.
func (rlweStruct *SimpleRLWEPIR) MarshalRequestToPB() (*pb.PIR_Request, error) {
	params_bytes, err := rlweStruct.parameters.MarshalBinary()
	if err != nil {
		return nil, err
	}
	evk_bytes, err := rlweStruct.evaluation_keys.MarshalBinary()
	if err != nil {
		return nil, err
	}
	query_bytes, err := rlweStruct.encrypted_query.MarshalBinary()
	if err != nil {
		return nil, err
	}

	pirRequest := pb.PIR_Request{
		Parameters: params_bytes,
		SchemeDependent: &pb.PIR_Request_RLWEEvaluationKeys{
			RLWEEvaluationKeys: evk_bytes,
		},
		EncryptedQuery: query_bytes,
	}

	return &pirRequest, nil
}

func (rlweStruct *SimpleRLWEPIR) UnmarshallRequestFromPB(req *pb.PIR_Request) error {
	err := rlweStruct.parameters.UnmarshalBinary(req.GetParameters())
	if err != nil {
		return fmt.Errorf("error unmarshalling parameter bytes")
	}

	err = rlweStruct.encrypted_query.UnmarshalBinary(req.GetEncryptedQuery())
	if err != nil {
		return fmt.Errorf("error unmarshalling encrypted query bytes")
	}

	switch schemeDependent := req.SchemeDependent.(type) {
	case *pb.PIR_Request_RLWEEvaluationKeys:
		evaluationKeysBytes := schemeDependent.RLWEEvaluationKeys
		println("OptionalParameters is set to EV Keys")
		err = rlweStruct.evaluation_keys.UnmarshalBinary(evaluationKeysBytes)
		if err != nil {
			return fmt.Errorf("error unmarshalling evaluation key bytes")
		}
	case *pb.PIR_Request_OtherKeys:
		otherKeysBytes := schemeDependent.OtherKeys
		println("OptionalParameters is set to other keys", otherKeysBytes)
	case nil:
		return fmt.Errorf("unmarshalling request from PB: need one of EV Keys or Random lol")
	default:
		return fmt.Errorf("unmarshalling request from PB: req.OptionalParameters has unexpected type %T", schemeDependent)
	}

	return nil
}

func (rlweStruct *SimpleRLWEPIR) MarshalBinary() ([]byte, error) {
	params_bytes, err := rlweStruct.parameters.MarshalBinary()
	if err != nil {
		return nil, err
	}
	evk_bytes, err := rlweStruct.evaluation_keys.MarshalBinary()
	if err != nil {
		return nil, err
	}
	query_bytes, err := rlweStruct.encrypted_query.MarshalBinary()
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

func (rlweStruct *SimpleRLWEPIR) UnmarshalBinary(data []byte) error {
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

	if err := rlweStruct.parameters.UnmarshalBinary(params_bytes); err != nil {
		return err
	}
	if err := rlweStruct.evaluation_keys.UnmarshalBinary(evk_bytes); err != nil {
		return err
	}
	if err := rlweStruct.encrypted_query.UnmarshalBinary(query_bytes); err != nil {
		return err
	}

	return nil
}

type PIR_Protocol interface {
	ProcessRequestAndReturnResponse(msg []byte, database [][]byte) ([]byte, error)
}

type PIR_Protocol_Simple_RLWE struct {
}

func ProcessRequestAndReturnResponse(request *pb.PIR_Request, database [][]byte) (*pb.PIR_Response, error) {

	start := time.Now()

	// Set to the bytes of the rlweStruct

	rlweStruct := &SimpleRLWEPIR{}
	err := rlweStruct.UnmarshallRequestFromPB(request)
	if err != nil {
		return nil, err
	}

	log2_num_rows := 8
	params := rlweStruct.parameters
	evaluation_keys := rlweStruct.evaluation_keys
	encrypted_query := rlweStruct.encrypted_query

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

	//// println("Response:", ciphertexts[0].BinarySize()/1024, "KB")
	//response_bytes, err := structs.Vector[rlwe.Ciphertext](response_ciphertexts).MarshalBinary()
	//if err != nil {
	//	return nil, err
	//}
	// return response_bytes

	ctBytesArray := make([][]byte, len(response_ciphertexts))
	for i, ct := range response_ciphertexts {
		ctBytes, err := ct.MarshalBinary()
		if err != nil {
			return nil, fmt.Errorf("error marshalling %dth ciphertext. Error: %s", i, err)
		}
		ctBytesArray[i] = ctBytes
	}
	response := &pb.PIR_Response{Ciphertexts: ctBytesArray}

	elapsed := time.Since(start)
	log.Printf("elapsed time: %v", elapsed)

	return response, nil

}
