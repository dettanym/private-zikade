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
	"github.com/tuneinsight/lattigo/v5/utils/structs"
)

type SimpleRLWE_PIR_Protocol struct {
	PIR_Protocol

	log2_num_rows int
	parameters    heint.Parameters

	secret_key rlwe.SecretKey

	evaluation_keys      *rlwe.MemEvaluationKeySet
	encrypted_query      []rlwe.Ciphertext
	response_ciphertexts []rlwe.Ciphertext
}

func NewSimpleRLWE_PIR_Protocol(log2_num_rows int) *SimpleRLWE_PIR_Protocol {
	return &SimpleRLWE_PIR_Protocol{log2_num_rows: log2_num_rows}
}

func (rlweStruct *SimpleRLWE_PIR_Protocol) MarshalRequestToPB() (*pb.PIR_Request, error) {
	params_bytes, err := rlweStruct.parameters.MarshalBinary()
	if err != nil {
		return nil, err
	}
	evk_bytes, err := rlweStruct.evaluation_keys.MarshalBinary()
	if err != nil {
		return nil, err
	}
	query_bytes, err := structs.Vector[rlwe.Ciphertext](rlweStruct.encrypted_query).MarshalBinary()
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

func (rlweStruct *SimpleRLWE_PIR_Protocol) UnmarshallRequestFromPB(req *pb.PIR_Request) error {

	if rlweStruct.log2_num_rows == 0 {
		panic("log2_num_rows is not set")
	}

	err := rlweStruct.parameters.UnmarshalBinary(req.GetParameters())
	if err != nil {
		return fmt.Errorf("error unmarshalling parameter bytes")
	}

	var encrypted_query structs.Vector[rlwe.Ciphertext]
	err = encrypted_query.UnmarshalBinary(req.GetEncryptedQuery())
	if err != nil {
		return fmt.Errorf("error unmarshalling encrypted query bytes")
	}
	rlweStruct.encrypted_query = encrypted_query

	switch schemeDependent := req.SchemeDependent.(type) {
	case *pb.PIR_Request_RLWEEvaluationKeys:
		evaluationKeysBytes := schemeDependent.RLWEEvaluationKeys
		println("OptionalParameters is set to EV Keys")
		rlweStruct.evaluation_keys = &rlwe.MemEvaluationKeySet{}
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

func (rlweStruct *SimpleRLWE_PIR_Protocol) MarshalResponseToPB() (*pb.PIR_Response, error) {
	// ctBytesArray := make([][]byte, len(rlweStruct.response_ciphertexts))
	// for i, ct := range rlweStruct.response_ciphertexts {
	// 	ctBytes, err := ct.MarshalBinary()
	// 	if err != nil {
	// 		return nil, fmt.Errorf("error marshalling %dth ciphertext. Error: %s", i, err)
	// 	}
	// 	ctBytesArray[i] = ctBytes
	// }
	// response := &pb.PIR_Response{Ciphertexts: ctBytesArray}
	ciphertexts_bytes, err := structs.Vector[rlwe.Ciphertext](rlweStruct.response_ciphertexts).MarshalBinary()
	if err != nil {
		return nil, err
	}
	response := &pb.PIR_Response{Ciphertexts: ciphertexts_bytes}
	return response, nil
}

func (rlweStruct *SimpleRLWE_PIR_Protocol) UnmarshalResponseFromPB(res *pb.PIR_Response) error {
	// ctBytesArray := res.GetCiphertexts()
	// rlweStruct.response_ciphertexts = make([]rlwe.Ciphertext, len(ctBytesArray))
	// for i, ctBytes := range ctBytesArray {
	// 	ct := rlweStruct.response_ciphertexts[i]
	// 	err := ct.UnmarshalBinary(ctBytes)
	// 	if err != nil {
	// 		return fmt.Errorf("error unmarshalling %dth ciphertext. Error: %s", i, err)
	// 	}
	// }
	var response_encrypted structs.Vector[rlwe.Ciphertext]
	err := response_encrypted.UnmarshalBinary(res.GetCiphertexts())
	rlweStruct.response_ciphertexts = response_encrypted
	if err != nil {
		return err
	}
	return nil
}

func (rlweStruct *SimpleRLWE_PIR_Protocol) GenerateRequestFromQuery(requested_row int) (*pb.PIR_Request, error) {

	err := rlweStruct.generateParameters()
	if err != nil {
		return nil, err
	}

	encoder := heint.NewEncoder(rlweStruct.parameters)
	num_slots := rlweStruct.parameters.MaxSlots()
	// num_rows := 1 << rlweStruct.log2_num_rows
	// TODO: Find the best value for this parameter
	log_num_cts := 2
	num_cts := 1 << log_num_cts
	log2_bits_per_ct := rlweStruct.log2_num_rows - log_num_cts
	bits_per_ct := 1 << log2_bits_per_ct

	ciphertext_index := requested_row / bits_per_ct
	bit_index := requested_row % bits_per_ct

	plaintexts := make([]*rlwe.Plaintext, num_cts)

	for i := 0; i < num_cts; i++ {
		query_encoded := make([]uint64, num_slots) // default value is zero
		if i == ciphertext_index {
			query_encoded[bit_index] = 1
		}
		query_plaintext := heint.NewPlaintext(rlweStruct.parameters, rlweStruct.parameters.MaxLevel())
		query_plaintext.IsBatched = false
		encoder.Encode(query_encoded, query_plaintext)
		plaintexts[i] = query_plaintext
	}

	ciphertext, err := rlweStruct.encryptRLWEPlaintexts(plaintexts)
	if err != nil {
		return nil, err
	}
	rlweStruct.encrypted_query = ciphertext

	// log2_num_cts := int(math.Log2(float64(len(rlweStruct.encrypted_query))))
	// log2_bits_per_ct := rlweStruct.log2_num_rows - log2_num_cts
	keys, err := rlweStruct.generateEvaluationKeys(log2_bits_per_ct)
	if err != nil {
		return nil, err
	}
	rlweStruct.evaluation_keys = keys

	return rlweStruct.MarshalRequestToPB()
}

func (rlweStruct *SimpleRLWE_PIR_Protocol) ProcessResponseToPlaintext(res *pb.PIR_Response) ([]byte, error) {
	err := rlweStruct.UnmarshalResponseFromPB(res)
	if err != nil {
		return nil, err
	}

	// println(rlweStruct.response_ciphertexts)
	// TODO: @Rasoul: this should return a row of the DB input into ProcessRequestAndReturnResponse
	bytes_per_coefficient := int(math.Floor(math.Log2(float64(rlweStruct.parameters.PlaintextModulus())))) / 8
	decryptor := heint.NewDecryptor(rlweStruct.parameters, &rlweStruct.secret_key)
	decoder := heint.NewEncoder(rlweStruct.parameters)
	var response []byte
	for i := range rlweStruct.response_ciphertexts {
		plaintext := decryptor.DecryptNew(&rlweStruct.response_ciphertexts[i])
		temp_response := make([]uint64, rlweStruct.parameters.N())
		decoder.Decode(plaintext, temp_response)
		for j := range temp_response {
			temp_bytes := make([]byte, 8)
			binary.LittleEndian.PutUint64(temp_bytes, temp_response[j])
			response = append(response, temp_bytes[:bytes_per_coefficient]...)
		}
	}

	return response, nil
}

func (rlweStruct *SimpleRLWE_PIR_Protocol) ProcessRequestAndReturnResponse(request *pb.PIR_Request, database [][]byte) (*pb.PIR_Response, error) {

	// TODO: Replace logging the time with Go Benchmarks
	//   https://pkg.go.dev/testing#hdr-Benchmarks
	start := time.Now()

	err := rlweStruct.UnmarshallRequestFromPB(request)
	if err != nil {
		return nil, err
	}

	params := rlweStruct.parameters
	evaluation_keys := rlweStruct.evaluation_keys
	encrypted_query := rlweStruct.encrypted_query

	num_cts := len(encrypted_query)
	log2_num_cts := int(math.Log2(float64(num_cts)))

	N := params.N()
	evaluator := heint.NewEvaluator(params, evaluation_keys)
	encoder := heint.NewEncoder(params)

	var indicator_bits []*rlwe.Ciphertext
	for i := 0; i < len(encrypted_query); i++ {
		indicator_bits_slice, err := evaluator.Expand(&encrypted_query[i], rlweStruct.log2_num_rows-log2_num_cts, 0)
		if err != nil {
			return nil, err
		}
		indicator_bits = append(indicator_bits, indicator_bits_slice...)
	}

	num_rows := 1 << rlweStruct.log2_num_rows

	bytes_per_coefficient := int(math.Floor(math.Log2(float64(params.PlaintextModulus())))) / 8
	if bytes_per_coefficient > 8 {
		panic("bytes_per_coefficient > 8")
	}
	bytes_per_ciphertext := bytes_per_coefficient * N

	max_len_database_entries := maxLengthDBRows(database)
	number_of_response_ciphertexts := (max_len_database_entries + bytes_per_ciphertext - 1) / bytes_per_ciphertext

	rlweStruct.response_ciphertexts = make([]rlwe.Ciphertext, number_of_response_ciphertexts)

	// WARNING: Inner loop is not paralleliable
	for k := 0; k < number_of_response_ciphertexts; k++ {
		for i := 0; i < num_rows; i++ {
			// encoding the row of the database into the coefficients of a plaintext
			coeffs := make([]uint64, N)
			for j := 0; j < N; j++ {
				the_bytes := make([]byte, 8)
				for b := 0; b < bytes_per_coefficient; b++ {
					if bytes_per_ciphertext*k+j*bytes_per_coefficient+b < len(database[i]) {
						the_bytes[b] = database[i][bytes_per_ciphertext*k+j*bytes_per_coefficient+b]
					}
				}
				coeffs[j] = binary.LittleEndian.Uint64(the_bytes)
				if coeffs[j] > uint64(params.PlaintextModulus()) {
					panic("coeffs[j] > uint64(params.PlaintextModulus())")
				}
			}
			row_data_plaintext := heint.NewPlaintext(params, params.MaxLevel())
			row_data_plaintext.IsBatched = false
			err := encoder.Encode(coeffs, row_data_plaintext)
			if err != nil {
				return nil, fmt.Errorf("could not encode a row of plaintext data %s", err)
			}
			///

			// We accumulate the results in the first cipertext so we don't require the
			// public key to create a new ciphertext
			if i == 0 {
				tmp, err := evaluator.MulNew(indicator_bits[i], row_data_plaintext)
				if err != nil {
					return nil, fmt.Errorf("MulNew failed. Check function description for conditions leading to errors. Error: %s", err)
				}
				rlweStruct.response_ciphertexts[k] = *tmp
			} else {
				err := evaluator.MulThenAdd(indicator_bits[i], row_data_plaintext, &rlweStruct.response_ciphertexts[k])
				if err != nil {
					return nil, fmt.Errorf("MulThenAdd failed. Check function description for conditions leading to errors. Error: %s", err)
				}
			}
		}
	}

	//// println("Response:", ciphertexts[0].BinarySize()/1024, "KB")
	//response_bytes, err := structs.Vector[rlwe.Ciphertext](response_ciphertexts).MarshalBinary()
	//if err != nil {
	//	return nil, err
	//}
	// return response_bytes
	response, err := rlweStruct.MarshalResponseToPB()
	if err != nil {
		return nil, err
	}

	elapsed := time.Since(start)
	log.Printf("elapsed time: %v", elapsed)

	return response, nil
}
