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

	parameters heint.Parameters

	secret_key *rlwe.SecretKey

	evaluation_keys      *rlwe.MemEvaluationKeySet
	encrypted_query      structs.Vector[rlwe.Ciphertext]
	response_ciphertexts structs.Vector[rlwe.Ciphertext]
}

func (rlweStruct *SimpleRLWE_PIR_Protocol) num_rows() int {
	return 1 << rlweStruct.log2_num_rows
}

func (rlweStruct *SimpleRLWE_PIR_Protocol) num_cts() int {
	return len(rlweStruct.encrypted_query)
}

func (rlweStruct *SimpleRLWE_PIR_Protocol) bytes_per_coefficient() int {
	return int(math.Floor(math.Log2(float64(rlweStruct.parameters.PlaintextModulus())))) / 8
}

func (rlweStruct *SimpleRLWE_PIR_Protocol) bytes_per_ciphertext() int {
	return rlweStruct.bytes_per_coefficient() * rlweStruct.parameters.N()
}

// Use by client to create a new PIR request
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
		Log2NumRows: int64(rlweStruct.log2_num_rows),
		Parameters:  params_bytes,
		SchemeDependent: &pb.PIR_Request_RLWEEvaluationKeys{
			RLWEEvaluationKeys: evk_bytes,
		},
		EncryptedQuery: query_bytes,
	}

	return &pirRequest, nil
}

func (rlweStruct *SimpleRLWE_PIR_Protocol) UnmarshallRequestFromPB(req *pb.PIR_Request) error {

	rlweStruct.log2_num_rows = int(req.GetLog2NumRows())

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
	ciphertexts_bytes, err := rlweStruct.response_ciphertexts.MarshalBinary()
	if err != nil {
		return nil, err
	}
	response := &pb.PIR_Response{Ciphertexts: ciphertexts_bytes}
	return response, nil
}

func (rlweStruct *SimpleRLWE_PIR_Protocol) UnmarshalResponseFromPB(res *pb.PIR_Response) error {
	err := rlweStruct.response_ciphertexts.UnmarshalBinary(res.GetCiphertexts())
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
	keygen := rlwe.NewKeyGenerator(rlweStruct.parameters)
	rlweStruct.secret_key = keygen.GenSecretKeyNew()

	encoder := heint.NewEncoder(rlweStruct.parameters)
	num_slots := rlweStruct.parameters.MaxSlots()
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
		err := encoder.Encode(query_encoded, query_plaintext)
		if err != nil {
			return nil, fmt.Errorf("could not encode query ciphertext %s", err)
		}
		plaintexts[i] = query_plaintext
	}

	ciphertext, err := rlweStruct.encryptRLWEPlaintexts(plaintexts)
	if err != nil {
		return nil, err
	}
	rlweStruct.encrypted_query = ciphertext

	keys, err := rlweStruct.generateEvaluationKeys(log2_bits_per_ct)
	if err != nil {
		return nil, err
	}
	rlweStruct.evaluation_keys = keys

	return rlweStruct.MarshalRequestToPB()
}

// Encodes byte_array from [start_index, end_index) into a plaintext
func (rlweStruct *SimpleRLWE_PIR_Protocol) BytesArrayToPlaintext(byte_array []byte, start_index int, end_index int) (*rlwe.Plaintext, error) {
	if start_index < 0 || end_index > len(byte_array) || start_index > end_index {
		return nil, fmt.Errorf("start_index < 0 || end_index > len(byte_array) || start_index > end_index")
	}
	N := rlweStruct.parameters.N()
	coeffs := make([]uint64, N)
	for j := 0; j < N; j++ {
		the_bytes := make([]byte, 8)
		if rlweStruct.bytes_per_coefficient() > 8 {
			panic("rlweStruct.bytes_per_coefficient() > 8, Code can not handle coefficients larger than 64 bits")
		}
		for b := 0; b < rlweStruct.bytes_per_coefficient(); b++ {
			if j*rlweStruct.bytes_per_coefficient()+b < end_index {
				the_bytes[b] = byte_array[start_index+j*rlweStruct.bytes_per_coefficient()+b]
			}
		}
		coeffs[j] = binary.LittleEndian.Uint64(the_bytes)
		if coeffs[j] > uint64(rlweStruct.parameters.PlaintextModulus()) {
			panic("coeffs[j] > uint64(params.PlaintextModulus()), Coefficients are larger than the plaintext modulus")
		}
	}
	row_data_plaintext := heint.NewPlaintext(rlweStruct.parameters, rlweStruct.parameters.MaxLevel())
	row_data_plaintext.IsBatched = false
	encoder := heint.NewEncoder(rlweStruct.parameters)
	err := encoder.Encode(coeffs, row_data_plaintext)
	if err != nil {
		return nil, fmt.Errorf("could not encode a row of plaintext data %s", err)
	}
	return row_data_plaintext, nil
}

func (rlweStruct *SimpleRLWE_PIR_Protocol) PlaintextToBytesArray(plaintext *rlwe.Plaintext) ([]byte, error) {
	decoder := heint.NewEncoder(rlweStruct.parameters)
	temp_response := make([]uint64, rlweStruct.parameters.N())
	err := decoder.Decode(plaintext, temp_response)
	if err != nil {
		return nil, fmt.Errorf("could not decode response ciphertext %s", err)
	}
	var plaintextBytes []byte
	for j := range temp_response {
		temp_bytes := make([]byte, 8)
		binary.LittleEndian.PutUint64(temp_bytes, temp_response[j])
		plaintextBytes = append(plaintextBytes, temp_bytes[:rlweStruct.bytes_per_coefficient()]...)
	}
	return plaintextBytes, nil
}

func (rlweStruct *SimpleRLWE_PIR_Protocol) ProcessResponseToPlaintext(res *pb.PIR_Response) ([]byte, error) {
	err := rlweStruct.UnmarshalResponseFromPB(res)
	if err != nil {
		return nil, fmt.Errorf("could not unmarshal response from PB %s", err)
	}

	decryptor := heint.NewDecryptor(rlweStruct.parameters, rlweStruct.secret_key)
	var allPlaintextBytes []byte
	for i := range rlweStruct.response_ciphertexts {
		plaintext := decryptor.DecryptNew(&rlweStruct.response_ciphertexts[i])
		slice, err := rlweStruct.PlaintextToBytesArray(plaintext)
		if err != nil {
			return nil, err
		}
		allPlaintextBytes = append(allPlaintextBytes, slice...)
	}

	return allPlaintextBytes, nil
}

func (rlweStruct *SimpleRLWE_PIR_Protocol) ProcessRequestAndReturnResponse(request *pb.PIR_Request, database [][]byte) (*pb.PIR_Response, error) {

	// TODO: @Miti Replace logging the time with Go Benchmarks
	//   https://pkg.go.dev/testing#hdr-Benchmarks
	start := time.Now()

	err := rlweStruct.UnmarshallRequestFromPB(request)
	if err != nil {
		return nil, err
	}

	evaluation_keys := rlweStruct.evaluation_keys
	encrypted_query := rlweStruct.encrypted_query

	log2_num_cts := int(math.Log2(float64(rlweStruct.num_cts())))

	N := rlweStruct.parameters.N()
	evaluator := heint.NewEvaluator(rlweStruct.parameters, evaluation_keys)

	var indicator_bits []*rlwe.Ciphertext
	for i := range encrypted_query {
		var indicator_bits_slice []*rlwe.Ciphertext
		if rlweStruct.log2_num_rows-log2_num_cts > 0 {

			indicator_bits_slice, err = evaluator.Expand(&encrypted_query[i], rlweStruct.log2_num_rows-log2_num_cts, 0)
			if err != nil {
				return nil, err
			}

		} else if rlweStruct.log2_num_rows == log2_num_cts {
			indicator_bits_slice = []*rlwe.Ciphertext{&encrypted_query[i]}
		} else {
			return nil, fmt.Errorf("num_rows should be bigger than num_cts")
		}
		indicator_bits = append(indicator_bits, indicator_bits_slice...)
	}

	bytes_per_ciphertext := rlweStruct.bytes_per_coefficient() * N
	max_len_database_entries := maxLengthDBRows(database)
	number_of_response_ciphertexts := (max_len_database_entries + bytes_per_ciphertext - 1) / bytes_per_ciphertext
	rlweStruct.response_ciphertexts = make(structs.Vector[rlwe.Ciphertext], number_of_response_ciphertexts)

	// WARNING: Inner loop is not paralleliable
	for k := 0; k < number_of_response_ciphertexts; k++ {
		for i := 0; i < rlweStruct.num_rows(); i++ {
			// encoding the row of the database into the coefficients of a plaintext
			start_index := bytes_per_ciphertext * k
			end_index := bytes_per_ciphertext * (k + 1)
			if end_index > len(database[i]) {
				end_index = len(database[i])
			}
			row_data_plaintext, err := rlweStruct.BytesArrayToPlaintext(database[i], start_index, end_index)
			if err != nil {
				return nil, err
			}

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

	response, err := rlweStruct.MarshalResponseToPB()
	if err != nil {
		return nil, err
	}

	elapsed := time.Since(start)
	log.Printf("elapsed time: %v", elapsed)

	return response, nil
}
