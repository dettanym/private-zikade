package pir

import (
	"fmt"
	"math/rand"
	"time"

	"github.com/tuneinsight/lattigo/v5/schemes/bgv"
	"github.com/tuneinsight/lattigo/v5/utils/structs"

	"github.com/plprobelab/zikade/pb"
	"github.com/tuneinsight/lattigo/v5/core/rlwe"
)

// From https://github.com/tuneinsight/lattigo/blob/master/schemes/bgv/examples_parameters.go
func (rlweStruct *SimpleRLWE_PIR_Protocol) generateParameters() error { //
	BGVParamsN12QP109 := bgv.ParametersLiteral{
		LogN:             12,
		LogQ:             []int{54},
		LogP:             []int{55},
		PlaintextModulus: 270337,
		// PlaintextModulus: 0x1001,
	}

	params, err := bgv.NewParametersFromLiteral(BGVParamsN12QP109)
	if err != nil {
		return fmt.Errorf("could not create test HE Parameters %s", err)
	}
	rlweStruct.parameters = params

	return nil
}

func (rlweStruct *SimpleRLWE_PIR_Protocol) encryptRLWEPlaintexts(plaintexts []*rlwe.Plaintext) ([]rlwe.Ciphertext, error) {
	if rlweStruct.secret_key == nil {
		return nil, fmt.Errorf("secret key has not been generated yet")
	}
	ciphertexts := make([]rlwe.Ciphertext, len(plaintexts))
	sk_encryptor := bgv.NewEncryptor(rlweStruct.parameters, rlweStruct.secret_key)
	for i := range plaintexts {
		tmp, err := sk_encryptor.EncryptNew(plaintexts[i])
		if err != nil {
			return nil, err
		}
		ciphertexts[i] = *tmp
	}
	return ciphertexts, nil
}

func (rlweStruct *SimpleRLWE_PIR_Protocol) generateEvaluationKeys(log2_bits_per_ct int) (*rlwe.MemEvaluationKeySet, error) {
	kgen := rlwe.NewKeyGenerator(rlweStruct.parameters)

	gal_keys := kgen.GenGaloisKeysNew(rlwe.GaloisElementsForExpand(rlweStruct.parameters, log2_bits_per_ct), rlweStruct.secret_key)
	evk := rlwe.NewMemEvaluationKeySet(nil, gal_keys...)

	return evk, nil
}

func (rlweStruct *SimpleRLWE_PIR_Protocol) SampleGeneratePIRRequest(number_of_rows int) (*pb.PIR_Request, error) {
	seed := rand.NewSource(time.Now().UnixNano())
	query := rand.New(seed).Intn(number_of_rows)
	pirRequest, err := rlweStruct.GenerateRequestFromQuery(query)
	if err != nil {
		return nil, fmt.Errorf("error generating request from query")
	}
	return pirRequest, nil
}

// For the routing case, the normalization algorithm will ensure that all rows have the same number of peer records.
// Potentially, a record can have many multiaddresses, so that could be the only reason why the size of a row can vary (routing case).
// Similarly, a CID can be provided by multiple peers, so that is a reason why the size of a row can vary for the provider advertisements case.
// It's perfectly reasonable to use this function for each request, and optimize it later.
func maxLengthDBRows(database [][]byte) int {
	num_rows := len(database)
	max_len_database_entries := len(database[0])
	for i := 1; i < num_rows; i++ {
		if len(database[i]) > max_len_database_entries {
			max_len_database_entries = len(database[i])
		}
	}
	return max_len_database_entries
}

func (rlweStruct *SimpleRLWE_PIR_Protocol) initializeResponseCTs(database [][]byte) {
	max_len_database_entries := maxLengthDBRows(database)
	number_of_response_ciphertexts := (max_len_database_entries + rlweStruct.bytesPerCiphertext - 1) / rlweStruct.bytesPerCiphertext
	rlweStruct.response_ciphertexts = make(structs.Vector[rlwe.Ciphertext], number_of_response_ciphertexts)
}

// encodes the rows of the database into the coefficients of a plaintext
func (rlweStruct *SimpleRLWE_PIR_Protocol) transformDBToPlaintextForm(database [][]byte) error {
	rlweStruct.initializeResponseCTs(database)
	num_db_rows := len(database)

	// Generating a matrix for the transformed DB,
	// while ensuring that the assigned slices are local in memory
	// https://go.dev/doc/effective_go#slices
	transformedDB := make([][]*rlwe.Plaintext, num_db_rows) // One row per unit of y.
	for i := range transformedDB {
		transformedDB[i] = make([]*rlwe.Plaintext, len(rlweStruct.response_ciphertexts))
	}

	// WARNING: Inner loop is not parallelizable
	for k := 0; k < len(rlweStruct.response_ciphertexts); k++ {
		for i := 0; i < num_db_rows; i++ {
			start_index := rlweStruct.bytesPerCiphertext * k
			end_index := rlweStruct.bytesPerCiphertext * (k + 1)
			if end_index > len(database[i]) {
				end_index = len(database[i])
			}

			row_data_plaintext, err := rlweStruct.BytesArrayToPlaintext(database[i], start_index, end_index)
			if err != nil {
				return err
			}

			transformedDB[i][k] = row_data_plaintext
		}
	}

	rlweStruct.plaintextDB = transformedDB
	return nil
}
