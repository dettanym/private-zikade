package pir

import (
	"fmt"
	"math/rand"
	"time"

	"github.com/plprobelab/zikade/pb"
	"github.com/tuneinsight/lattigo/v5/core/rlwe"
	"github.com/tuneinsight/lattigo/v5/he/heint"
)

// From https://github.com/tuneinsight/lattigo/blob/master/schemes/bgv/examples_parameters.go
func (rlweStruct *SimpleRLWE_PIR_Protocol) generateParameters() error { //
	HEIntParamsN12QP109 := heint.ParametersLiteral{
		LogN:             12,
		LogQ:             []int{39, 31},
		LogP:             []int{39},
		PlaintextModulus: 0x10001,
	}

	params, err := heint.NewParametersFromLiteral(HEIntParamsN12QP109)
	if err != nil {
		return fmt.Errorf("could not create test HE Parameters %s", err)
	}
	rlweStruct.parameters = params

	return nil
}

func (rlweStruct *SimpleRLWE_PIR_Protocol) encryptRLWEPlaintexts(plaintexts []*rlwe.Plaintext) ([]rlwe.Ciphertext, error) {
	ciphertexts := make([]rlwe.Ciphertext, len(plaintexts))
	sk_encryptor := heint.NewEncryptor(rlweStruct.parameters, rlweStruct.secret_key)
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
