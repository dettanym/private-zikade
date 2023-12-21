package pir

import (
	"fmt"

	"github.com/plprobelab/zikade/pb"
	"github.com/tuneinsight/lattigo/v5/core/rlwe"
	"github.com/tuneinsight/lattigo/v5/he/heint"
	"github.com/tuneinsight/lattigo/v5/utils/sampling"
	"github.com/tuneinsight/lattigo/v5/utils/structs"
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

func (rlweStruct *SimpleRLWE_PIR_Protocol) sampleGenerateRLWECiphertextVector() ([]rlwe.Ciphertext, error) {
	prng, err := sampling.NewPRNG()
	if err != nil {
		return nil, err
	}

	err = rlweStruct.generateParameters()
	if err != nil {
		return nil, err
	}

	// TODO: @Rasoul CHECK THIS
	//  The degree and level below are set on the basis of the heint benchmarks from here:
	//  https://github.com/tuneinsight/lattigo/blob/master/he/heint/heint_benchmark_test.go#L244
	//   Set them meaningfully.
	ct := rlwe.NewCiphertextRandom(prng, rlweStruct.parameters, 1, rlweStruct.parameters.MaxLevel())
	return []rlwe.Ciphertext{*ct}, nil
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

// TODO: @Rasoul --- test this: it throws a panic: key is not correct: sk ring degree does not match params ring degree
func (rlweStruct *SimpleRLWE_PIR_Protocol) generateEvaluationKeys(log2_bits_per_ct int) (*rlwe.MemEvaluationKeySet, error) {
	kgen := rlwe.NewKeyGenerator(rlweStruct.parameters)

	gal_keys := kgen.GenGaloisKeysNew(rlwe.GaloisElementsForExpand(rlweStruct.parameters, log2_bits_per_ct), rlweStruct.secret_key)
	evk := rlwe.NewMemEvaluationKeySet(nil, gal_keys...)

	return evk, nil
}

func (rlweStruct *SimpleRLWE_PIR_Protocol) SampleGeneratePIRRequest() (*pb.PIR_Request, error) {

	// rlweStruct.log2_num_rows = log2_num_rows

	err := rlweStruct.generateParameters()
	if err != nil {
		return nil, err
	}

	parametersBinary, err := rlweStruct.parameters.MarshalBinary()
	if err != nil {
		fmt.Printf("could not create test HE Parameters %s", err)
		return nil, err
	}

	ciphertexts, err := rlweStruct.sampleGenerateRLWECiphertextVector()
	if err != nil {
		return nil, err
	}

	ciphertextBinary, err := structs.Vector[rlwe.Ciphertext](ciphertexts).MarshalBinary()
	if err != nil {
		return nil, err
	}

	evKey, err := rlweStruct.generateEvaluationKeys(rlweStruct.log2_num_rows)
	if err != nil {
		return nil, err
	}
	evKeyBinary, err := evKey.MarshalBinary()
	if err != nil {
		return nil, err
	}

	pirRequest := &pb.PIR_Request{
		Log2NumRows: int64(rlweStruct.log2_num_rows),
		Parameters:  parametersBinary,
		SchemeDependent: &pb.PIR_Request_RLWEEvaluationKeys{
			RLWEEvaluationKeys: evKeyBinary},
		EncryptedQuery: ciphertextBinary,
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
