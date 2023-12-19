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

	// TODO: The degree and level below are set on the basis of the heint benchmarks from here:
	//  https://github.com/tuneinsight/lattigo/blob/master/he/heint/heint_benchmark_test.go#L244
	//   Set them meaningfully.
	ct := rlwe.NewCiphertextRandom(prng, rlweStruct.parameters, 1, rlweStruct.parameters.MaxLevel())
	return []rlwe.Ciphertext{*ct}, nil
}

func (rlweStruct *SimpleRLWE_PIR_Protocol) encryptRLWEPlaintexts(plaintexts []*rlwe.Plaintext) ([]rlwe.Ciphertext, error) {
	ciphertexts := make([]rlwe.Ciphertext, len(plaintexts))
	sk_encryptor := heint.NewEncryptor(rlweStruct.parameters, &rlweStruct.secret_key)
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
	sk := kgen.GenSecretKeyNew()

	gal_keys := kgen.GenGaloisKeysNew(rlwe.GaloisElementsForExpand(rlweStruct.parameters, log2_bits_per_ct), sk)
	evk := rlwe.NewMemEvaluationKeySet(nil, gal_keys...)

	return evk, nil
}

func (rlweStruct *SimpleRLWE_PIR_Protocol) SampleGeneratePIRRequest() (*pb.PIR_Request, error) {
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
		Parameters: parametersBinary,
		SchemeDependent: &pb.PIR_Request_RLWEEvaluationKeys{
			RLWEEvaluationKeys: evKeyBinary},
		EncryptedQuery: ciphertextBinary,
	}

	return pirRequest, nil
}
