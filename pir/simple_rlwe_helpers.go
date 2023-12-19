package pir

import (
	"fmt"
	"github.com/plprobelab/zikade/pb"
	"github.com/tuneinsight/lattigo/v5/core/rlwe"
	"github.com/tuneinsight/lattigo/v5/he/heint"
	"github.com/tuneinsight/lattigo/v5/utils"
	"github.com/tuneinsight/lattigo/v5/utils/sampling"
)

// From https://github.com/tuneinsight/lattigo/blob/master/schemes/bgv/examples_parameters.go
func sampleGenerateParameters() (*heint.Parameters, error) { //
	var (
		// ExampleParameters128BitLogN14LogQP438 is an example parameters set with logN=14, logQP=438
		// and a 16-bit plaintext modulus, offering 128-bit of security.
		ExampleParameters128BitLogN14LogQP438 = heint.ParametersLiteral{
			LogN: 14,
			Q: []uint64{0x10000048001, 0x20008001, 0x1ffc8001,
				0x20040001, 0x1ffc0001, 0x1ffb0001,
				0x20068001, 0x1ff60001, 0x200b0001,
				0x200d0001, 0x1ff18001, 0x200f8001}, // 40 + 11*29 bits
			P:                []uint64{0x10000140001, 0x7ffffb0001}, // 40 + 39 bits
			PlaintextModulus: 0x10001,                               // 16 bits
		}
	)

	literal, err := heint.NewParametersFromLiteral(ExampleParameters128BitLogN14LogQP438)
	if err != nil {
		return nil, fmt.Errorf("could not create test HE Parameters %s", err)
	}

	return &literal, nil
}

func sampleGenerateRLWECiphertext() (*rlwe.Ciphertext, error) {
	prng, err := sampling.NewPRNG()
	if err != nil {
		return nil, err
	}

	params, err := sampleGenerateParameters()
	if err != nil {
		return nil, err
	}

	// TODO: The degree and level below are set on the basis of the heint benchmarks from here:
	//  https://github.com/tuneinsight/lattigo/blob/master/he/heint/heint_benchmark_test.go#L244
	//   Set them meaningfully.
	ct := rlwe.NewCiphertextRandom(prng, params, 1, params.MaxLevel())
	return ct, nil
}

func sampleGenerateEvaluationKeys() (*rlwe.EvaluationKey, error) {
	params, err := sampleGenerateParameters()
	if err != nil {
		return nil, err
	}
	// https://github.com/tuneinsight/lattigo/blob/v5.0.2/core/rlwe/rlwe_benchmark_test.go#L136
	// https://github.com/tuneinsight/lattigo/blob/v5.0.2/core/rlwe/test_params.go
	evkParams := rlwe.EvaluationKeyParameters{
		LevelQ:               utils.Pointy(params.MaxLevelQ()),
		LevelP:               utils.Pointy(params.MaxLevelP()),
		BaseTwoDecomposition: utils.Pointy(16),
	}

	// https://github.com/tuneinsight/lattigo/blob/v5.0.2/core/rlwe/keys.go#L327
	evKey := rlwe.NewEvaluationKey(params, evkParams)
	return evKey, nil
}

func SampleGeneratePIRRequest() (*pb.PIR_Request, error) {
	parameters, err := sampleGenerateParameters()
	if err != nil {
		return nil, err
	}

	parametersBinary, err := parameters.MarshalBinary()
	if err != nil {
		fmt.Printf("could not create test HE Parameters %s", err)
		return nil, err
	}

	ciphertext, err := sampleGenerateRLWECiphertext()
	if err != nil {
		return nil, err
	}

	ciphertextBinary, err := ciphertext.MarshalBinary()
	if err != nil {
		return nil, err
	}

	evKey, err := sampleGenerateEvaluationKeys()
	if err != nil {
		return nil, err
	}
	evKeyBinary, err := evKey.MarshalBinary()
	if err != nil {
		return nil, err
	}

	pirRequest := &pb.PIR_SimpleRLWE_Request{
		Parameters: parametersBinary,
		OneOfParameters: &pb.PIR_SimpleRLWE_Request_EvaluationKeys{
			EvaluationKeys: evKeyBinary},
		EncryptedQuery: ciphertextBinary,
	}

	return pirRequest, nil
}
