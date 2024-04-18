package pir

import (
	"fmt"
	"math/big"
	"math/rand"
	"sync"
	"time"

	"github.com/tuneinsight/lattigo/v5/ring"
	"github.com/tuneinsight/lattigo/v5/schemes/bgv"
	"github.com/tuneinsight/lattigo/v5/utils/structs"

	"github.com/plprobelab/zikade/pb"
	"github.com/tuneinsight/lattigo/v5/core/rlwe"
)

// From https://github.com/tuneinsight/lattigo/blob/master/schemes/bgv/examples_parameters.go
func (rlweStruct *SimpleRLWE_PIR_Protocol) generateParameters() error { //
	var pt_mod uint64
	switch rlweStruct.mode {
	case 0:
		pt_mod = 40961 //188417
	case 1:
		pt_mod = 40961
	case 2:
		pt_mod = 40961
	}

	BGVParamsN12QP109 := bgv.ParametersLiteral{
		LogN:             12,
		LogQ:             []int{54},
		LogP:             []int{55},
		PlaintextModulus: pt_mod,
	}

	// Possible values for Plaintext Modulus:
	// The larger, the higher a chance of failure
	// 40961 -> the only one that works with WhisPIR trick
	// 65537
	// 114689
	// 147457
	// 163841
	// 188417
	// 270337 -> this one fails too frequently

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

	var gal_keys []*rlwe.GaloisKey
	if rlweStruct.mode == 0 {
		gal_keys = kgen.GenGaloisKeysNew(rlwe.GaloisElementsForExpand(rlweStruct.parameters, log2_bits_per_ct), rlweStruct.secret_key)
	} else if rlweStruct.mode == 1 {
		gal_keys = kgen.GenGaloisKeysNew([]uint64{3, 5, 1167}, rlweStruct.secret_key)
	} else if rlweStruct.mode == 2 {
		gal_keys = kgen.GenGaloisKeysNew([]uint64{3, 1173}, rlweStruct.secret_key)
	}

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

func twoKeyAutomorphism(eval *bgv.Evaluator, ctIn *rlwe.Ciphertext, galEl uint64) (*rlwe.Ciphertext, error) {

	numMap := map[int][]int{
		4097: {10, 42}, // 1 + 4096
		2049: {32, 32}, // 1 + 2048
		1025: {16, 16}, // 1 + 1024
		513:  {18, 50}, // 1 + 512
		257:  {80, 16}, // 1 + 256
		129:  {50, 50}, // 1 + 128
		65:   {20, 4},  // 1 + 64
		33:   {28, 52}, // 1 + 32
		17:   {0, 12},  // 1 + 16
		9:    {2, 0},   // 1 + 8
		5:    {0, 5},   // 1 + 4
		3:    {1, 0},   // 1 + 2
	}

	g_pow, h_pow := numMap[int(galEl)][0], numMap[int(galEl)][1]

	g := uint64(3)
	h := uint64(1173)

	opOut := ctIn.CopyNew()
	for k := 0; k < g_pow; k++ {
		err := eval.Automorphism(opOut, g, opOut)
		if err != nil {
			return nil, err
		}
	}
	for l := 0; l < h_pow; l++ {
		err := eval.Automorphism(opOut, h, opOut)
		if err != nil {
			return nil, err
		}
	}
	return opOut, nil
}

func threeKeyAutomorphism(eval *bgv.Evaluator, ctIn *rlwe.Ciphertext, galEl uint64) (*rlwe.Ciphertext, error) {
	numMap := map[int][]int{
		4097: {14, 6, 4},  // 1 + 4096
		2049: {2, 2, 14},  // 1 + 2048
		1025: {1, 1, 7},   // 1 + 1024
		513:  {18, 10, 0}, // 1 + 512
		257:  {4, 4, 12},  // 1 + 256
		129:  {19, 3, 1},  // 1 + 128
		65:   {1, 1, 3},   // 1 + 64
		33:   {1, 1, 5},   // 1 + 32
		17:   {4, 0, 4},   // 1 + 16
		9:    {2, 0, 0},   // 1 + 8
		5:    {0, 1, 0},   // 1 + 4
		3:    {1, 0, 0},   // 1 + 2
	}

	f_pow, g_pow, h_pow := numMap[int(galEl)][0], numMap[int(galEl)][1], numMap[int(galEl)][2]

	f := uint64(3)
	g := uint64(5)
	h := uint64(1167)

	opOut := ctIn.CopyNew()
	for i := 0; i < f_pow; i++ {
		err := eval.Automorphism(opOut, f, opOut)
		if err != nil {
			return nil, err
		}
	}
	for k := 0; k < g_pow; k++ {
		err := eval.Automorphism(opOut, g, opOut)
		if err != nil {
			return nil, err
		}
	}
	for l := 0; l < h_pow; l++ {
		err := eval.Automorphism(opOut, h, opOut)
		if err != nil {
			return nil, err
		}
	}
	return opOut, nil
}

// Expand expands a RLWE Ciphertext encrypting sum ai * X^i to 2^logN ciphertexts,
// each encrypting ai * X^0 for 0 <= i < 2^LogN. That is, it extracts the first 2^logN
// coefficients, whose degree is a multiple of 2^logGap, of ctIn and returns an RLWE
// Ciphertext for each coefficient extracted.
//
// The method will return an error if:
//   - The input ciphertext degree is not one
//   - The ring type is not ring.Standard
func customExpand(eval *bgv.Evaluator, mode int, ctIn *rlwe.Ciphertext, logN, logGap int) (opOut []*rlwe.Ciphertext, err error) {

	if ctIn.Degree() != 1 {
		return nil, fmt.Errorf("cannot Expand: ctIn.Degree() != 1")
	}

	params := eval.GetRLWEParameters()

	if params.RingType() != ring.Standard {
		return nil, fmt.Errorf("cannot Expand: method is only supported for ring.Type = ring.Standard (X^{-2^{i}} does not exist in the sub-ring Z[X + X^{-1}])")
	}

	level := ctIn.Level()

	ringQ := params.RingQ().AtLevel(level)

	// Compute X^{-2^{i}} from 1 to LogN
	xPow2 := rlwe.GenXPow2(ringQ, logN, true)

	opOut = make([]*rlwe.Ciphertext, 1<<(logN-logGap))
	opOut[0] = ctIn.CopyNew()
	opOut[0].LogDimensions = ring.Dimensions{Rows: 0, Cols: 0}

	if ct := opOut[0]; !ctIn.IsNTT {
		ringQ.NTT(ct.Value[0], ct.Value[0])
		ringQ.NTT(ct.Value[1], ct.Value[1])
		ct.IsNTT = true
	}

	// Multiplies by 2^{-logN} mod Q
	NInv := new(big.Int).SetUint64(1 << logN)
	NInv.ModInverse(NInv, ringQ.ModulusAtLevel[level])

	ringQ.MulScalarBigint(opOut[0].Value[0], NInv, opOut[0].Value[0])
	ringQ.MulScalarBigint(opOut[0].Value[1], NInv, opOut[0].Value[1])

	gap := 1 << logGap

	var wg sync.WaitGroup
	for i := 0; i < logN; i++ {

		n := 1 << i

		galEl := uint64(ringQ.N()/n + 1)

		half := n / gap

		// start := time.Now()
		maxJ := (n + gap - 1) / gap
		for j := 0; j < maxJ; j++ {
			wg.Add(1)

			go func(j int, eval *bgv.Evaluator, galEl uint64, c0 *rlwe.Ciphertext) {
				defer wg.Done()

				tmp, err := rlwe.NewCiphertextAtLevelFromPoly(level, []ring.Poly{eval.BuffCt.Value[0], eval.BuffCt.Value[1]})

				// Sanity check, this error should not happen unless the
				// evaluator's buffer thave been improperly tempered with.
				if err != nil {
					panic(err)
				}

				tmp.MetaData = ctIn.MetaData

				// X -> X^{N/n + 1}
				//[a, b, c, d] -> [a, -b, c, -d]

				switch mode {
				case 0:
					if err = eval.Automorphism(c0, galEl, tmp); err != nil {
						return
					}
				case 1:
					if tmp, err = threeKeyAutomorphism(eval, c0, galEl); err != nil {
						return
					}

				case 2:
					if tmp, err = twoKeyAutomorphism(eval, c0, galEl); err != nil {
						return
					}
				}

				if j+half > 0 {

					c1 := opOut[j].CopyNew()

					// opOut[j] is only modified by the next two lines
					// Zeroes odd coeffs: [a, b, c, d] + [a, -b, c, -d] -> [2a, 0, 2b, 0]
					ringQ.Add(c0.Value[0], tmp.Value[0], c0.Value[0])
					ringQ.Add(c0.Value[1], tmp.Value[1], c0.Value[1])

					// compute the value for opOut[half + j]
					// Zeroes even coeffs: [a, b, c, d] - [a, -b, c, -d] -> [0, 2b, 0, 2d]
					ringQ.Sub(c1.Value[0], tmp.Value[0], c1.Value[0])
					ringQ.Sub(c1.Value[1], tmp.Value[1], c1.Value[1])

					// c1 * X^{-2^{i}}: [0, 2b, 0, 2d] * X^{-n} -> [2b, 0, 2d, 0]
					ringQ.MulCoeffsMontgomery(c1.Value[0], xPow2[i], c1.Value[0])
					ringQ.MulCoeffsMontgomery(c1.Value[1], xPow2[i], c1.Value[1])

					opOut[j+half] = c1

				} else {

					// Zeroes odd coeffs: [a, b, c, d] + [a, -b, c, -d] -> [2a, 0, 2b, 0]
					ringQ.Add(c0.Value[0], tmp.Value[0], c0.Value[0])
					ringQ.Add(c0.Value[1], tmp.Value[1], c0.Value[1])
				}
			}(j, eval.ShallowCopy(), galEl, opOut[j])

		}
		wg.Wait()
		// duration := time.Since(start)
		// fmt.Println(" - custom expansion: for loop: i", i, " maxJ: ", maxJ, " takes:\t\t\t", duration)

	}

	for _, ct := range opOut {
		if ct != nil && !ctIn.IsNTT {
			ringQ.INTT(ct.Value[0], ct.Value[0])
			ringQ.INTT(ct.Value[1], ct.Value[1])
			ct.IsNTT = false
		}
	}
	return
}
