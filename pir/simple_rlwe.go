package private_routing

import (
	"log"
	"time"

	"github.com/plprobelab/zikade/pb"
	"github.com/tuneinsight/lattigo/v4/bfv"
	"github.com/tuneinsight/lattigo/v4/rlwe"
)

// This function needs to fetch the 'index'th row from the database.
// And return the data as a vector of N uint64, where each number if less than mod
func encode_db_row_as_size_N_vector(index uint64, N uint64, mod uint64) []uint64 {
	// TODO: Make this function actually fetch the row from the database
	// Right now it's just generating a random row
	db_rows := make([]uint64, N)
	for i := uint64(0); i < N; i++ {
		db_rows[i] = uint64(((i*i)%mod + i) % mod)
	}
	return db_rows
}

type PIR_Protocol interface {
	ProcessRequestAndReturnResponse(msg *pb.PIR_Message) (*pb.PIR_Message, error)
}

type PIR_Protocol_Simple_RLWE struct {
}

func (p *PIR_Protocol_Simple_RLWE) ProcessRequestAndReturnResponse(msg *pb.PIR_Protocol_Simple_RLWE_Request) (*pb.PIR_Protocol_Simple_RLWE_Response, error) {
	start := time.Now()

	server_params, err := bfv.NewParametersFromLiteral(bfv.PN12QP109)
	if err != nil {
		panic(err)
	}
	server_encoder := bfv.NewEncoder(server_params)
	number_of_rows := 256
	N := server_params.N()
	plain_mod := server_params.T()
	evaluator := bfv.NewEvaluator(server_params, &rlwe.EvaluationKeySet{})
	server_plaintext := bfv.NewPlaintext(server_params, server_params.MaxLevel())

	number_of_input_ciphertexts := int(msg.NumberOfCiphertexts)
	ciphertexts := make([]*rlwe.Ciphertext, number_of_input_ciphertexts)
	for i := 0; i < number_of_input_ciphertexts; i++ {
		ciphertexts[i] = new(rlwe.Ciphertext)
		err = ciphertexts[i].UnmarshalBinary(msg.Ciphertext[i])
		if err != nil {
			return nil, err
		}
	}

	db_row := encode_db_row_as_size_N_vector(0, uint64(N), uint64(plain_mod))
	server_encoder.EncodeCoeffs(db_row, server_plaintext)
	evaluator.Mul(ciphertexts[0], server_plaintext, ciphertexts[0])
	for i := 1; i < number_of_rows; i++ {
		db_row = encode_db_row_as_size_N_vector(uint64(i), uint64(N), uint64(plain_mod))
		server_encoder.EncodeCoeffs(db_row, server_plaintext)
		evaluator.Mul(ciphertexts[i], server_plaintext, ciphertexts[i])
		evaluator.Add(ciphertexts[0], ciphertexts[i], ciphertexts[0])
	}

	elapsed := time.Since(start)
	log.Printf("elapsed time: %v", elapsed)

	marshalled_response, err := ciphertexts[0].MarshalBinary()
	if err != nil {
		return nil, err
	}
	// return &pb.PIR_Message{Ciphertext: marshalled_response}, nil
	return &pb.PIR_Protocol_Simple_RLWE_Response{
		NumberOfCiphertexts: 1,
		Ciphertext:          [][]byte{marshalled_response},
	}, nil
}
