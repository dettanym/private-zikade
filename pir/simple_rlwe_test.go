package pir

import (
	"math/rand"
	"testing"
	"time"

	"github.com/plprobelab/zikade/pb"
	"github.com/stretchr/testify/require"
)

func TestSimpleRLWEPIRQuery_UnmarshallRequestFromPB(t *testing.T) {
	log2_number_of_rows := 8
	chosen_PIR_Protocol := NewSimpleRLWE_PIR_Protocol(log2_number_of_rows)
	err := chosen_PIR_Protocol.CreatePrivateKeyMaterial()
	require.NoError(t, err)

	// Generate random sample PIR request as follows:
	pirRequest, err := chosen_PIR_Protocol.SampleGeneratePIRRequest(1 << log2_number_of_rows)
	require.NoError(t, err)

	server_PIR_Protocol := SimpleRLWE_PIR_Protocol{}

	err = server_PIR_Protocol.unmarshallRequestFromPB(pirRequest)
	require.NoError(t, err)
}

func TestPIR_Protocol_Simple_RLWE_ProcessRequestAndReturnResponse(t *testing.T) {
	log2_number_of_rows := 8
	chosen_PIR_Protocol := NewSimpleRLWE_PIR_Protocol(log2_number_of_rows)
	err := chosen_PIR_Protocol.CreatePrivateKeyMaterial()
	require.NoError(t, err)

	pirRequest, err := chosen_PIR_Protocol.SampleGeneratePIRRequest(1 << log2_number_of_rows)
	require.NoError(t, err)

	db := make([][]byte, 1<<log2_number_of_rows)
	for i := range db {
		db[i] = make([]byte, 20*256)
	}

	_, err = chosen_PIR_Protocol.ProcessRequestAndReturnResponse(pirRequest, db)
	require.NoError(t, err)

}

func TestPlaintextToBytesArray(t *testing.T) {
	PIR_Protocol := NewSimpleRLWE_PIR_Protocol(1)
	PIR_Protocol.generateParameters()

	seed := rand.NewSource(time.Now().UnixNano())

	bytesArray := make([]byte, 100)

	for i := range bytesArray {
		bytesArray[i] = byte(rand.New(seed).Intn(256))
	}
	start_index := 12
	end_index := 34
	plaintext, err := PIR_Protocol.BytesArrayToPlaintext(bytesArray, start_index, end_index)
	require.NoError(t, err)
	bytesArray2, err := PIR_Protocol.PlaintextToBytesArray(plaintext)
	require.NoError(t, err)
	for i := 0; i < end_index-start_index; i++ {
		require.Equal(t, bytesArray[start_index+i], bytesArray2[i])
	}
}

func TestPIR_ProcessRequestAndReturnResponse_Correctness(t *testing.T) {

	// client query generation
	log2_number_of_rows := 12
	mode := RLWE_All_Keys
	client_PIR_Protocol := NewSimpleRLWE_PIR_Protocol_mode(log2_number_of_rows, mode)
	err := client_PIR_Protocol.CreatePrivateKeyMaterial()
	require.NoError(t, err)

	seed := rand.NewSource(time.Now().UnixNano())
	query := rand.New(seed).Intn(1 << log2_number_of_rows)
	pirRequest, err := client_PIR_Protocol.GenerateRequestFromQuery(query)
	require.NoError(t, err)

	// server
	db := make([][]byte, 1<<log2_number_of_rows)
	db_element_size := 20 * 256
	response := &pb.PIR_Response{}
	{
		server_PIR_Protocol := NewSimpleRLWE_PIR_Protocol_mode(log2_number_of_rows, mode)

		for i := range db {
			db[i] = make([]byte, db_element_size)
			for j := 0; j < db_element_size; j++ {
				db[i][j] = byte(rand.New(seed).Intn(256))
			}
		}

		response, err = server_PIR_Protocol.ProcessRequestAndReturnResponse(pirRequest, db)
		require.NoError(t, err)

	} // end server

	// client response processing
	response_bytes, err := client_PIR_Protocol.ProcessResponseToPlaintext(response)
	require.NoError(t, err)
	for k := 0; k < db_element_size; k++ {
		require.Equal(t, db[query][k], response_bytes[k])
	}
}

func TestPIR_ProcessRequestAndReturnResponse_Correctness_LessThan256Rows(t *testing.T) {

	// client query generation
	log2_num_db_rows := 4
	log2_number_of_rows := 8

	num_db_rows := 1 << log2_num_db_rows
	number_of_rows := 1 << log2_number_of_rows

	mode := RLWE_Whispir_3_Keys
	client_PIR_Protocol := NewSimpleRLWE_PIR_Protocol_mode(log2_number_of_rows, mode)
	err := client_PIR_Protocol.CreatePrivateKeyMaterial()
	require.NoError(t, err)

	seed := rand.NewSource(time.Now().UnixNano())
	query := num_db_rows + rand.New(seed).Intn(number_of_rows-num_db_rows)
	pirRequest, err := client_PIR_Protocol.GenerateRequestFromQuery(query)
	require.NoError(t, err)

	// server
	db := make([][]byte, num_db_rows)
	db_element_size := 20 * 256
	response := &pb.PIR_Response{}
	{
		server_PIR_Protocol := NewSimpleRLWE_PIR_Protocol_mode(log2_number_of_rows, mode)

		for i := range db {
			db[i] = make([]byte, db_element_size)
			for j := 0; j < db_element_size; j++ {
				db[i][j] = byte(rand.New(seed).Intn(256))
			}
		}

		response, err = server_PIR_Protocol.ProcessRequestAndReturnResponse(pirRequest, db)
		require.NoError(t, err)

	} // end server

	// client response processing
	response_bytes, err := client_PIR_Protocol.ProcessResponseToPlaintext(response)
	require.NoError(t, err)
	compared_query := query
	if query > num_db_rows {
		compared_query = num_db_rows - 1
	}
	for k := 0; k < db_element_size; k++ {
		require.Equal(t, db[compared_query][k], response_bytes[k])
	}

}

func Benchmark_Key_Sizes(b *testing.B) {
	log2_number_of_rows := 4
	client_PIR_Protocol := NewSimpleRLWE_PIR_Protocol(log2_number_of_rows)
	client_PIR_Protocol.generateParameters()
	client_PIR_Protocol.CreatePrivateKeyMaterial()

	query := 0
	pirRequest, err := client_PIR_Protocol.GenerateRequestFromQuery(query)
	require.NoError(b, err)

	println("Evlauation Key Sizes:", len(pirRequest.GetRLWEEvaluationKeys()), "B")
	println("Query Ciphertext Sizes", len(pirRequest.GetEncryptedQuery()), "B")

	// server
	num_db_rows := 16
	db := make([][]byte, num_db_rows)
	db_element_size := 10
	response := &pb.PIR_Response{}
	{
		server_PIR_Protocol := NewSimpleRLWE_PIR_Protocol(log2_number_of_rows)

		for i := range db {
			db[i] = make([]byte, db_element_size)
			for j := 0; j < db_element_size; j++ {
				db[i][j] = 1
			}
		}

		response, err = server_PIR_Protocol.ProcessRequestAndReturnResponse(pirRequest, db)
		require.NoError(b, err)

	} // end server

	println("Response Ciphertext Sizes", len(response.Ciphertexts), "B")

}

func Benchmark_Possible_Eval_key_sizes(b *testing.B) {
	for log2_number_of_rows := 0; log2_number_of_rows <= 12; log2_number_of_rows++ {
		client_PIR_Protocol := NewSimpleRLWE_PIR_Protocol(log2_number_of_rows)
		client_PIR_Protocol.generateParameters()
		client_PIR_Protocol.CreatePrivateKeyMaterial()

		query := 0
		pirRequest, err := client_PIR_Protocol.GenerateRequestFromQuery(query)
		require.NoError(b, err)

		println("Evaluation Key Sizes (N=", log2_number_of_rows, ") :", len(pirRequest.GetRLWEEvaluationKeys()), "B")

	}

}
