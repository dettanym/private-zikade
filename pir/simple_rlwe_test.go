package pir

import (
	"math/rand"
	"testing"
	"time"

	"github.com/plprobelab/zikade/pb"
	"github.com/stretchr/testify/require"
)

func TestSimpleRLWEPIRQuery_UnmarshallRequestFromPB(t *testing.T) {
	number_of_rows := 8
	chosen_PIR_Protocol := NewSimpleRLWE_PIR_Protocol(number_of_rows)

	pirRequest, err := chosen_PIR_Protocol.SampleGeneratePIRRequest()
	require.NoError(t, err)

	query := SimpleRLWE_PIR_Protocol{}

	err = query.UnmarshallRequestFromPB(pirRequest)
	require.NoError(t, err)
}

func TestPIR_Protocol_Simple_RLWE_ProcessRequestAndReturnResponse(t *testing.T) {
	log2_number_of_rows := 8
	chosen_PIR_Protocol := NewSimpleRLWE_PIR_Protocol(log2_number_of_rows)

	pirRequest, err := chosen_PIR_Protocol.SampleGeneratePIRRequest()
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
	log2_number_of_rows := 8
	client_PIR_Protocol := NewSimpleRLWE_PIR_Protocol(log2_number_of_rows)
	seed := rand.NewSource(time.Now().UnixNano())
	query := rand.New(seed).Intn(1 << log2_number_of_rows)
	pirRequest, err := client_PIR_Protocol.GenerateRequestFromQuery(query)
	require.NoError(t, err)

	// server
	db := make([][]byte, 1<<log2_number_of_rows)
	db_element_size := 20 * 256
	response := &pb.PIR_Response{}
	{
		server_PIR_Protocol := SimpleRLWE_PIR_Protocol{}

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
	for i := 0; i < db_element_size; i++ {
		require.Equal(t, db[query][i], response_bytes[i])
	}

}
