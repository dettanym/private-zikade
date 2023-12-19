package pir

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSimpleRLWEPIRQuery_UnmarshallRequestFromPB(t *testing.T) {
	number_of_rows := 8
	chosen_PIR_Protocol := NewSimpleRLWE_PIR_Protocol(number_of_rows)

	pirRequest, err := chosen_PIR_Protocol.SampleGeneratePIRRequest()
	require.NoError(t, err)

	query := NewSimpleRLWE_PIR_Protocol(number_of_rows)

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

	response, err := chosen_PIR_Protocol.ProcessRequestAndReturnResponse(pirRequest, db)
	require.NoError(t, err)

	println(response)
}
