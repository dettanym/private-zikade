package pir

import (
	"github.com/stretchr/testify/require"
	"testing"
)

func TestSimpleRLWEPIRQuery_UnmarshallRequestFromPB(t *testing.T) {
	chosen_PIR_Protocol := SimpleRLWE_PIR_Protocol{}

	pirRequest, err := chosen_PIR_Protocol.SampleGeneratePIRRequest()
	require.NoError(t, err)

	query := &SimpleRLWE_PIR_Protocol{}

	err = query.UnmarshallRequestFromPB(pirRequest)
	require.NoError(t, err)
}

func TestPIR_Protocol_Simple_RLWE_ProcessRequestAndReturnResponse(t *testing.T) {
	chosen_PIR_Protocol := SimpleRLWE_PIR_Protocol{}

	pirRequest, err := chosen_PIR_Protocol.SampleGeneratePIRRequest()
	require.NoError(t, err)

	db := make([][]byte, 256)
	for i := range db {
		db[i] = make([]byte, 20*256)
	}

	response, err := chosen_PIR_Protocol.ProcessRequestAndReturnResponse(pirRequest, db)
	require.NoError(t, err)

	println(response)
}
