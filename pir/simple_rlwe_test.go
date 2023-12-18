package pir

import (
	"github.com/stretchr/testify/require"
	"testing"
)

func TestSimpleRLWEPIRQuery_UnmarshallRequestFromPB(t *testing.T) {
	pirRequest, err := GeneratePIRRequest()
	require.NoError(t, err)

	query := &SimpleRLWEPIRQuery{}

	err = query.UnmarshallRequestFromPB(pirRequest)
	require.NoError(t, err)
}

func TestPIR_Protocol_Simple_RLWE_ProcessRequestAndReturnResponse(t *testing.T) {
	pirRequest, err := GeneratePIRRequest()
	require.NoError(t, err)

	// TODO: Gen random DB of right size
	db := make([][]byte, 256)

	response, err := ProcessRequestAndReturnResponse(pirRequest, db)
	require.NoError(t, err)

	println(response)
}
