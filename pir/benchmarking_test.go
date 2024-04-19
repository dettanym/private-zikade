package pir

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"math"
	"math/rand"
	"runtime"
	"testing"
	"time"

	"github.com/plprobelab/zikade/pb"
)

func getPaillierPIRRequestSize(req *pb.PIR_Request) int {
	// TODO: there must be a better way!
	total := len(req.Parameters)
	for _, ct := range req.EncryptedPaillierQuery {
		total += len(ct)
	}
	return total
}

func getPaillierPIRResponseSize(resp *pb.PIR_Response) int {
	// TODO: there must be a better way!
	total := 0
	for _, ct := range resp.EncryptedPaillierResponse {
		total += len(ct)
	}
	return total
}

func getRLWEPIRRequestSize(req *pb.PIR_Request) int {
	// TODO: there must be a better way!
	return len(req.Parameters) + len(req.EncryptedQuery) + len(req.GetRLWEEvaluationKeys())
}

func getRLWEPIRResponseSize(resp *pb.PIR_Response) int {
	// TODO: there must be a better way!
	return len(resp.Ciphertexts)
}

func end_to_end_PIR(b *testing.B, log2_number_of_rows int, log2_num_db_rows int, mode int, row_size int) {

	fmt.Println("- log_2_num_rows: ", log2_number_of_rows)
	fmt.Println("- log_2_num_db_rows: ", log2_num_db_rows)

	db_seed := rand.NewSource(-1) // time.Now().UnixNano())
	num_db_rows := 1 << log2_num_db_rows
	db := make([][]byte, num_db_rows)
	db_element_size := row_size
	for i := range db {
		db[i] = make([]byte, db_element_size)
		for j := 0; j < db_element_size; j++ {
			db[i][j] = byte(rand.New(db_seed).Intn(256))
		}
	}

	var client_PIR_Protocol PIR_Protocol
	if mode == RLWE_All_Keys || mode == RLWE_Whispir_3_Keys || mode == RLWE_Whispir_2_Keys {
		client_PIR_Protocol = NewSimpleRLWE_PIR_Protocol_mode(log2_number_of_rows, mode)
	} else { // mode == Basic_Paillier
		client_PIR_Protocol = NewBasicPaillier_PIR_Protocol(log2_number_of_rows)
	}
	err := client_PIR_Protocol.CreatePrivateKeyMaterial()
	assert.NoError(b, err)

	runs := 2
	// prepare requests
	ourResults := make([]*results, runs)
	for i := 0; i < runs; i++ {
		r := &results{seed: rand.NewSource(int64(i))}

		r.pirRequest = r.Client_PIR_Request(b, client_PIR_Protocol, log2_number_of_rows)
		ourResults[i] = r
	}

	// run them against the server
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < runs; i++ {
		r := ourResults[i]
		r.pirResponse = r.Server_PIR(b, log2_number_of_rows, mode, r.pirRequest, db)
	}
	b.ReportAllocs()
	b.ResetTimer()

	// process response
	for i := 0; i < runs; i++ {
		r := ourResults[i]
		r.Client_PIR_Response(b, client_PIR_Protocol, log2_num_db_rows, row_size, db)
		r.setReqResLen(mode)
	}

	printStats(ourResults)
}

func (r *results) Client_PIR_Request(b *testing.B, client_PIR_Protocol PIR_Protocol, log2_number_of_rows int) *pb.PIR_Request {
	number_of_rows := 1 << log2_number_of_rows

	query := rand.New(r.seed).Intn(number_of_rows)
	r.query = query
	pirRequest, err := client_PIR_Protocol.GenerateRequestFromQuery(query)
	assert.NoError(b, err)

	return pirRequest
}

func (r *results) Client_PIR_Response(b *testing.B, client_PIR_Protocol PIR_Protocol, log2_num_db_rows int, row_size int, db [][]byte) {
	num_db_rows := 1 << log2_num_db_rows

	// client response processing
	response_bytes, err := client_PIR_Protocol.ProcessResponseToPlaintext(r.pirResponse)
	assert.NoError(b, err)
	compared_query := r.query
	if r.query > num_db_rows {
		compared_query = num_db_rows - 1
	}
	db_element_size := row_size
	for k := 0; k < db_element_size; k++ {
		// incorrect response
		require.Equal(b, db[compared_query][k], response_bytes[k])
	}
}

func (r *results) Server_PIR(b *testing.B, log2_number_of_rows int, mode int, pirRequest *pb.PIR_Request, db [][]byte) *pb.PIR_Response {
	response := &pb.PIR_Response{}

	var server_PIR_Protocol PIR_Protocol
	if mode == RLWE_All_Keys || mode == RLWE_Whispir_3_Keys || mode == RLWE_Whispir_2_Keys {
		server_PIR_Protocol = NewSimpleRLWE_PIR_Protocol_mode(log2_number_of_rows, mode)
	} else { // mode == Basic_Paillier
		server_PIR_Protocol = NewBasicPaillier_PIR_Protocol(log2_number_of_rows)
	}

	start_time := time.Now()
	response, err := server_PIR_Protocol.ProcessRequestAndReturnResponse(pirRequest, db)
	assert.NoError(b, err)
	elapsed := time.Since(start_time)
	r.serverRuntime = elapsed.Milliseconds()
	fmt.Println("- server PIR time:", elapsed)
	return response
}

func (r *results) setReqResLen(mode int) {
	if mode == RLWE_All_Keys || mode == RLWE_Whispir_3_Keys || mode == RLWE_Whispir_2_Keys {
		r.requestLen = getRLWEPIRRequestSize(r.pirRequest)
		r.responseLen = getRLWEPIRResponseSize(r.pirResponse)
	} else { // mode == Basic_Paillier
		r.requestLen = getPaillierPIRRequestSize(r.pirRequest)
		r.responseLen = getPaillierPIRResponseSize(r.pirResponse)
	}
	fmt.Println("- request size B: ", r.requestLen)
	fmt.Println("- response size B: ", r.responseLen)
}

func Benchmark_PIR_for_Routing_Table(b *testing.B) {
	// ensures that all CPUs are used
	fmt.Println(runtime.GOMAXPROCS(runtime.NumCPU()))

	row_size := 20 * 256
	modes := []int{Basic_Paillier, RLWE_All_Keys, RLWE_Whispir_2_Keys, RLWE_Whispir_3_Keys}
	for log_2_db_rows := 4; log_2_db_rows <= 8; log_2_db_rows++ {
		for _, mode := range modes {
			fmt.Println("---- mode: ", mode, "Legend:",
				"Paillier = ", Basic_Paillier,
				"RLWE_All_Keys = ", RLWE_All_Keys,
				"RLWE_Whispir_2_Keys = ", RLWE_Whispir_2_Keys,
				"RLWE_Whispir_3_Keys = ", RLWE_Whispir_3_Keys)
			end_to_end_PIR(b, 8, log_2_db_rows, mode, row_size)
		}
	}
}

func Benchmark_PIR_for_Provider_Routing(b *testing.B) {
	// ensures that all CPUs are used
	fmt.Println(runtime.GOMAXPROCS(runtime.NumCPU()))
	for num_cids := 8192; num_cids < 100000; num_cids += 8192 {

		log_2_db_rows := 12

		const BINNING_CONSTANT = 1.001
		// Assuming num_cids and log_2_db_rows are already defined variables
		row_size := int(math.Ceil(BINNING_CONSTANT * float64(num_cids*81) / float64(uint64(1)<<log_2_db_rows)))

		modes := []int{RLWE_All_Keys, RLWE_Whispir_2_Keys, RLWE_Whispir_3_Keys}
		for _, mode := range modes {
			fmt.Println("---- mode: ", mode, "Legend:",
				"RLWE_All_Keys = ", RLWE_All_Keys,
				"RLWE_Whispir_2_Keys = ", RLWE_Whispir_2_Keys,
				"RLWE_Whispir_3_Keys = ", RLWE_Whispir_3_Keys)
			fmt.Println("- num_cids: ", num_cids)
			fmt.Println("- row_size: ", row_size)
			end_to_end_PIR(b, log_2_db_rows, log_2_db_rows, mode, row_size)
		}
	}
}

type results struct {
	seed          rand.Source
	query         int
	requestLen    int
	responseLen   int
	serverRuntime int64
	pirRequest    *pb.PIR_Request
	pirResponse   *pb.PIR_Response
}

func printStats(ourResults []*results) {
	var avgReqLen float64
	var avgResLen float64
	var avgServerTime float64
	runs := len(ourResults)
	for _, res := range ourResults {
		// print("\n ", i, " ", res.requestLen, " ", res.responseLen, " ", res.serverRuntime, "\n")
		avgReqLen += float64(res.requestLen)
		avgResLen += float64(res.responseLen)
		avgServerTime += float64(res.serverRuntime)
	}
	avgReqLen = avgReqLen / float64(runs)
	avgResLen = avgResLen / float64(runs)
	avgServerTime = float64(int64(int(avgServerTime) / runs))
	fmt.Printf("Averaged results over %d runs: Req Length %f, Response Length %f, Server time %f\n", runs, avgReqLen, avgResLen, avgServerTime)
}
