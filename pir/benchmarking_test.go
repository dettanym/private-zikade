package pir

import (
	"fmt"
	"math/rand"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/gocarina/gocsv"
	"github.com/plprobelab/zikade/pb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gonum.org/v1/gonum/stat"
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

func (s *resultsStats) end_to_end_PIR(b *testing.B, log2_number_of_rows int, log2_num_db_rows int, mode int, row_size int) {

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

	// prepare requests
	runs := s.Runs
	ourResults := make([]*results, runs)
	s.SeedMin = 0
	for i := 0; i < runs; i++ {
		r := &results{seed: rand.NewSource(int64(i))}

		r.pirRequest = r.Client_PIR_Request(b, client_PIR_Protocol, log2_number_of_rows)
		r.pirResponse = r.Server_PIR(b, log2_number_of_rows, mode, r.pirRequest, db)
		r.Client_PIR_Response(b, client_PIR_Protocol, log2_num_db_rows, row_size, db)
		r.setReqResLen(mode)

		ourResults[i] = r
	}
	s.SeedMax = runs - 1
	s.setStats(ourResults)

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

	runs := 10 // b.N
	peerRoutingResultsStats := make([]resultsStats, runs)

	modes := []int{Basic_Paillier, RLWE_All_Keys, RLWE_Whispir_2_Keys, RLWE_Whispir_3_Keys}
	for log_2_db_rows := 4; log_2_db_rows <= 8; log_2_db_rows++ {
		for _, mode := range modes {
			fmt.Println("---- mode: ", mode, "Legend:",
				"Paillier = ", Basic_Paillier,
				"RLWE_All_Keys = ", RLWE_All_Keys,
				"RLWE_Whispir_2_Keys = ", RLWE_Whispir_2_Keys,
				"RLWE_Whispir_3_Keys = ", RLWE_Whispir_3_Keys)
			s := resultsStats{
				NumRows: 1 << log_2_db_rows,
				Mode:    mode,
				Runs:    runs,
			}

			s.end_to_end_PIR(b, 8, log_2_db_rows, mode, row_size)
			peerRoutingResultsStats = append(peerRoutingResultsStats, s)
		}
	}
}

func Benchmark_PIR_for_Provider_Routing(b *testing.B) {
	// ensures that all CPUs are used
	fmt.Println(runtime.GOMAXPROCS(runtime.NumCPU()))

	var providerRoutingResultsStats []resultsStats
	runs := 10 // b.N

	// These numbers are derived using the script
	maxBinLoad := map[int]int{
		8192:   17,
		16384:  22,
		24576:  27,
		32768:  32,
		40960:  35,
		49152:  39,
		57344:  45,
		65536:  49,
		73728:  50,
		81920:  54,
		90112:  57,
		98304:  62,
		106496: 65,
		114688: 70,
		122880: 73,
		131072: 73,
		139264: 77,
		147456: 80,
		155648: 82,
		163840: 85,
		172032: 91,
		180224: 94,
		188416: 95,
		196608: 99,
	}

	for num_cids := 8192; num_cids < 100000; num_cids += 8192 {

		log_2_db_rows := 12

		row_size := maxBinLoad[num_cids] + 2 // Adding 2, just to be safe

		modes := []int{RLWE_All_Keys, RLWE_Whispir_2_Keys, RLWE_Whispir_3_Keys}
		for _, mode := range modes {
			fmt.Println("---- mode: ", mode, "Legend:",
				"RLWE_All_Keys = ", RLWE_All_Keys,
				"RLWE_Whispir_2_Keys = ", RLWE_Whispir_2_Keys,
				"RLWE_Whispir_3_Keys = ", RLWE_Whispir_3_Keys)
			fmt.Println("- num_cids: ", num_cids)
			fmt.Println("- RowSize: ", row_size)
			s := resultsStats{
				NumRows: num_cids,
				RowSize: row_size,
				Mode:    mode,
				Runs:    runs,
			}
			s.end_to_end_PIR(b, log_2_db_rows, log_2_db_rows, mode, row_size)
			providerRoutingResultsStats = append(providerRoutingResultsStats, s)

		}
	}
	err := writeStatsToCSV(providerRoutingResultsStats, "providerRouting-")
	require.NoError(b, err)
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

func (s *resultsStats) setStats(ourResults []*results) {
	runs := len(ourResults)
	var reqLens, resLens, runtimes []float64
	reqLens = make([]float64, runs)
	resLens = make([]float64, runs)
	runtimes = make([]float64, runs)
	for i, res := range ourResults {
		// print("\n ", i, " ", res.requestLen, " ", res.responseLen, " ", res.serverRuntime, "\n")
		reqLens[i] = float64(res.requestLen)
		resLens[i] = float64(res.responseLen)
		runtimes[i] = float64(res.serverRuntime)
	}

	reqLenMean, _ := stat.MeanStdDev(reqLens, nil)
	resLenMean, _ := stat.MeanStdDev(resLens, nil)
	s.ReqLenMean = int(reqLenMean)
	s.ResLenMean = int(resLenMean)
	s.TotalLenMean = s.ReqLenMean + s.ResLenMean
	s.ServerRuntimeMean, s.ServerRuntimeStddev = stat.MeanStdDev(runtimes, nil)
	fmt.Printf("Averaged results over %d Runs: Req Length %f(B), Response Length %f(B), Server time (ms)%f\n", runs, s.ReqLenMean, s.ResLenMean, s.ServerRuntimeMean)
	fmt.Printf("Stddev of server time (ms) %f\n", s.ServerRuntimeStddev)
}

func writeStatsToCSV(arr []resultsStats, experimentName string) error {
	timestamp := time.Now().Format(time.DateTime)
	filename := experimentName + timestamp + ".csv"
	statsFile, err := os.OpenFile(filename, os.O_RDWR|os.O_CREATE, os.ModePerm)
	if err != nil {
		return err
	}

	err = gocsv.MarshalFile(&arr, statsFile) // Use this to save the CSV back to the file
	if err != nil {
		return err
	}

	return statsFile.Close()
}

type resultsStats struct {
	Mode    int `csv:"Mode"`
	NumRows int `csv:"NumRows"`
	RowSize int `csv:"RowSize(Bytes)"`
	Runs    int `csv:"Runs"`
	SeedMin int `csv:"SeedMin"`
	SeedMax int `csv:"SeedMax"`

	TotalLenMean        int     `csv:"TotalLeanMean(Bytes)"`
	ReqLenMean          int     `csv:"ReqLenMean(Bytes)"`
	ResLenMean          int     `csv:"ResLenMean(Bytes)"`
	ServerRuntimeMean   float64 `csv:"ServerRuntimeMean(ms)"`
	ServerRuntimeStddev float64 `csv:"ServerRuntimeStddev(ms)"`
}
