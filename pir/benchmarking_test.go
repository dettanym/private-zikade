package pir

import (
	"fmt"
	"math/rand"
	"os"
	"runtime"
	"strconv"
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
	pubKey := req.GetPaillier_Public_Key()
	total += len(pubKey.N) + len(pubKey.G)
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

func TestE2E(t *testing.T) {
	log2_number_of_rows_str := os.Getenv("LOG2_NUMBER_OF_ROWS")
	log2_number_of_rows, err := strconv.Atoi(log2_number_of_rows_str)
	assert.NoError(t, err)

	log2_num_db_rows_str := os.Getenv("LOG2_NUM_DB_ROWS")
	log2_num_db_rows, err := strconv.Atoi(log2_num_db_rows_str)
	assert.NoError(t, err)

	mode_str := os.Getenv("MODE")

	row_size_str := os.Getenv("ROW_SIZE")
	row_size, err := strconv.Atoi(row_size_str)
	assert.NoError(t, err)

	s := resultsStats{
		NumRows: 1 << log2_num_db_rows,
		Runs:    1,
	}

	b := testing.B{N: 1}
	s.end_to_end_PIR(&b, log2_number_of_rows, log2_num_db_rows, mode_str, row_size)
}

func (s *resultsStats) end_to_end_PIR(b *testing.B, log2_number_of_rows int, log2_num_db_rows int, mode string, row_size int) {

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
		if db[compared_query][k] != response_bytes[k] {
			b.Error("incorrect response for byte", k, "expected:", db[compared_query][k], "actual:", response_bytes[k])
		}
	}
	for k := 0; k < db_element_size; k++ {
		require.Equal(b, db[compared_query][k], response_bytes[k])
	}
}

func (r *results) Server_PIR(b *testing.B, log2_number_of_rows int, mode string, pirRequest *pb.PIR_Request, db [][]byte) *pb.PIR_Response {
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
	fmt.Println("- server PIR time (ms):", elapsed.Milliseconds())
	return response
}

func (r *results) setReqResLen(mode string) {
	if mode == RLWE_All_Keys || mode == RLWE_Whispir_3_Keys || mode == RLWE_Whispir_2_Keys {
		// All RLWE schemes can be optimized with a seeding trick
		// Lattigo library doesn't implement this trick yet
		r.requestLen = getRLWEPIRRequestSize(r.pirRequest) / 2
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

	runs := 1                         // b.N
	modes := []string{Basic_Paillier} //, RLWE_All_Keys, RLWE_Whispir_2_Keys, RLWE_Whispir_3_Keys}
	experimentName := "peerRouting-"
	resultFiles := createResultsFiles(b, experimentName, modes)

	peerRoutingResultsStats := make([][]resultsStats, len(modes))

	for log_2_db_rows := 4; log_2_db_rows <= 4; log_2_db_rows++ {
		for i, mode := range modes {
			fmt.Println("---- mode: ", mode)
			s := resultsStats{
				NumRows: 1 << log_2_db_rows,
				Runs:    runs,
			}
			s.Mode = getMode(mode)
			s.end_to_end_PIR(b, 8, log_2_db_rows, mode, row_size)
			peerRoutingResultsStats[i] = append(peerRoutingResultsStats[i], s)
		}
	}

	for i, modeStats := range peerRoutingResultsStats {
		resultFile := resultFiles[i]
		writeStatsToCSVFileHandle(b, resultFile, modeStats)
	}
}

func Benchmark_PIR_for_Provider_Routing(b *testing.B) {
	// ensures that all CPUs are used
	fmt.Println(runtime.GOMAXPROCS(runtime.NumCPU()))

	runs := 1 // b.N

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

	modes := []string{RLWE_All_Keys, RLWE_Whispir_2_Keys, RLWE_Whispir_3_Keys}
	experimentName := "providerRouting-"
	resultFiles := createResultsFiles(b, experimentName, modes)

	cidsMin := 8192
	cidsMax := 200000
	cidsStep := cidsMin
	providerRoutingResultsStats := make([][]resultsStats, len(modes))

	for num_cids := cidsMin; num_cids < cidsMax; num_cids += cidsStep {

		log_2_db_rows := 12

		row_size := maxBinLoad[num_cids] + 2 // Adding 2, just to be safe

		for i, mode := range modes {
			fmt.Println("---- mode: ", mode)
			fmt.Println("- num_cids: ", num_cids)
			fmt.Println("- RowSize: ", row_size)
			s := resultsStats{
				NumRows: num_cids,
				RowSize: row_size,
				Runs:    runs,
			}
			s.Mode = getMode(mode)
			s.end_to_end_PIR(b, log_2_db_rows, log_2_db_rows, mode, row_size)
			providerRoutingResultsStats[i] = append(providerRoutingResultsStats[i], s)

		}
	}
	for i, modeStats := range providerRoutingResultsStats {
		resultFile := resultFiles[i]
		writeStatsToCSVFileHandle(b, resultFile, modeStats)
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

func getMode(mode string) string {
	if mode == RLWE_All_Keys {
		return "RLWE_All_Keys"
	} else if mode == RLWE_Whispir_2_Keys {
		return "RLWE_Whispir_2_Keys"
	} else if mode == RLWE_Whispir_3_Keys {
		return "RLWE_Whispir_3_Keys"
	} else if mode == Basic_Paillier {
		return "Basic_Paillier"
	}
	return ""
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
	fmt.Printf("Averaged results over %d Runs: Req Length %d(B), Response Length %d(B), Server time (ms)%f\n", runs, s.ReqLenMean, s.ResLenMean, s.ServerRuntimeMean)
	fmt.Printf("Stddev of server time (ms) %f\n", s.ServerRuntimeStddev)
}

func writeStatsToCSVFileHandle(b *testing.B, statsFile *os.File, arr []resultsStats) {
	err := gocsv.MarshalFile(&arr, statsFile) // Use this to save the CSV back to the file
	assert.NoError(b, err)

	err = statsFile.Close()
	assert.NoError(b, err)
}

func createResultsFiles(b *testing.B, experimentName string, modes []string) []*os.File {
	// for all modes
	// first create a file handle with a name
	resultFiles := make([]*os.File, len(modes))

	timestamp := time.Now().Format(time.RFC3339)
	filePrefix := experimentName + timestamp
	for i, mode := range modes {
		modeStr := getMode(mode)
		filename := filePrefix + modeStr + ".csv"
		fmt.Println(filename)
		statsFile, err := os.OpenFile(filename, os.O_RDWR|os.O_CREATE, os.ModePerm)
		require.NoError(b, err)
		resultFiles[i] = statsFile
	}
	return resultFiles
}

type resultsStats struct {
	Mode    string `csv:"Mode"`
	NumRows int    `csv:"NumRows"`
	RowSize int    `csv:"RowSize(Bytes)"`
	Runs    int    `csv:"Runs"`
	SeedMin int    `csv:"SeedMin"`
	SeedMax int    `csv:"SeedMax"`

	TotalLenMean        int     `csv:"TotalLenMean(Bytes)"`
	ReqLenMean          int     `csv:"ReqLenMean(Bytes)"`
	ResLenMean          int     `csv:"ResLenMean(Bytes)"`
	ServerRuntimeMean   float64 `csv:"ServerRuntimeMean(ms)"`
	ServerRuntimeStddev float64 `csv:"ServerRuntimeStddev(ms)"`
}
