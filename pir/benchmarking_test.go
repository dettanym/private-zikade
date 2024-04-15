package pir

import (
	"fmt"
	"math"
	"math/rand"
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

func end_to_end_Paillier_PIR(log_2_num_rows int, log_2_num_db_rows int, row_size int) error {

	fmt.Println("- log_2_num_rows: ", log_2_num_rows)
	fmt.Println("- log_2_num_db_rows: ", log_2_num_db_rows)

	client_PIR_Protocol := NewBasicPaillier_PIR_Protocol(log_2_num_rows)
	err := client_PIR_Protocol.createPrivateKeyMaterial()
	if err != nil {
		return err
	}

	seed := rand.NewSource(time.Now().UnixNano())
	query := rand.New(seed).Intn(1 << log_2_num_rows)
	pirRequest, err := client_PIR_Protocol.GenerateRequestFromQuery(query)
	if err != nil {
		return err
	}

	fmt.Println("- request size B: ", getPaillierPIRRequestSize(pirRequest))

	// server
	num_db_rows := 1 << log_2_num_db_rows
	db := make([][]byte, num_db_rows)
	db_element_size := row_size

	response := &pb.PIR_Response{}
	{
		server_PIR_Protocol := NewBasicPaillier_PIR_Protocol(log_2_num_rows)

		for i := range db {
			db[i] = make([]byte, db_element_size)
			for j := 0; j < db_element_size; j++ {
				db[i][j] = byte(rand.New(seed).Intn(256))
			}
		}

		start_time := time.Now()
		response, err = server_PIR_Protocol.ProcessRequestAndReturnResponse(pirRequest, db)
		if err != nil {
			return err
		}
		elapsed := time.Since(start_time)
		fmt.Println("- server PIR time:", elapsed)

	} // end server

	fmt.Println("- response size B: ", getPaillierPIRResponseSize(response))

	response_bytes, err := client_PIR_Protocol.ProcessResponseToPlaintext(response)
	if err != nil {
		return err
	}
	compared_query := query
	if query > num_db_rows {
		compared_query = num_db_rows - 1
	}
	for k := 0; k < db_element_size; k++ {
		if db[compared_query][k] != response_bytes[k] {
			return err
		}
	}

	return nil
}

func end_to_end_RLWE_PIR(log2_number_of_rows int, log2_num_db_rows int, mode int, row_size int) error {

	fmt.Println("- log_2_num_rows: ", log2_number_of_rows)
	fmt.Println("- log_2_num_db_rows: ", log2_num_db_rows)

	num_db_rows := 1 << log2_num_db_rows
	number_of_rows := 1 << log2_number_of_rows

	client_PIR_Protocol := NewSimpleRLWE_PIR_Protocol_mode(log2_number_of_rows, mode)
	err := client_PIR_Protocol.createPrivateKeyMaterial()
	if err != nil {
		return err
	}

	seed := rand.NewSource(time.Now().UnixNano())
	query := rand.New(seed).Intn(number_of_rows)
	pirRequest, err := client_PIR_Protocol.GenerateRequestFromQuery(query)
	if err != nil {
		return err
	}

	fmt.Println("- request size B: ", getRLWEPIRRequestSize(pirRequest))

	// server
	db := make([][]byte, num_db_rows)
	db_element_size := row_size
	response := &pb.PIR_Response{}
	{
		server_PIR_Protocol := NewSimpleRLWE_PIR_Protocol_mode(log2_number_of_rows, mode)

		for i := range db {
			db[i] = make([]byte, db_element_size)
			for j := 0; j < db_element_size; j++ {
				db[i][j] = byte(rand.New(seed).Intn(256))
			}
		}

		start_time := time.Now()
		response, err = server_PIR_Protocol.ProcessRequestAndReturnResponse(pirRequest, db)
		if err != nil {
			return err
		}
		elapsed := time.Since(start_time)
		fmt.Println("- server PIR time:", elapsed)

	} // end server

	fmt.Println("- response size B: ", getRLWEPIRResponseSize(response))
	// client response processing
	response_bytes, err := client_PIR_Protocol.ProcessResponseToPlaintext(response)
	if err != nil {
		return err
	}
	compared_query := query
	if query > num_db_rows {
		compared_query = num_db_rows - 1
	}
	for k := 0; k < db_element_size; k++ {
		// require.Equal(t, db[compared_query][k], response_bytes[k])
		if db[compared_query][k] != response_bytes[k] {
			return fmt.Errorf("incorrect response")
		}
	}
	return nil
}

func Test_PIR_for_Routing_Table(t *testing.T) {
	row_size := 20 * 256
	for log_2_db_rows := 4; log_2_db_rows <= 8; log_2_db_rows++ {
		if end_to_end_Paillier_PIR(8, log_2_db_rows, row_size) != nil {
			fmt.Println("- Error in PIR")
		}
		for mode := 0; mode <= 2; mode++ {
			if err := end_to_end_RLWE_PIR(8, log_2_db_rows, mode, row_size); err != nil {
				fmt.Println("- Error in PIR")
				fmt.Println(err)
			}
		}
	}
}

func Test_PIR_for_Provider_Routing(t *testing.T) {
	for num_cids := 8192; num_cids < 100000; num_cids += 8192 {

		log_2_db_rows := 12

		const BINNING_CONSTANT = 1.001
		// Assuming num_cids and log_2_db_rows are already defined variables
		row_size := int(math.Ceil(BINNING_CONSTANT * float64(num_cids*81) / float64(uint64(1)<<log_2_db_rows)))

		// fmt.Println("BasicPaillier")
		// if end_to_end_Paillier_PIR(log_2_db_rows, log_2_db_rows, row_size) != nil {
		// 	fmt.Println("- Error in PIR")
		// }
		for mode := 0; mode <= 2; mode++ {
			fmt.Printf("BasicRLWE_%d\n", mode)
			fmt.Println("- num_cids: ", num_cids)
			fmt.Println("- row_size: ", row_size)
			if err := end_to_end_RLWE_PIR(log_2_db_rows, log_2_db_rows, mode, row_size); err != nil {
				fmt.Println("- Error in PIR")
				fmt.Println(err)
			}
		}
	}
}
