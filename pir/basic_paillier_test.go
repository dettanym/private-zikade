package pir

import (
	"math/big"
	"math/rand"
	"testing"
	"time"

	"github.com/lucasmenendez/gopaillier/pkg/paillier"
	"github.com/plprobelab/zikade/pb"
)

func TestBasicPIR_with_Paillier_marshal_and_unmarshal_public_key(t *testing.T) {
	key, _ := paillier.NewKeys(128)
	marshalled_key := marshalPaillierPublicKeyToBytes(key.PubKey)
	unmarshalled_key := unmarshalPaillierPublicKeyFromBytes(marshalled_key)
	if unmarshalled_key.N.Cmp(key.PubKey.N) != 0 {
		t.Error("Error in marshalling and unmarshalling public key")
	}
	if unmarshalled_key.G.Cmp(key.PubKey.G) != 0 {
		t.Error("Error in marshalling and unmarshalling public key")
	}
	// if unmarshalled_key.Len != key.PubKey.Len {
	// 	t.Error("Error in marshalling and unmarshalling public key")
	// }
	if unmarshalled_key.Nsq.Cmp(key.PubKey.Nsq) != 0 {
		t.Error("Error in marshalling and unmarshalling public key")
	}
}

func TestBasicPIR_with_Paillier_KeyGen(t *testing.T) {
	log_2_num_rows := 8
	pir_protocol := NewBasicPaillier_PIR_Protocol(log_2_num_rows)
	err := pir_protocol.createPrivateKeyMaterial()
	if err != nil {
		t.Error("Error in creating private key material")
	}
}

func TestBasicPIR_with_Paillier_MarshalRequestToPB(t *testing.T) {
	log_2_num_rows := 8
	pir_protocol := NewBasicPaillier_PIR_Protocol(log_2_num_rows)
	pir_protocol.createPrivateKeyMaterial()
	_, err := pir_protocol.marshalRequestToPB()
	if err != nil {
		t.Error("Error in marshalling request to PB")
	}
}

func TestBasicPIR_with_Paillier_UnmarshalRequestFromPB(t *testing.T) {
	log_2_num_rows := 8
	pir_protocol := INSECURE_NewBasicPaillier_PIR_Protocol_INSECURE(log_2_num_rows)
	pir_protocol.createPrivateKeyMaterial()
	seed := rand.NewSource(time.Now().UnixNano())
	random_query := rand.New(seed).Intn(1 << log_2_num_rows)
	marshalled_request, err := pir_protocol.GenerateRequestFromQuery(random_query)
	// marshalled_request, err := pir_protocol.marshalRequestToPB()
	if err != nil {
		t.Error("Error in marshalling request to PB")
	}
	err = pir_protocol.unmarshallRequestFromPB(marshalled_request)
	if err != nil {
		t.Error("Error in unmarshalling request from PB")
	}

	decrypted, err := pir_protocol.secret_key.Decrypt(pir_protocol.encrypted_query[random_query])
	if err != nil {
		t.Error("Error in unmarshalling request from PB")
	}
	if decrypted.Cmp(big.NewInt(int64(1))) != 0 {
		t.Error("Error in unmarshalling request from PB")
	}

}

func TestBasicPIR_with_Paillier_Gen_Query(t *testing.T) {
	log_2_num_rows := 8
	pir_protocol := INSECURE_NewBasicPaillier_PIR_Protocol_INSECURE(log_2_num_rows)
	err := pir_protocol.createPrivateKeyMaterial()
	if err != nil {
		t.Error("Error in creating private key material")
	}

	_, err = pir_protocol.GenerateRequestFromQuery(1 << log_2_num_rows)
	if err != nil {
		t.Error("Error in generating request from query")
	}
}

func TestBasicPIR_with_Paillier_ProcessRequestAndReturnResponse(t *testing.T) {
	log_2_num_rows := 5
	client_PIR_Protocol := INSECURE_NewBasicPaillier_PIR_Protocol_INSECURE(log_2_num_rows)
	err := client_PIR_Protocol.createPrivateKeyMaterial()
	if err != nil {
		t.Error("Error in creating private key material")
	}

	seed := rand.NewSource(time.Now().UnixNano())
	query := rand.New(seed).Intn(1 << log_2_num_rows)
	pirRequest, err := client_PIR_Protocol.GenerateRequestFromQuery(query)

	if err != nil {
		t.Error("Error in generating request from query")
	}

	// server
	log_2_num_db_rows := 4
	num_db_rows := 1 << log_2_num_db_rows
	db := make([][]byte, num_db_rows)
	db_element_size := 5
	response := &pb.PIR_Response{}
	{
		server_PIR_Protocol := INSECURE_NewBasicPaillier_PIR_Protocol_INSECURE(log_2_num_rows)

		for i := range db {
			db[i] = make([]byte, db_element_size)
			for j := 0; j < db_element_size; j++ {
				db[i][j] = byte(rand.New(seed).Intn(256))
			}
		}

		response, err = server_PIR_Protocol.ProcessRequestAndReturnResponse(pirRequest, db)
		if err != nil {
			t.Error("Error in processing request and returning response")
		}

	} // end server

	response_bytes, err := client_PIR_Protocol.ProcessResponseToPlaintext(response)
	if err != nil {
		t.Error("Error in processing response to plaintext")
	}
	compared_query := query
	if query > num_db_rows {
		compared_query = num_db_rows - 1
	}
	for k := 0; k < db_element_size; k++ {
		if db[compared_query][k] != response_bytes[k] {
			t.Error("Error in processing response to plaintext")
		}
	}
}

func BenchmarkBasicPIR_with_Paillier_ProcessRequestAndReturnResponse(b *testing.B) {
	log_2_num_rows := 4
	client_PIR_Protocol := NewBasicPaillier_PIR_Protocol(log_2_num_rows)
	err := client_PIR_Protocol.createPrivateKeyMaterial()
	if err != nil {
		b.Error("Error in creating private key material")
	}

	seed := rand.NewSource(time.Now().UnixNano())
	query := rand.New(seed).Intn(1 << log_2_num_rows)
	pirRequest, err := client_PIR_Protocol.GenerateRequestFromQuery(query)

	if err != nil {
		b.Error("Error in generating request from query")
	}

	// server
	log_2_num_db_rows := 4
	num_db_rows := 1 << log_2_num_db_rows
	db := make([][]byte, num_db_rows)
	db_element_size := 5
	response := &pb.PIR_Response{}
	{
		server_PIR_Protocol := NewBasicPaillier_PIR_Protocol(log_2_num_rows)

		for i := range db {
			db[i] = make([]byte, db_element_size)
			for j := 0; j < db_element_size; j++ {
				db[i][j] = byte(rand.New(seed).Intn(256))
			}
		}

		response, err = server_PIR_Protocol.ProcessRequestAndReturnResponse(pirRequest, db)
		if err != nil {
			b.Errorf("Error: %v", err)
			// return
		}

	} // end server

	response_bytes, err := client_PIR_Protocol.ProcessResponseToPlaintext(response)
	if err != nil {
		b.Errorf("Error : %v", err)
		// return
	}
	compared_query := query
	if query > num_db_rows {
		compared_query = num_db_rows - 1
	}
	for k := 0; k < db_element_size; k++ {
		if db[compared_query][k] != response_bytes[k] {
			b.Errorf("Error: incorrect response to plaintext")
			return
		}
	}
}

func Test_BeckTrick(t *testing.T) {
	paillierProtocol := INSECURE_NewBasicPaillier_PIR_Protocol_INSECURE(4)
	err := paillierProtocol.createPrivateKeyMaterial()
	if err != nil {
		t.Error("Error in creating private key material")
	}
	marshalled_request, err := paillierProtocol.GenerateRequestFromQuery(1)
	if err != nil {
		t.Error("Error in generating request from query")
	}

	err = paillierProtocol.unmarshallRequestFromPB(marshalled_request)
	if err != nil {
		t.Error("Error in unmarshalling request from PB")
	}

}
