package pir

import (
	"log"
	"math/big"
	"time"

	"github.com/lucasmenendez/gopaillier/pkg/paillier"
	"github.com/plprobelab/zikade/pb"
)

type BasicPaillier_PIR_Protocol struct {
	PIR_Protocol

	log2_num_rows int

	secret_key        *paillier.PrivateKey
	public_key        *paillier.PublicKey
	pailler_bitlength int

	encrypted_query      []*big.Int
	response_ciphertexts []*big.Int

	bytesPerCiphertext int
	needed_cts         int

	plaintextDB [][]*big.Int
}

func NewBasicPaillier_PIR_Protocol(log2_num_rows int) *BasicPaillier_PIR_Protocol {

	basic_paillier_protocol := &BasicPaillier_PIR_Protocol{
		log2_num_rows: log2_num_rows,
	}
	basic_paillier_protocol.pailler_bitlength = 3072
	basic_paillier_protocol.bytesPerCiphertext = basic_paillier_protocol.pailler_bitlength / 8
	return basic_paillier_protocol
}

func marshalPaillierPublicKeyToBytes(public_key *paillier.PublicKey) *pb.Paillier_Public_Key {
	return &pb.Paillier_Public_Key{
		N:      public_key.N.Bytes(),
		G:      public_key.G.Bytes(),
		Length: public_key.Len,
	}
}

func unmarshalPaillierPublicKeyFromBytes(public_key_bytes *pb.Paillier_Public_Key) *paillier.PublicKey {
	N := new(big.Int).SetBytes(public_key_bytes.N)
	G := new(big.Int).SetBytes(public_key_bytes.G)
	Nsq := new(big.Int).Mul(N, N)
	len := public_key_bytes.Length
	return &paillier.PublicKey{N: N, G: G, Nsq: Nsq, Len: len}
}

func (paillierProtocol *BasicPaillier_PIR_Protocol) createPrivateKeyMaterial() error {
	var key, _ = paillier.NewKeys(paillierProtocol.pailler_bitlength)
	paillierProtocol.secret_key = key

	paillierProtocol.public_key = key.PubKey
	return nil
}

func (paillierProtocol *BasicPaillier_PIR_Protocol) marshalRequestToPB() (*pb.PIR_Request, error) {
	query_bytes := make([][]byte, len(paillierProtocol.encrypted_query))
	for i := range paillierProtocol.encrypted_query {
		query_bytes[i] = paillierProtocol.encrypted_query[i].Bytes()
	}
	pirRequest := pb.PIR_Request{
		Log2NumRows: int64(paillierProtocol.log2_num_rows),
		SchemeDependent: &pb.PIR_Request_Paillier_Public_Key{
			Paillier_Public_Key: marshalPaillierPublicKeyToBytes(paillierProtocol.public_key),
		},
		EncryptedPaillierQuery: query_bytes,
	}
	return &pirRequest, nil
}

func (paillierProtocol *BasicPaillier_PIR_Protocol) unmarshallRequestFromPB(req *pb.PIR_Request) error {
	paillierProtocol.log2_num_rows = int(req.Log2NumRows)
	paillierProtocol.encrypted_query = make([]*big.Int, len(req.EncryptedPaillierQuery))
	for i := range req.EncryptedPaillierQuery {
		paillierProtocol.encrypted_query[i] = new(big.Int).SetBytes(req.EncryptedPaillierQuery[i])
	}
	switch schemeDependent := req.SchemeDependent.(type) {
	case *pb.PIR_Request_Paillier_Public_Key:
		paillierProtocol.public_key = unmarshalPaillierPublicKeyFromBytes(schemeDependent.Paillier_Public_Key)
	}
	return nil
}

func (paillierProtocol *BasicPaillier_PIR_Protocol) GenerateRequestFromQuery(requested_row int) (*pb.PIR_Request, error) {
	// generate 256 ciphertext. All are encryptions of 0 except for the requested row
	var err error
	num_rows := 1 << paillierProtocol.log2_num_rows
	paillierProtocol.encrypted_query = make([]*big.Int, num_rows)
	for i := 0; i < num_rows; i++ {
		bit := 0
		if i == requested_row {
			bit = 1
		}
		paillierProtocol.encrypted_query[i], err = paillierProtocol.secret_key.PubKey.Encrypt(big.NewInt(int64(bit)))
		if err != nil {
			return nil, err
		}
	}
	return paillierProtocol.marshalRequestToPB()
}

func (paillierProtocol *BasicPaillier_PIR_Protocol) transformDBToPlaintextForm(database [][]byte) error {
	// transform the database into a plaintext
	paillierProtocol.plaintextDB = make([][]*big.Int, len(database))
	// TODO: For now, assuming that the bytes in each row can fit in one plaintext
	paillierProtocol.needed_cts = (len(database) + paillierProtocol.bytesPerCiphertext - 1) / paillierProtocol.bytesPerCiphertext
	for i := range database {
		paillierProtocol.plaintextDB[i] = make([]*big.Int, paillierProtocol.needed_cts)
		// TODO: assumes all rows have the same length
		for j := 0; j < paillierProtocol.needed_cts; j++ {
			// get slice of bytes
			plaintext_bytes := make([]byte, paillierProtocol.bytesPerCiphertext)
			start := j * paillierProtocol.bytesPerCiphertext
			end := (j + 1) * paillierProtocol.bytesPerCiphertext
			if end > len(database[i]) {
				end = len(database[i])
			}
			copy(plaintext_bytes, database[i][start:end])
			paillierProtocol.plaintextDB[i][j] = new(big.Int).SetBytes(plaintext_bytes)
		}
	}
	return nil
}

func (paillierProtocol *BasicPaillier_PIR_Protocol) marshalResponseToPB() (*pb.PIR_Response, error) {
	response_bytes := make([][]byte, len(paillierProtocol.response_ciphertexts))
	for i := range paillierProtocol.response_ciphertexts {
		response_bytes[i] = paillierProtocol.response_ciphertexts[i].Bytes()
	}
	pirResponse := pb.PIR_Response{
		EncryptedPaillierResponse: response_bytes,
	}
	return &pirResponse, nil
}

func (paillierProtocol *BasicPaillier_PIR_Protocol) unmarshallResponseFromPB(res *pb.PIR_Response) error {
	paillierProtocol.response_ciphertexts = make([]*big.Int, len(res.EncryptedPaillierResponse))
	for i := range res.EncryptedPaillierResponse {
		paillierProtocol.response_ciphertexts[i] = new(big.Int).SetBytes(res.EncryptedPaillierResponse[i])
	}
	return nil
}

func (paillierProtocol *BasicPaillier_PIR_Protocol) ProcessRequestAndReturnResponse(request *pb.PIR_Request, database [][]byte) (*pb.PIR_Response, error) {

	start := time.Now()

	err := paillierProtocol.unmarshallRequestFromPB(request)
	if err != nil {
		return nil, err
	}

	err = paillierProtocol.transformDBToPlaintextForm(database)
	if err != nil {
		return nil, err
	}

	// access encrypted query and validate its length
	encrypted_query := paillierProtocol.encrypted_query
	// numberOfQueryCiphertexts := len(encrypted_query)

	num_db_rows := len(database)

	paillierProtocol.response_ciphertexts = make([]*big.Int, paillierProtocol.needed_cts)

	for j := 0; j < paillierProtocol.needed_cts; j++ {
		for i := 0; i < num_db_rows; i++ {
			encryptedMul := paillierProtocol.public_key.Mul(encrypted_query[i], paillierProtocol.plaintextDB[i][j])
			if i == 0 {
				paillierProtocol.response_ciphertexts[j] = encryptedMul
			} else {
				paillierProtocol.response_ciphertexts[j] = paillierProtocol.public_key.AddEncrypted(encryptedMul, paillierProtocol.response_ciphertexts[j])
			}
		}
	}

	response, err := paillierProtocol.marshalResponseToPB()
	if err != nil {
		return nil, err
	}

	elapsed := time.Since(start)
	log.Printf("elapsed time: %v", elapsed)

	return response, nil
}

func (paillierProtocol *BasicPaillier_PIR_Protocol) ProcessResponseToPlaintext(res *pb.PIR_Response) ([]byte, error) {
	err := paillierProtocol.unmarshallResponseFromPB(res)
	if err != nil {
		return nil, err
	}

	// decrypt the response ciphertexts
	decrypted, err := paillierProtocol.secret_key.Decrypt(paillierProtocol.response_ciphertexts[0])
	if err != nil {
		return nil, err
	}

	return decrypted.Bytes(), nil
}
