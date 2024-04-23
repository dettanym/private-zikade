package pir

import (
	"fmt"
	"math/big"
	"math/rand"
	"time"

	"sync"

	"github.com/lucasmenendez/gopaillier/pkg/paillier"
	"github.com/plprobelab/zikade/pb"
)

const (
	Basic_Paillier string = "Basic_Paillier"
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
	basic_paillier_protocol.bytesPerCiphertext = basic_paillier_protocol.pailler_bitlength/8 - 1
	return basic_paillier_protocol
}

func INSECURE_NewBasicPaillier_PIR_Protocol_INSECURE(log2_num_rows int) *BasicPaillier_PIR_Protocol {

	basic_paillier_protocol := &BasicPaillier_PIR_Protocol{
		log2_num_rows: log2_num_rows,
	}
	basic_paillier_protocol.pailler_bitlength = 1024
	basic_paillier_protocol.bytesPerCiphertext = basic_paillier_protocol.pailler_bitlength/8 - 1
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

func (paillierProtocol *BasicPaillier_PIR_Protocol) CreatePrivateKeyMaterial() error {
	var key, _ = paillier.NewKeys(paillierProtocol.pailler_bitlength / 2)
	paillierProtocol.secret_key = key

	paillierProtocol.public_key = key.PubKey
	return nil
}

func (paillierProtocol *BasicPaillier_PIR_Protocol) marshalRequestToPB() (*pb.PIR_Request, error) {
	query_bytes := make([][]byte, len(paillierProtocol.encrypted_query))
	for i := range paillierProtocol.encrypted_query {
		query_bytes[i] = paillierProtocol.encrypted_query[i].Bytes()
	}
	paillierPublicKey := marshalPaillierPublicKeyToBytes(paillierProtocol.public_key)
	pirRequest := pb.PIR_Request{
		Log2NumRows: int64(paillierProtocol.log2_num_rows),
		SchemeDependent: &pb.PIR_Request_Paillier_Public_Key{
			Paillier_Public_Key: paillierPublicKey,
		},
		EncryptedPaillierQuery: query_bytes,
	}
	queryLen := 0
	for _, query := range query_bytes {
		queryLen += len(query)
	}
	fmt.Println(" - marshalling phase: request total length: ", queryLen+len(paillierPublicKey.N)+len(paillierPublicKey.G))

	return &pirRequest, nil
}

func (paillierProtocol *BasicPaillier_PIR_Protocol) unmarshallRequestFromPB(req *pb.PIR_Request) error {
	paillierProtocol.log2_num_rows = int(req.Log2NumRows)

	switch schemeDependent := req.SchemeDependent.(type) {
	case *pb.PIR_Request_Paillier_Public_Key:
		paillierProtocol.public_key = unmarshalPaillierPublicKeyFromBytes(schemeDependent.Paillier_Public_Key)
	}

	Nsq := paillierProtocol.public_key.Nsq

	paillierProtocol.encrypted_query = make([]*big.Int, len(req.EncryptedPaillierQuery))
	var wg sync.WaitGroup
	for i := range req.EncryptedPaillierQuery {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()

			seededRand := rand.New(rand.NewSource(42 + int64(i)))
			randomPaillier := new(big.Int).Rand(seededRand, Nsq)

			correction := new(big.Int).SetBytes(req.EncryptedPaillierQuery[i])

			// Assuming paillierProtocol.encrypted_query is safe for concurrent use or properly synchronized
			paillierProtocol.encrypted_query[i] = paillierProtocol.public_key.Add(randomPaillier, correction)
		}(i)
	}
	wg.Wait()
	return nil
}

func (paillierProtocol *BasicPaillier_PIR_Protocol) GenerateRequestFromQuery(requested_row int) (*pb.PIR_Request, error) {
	// generate 256 ciphertext. All are encryptions of 0 except for the requested row
	// var err error
	num_rows := 1 << paillierProtocol.log2_num_rows
	paillierProtocol.encrypted_query = make([]*big.Int, num_rows)

	var randomPaillier *big.Int
	Nsq := paillierProtocol.public_key.Nsq
	N := paillierProtocol.public_key.N

	for i := 0; i < num_rows; i++ {
		bit := 0
		if i == requested_row {
			bit = 1
		}
		// // normal way
		// paillierProtocol.encrypted_query[i], err = paillierProtocol.secret_key.PubKey.Encrypt(big.NewInt(int64(bit)))
		// if err != nil {
		// 	return nil, err
		// }

		// Beck way
		seededRand := rand.New(rand.NewSource(42 + int64(i)))
		randomPaillier = new(big.Int).Rand(seededRand, Nsq)
		decrypted, err := paillierProtocol.secret_key.Decrypt(randomPaillier)
		if err != nil {
			return nil, err
		}
		correction := big.NewInt(0)
		correction.Add(N, big.NewInt(int64(bit)))
		correction.Sub(correction, decrypted)
		if correction.Cmp(N) == 1 {
			correction.Sub(correction, N)
		}
		paillierProtocol.encrypted_query[i] = correction
	}
	return paillierProtocol.marshalRequestToPB()
}

func (paillierProtocol *BasicPaillier_PIR_Protocol) transformDBToPlaintextForm(database [][]byte) error {
	// transform the database into a plaintext
	paillierProtocol.plaintextDB = make([][]*big.Int, len(database))
	// TODO: For now, assuming that the bytes in each row can fit in one plaintext
	max_len_database_entries := maxLengthDBRows(database)
	paillierProtocol.needed_cts = (max_len_database_entries + paillierProtocol.bytesPerCiphertext - 1) / paillierProtocol.bytesPerCiphertext
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
	resLen := 0
	for _, res := range response_bytes {
		resLen += len(res)
	}
	fmt.Println(" - marshalling phase: response total length: ", resLen)
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

	// start := time.Now()

	err := paillierProtocol.unmarshallRequestFromPB(request)
	if err != nil {
		return nil, err
	}

	start := time.Now()
	err = paillierProtocol.transformDBToPlaintextForm(database)
	if err != nil {
		return nil, err
	}
	duration := time.Since(start)
	fmt.Println("- time elapsed for transformDBToPlaintextForm is: \t\t\t", duration.Milliseconds())

	// access encrypted query and validate its length
	encrypted_query := paillierProtocol.encrypted_query
	// numberOfQueryCiphertexts := len(encrypted_query)

	num_db_rows := len(database)
	num_rows := 1 << paillierProtocol.log2_num_rows

	start = time.Now()
	if num_rows > num_db_rows {
		for j := num_db_rows; j < num_rows; j++ {
			encrypted_query[num_db_rows-1] = paillierProtocol.public_key.AddEncrypted(encrypted_query[num_db_rows-1], encrypted_query[j])
		}
	} else if num_rows < num_db_rows {
		return nil, fmt.Errorf("initialize this struct with log2_num_rows as greater than or equal to the log of the number of rows in the DB")
	}
	duration = time.Since(start)
	fmt.Println("- time elapsed for public_key.AddEncrypted: is: \t", duration.Milliseconds())

	var wg sync.WaitGroup
	var mu sync.Mutex

	paillierProtocol.response_ciphertexts = make([]*big.Int, paillierProtocol.needed_cts)
	initialized := make([]bool, paillierProtocol.needed_cts)

	for j := 0; j < paillierProtocol.needed_cts; j++ {
		for i := 0; i < num_db_rows; i++ {
			// encryptedMul := paillierProtocol.public_key.Mul(encrypted_query[i], paillierProtocol.plaintextDB[i][j])
			// if i == 0 {
			// 	paillierProtocol.response_ciphertexts[j] = encryptedMul
			// } else {
			// 	paillierProtocol.response_ciphertexts[j] = paillierProtocol.public_key.AddEncrypted(encryptedMul, paillierProtocol.response_ciphertexts[j])
			// }
			wg.Add(1)
			go func(i, j int) {
				defer wg.Done()
				encryptedMul := paillierProtocol.public_key.Mul(encrypted_query[i], paillierProtocol.plaintextDB[i][j])
				mu.Lock()
				defer mu.Unlock()
				if !initialized[j] {
					paillierProtocol.response_ciphertexts[j] = encryptedMul
					initialized[j] = true
				} else {
					paillierProtocol.response_ciphertexts[j] = paillierProtocol.public_key.AddEncrypted(encryptedMul, paillierProtocol.response_ciphertexts[j])
				}
			}(i, j)
		}
	}
	wg.Wait()

	response, err := paillierProtocol.marshalResponseToPB()
	if err != nil {
		return nil, err
	}

	// elapsed := time.Since(start)
	// log.Printf("elapsed time: %v", elapsed)

	return response, nil
}

func (paillierProtocol *BasicPaillier_PIR_Protocol) ProcessResponseToPlaintext(res *pb.PIR_Response) ([]byte, error) {
	err := paillierProtocol.unmarshallResponseFromPB(res)
	if err != nil {
		return nil, err
	}

	// decrypt the response ciphertexts
	var all_bytes []byte
	for i := range paillierProtocol.response_ciphertexts {
		decrypted, err := paillierProtocol.secret_key.Decrypt(paillierProtocol.response_ciphertexts[i])
		if err != nil {
			return nil, err
		}
		all_bytes = append(all_bytes, decrypted.Bytes()...)
	}

	return all_bytes, nil
}
