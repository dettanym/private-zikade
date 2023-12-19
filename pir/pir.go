package pir

import "github.com/plprobelab/zikade/pb"

// TODO: The marshalling, unmarshalling functions don't need to be public.
//
//	make them private, while being able to test their implementations.

type PIR_Protocol interface {
	ProcessRequestAndReturnResponse(request *pb.PIR_Request, database [][]byte) (*pb.PIR_Response, error)
	GenerateRequestFromQuery(int) (*pb.PIR_Request, error)
	ProcessResponseToPlaintext(res *pb.PIR_Response) ([]byte, error)

	MarshalRequestToPB() (*pb.PIR_Request, error)
	UnmarshallRequestFromPB(req *pb.PIR_Request) error
	MarshalResponseToPB() (*pb.PIR_Response, error)
	UnmarshallResponseFromPB(res *pb.PIR_Response) error
}
