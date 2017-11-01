package main

import (
	"fmt"
	"google.golang.org/grpc"
	//	"github.com/golang/protobuf/proto"
	"container/list"
	"errors"
	"flag"
	pb "golang.conradwood.net/registrar/proto"
	"golang.org/x/net/context"
	"google.golang.org/grpc/peer"
	"log"
	"net"
)

// static variables for flag parser
var (
	port     = flag.Int("port", 5000, "The server port")
	services *list.List
)

func main() {
	flag.Parse() // parse stuff. see "var" section above
	listenAddr := fmt.Sprintf(":%d", *port)
	fmt.Println("Starting Registry Service on ", listenAddr)
	lis, err := net.Listen("tcp4", fmt.Sprintf(":%d", *port))
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	services = list.New()

	var opts []grpc.ServerOption
	grpcServer := grpc.NewServer(opts...)

	s := new(RegistryService)
	pb.RegisterRegistryServer(grpcServer, s) // created by proto

	grpcServer.Serve(lis)
}

/**********************************
* helpers
***********************************/
func FindService(sd *pb.ServiceDescription) *pb.ServiceLocation {
	for e := services.Front(); e != nil; e = e.Next() {
		srvloc := e.Value.(pb.ServiceLocation)
		if srvloc.Service.Name == sd.Name {
			return &srvloc
		}
	}
	return nil
}
func AddService(sd *pb.ServiceDescription, address string) {
	sl := new(pb.ServiceLocation)
	sl.Service = new(pb.ServiceDescription)
	*sl.Service = *sd
	if sd.Name == "" {
		fmt.Printf("NO NAME: %v\n%v\n", sd, sl)
	}
	services.PushFront(sl)
	fmt.Printf("Registered service %s (%s) at %s\n", sd.Name, sd.Type, address)
}

/**********************************
* implementing the functions here:
***********************************/
type RegistryService struct {
	wtf int
}

// in C we put methods into structs and call them pointers to functions
// in java/python we also put pointers to functions into structs and but call them "objects" instead
// in Go we don't put functions pointers into structs, we "associate" a function with a struct.
// (I think that's more or less the same as what C does, just different Syntax)
func (s *RegistryService) GetServiceAddress(ctx context.Context, gr *pb.GetRequest) (*pb.GetResponse, error) {
	peer, ok := peer.FromContext(ctx)
	if !ok {
		fmt.Println("Error getting peer ")
		return nil, errors.New("Error getting peer from contextn")
	}
	fmt.Printf("%s called get service address for service %s\n", peer.Addr, gr.Service.Name)
	resp := pb.GetResponse{}
	return &resp, nil
}

func (s *RegistryService) RegisterService(ctx context.Context, pr *pb.ServiceLocation) (*pb.GetResponse, error) {

	peer, ok := peer.FromContext(ctx)
	if !ok {
		fmt.Println("Error getting peer ")
		return nil, errors.New("Error getting peer from context")
	}
	fmt.Println("Connection from %v", peer.Addr)
	peerhost, peerport, err := net.SplitHostPort(peer.Addr.String())
	if err != nil {
		return nil, errors.New("Invalid peer")
	}
	fmt.Printf("Connection from host %s on port %d\n", peerhost, peerport)
	if len(pr.Address) == 0 {
		return nil, errors.New("Missing address!")
	}
	if pr.Service.Name == "" {
		return nil, errors.New("Missing servicename!")
	}
	for _, address := range pr.Address {
		fmt.Printf("%s @ %v\n", pr.Service.Name, address)
		host := address.Host
		if host == "" {
			host = peerhost
		}
		addr := fmt.Sprintf("%s:%d", host, address.Port)
		AddService(pr.Service, addr)
	}
	rr := new(pb.GetResponse)
	return rr, nil
}

func (s *RegistryService) ListServices(ctx context.Context, pr *pb.ListRequest) (*pb.ListResponse, error) {
	lr := new(pb.ListResponse)
	for e := services.Front(); e != nil; e = e.Next() {
	}
	return lr, nil
}
