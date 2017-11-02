package main

// see: https://grpc.io/docs/tutorials/basic/go.html

import (
	"fmt"
	//	"google.golang.org/grpc/metadata"

	"google.golang.org/grpc"
	//	"github.com/golang/protobuf/proto"
	"flag"
	"golang.org/x/net/context"
	//	"net"
	"crypto/x509"
	pb "golang.conradwood.net/auth/proto"
	"google.golang.org/grpc/credentials"
	"io/ioutil"
)

// static variables for flag parser
var (
	serverAddr = flag.String("server_addr", "127.0.0.1:10000", "The server address in the format of host:port")
	crt        = "/etc/cnw/certs/rpc-client/certificate.pem"
	key        = "/etc/cnw/certs/rpc-client/privatekey.pem"
	ca         = "/etc/cnw/certs/rpc-client/ca.pem"
)

func main() {
	flag.Parse()
	roots := x509.NewCertPool()
	FrontendCert, _ := ioutil.ReadFile(crt)
	roots.AppendCertsFromPEM(FrontendCert)
	ImCert, _ := ioutil.ReadFile(ca)
	roots.AppendCertsFromPEM(ImCert)

	// Create credentials
	creds := credentials.NewClientTLSFromCert(roots, "")

	fmt.Println("Connecting to server...", *serverAddr, creds)
	//conn, err := grpc.Dial(*serverAddr, grpc.WithInsecure())
	conn, err := grpc.Dial(*serverAddr, grpc.WithTransportCredentials(creds))
	if err != nil {
		fmt.Println("fail to dial: %v", err)
		return
	}
	defer conn.Close()
	fmt.Println("Creating client...")
	client := pb.NewAuthenticationServiceClient(conn)
	req := pb.VerifyRequest{Token: "bla"}
	fmt.Println("RPC call...")
	ctx := context.Background()
	resp, err := client.VerifyUserToken(ctx, &req)
	if err != nil {
		fmt.Printf("failed to verify user token: %v", err)
	}
	fmt.Printf("Response to verify token: %v\n", resp)
}