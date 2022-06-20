package main

import (
	"context"
	"flag"
	"google.golang.org/grpc/credentials/insecure"
	"log"
	"time"

	pb "github.com/firekitz/fk-lib-iam-go/proto/iam"
	"google.golang.org/grpc"
)

type IamConfig struct {
	Host string
	Port string
}

var config IamConfig

func Init(cfg IamConfig) {
	config = cfg
}

func authTest() {
	flag.Parse()
	//token := "Bearer xxx"
	//values := strings.Split(token, " ")
	//fmt.Println(values)
	Init(IamConfig{
		Host: "localhost",
		Port: "9090",
	})
	addr := config.Host + ":" + config.Port
	conn, err := grpc.Dial(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatalf("did not connect: %v", err)
	}
	defer conn.Close()
	c := pb.NewIamClient(conn)

	// Contact the server and print out its response.
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	var permissions = []int64{1}
	r, err1 := c.Auth(ctx, &pb.AuthRequest{
		AccessToken: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIyIiwiaWF0IjoxNjM3MTM5NDUzLCJleHAiOjIyNjgyOTE0NTMsImRpIjoxMDAsInBpIjo1LCJhaSI6MiwiYXQiOjEsInR5cGUiOiJhY2Nlc3MifQ.tFD62Lfy5aKLoP-eGV51t5SBa57WxqwBYoE6EB_Ggt8",
		Permissions: permissions,
	})
	if err1 != nil {
		log.Fatalf("could not greet: %v", err)
	}
	log.Printf("Response: %s", r)
}

func verifyTokenTest() {
	flag.Parse()
	//token := "Bearer xxx"
	//values := strings.Split(token, " ")
	//fmt.Println(values)
	Init(IamConfig{
		Host: "localhost",
		Port: "9090",
	})
	addr := config.Host + ":" + config.Port
	conn, err := grpc.Dial(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatalf("did not connect: %v", err)
	}
	defer conn.Close()
	c := pb.NewIamClient(conn)

	// Contact the server and print out its response.
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	r, err1 := c.VerifyToken(ctx, &pb.VerifyTokenRequest{
		AccessToken: "xxx",
	})
	if err1 != nil {
		log.Fatalf("Response: %v", err1)
	}
	log.Printf("Response: %s", r)
}

func main() {
	//authTest()
	verifyTokenTest()
}
