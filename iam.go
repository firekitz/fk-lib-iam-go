package iam

import (
	"context"
	"github.com/firekitz/fk-lib-iam-go/ctxauth"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"log"
	"strconv"
	"strings"
	"time"

	pb "github.com/firekitz/fk-lib-iam-go/proto/iam"
	"google.golang.org/grpc"
)

const (
	ERROR_INVALID_TOKEN = 1
	ERROR_EXPIRED_TOKEN = 2
)

type IamConfig struct {
	Host string
	Port string
}

type FKInfo struct {
	DomainId       int64
	ProjectId      int64
	AccountType    int64
	AccountId      int64
	SrcServiceName string
}

var config IamConfig
var conn *grpc.ClientConn

func Init(cfg IamConfig) {
	config = cfg
}

func Connect() error {
	addr := config.Host + ":" + config.Port
	var err error

	if conn == nil {
		conn, err = grpc.Dial(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
		if err != nil {
			log.Fatalf("did not connect: %v", err)
			return err
		}
	}
	return nil
}

func newTagsForCtx(ctx context.Context, res *pb.AuthResponse) context.Context {
	t := ctxauth.NewTags()
	t.Set("auth.domainId", res.DomainId)
	t.Set("auth.projectId", res.ProjectId)
	t.Set("auth.accountType", res.AccountType)
	t.Set("auth.accountId", res.AccountId)
	return ctxauth.SetInContext(ctx, t)
}

func newTagsForCtx2(ctx context.Context, res FKInfo) context.Context {
	t := ctxauth.NewTags()
	t.Set("auth.domainId", res.DomainId)
	t.Set("auth.projectId", res.ProjectId)
	t.Set("auth.accountType", res.AccountType)
	t.Set("auth.accountId", res.AccountId)
	return ctxauth.SetInContext(ctx, t)
}

func IamServerUnaryInterceptor(args map[string][]int64) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		//startTime := time.Now()
		//startMs := time.Now().UnixMilli()
		logrus.Debug(info.FullMethod)
		//service := path.Dir(info.FullMethod)[1:]
		//method := path.Base(info.FullMethod)

		md, ok := metadata.FromIncomingContext(ctx)
		if !ok {
			logrus.Debug(ok)
		}

		fkSrcServiceName := md["x-request-fk-src-service-name"]
		if len(fkSrcServiceName) == 0 {
			//logrus.Error("missing 'x-request-fk-src-service-name' header")
			return nil, status.Error(codes.InvalidArgument, "missing 'x-request-fk-src-service-name' header")
		} else {
			if strings.Trim(fkSrcServiceName[0], " ") == "" {
				//logrus.Error("empty 'x-response-src-service-name' header")
				return nil, status.Error(codes.InvalidArgument, "empty 'x-response-src-service-name' header")
			}
		}

		var newCtx context.Context

		protocol := md["x-request-fk-protocol"]
		if len(protocol) == 0 { // HTTP
			values := md["authorization"]
			if len(values) == 0 {
				return nil, status.Error(codes.Unauthenticated, "AccessToken is required")
			}
			token := strings.Split(values[0], " ")
			if len(token) != 2 {
				return nil, status.Error(codes.Unauthenticated, "Wrong Authorization format")
			}
			if !strings.EqualFold(token[0], "bearer") {
				return nil, status.Error(codes.Unauthenticated, "Wrong Authorization scheme")
			}
			permissions := args[info.FullMethod]
			res, err := Auth(token[1], permissions)
			if err != nil {
				return nil, err
			}

			if res.StatusCode == ERROR_INVALID_TOKEN {
				return nil, status.Error(codes.Unauthenticated, "invalid-token")
			} else if res.StatusCode == ERROR_EXPIRED_TOKEN {
				return nil, status.Error(codes.Unauthenticated, "expired-token")
			}
			//if res.StatusCode != 200 {
			//	logrus.Error(res.ErrorMessage)
			//	errorMessage := res.ErrorMessage
			//	if res.StatusCode == 403 {
			//		errorMessage = "Required permissions : " + strings.Trim(strings.Join(strings.Split(fmt.Sprint(permissions), " "), "[]"), "[]")
			//	}
			//	return nil, status.Error(codes.PermissionDenied, errorMessage)
			//}
			newCtx = newTagsForCtx(ctx, res)
		} else { // gRPC

			_domainId := md["x-request-fk-domain-id"]
			if len(_domainId) == 0 {
				return nil, status.Error(codes.InvalidArgument, "missing 'x-request-fk-domain-id' header")
			}
			if strings.Trim(_domainId[0], " ") == "" {
				return nil, status.Error(codes.InvalidArgument, "empty 'x-response-fk-domain-id' header")
			}
			domainId, _ := strconv.Atoi(_domainId[0])

			_projectId := md["x-request-fk-project-id"]
			if len(_projectId) == 0 {
				return nil, status.Error(codes.InvalidArgument, "missing 'x-request-fk-project-id' header")
			}
			if strings.Trim(_projectId[0], " ") == "" {
				return nil, status.Error(codes.InvalidArgument, "empty 'x-response-fk-project-id' header")
			}
			projectId, _ := strconv.Atoi(_projectId[0])

			_accountId := md["x-request-fk-account-id"]
			if len(_accountId) == 0 {
				return nil, status.Error(codes.InvalidArgument, "missing 'x-request-fk-account-id' header")
			}
			if strings.Trim(_accountId[0], " ") == "" {
				return nil, status.Error(codes.InvalidArgument, "empty 'x-response-fk-account-id' header")
			}
			accountId, _ := strconv.Atoi(_accountId[0])

			_accountType := md["x-request-fk-account-type"]
			if len(_accountType) == 0 {
				return nil, status.Error(codes.InvalidArgument, "missing 'x-request-fk-account-type' header")
			}
			if strings.Trim(_accountType[0], " ") == "" {
				return nil, status.Error(codes.InvalidArgument, "empty 'x-response-fk-account-type' header")
			}
			accountType, _ := strconv.Atoi(_accountType[0])

			newCtx = newTagsForCtx2(ctx, FKInfo{
				DomainId:    int64(domainId),
				ProjectId:   int64(projectId),
				AccountId:   int64(accountId),
				AccountType: int64(accountType),
			})
		}

		return handler(newCtx, req)
	}
}

func Auth(accessToken string, permissions []int64) (*pb.AuthResponse, error) {
	err := Connect()
	if err != nil {
		return nil, err
	}
	c := pb.NewIamClient(conn)

	// Contact the server and print out its response.
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	res, err := c.Auth(ctx, &pb.AuthRequest{
		AccessToken: accessToken,
		Permissions: permissions,
	})
	if err != nil {
		return res, err
	}

	return &pb.AuthResponse{
		StatusCode:   res.StatusCode,
		ErrorMessage: res.ErrorMessage,
		DomainId:     res.DomainId,
		ProjectId:    res.ProjectId,
		AccountId:    res.AccountId,
		AccountType:  res.AccountType,
	}, nil
}

func VerifyToken(accessToken string) (*pb.VerifyTokenResponse, error) {
	err := Connect()
	if err != nil {
		return nil, err
	}

	c := pb.NewIamClient(conn)

	// Contact the server and print out its response.
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	return c.VerifyToken(ctx, &pb.VerifyTokenRequest{
		AccessToken: accessToken,
	})
}

func CreateToken(req *pb.CreateTokenRequest) (*pb.CreateTokenResponse, error) {
	err := Connect()
	if err != nil {
		return nil, err
	}

	c := pb.NewIamClient(conn)

	// Contact the server and print out its response.
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	return c.CreateToken(ctx, req)
}

func GetDomainIdFromContext(ctx context.Context) (int64, error) {
	_auth := ctxauth.Extract(ctx)
	auth := _auth.Values()

	if _auth.Has("auth.domainId") {
		return auth["auth.domainId"].(int64), nil
	}
	return 0, status.Error(codes.NotFound, "Not found auth.domainId in Context")
}

func GetProjectIdFromContext(ctx context.Context) (int64, error) {
	_auth := ctxauth.Extract(ctx)
	auth := _auth.Values()

	if _auth.Has("auth.projectId") {
		return auth["auth.projectId"].(int64), nil
	}
	return 0, status.Error(codes.NotFound, "Not found auth.projectId in Context")
}

func GetAccountIdFromContext(ctx context.Context) (int64, error) {
	_auth := ctxauth.Extract(ctx)
	auth := _auth.Values()

	if _auth.Has("auth.accountId") {
		return auth["auth.accountId"].(int64), nil
	}
	return 0, status.Error(codes.NotFound, "Not found auth.accountId in Context")
}

func GetAccountTypeFromContext(ctx context.Context) (int64, error) {
	_auth := ctxauth.Extract(ctx)
	auth := _auth.Values()

	if _auth.Has("auth.accountType") {
		return auth["auth.accountType"].(int64), nil
	}
	return 0, status.Error(codes.NotFound, "Not found auth.accountType in Context")
}
