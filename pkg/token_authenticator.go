package pkg

import (
	"context"
	"fmt"
	"github.com/mr-tron/base58"
	jitopb "github.com/rubby-c/jito-go/pb"
	"github.com/rubby-c/solana-go"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"sync"
	"time"
)

type AuthenticationService struct {
	AuthService jitopb.AuthServiceClient
	GrpcCtx     context.Context
	KeyPair     *Keypair
	BearerToken string
	ExpiresAt   int64 // seconds
	ErrChan     chan error
	mu          sync.Mutex
}

func NewAuthenticationService(grpcConn *grpc.ClientConn, privateKey solana.PrivateKey) *AuthenticationService {
	return &AuthenticationService{
		GrpcCtx:     context.Background(),
		AuthService: jitopb.NewAuthServiceClient(grpcConn),
		KeyPair:     NewKeyPair(privateKey),
		ErrChan:     make(chan error),
		mu:          sync.Mutex{},
	}
}

// AuthenticateAndRefresh is a function that authenticates the client and refreshes the access token.
func (as *AuthenticationService) AuthenticateAndRefresh(role jitopb.Role) error {
	respChallenge, err := as.AuthService.GenerateAuthChallenge(as.GrpcCtx,
		&jitopb.GenerateAuthChallengeRequest{
			Role:   role,
			Pubkey: as.KeyPair.PublicKey.Bytes(),
		},
	)
	if err != nil {
		return err
	}

	challenge := fmt.Sprintf("%s-%s", as.KeyPair.PublicKey.String(), respChallenge.GetChallenge())

	sig, err := as.generateChallengeSignature([]byte(challenge))
	if err != nil {
		return err
	}

	respToken, err := as.AuthService.GenerateAuthTokens(as.GrpcCtx, &jitopb.GenerateAuthTokensRequest{
		Challenge:       challenge,
		SignedChallenge: sig,
		ClientPubkey:    as.KeyPair.PublicKey.Bytes(),
	})
	if err != nil {
		return err
	}

	as.updateAuthorizationMetadata(respToken.AccessToken)

	go func() {
		for {
			select {
			case <-as.GrpcCtx.Done():
				as.ErrChan <- as.GrpcCtx.Err()
			default:
				var resp *jitopb.RefreshAccessTokenResponse
				resp, err = as.AuthService.RefreshAccessToken(as.GrpcCtx, &jitopb.RefreshAccessTokenRequest{
					RefreshToken: respToken.RefreshToken.Value,
				})
				if err != nil {
					as.ErrChan <- fmt.Errorf("failed to refresh access token: %w", err)
					continue
				}

				as.updateAuthorizationMetadata(resp.AccessToken)
				time.Sleep(time.Until(resp.AccessToken.ExpiresAtUtc.AsTime()) - 15*time.Second)
			}
		}
	}()

	return nil
}

// updateAuthorizationMetadata updates headers of the gRPC connection.
func (as *AuthenticationService) updateAuthorizationMetadata(token *jitopb.Token) {
	as.mu.Lock()
	defer as.mu.Unlock()

	as.GrpcCtx = metadata.NewOutgoingContext(context.Background(), metadata.Pairs("authorization", "Bearer "+token.Value))
	as.BearerToken = token.Value
	as.ExpiresAt = token.ExpiresAtUtc.Seconds
}

func (as *AuthenticationService) generateChallengeSignature(challenge []byte) ([]byte, error) {
	sig, err := as.KeyPair.PrivateKey.Sign(challenge)
	if err != nil {
		return nil, err
	}

	return base58.Decode(sig.String())
}
