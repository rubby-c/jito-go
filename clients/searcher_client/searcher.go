package searcher_client

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"github.com/goccy/go-json"
	"github.com/rubby-c/jito-go/pkg"
	"github.com/rubby-c/solana-go"
	"github.com/rubby-c/solana-go/programs/system"
	"github.com/rubby-c/solana-go/rpc"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"sync"
	"time"
)

// New creates a new Searcher Client instance.
func New(
	ctx context.Context,
	grpcDialURL string,
	jitoRpcClient, rpcClient *rpc.Client,
	privateKey solana.PrivateKey,
	tlsConfig *tls.Config,
	opts ...grpc.DialOption,
) (
	*Client, error) {

	if tlsConfig != nil {
		opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)))
	} else {
		opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{})))
	}

	chErr := make(chan error)
	conn, err := pkg.CreateAndObserveGRPCConn(ctx, chErr, grpcDialURL, opts...)
	if err != nil {
		return nil, err
	}

	searcherService := jitopb.NewSearcherServiceClient(conn)
	authService := pkg.NewAuthenticationService(conn, privateKey)
	if err = authService.AuthenticateAndRefresh(jitopb.Role_SEARCHER); err != nil {
		return nil, err
	}

	subBundleRes, err := searcherService.SubscribeBundleResults(authService.GrpcCtx, &jitopb.SubscribeBundleResultsRequest{})
	if err != nil {
		return nil, err
	}

	return &Client{
		GrpcConn:                 conn,
		RpcConn:                  rpcClient,
		JitoRpcConn:              jitoRpcClient,
		SearcherService:          searcherService,
		BundleStreamSubscription: subBundleRes,
		Auth:                     authService,
		ErrChan:                  chErr,
	}, nil
}

// NewNoAuth initializes and returns a new instance of the Searcher Client which does not require private key signing.
func NewNoAuth(
	ctx context.Context,
	grpcDialURL string,
	jitoRpcClient, rpcClient *rpc.Client,
	tlsConfig *tls.Config,
	opts ...grpc.DialOption,
) (
	*Client, error) {
	if tlsConfig != nil {
		opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)))
	} else {
		opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{})))
	}

	chErr := make(chan error)
	conn, err := pkg.CreateAndObserveGRPCConn(ctx, chErr, grpcDialURL, opts...)
	if err != nil {
		return nil, err
	}

	searcherService := jitopb.NewSearcherServiceClient(conn)
	subBundleRes, err := searcherService.SubscribeBundleResults(ctx, &jitopb.SubscribeBundleResultsRequest{})
	if err != nil {
		return nil, err
	}

	return &Client{
		GrpcConn:                 conn,
		RpcConn:                  rpcClient,
		JitoRpcConn:              jitoRpcClient,
		SearcherService:          searcherService,
		BundleStreamSubscription: subBundleRes,
		ErrChan:                  chErr,
		Auth:                     &pkg.AuthenticationService{GrpcCtx: ctx},
	}, nil
}

func (c *Client) Close() error {
	close(c.ErrChan)
	defer c.Auth.GrpcCtx.Done()

	if err := c.RpcConn.Close(); err != nil {
		return err
	}

	if err := c.JitoRpcConn.Close(); err != nil {
		return err
	}

	return c.GrpcConn.Close()
}

func (c *Client) GetRegions(opts ...grpc.CallOption) (*jitopb.GetRegionsResponse, error) {
	return c.SearcherService.GetRegions(c.Auth.GrpcCtx, &jitopb.GetRegionsRequest{}, opts...)
}

func (c *Client) GetConnectedLeaders(opts ...grpc.CallOption) (*jitopb.ConnectedLeadersResponse, error) {
	return c.SearcherService.GetConnectedLeaders(c.Auth.GrpcCtx, &jitopb.ConnectedLeadersRequest{}, opts...)
}

func (c *Client) GetConnectedLeadersRegioned(regions []string, opts ...grpc.CallOption) (*jitopb.ConnectedLeadersRegionedResponse, error) {
	return c.SearcherService.GetConnectedLeadersRegioned(c.Auth.GrpcCtx, &jitopb.ConnectedLeadersRegionedRequest{Regions: regions}, opts...)
}

// GetTipAccounts returns Jito Tip Accounts.
func (c *Client) GetTipAccounts(opts ...grpc.CallOption) (*jitopb.GetTipAccountsResponse, error) {
	return c.SearcherService.GetTipAccounts(c.Auth.GrpcCtx, &jitopb.GetTipAccountsRequest{}, opts...)
}

// GetRandomTipAccount returns a random Jito TipAccount.
func (c *Client) GetRandomTipAccount(opts ...grpc.CallOption) (string, error) {
	resp, err := c.GetTipAccounts(opts...)
	if err != nil {
		return "", err
	}

	return resp.Accounts[rand.Intn(len(resp.Accounts))], nil
}

func (c *Client) GetNextScheduledLeader(regions []string, opts ...grpc.CallOption) (*jitopb.NextScheduledLeaderResponse, error) {
	return c.SearcherService.GetNextScheduledLeader(c.Auth.GrpcCtx, &jitopb.NextScheduledLeaderRequest{Regions: regions}, opts...)
}

// NewBundleSubscriptionResults creates a new bundle subscription stream, allowing to receive information about broadcasted bundles.
func (c *Client) NewBundleSubscriptionResults(opts ...grpc.CallOption) (jitopb.SearcherService_SubscribeBundleResultsClient, error) {
	return c.SearcherService.SubscribeBundleResults(c.Auth.GrpcCtx, &jitopb.SubscribeBundleResultsRequest{}, opts...)
}

// BroadcastBundle sends a bundle of transaction(s) on chain through Jito.
func (c *Client) BroadcastBundle(transactions []*solana.Transaction, opts ...grpc.CallOption) (*jitopb.SendBundleResponse, error) {
	bundle, err := c.AssembleBundle(transactions)
	if err != nil {
		return nil, err
	}

	return c.SearcherService.SendBundle(c.Auth.GrpcCtx, &jitopb.SendBundleRequest{Bundle: bundle}, opts...)
}

// SpamBundle spams BroadcastBundle (spam being the amount of bundles sent). Beware, it uses goroutines 😉.
func (c *Client) SpamBundle(transactions []*solana.Transaction, spam int, opts ...grpc.CallOption) ([]*jitopb.SendBundleResponse, []error) {
	bundles := make([]*jitopb.SendBundleResponse, spam)
	errs := make([]error, spam)
	mu := sync.Mutex{}
	for i := 0; i < spam; i++ {
		go func() {
			bundle, err := c.BroadcastBundle(transactions, opts...)
			if err != nil {
				errs = append(errs, err)
				return
			}
			mu.Lock()
			bundles = append(bundles, bundle)
			mu.Unlock()
		}()
	}
	return bundles, errs
}

type BroadcastBundleResponse struct {
	Jsonrpc string `json:"jsonrpc"`
	Result  string `json:"result"`
	Id      int    `json:"id"`
}

// BroadcastBundleWithConfirmation sends a bundle of transactions on chain thru Jito BlockEngine and waits for its confirmation.
func (c *Client) BroadcastBundleWithConfirmation(ctx context.Context, transactions []*solana.Transaction, opts ...grpc.CallOption) (*jitopb.SendBundleResponse, error) {
	bundle, err := c.BroadcastBundle(transactions, opts...)
	if err != nil {
		return nil, err
	}

	bundleSignatures := pkg.BatchExtractSigFromTx(transactions)

	for {
		select {
		case <-c.Auth.GrpcCtx.Done():
			return nil, c.Auth.GrpcCtx.Err()
		default:
			time.Sleep(5 * time.Second)

			bundleResult, err := c.BundleStreamSubscription.Recv()
			if err != nil {
				return bundle, err
			}

			if err = handleBundleResult(bundleResult, ""); err != nil {
				return bundle, err
			}

			var start = time.Now()
			var statuses *rpc.GetSignatureStatusesResult

			isRPCNil(c.RpcConn)

			for {
				statuses, err = c.RpcConn.GetSignatureStatuses(ctx, false, bundleSignatures...)
				if err != nil {
					return bundle, err
				}
				ready := true

				for _, status := range statuses.Value {
					if status == nil {
						ready = false
						break
					}
				}

				if ready {
					break
				}

				if time.Since(start) > 15*time.Second {
					return bundle, errors.New("operation timed out after 15 seconds")
				} else {
					time.Sleep(1 * time.Second)
				}
			}

			for _, status := range statuses.Value {
				if status.ConfirmationStatus != rpc.ConfirmationStatusProcessed && status.ConfirmationStatus != rpc.ConfirmationStatusConfirmed {
					return bundle, errors.New("searcher service did not provide bundle status in time")
				}
			}

			return bundle, nil
		}
	}
}

// bundleID arg is solely for JSON RPC API.
func handleBundleResult[T *GetInflightBundlesStatusesResponse | *jitopb.BundleResult](t T, bundleID string) error {
	switch bundle := any(t).(type) {
	case *jitopb.BundleResult:
		switch bundle.Result.(type) {
		case *jitopb.BundleResult_Accepted:
			break
		case *jitopb.BundleResult_Rejected:
			rejected := bundle.Result.(*jitopb.BundleResult_Rejected)
			switch rejected.Rejected.Reason.(type) {
			case *jitopb.Rejected_SimulationFailure:
				rejection := rejected.Rejected.GetSimulationFailure()
				return NewSimulationFailureError(rejection.TxSignature, rejection.GetMsg())
			case *jitopb.Rejected_StateAuctionBidRejected:
				rejection := rejected.Rejected.GetStateAuctionBidRejected()
				return NewStateAuctionBidRejectedError(rejection.AuctionId, rejection.SimulatedBidLamports)
			case *jitopb.Rejected_WinningBatchBidRejected:
				rejection := rejected.Rejected.GetWinningBatchBidRejected()
				return NewWinningBatchBidRejectedError(rejection.AuctionId, rejection.SimulatedBidLamports)
			case *jitopb.Rejected_InternalError:
				rejection := rejected.Rejected.GetInternalError()
				return NewInternalError(rejection.Msg)
			case *jitopb.Rejected_DroppedBundle:
				rejection := rejected.Rejected.GetDroppedBundle()
				return NewDroppedBundle(rejection.Msg)
			default:
				return nil
			}
		}
	case *GetInflightBundlesStatusesResponse: // experimental, subject to changes
		for i, value := range bundle.Result.Value {
			if value.BundleId == bundleID {
				switch value.Status {
				case "Invalid":
					return fmt.Errorf("bundle %d is invalid", i)
				case "Pending":
					return fmt.Errorf("bundle %d is pending", i)
				case "Failed":
					return fmt.Errorf("bundle %d failed to land", i)
				case "Landed":
					return nil
				default:
					return fmt.Errorf("bundle %d unknown error", i)
				}
			}
		}
	}
	return nil
}

// SimulateBundle is an RPC method that simulates a Jito bundle – exclusively available to Jito-Solana validator.
func (c *Client) SimulateBundle(ctx context.Context, bundleParams SimulateBundleParams, simulationConfigs SimulateBundleConfig) (*SimulatedBundleResponse, error) {
	if len(bundleParams.EncodedTransactions) != len(simulationConfigs.PreExecutionAccountsConfigs) {
		return nil, errors.New("pre/post execution account config length must match bundle length")
	}

	var out SimulatedBundleResponse
	err := c.JitoRpcConn.RPCCallForInto(ctx, &out, "simulateBundle", []interface{}{bundleParams, simulationConfigs})
	return &out, err
}

// GetBundleStatuses returns the status of submitted bundle(s). This function operates similarly to the Solana RPC method getSignatureStatuses.
func (c *Client) GetBundleStatuses(ctx context.Context, bundleIDs []string) (*BundleStatusesResponse, error) {
	if len(bundleIDs) > 5 {
		return nil, fmt.Errorf("max length reached (exp 5, got %d), please use BatchGetBundleStatuses or reduce the amount of bundles", len(bundleIDs))
	}

	var params []interface{}
	for _, bundleID := range bundleIDs {
		params = append(params, bundleID)
	}

	var out BundleStatusesResponse
	err := c.JitoRpcConn.RPCCallForInto(ctx, &out, "getBundleStatuses", params)

	return &out, err
}

// BatchGetBundleStatuses returns the statuses of multiple submitted bundles by splitting the bundleIDs into groups of up to 5
// and calling GetBundleStatuses on each group.
func (c *Client) BatchGetBundleStatuses(ctx context.Context, bundleIDs ...string) ([]*BundleStatusesResponse, error) {
	if len(bundleIDs) > 5 {
		var bundles [][]string
		var out []*BundleStatusesResponse

		for _, bundleID := range bundleIDs {
			if len(bundles) == 0 || len(bundles[len(bundles)-1]) == 5 {
				bundles = append(bundles, []string{bundleID})
			} else {
				bundles[len(bundles)-1] = append(bundles[len(bundles)-1], bundleID)
			}
		}

		for _, bundle := range bundles {
			resp, err := c.GetBundleStatuses(ctx, bundle)
			if err != nil {
				return out, err
			}

			out = append(out, resp)
		}

		return out, nil
	} else {
		var out []*BundleStatusesResponse

		resp, err := c.GetBundleStatuses(ctx, bundleIDs)
		if err != nil {
			return nil, err
		}

		out = append(out, resp)

		return out, nil
	}
}

// GetBundleStatuses returns the status of submitted bundle(s). This function operates similarly to the Solana RPC method getSignatureStatuses.
func GetBundleStatuses(client *http.Client, bundleIDs []string) (*BundleStatusesResponse, error) {
	if len(bundleIDs) > 5 {
		return nil, fmt.Errorf("max length reached (exp 5, got %d), please use BatchGetBundleStatuses or reduce the amount of bundles", len(bundleIDs))
	}

	buf := new(bytes.Buffer)
	payload := map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "getBundleStatuses",
		"params":  [][]string{bundleIDs},
	}

	if err := json.NewEncoder(buf).Encode(payload); err != nil {
		return nil, err
	}

	req := &http.Request{
		Method: http.MethodPost,
		URL:    jitoBundleURL,
		Body:   io.NopCloser(buf),
		Header: DefaultHeader.Clone(),
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error performing GetBundleStatuses: client error > %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GetBundleStatuses error: unexpected response status %s", resp.Status)
	}

	var out BundleStatusesResponse
	err = json.NewDecoder(resp.Body).Decode(&out)
	return &out, err
}

// BatchGetBundleStatuses returns the statuses of multiple submitted bundles by splitting the bundleIDs into groups of up to 5
// and calling GetBundleStatuses on each group.
func BatchGetBundleStatuses(client *http.Client, bundleIDs ...string) ([]*BundleStatusesResponse, error) {
	if len(bundleIDs) > 5 {
		var bundles [][]string
		var out []*BundleStatusesResponse

		for _, bundleID := range bundleIDs {
			if len(bundles) == 0 || len(bundles[len(bundles)-1]) == 5 {
				bundles = append(bundles, []string{bundleID})
			} else {
				bundles[len(bundles)-1] = append(bundles[len(bundles)-1], bundleID)
			}
		}

		for _, bundle := range bundles {
			resp, err := GetBundleStatuses(client, bundle)
			if err != nil {
				return out, err
			}

			out = append(out, resp)
		}

		return out, nil
	} else {
		var out []*BundleStatusesResponse

		resp, err := GetBundleStatuses(client, bundleIDs)
		if err != nil {
			return nil, err
		}

		out = append(out, resp)

		return out, nil
	}
}

// AssembleBundle converts an array of SOL transactions to a Jito bundle.
func (c *Client) AssembleBundle(transactions []*solana.Transaction) (*jitopb.Bundle, error) {
	packets := make([]*jitopb.Packet, 0, len(transactions))

	// converts an array of transactions to an array of protobuf packets
	for i, tx := range transactions {
		packet, err := pkg.ConvertTransactionToProtobufPacket(tx)
		if err != nil {
			return nil, fmt.Errorf("%d: error converting tx to jitopb packet [%w]", i, err)
		}

		packets = append(packets, &packet)
	}

	return &jitopb.Bundle{Packets: packets, Header: nil}, nil
}

// GetInflightBundleStatuses returns the status of submitted bundles within the last five minutes, allowing up to five bundle IDs per request.
func GetInflightBundleStatuses(client *http.Client, bundles []string) (*GetInflightBundlesStatusesResponse, error) {
	buf := new(bytes.Buffer)

	payload := map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "getInflightBundleStatuses",
		"params": [][]string{
			bundles,
		},
	}

	if err := json.NewEncoder(buf).Encode(payload); err != nil {
		return nil, err
	}

	req := &http.Request{
		Method: http.MethodPost,
		URL:    jitoBundleURL,
		Body:   io.NopCloser(buf),
		Header: DefaultHeader.Clone(),
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GetInflightBundleStatuses error: unexpected response status %s", resp.Status)
	}

	var out GetInflightBundlesStatusesResponse
	err = json.NewDecoder(resp.Body).Decode(&out)
	return &out, err
}

// GetTipAccounts retrieves the tip accounts designated for tip payments for bundles.
func GetTipAccounts(client *http.Client) (*GetTipAccountsResponse, error) {
	buf := new(bytes.Buffer)

	payload := map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "getTipAccounts",
		"params":  []string{},
	}

	if err := json.NewEncoder(buf).Encode(payload); err != nil {
		return nil, err
	}

	req := &http.Request{
		Method: http.MethodPost,
		URL:    jitoBundleURL,
		Body:   io.NopCloser(buf),
		Header: DefaultHeader.Clone(),
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GetTipAccounts error: unexpected response status %s", resp.Status)
	}

	var out GetTipAccountsResponse
	err = json.NewDecoder(resp.Body).Decode(&out)
	return &out, err
}

// SendTransaction serves as a proxy to the Solana sendTransaction RPC method.
// It forwards the received transaction as a regular Solana transaction via the Solana RPC method and submits it as a bundle.
// Jito no longer provides a minimum tip for the bundle.
// Please note that this minimum tip might not be sufficient to get the bundle through the auction, especially during high-demand periods.
// Additionally, you need to set a priority fee and jito tip to ensure this transaction is setup correctly.
// Otherwise, if you set the query parameter bundleOnly=true, the transaction will only be sent out as a bundle and not as a regular transaction via RPC.
func SendTransaction(client *http.Client, sig string, bundleOnly bool) (*TransactionResponse, error) {
	buf := new(bytes.Buffer)

	payload := map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "sendTransaction",
		"params":  []string{sig},
	}

	if err := json.NewEncoder(buf).Encode(payload); err != nil {
		return nil, err
	}

	var path = "/api/v1/transactions"
	if bundleOnly {
		path = "/api/v1/transactions?bundleOnly=true"
	}

	req := &http.Request{
		Method: http.MethodPost,
		URL: &url.URL{
			Scheme: "https",
			Host:   "mainnet.block-engine.jito.wtf",
			Path:   path,
		},
		Body:   io.NopCloser(buf),
		Header: DefaultHeader.Clone(),
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("SendTransaction error: unexpected response status %s", resp.Status)
	}

	var tx TransactionResponse
	if err = json.NewDecoder(resp.Body).Decode(&tx); err != nil {
		return nil, err
	}

	tx.BundleID = resp.Header.Get("x-bundle-id")

	return &tx, nil
}

// GenerateTipInstruction is a function that generates a Solana tip instruction mandatory to broadcast a bundle to Jito.
func GenerateTipInstruction(tipAmount uint64, from, tipAccount solana.PublicKey) solana.Instruction {
	return system.NewTransferInstruction(tipAmount, from, tipAccount).Build()
}

// GenerateTipRandomAccountInstruction functions similarly to GenerateTipInstruction, but it selects a random tip account.
func (c *Client) GenerateTipRandomAccountInstruction(tipAmount uint64, from solana.PublicKey) (solana.Instruction, error) {
	tipAccount, err := c.GetRandomTipAccount()
	if err != nil {
		return nil, err
	}

	return system.NewTransferInstruction(tipAmount, from, solana.MustPublicKeyFromBase58(tipAccount)).Build(), nil
}

func isRPCNil(client *rpc.Client) {
	if client == nil {
		client = rpc.New(rpc.MainNetBeta_RPC)
	}
}

type BundleRejectionError struct {
	Message string
}

func (e BundleRejectionError) Error() string {
	return e.Message
}

func NewStateAuctionBidRejectedError(auction string, tip uint64) error {
	return BundleRejectionError{
		Message: fmt.Sprintf("bundle lost state auction, auction: %s, tip %d lamports", auction, tip),
	}
}

func NewWinningBatchBidRejectedError(auction string, tip uint64) error {
	return BundleRejectionError{
		Message: fmt.Sprintf("bundle won state auction but failed global auction, auction %s, tip %d lamports", auction, tip),
	}
}

func NewSimulationFailureError(tx string, message string) error {
	return BundleRejectionError{
		Message: fmt.Sprintf("bundle simulation failure on tx %s, message: %s", tx, message),
	}
}

func NewInternalError(message string) error {
	return BundleRejectionError{
		Message: fmt.Sprintf("internal error %s", message),
	}
}

func NewDroppedBundle(message string) error {
	return BundleRejectionError{
		Message: fmt.Sprintf("bundle dropped %s", message),
	}
}
