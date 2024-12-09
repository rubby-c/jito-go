# Jito Go SDK
[![GoDoc](https://pkg.go.dev/badge/github.com/weeaa/jito-go?status.svg)](https://pkg.go.dev/github.com/weeaa/jito-go?tab=doc)
[![Go Report Card](https://goreportcard.com/badge/github.com/weeaa/jito-go)](https://goreportcard.com/report/github.com/weeaa/jito-go)
[![License](https://img.shields.io/badge/license-Apache_2.0-crimson)](https://opensource.org/license/apache-2-0)

This library contains tooling to interact with **[Jito Labs](https://www.jito.wtf/)** MEV software. ⚠️ Work in progress. ⚠️

We currently use [gagliardetto/solana-go](https://github.com/rubby-c/solana-go) to interact with Solana.  PRs and contributions are welcome.

![jitolabs](https://github.com/weeaa/jito-go/assets/108926252/5751416c-333b-412e-8f3f-f26b2839be98)

## ❇️ Contents
- [Support](#-support)
- [Features](#-features)
- [Methods](#-methods)
- [Installing](#-installing)
- [Update Proto](#-update-proto)
- [Keypair Authentication](#-keypair-authentication)
- [Examples](#-examples)
  - [Send Bundle](#send-bundle)
  - [Subscribe to Mempool Transactions | Accounts](#subscribe-to-mempool-transactions-accounts)
  - [Get Regions](#get-regions)
  - [Simulate Bundle](#simulate-bundle)
- [Disclaimer](#-disclaimer)
- [License](#-license)

## 🛟 Support
If my work has been useful in building your for-profit services/infra/bots/etc, consider donating at
`EcrHvqa5Vh4NhR3bitRZVrdcUGr1Z3o6bXHz7xgBU2FB` (SOL).

## ✨ Features
- [x] Searcher
- [x] Block Engine
- [x] Relayer
- [x] [Geyser](https://github.com/weeaa/goyser) 🐳
- [x] Shredstream
- [x] JSON RPC API
- [x] Others
- [x] API

## 📡 Methods
`🤡* methods which are deprecated by Jito due to malicious use`

`both gRPC and JSON-RPC methods are supported`
- [x] **Searcher**
  - `SubscribeMempoolAccounts` 🤡
  - `SubscribeMempoolPrograms` 🤡
  - `GetNextScheduledLeader`
  - `GetRegions`
  - `GetConnectedLeaders`
  - `GetConnectedLeadersRegioned`
  - `GetTipAccounts`
  - `SimulateBundle`
  - `SendBundle` (gRPC & RPC)
  - `SendBundleWithConfirmation` (gRPC & RPC)
  - `SubscribeBundleResults`
  - `GetBundleStatuses` (gRPC & RPC)
- [x] **Block Engine**
  - Validator
    - `SubscribePackets`
    - `SubscribeBundles`
    - `GetBlockBuilderFeeInfo`
  - Relayer
    - `SubscribeAccountsOfInterest`
    - `SubscribeProgramsOfInterest`
    - `StartExpiringPacketStream`
- [X] **ShredStream**
  - `SendHeartbeat`
- [x] **Others** (pkg/util.go)
  - `SubscribeTipStream`
- [x] **API** (api/api.go)
  - `RetrieveRecentBundles`

## 💾 Installing

Go 1.22.0 or higher.
```shell
go get github.com/weeaa/jito-go@latest
```

If you want to run tests:

1. Install [Task](https://taskfile.dev/installation/).
2. Initialize your `.env` file by running `task install:<os>` (darwin/linux/windows).
3. Run tests with `task test`.

## 🔄 Update Proto
🚨 **Beware that due to duplicate types from jito proto files it will cause an error when building, this issue has been submitted to the team.** 🚨

In order to get latest proto generated files, make sure you have protobuf & its plugins installed!

Using Homebrew (macOS).
```shell
brew install protobuf
go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
```

Edit perms.
```shell
chmod +x ./scripts/generate_protos.sh
```

Run script.
```shell
./scripts/generate_protos.sh
```

## 🔑 Keypair Authentication
**[The following isn't mandatory anymore for Searcher access](https://docs.google.com/document/d/e/2PACX-1vRZoiYWNvIdX4r6lf-8E5E0l8SEPKeXXRYRcviwQJjmizeJkeQ_YM4IWGQne-C_8_lFFXv-z6yI6y4K/pub)**.

To access Jito MEV functionalities, you'll need a whitelisted Public Key obtained from a fresh KeyPair; submit your Public Key [here](https://web.miniextensions.com/WV3gZjFwqNqITsMufIEp).
In order to generate a new KeyPair, you can use the following function `GenerateKeypair()` from the `/pkg` package.

## 💻 Examples

### `Send Bundle – gRPC`
```go
package main

import (
  "context"
  "github.com/davecgh/go-spew/spew"
  "github.com/rubby-c/solana-go"
  "github.com/rubby-c/solana-go/programs/system"
  "github.com/rubby-c/solana-go/rpc"
  "github.com/joho/godotenv"
  "github.com/weeaa/jito-go"
  "github.com/weeaa/jito-go/clients/searcher_client"
  "log"
  "os"
  "time"
)

func main() {
  if err := godotenv.Load(); err != nil {
    log.Fatal(err)
  }

  rpcAddr, ok := os.LookupEnv("JITO_RPC")
  if !ok {
    log.Fatal("JITO_RPC could not be found in .env")
  }

  privateKey, ok := os.LookupEnv("PRIVATE_KEY")
  if !ok {
    log.Fatal("PRIVATE_KEY could not be found in .env")
  }

  key, err := solana.PrivateKeyFromBase58(privateKey)
  if err != nil {
    log.Fatal(err)
  }
  
  ctx := context.Background()

  client, err := searcher_client.New(
    ctx,
    jito_go.NewYork.BlockEngineURL,
    rpc.New(rpcAddr),
    rpc.New(rpc.MainNetBeta_RPC),
    key,
    nil,
  )
  if err != nil {
    log.Fatal(err)
  }
  defer client.Close()

  ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
  defer cancel()

  // max per bundle is 5 transactions
  txns := make([]*solana.Transaction, 0, 5)

  block, err := client.RpcConn.GetRecentBlockhash(context.Background(), rpc.CommitmentFinalized)
  if err != nil {
    log.Fatal(err)
  }

  // change w ur keys =)
  from := solana.MustPrivateKeyFromBase58("Tq5gFBU4QG6b6aUYAwi87CUx64iy5tZT1J6nuphN4FXov3UZahMYGSbxLGhb8a9UZ1VvxWB4NzDavSzTorqKCio")
  to := solana.MustPublicKeyFromBase58("BLrQPbKruZgFkNhpdGGrJcZdt1HnfrBLojLYYgnrwNrz")

  tipInst, err := client.GenerateTipRandomAccountInstruction(1000000, from.PublicKey())
  if err != nil {
    log.Fatal(err)
  }

  tx, err := solana.NewTransaction(
    []solana.Instruction{
      system.NewTransferInstruction(
        10000000,
        from.PublicKey(),
        to,
      ).Build(),
      tipInst,
    },
    block.Value.Blockhash,
    solana.TransactionPayer(from.PublicKey()),
  )
  if err != nil {
    log.Fatal(err)
  }

  if _, err = tx.Sign(
    func(key solana.PublicKey) *solana.PrivateKey {
      if from.PublicKey().Equals(key) {
        return &from
      }
      return nil
    },
  ); err != nil {
    log.Fatal(err)
  }

  // debug print
  spew.Dump(tx)

  txns = append(txns, tx)

  resp, err := client.BroadcastBundleWithConfirmation(ctx, txns)
  if err != nil {
    log.Fatal(err)
  }

  log.Println(resp)
}
```
### `Subscribe to MemPool Transactions [Accounts]` 🚨 DISABLED 🚨
```go
package main

import (
  "context"
  "github.com/rubby-c/solana-go"
  "github.com/rubby-c/solana-go/rpc"
  "github.com/joho/godotenv"
  "github.com/weeaa/jito-go"
  "github.com/weeaa/jito-go/clients/searcher_client"
  "log"
  "os"
)

func main() {
  if err := godotenv.Load(); err != nil {
    log.Fatal(err)
  }

  rpcAddr, ok := os.LookupEnv("JITO_RPC")
  if !ok {
    log.Fatal("JITO_RPC could not be found in .env")
  }

  privateKey, ok := os.LookupEnv("PRIVATE_KEY")
  if !ok {
    log.Fatal("PRIVATE_KEY could not be found in .env")
  }

  key, err := solana.PrivateKeyFromBase58(privateKey)
  if err != nil {
    log.Fatal(err)
  }

  ctx := context.Background()

  client, err := searcher_client.New(
    ctx,
    jito_go.NewYork.BlockEngineURL,
    rpc.New(rpcAddr),
    rpc.New(rpc.MainNetBeta_RPC),
    key,
    nil,
  )
  if err != nil {
    log.Fatal(err)
  }
  defer client.Close()

  regions := []string{jito_go.NewYork.Region}
  accounts := []string{
    "GuHvDyajPfQpHrg2oCWmArYHrZn2ynxAkSxAPFn9ht1g",
    "4EKP9SRfykwQxDvrPq7jUwdkkc93Wd4JGCbBgwapeJhs",
    "Hn98nGFGfZwJPjd4bk3uAX5pYHJe5VqtrtMhU54LNNhe",
    "MuUEAu5tFfEMhaFGoz66jYTFBUHZrwfn3KWimXLNft2",
    "CSGeQFoSuN56QZqf9WLqEEkWhRFt6QksTjMDLm68PZKA",
  }

  sub, _, err := client.SubscribeAccountsMempoolTransactions(ctx, accounts, regions)
  if err != nil {
    log.Fatal(err)
  }

  for tx := range sub {
    log.Println(tx)
  }
}
```

### `Get Regions`
```go
package main

import (
    "github.com/rubby-c/solana-go"
    "github.com/rubby-c/solana-go/rpc"
    "github.com/weeaa/jito-go"
    "github.com/weeaa/jito-go/clients/searcher_client"
    "log"
    "os"
)

func main() {
  if err := godotenv.Load(); err != nil {
    log.Fatal(err)
  }

  rpcAddr, ok := os.LookupEnv("JITO_RPC")
  if !ok {
    log.Fatal("JITO_RPC could not be found in .env")
  }

  privateKey, ok := os.LookupEnv("PRIVATE_KEY")
  if !ok {
    log.Fatal("PRIVATE_KEY could not be found in .env")
  }

  key, err := solana.PrivateKeyFromBase58(privateKey)
  if err != nil {
    log.Fatal(err)
  }

  ctx := context.Background()

  client, err := searcher_client.New(
    ctx,
    jito_go.NewYork.BlockEngineURL,
    rpc.New(rpcAddr),
    rpc.New(rpc.MainNetBeta_RPC),
    key,
    nil,
  )
  if err != nil {
    log.Fatal(err)
  }
  defer client.Close()

  resp, err := client.GetRegions()
  if err != nil {
    log.Fatal(err)
  }

  log.Println(resp)
}
```
### `Simulate Bundle`
```go
package main

import (
  "context"
  "github.com/rubby-c/solana-go"
  "github.com/rubby-c/solana-go/programs/system"
  "github.com/rubby-c/solana-go/rpc"
  "github.com/joho/godotenv"
  "github.com/weeaa/jito-go"
  "github.com/weeaa/jito-go/clients/searcher_client"
  "log"
  "os"
  "time"
)

func main() {
  if err := godotenv.Load(); err != nil {
    log.Fatal(err)
  }

  rpcAddr, ok := os.LookupEnv("JITO_RPC")
  if !ok {
    log.Fatal("JITO_RPC could not be found in .env")
  }

  privateKey, ok := os.LookupEnv("PRIVATE_KEY")
  if !ok {
    log.Fatal("PRIVATE_KEY could not be found in .env")
  }

  key, err := solana.PrivateKeyFromBase58(privateKey)
  if err != nil {
    log.Fatal(err)
  }

  ctx := context.Background()

  client, err := searcher_client.New(
    ctx,
    jito_go.NewYork.BlockEngineURL,
    rpc.New(rpcAddr),
    rpc.New(rpc.MainNetBeta_RPC),
    key,
    nil,
  )
  if err != nil {
    log.Fatal(err)
  }
  defer client.Close()

  ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
  defer cancel()

  var pkey string
  pkey, ok = os.LookupEnv("PRIVATE_KEY_WITH_FUNDS")
  if !ok {
    log.Fatal("could not get PRIVATE_KEY from .env")
  }

  var fundedWallet solana.PrivateKey
  fundedWallet, err = solana.PrivateKeyFromBase58(pkey)
  if err != nil {
    log.Fatal(err)
  }

  var blockHash *rpc.GetRecentBlockhashResult
  var tx *solana.Transaction

  blockHash, err = client.RpcConn.GetRecentBlockhash(ctx, rpc.CommitmentConfirmed)
  if err != nil {
    log.Fatal(err)
  }

  var tipInst solana.Instruction
  tipInst, err = client.GenerateTipRandomAccountInstruction(1000000, fundedWallet.PublicKey())
  if err != nil {
    log.Fatal(err)
  }

  tx, err = solana.NewTransaction(
    []solana.Instruction{
      system.NewTransferInstruction(
        10000000,
        fundedWallet.PublicKey(),
        solana.MustPublicKeyFromBase58("A6njahNqC6qKde6YtbHdr1MZsB5KY9aKfzTY1cj8jU3v"),
      ).Build(),
      tipInst,
    },
    blockHash.Value.Blockhash,
    solana.TransactionPayer(fundedWallet.PublicKey()),
  )
  if err != nil {
    log.Fatal(err)
  }

  _, err = tx.Sign(
    func(key solana.PublicKey) *solana.PrivateKey {
      if fundedWallet.PublicKey().Equals(key) {
        return &fundedWallet
      }
      return nil
    },
  )

  resp, err := client.SimulateBundle(
    ctx,
    searcher_client.SimulateBundleParams{
      EncodedTransactions: []string{tx.MustToBase64()},
    },
    searcher_client.SimulateBundleConfig{
      PreExecutionAccountsConfigs: []searcher_client.ExecutionAccounts{
        {
          Encoding:  "base64",
          Addresses: []string{"3vjULHsUbX4J2nXZJQQSHkTHoBqhedvHQPDNaAgT9dwG"},
        },
      },
      PostExecutionAccountsConfigs: []searcher_client.ExecutionAccounts{
        {
          Encoding:  "base64",
          Addresses: []string{"3vjULHsUbX4J2nXZJQQSHkTHoBqhedvHQPDNaAgT9dwG"},
        },
      },
    },
  )
  if err != nil {
    log.Fatal(err)
  }

  log.Println(resp)
}
```

## 🚨 Disclaimer

**This library is not affiliated with Jito Labs**. It is a community project and is not officially supported by Jito Labs. Use at your own risk.

## 📃 License

[Apache-2.0 License](https://github.com/weeaa/jito-go/blob/main/LICENSE).
