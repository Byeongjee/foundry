[JSON-RPC](http://www.jsonrpc.org/specification) is a stateless, light-weight remote procedure call (RPC) protocol. Primarily this specification defines several data structures and the rules around their processing. It is transport agnostic, meaning that the concepts can be used within the same process, over sockets, over HTTP, or in many various message passing environments. It uses JSON ([RFC 4627](https://www.ietf.org/rfc/rfc4627.txt)) as data format.

# CLI options for JSON-RPC

 * `--no-jsonrpc`
   > Do not run jsonrpc.
 * `--jsonrpc-port <PORT>`
   > Listen for rpc connections on PORT. [default: 8080]

In the current version, it's only supported through HTTP.

# List of types

## H160, H256, H512, ...

A XXX-bit hexadecimal string. (e.g. H160: 160-bit hexadecimal string)

## U64, U128, U256, ...

A hexadecimal string for XXX-bit unsigned integer

## NetworkID

A two-letter string to denote a network. For example, "cc" is for the main network, and "wc" is for the Corgi test network. See [the specification](List-of-Network-Id.md).

## PlatformAddress

A string that starts with "(NetworkID)c", and Bech32 string follows. For example, "cccqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqz6sxn0" is for the main network, and "wccqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqz6sxn0" is for the Corgi test network. See [the specification](CodeChain-Address.md#1-platform-account-address-format).

## Block

 - author: `PlatformAddress`
 - extraData: `any[]`
 - hash: `H256`
 - number: `number`
 - transactions: `Transaction[]`
 - transactionsRoot: `H256`
 - parentHash: `H256`
 - seal: `string[]`
 - stateRoot: `H256`
 - timestamp: `number`

## Transaction

 - blockHash: `H256`
 - blockNumber: `number`
 - fee: `U64`
 - hash: `H256`
 - networkId: `NetworkID`
 - seq: `number`
 - transactionIndex: `number`
 - sig: `Signature`
 - action: `Action`

## UnsignedTransaction

 - fee: `U64`
 - networkId: `NetworkID`
 - seq: `number` | `null`
 - action: `Action`

## Actions

### Pay Action

 - type: "pay"
 - networkId: `NetworkID`
 - receiver: `PlatformAddress`
 - quantity: `U64`

### Custom Action

 - type: "custom"
 - networkId: `NetworkID`
 - handlerId: `number`
 - bytes: `string`

### Transaction in Response

When `Transaction` is included in any response, there will be an additional field `hash` in the data, which is the hash value of the given transaction. This decreases the time to calculate the transaction hash when it is needed from the response.

#### Timelock

 - type: "block" | "blockAge" | "time" | "timeAge"
 - value: `number`

## Signature
`H512` for Ed25519 Signatures

## CommonParams

 - maxExtraDataSize: `U64`
 - maxTransferMetadataSize: `U64`
 - maxTextContentSize: `U64`
 - networkID: `string`
 - minPayCost: `U64`
 - minCreateShardCost: `U64`
 - minSetShardOwnersCost: `U64`
 - minSetShardUsersCost: `U64`
 - minCustomCost: `U64`
 - maxBodySize: `U64`
 - snapshotPeriod: `U64`
 - termSeconds?: `U64`
 - nominationExpiration?: `U64`
 - custodyPeriod?: `U64`
 - releasePeriod?: `U64`
 - maxNumOfValidators?: `U64`
 - minNumOfValidators?: `U64`
 - delegationThreshold?: `U64`
 - minDeposit?: `U64`

# Error codes

|  Code  |         Message        |                          Description                         |
|--------|------------------------|--------------------------------------------------------------|
| -32002 | `No Author`            | No author is configured                                      |
| -32004 | `No Work Required`     | No work is required                                          |
| -32005 | `No Work Found`        | No work is found                                             |
| -32009 | `Invalid RLP`          | Failed to decode the RLP string                              |
| -32011 | `KVDB Error`           | Failed to access the state (Internal error of CodeChain)     |
| -32010 | `Execution Failed`     | Failed to execute the transactions                           |
| -32030 | `Verification Failed`  | The signature is invalid                                     |
| -32031 | `Already Imported`     | The same transaction is already imported                     |
| -32032 | `Not Enough Balance`   | The signer's balance is insufficient                         |
| -32033 | `Too Low Fee`          | The fee is lower than the minimum required                   |
| -32034 | `Too Cheap to Replace` | The fee is lower than the existing one in the queue          |
| -32035 | `Invalid Seq`          | The signer's seq is invalid to import                        |
| -32036 | `Invalid NetworkId`    | The network id does not match                                |
| -32040 | `Keystore Error`       | Failed to access the key store (Internal error of CodeChain) |
| -32041 | `Key Error`            | The key is invalid                                           |
| -32042 | `Already Exists`       | The account already exists                                   |
| -32043 | `Wrong Password`       | The password does not match                                  |
| -32044 | `No Such Account`      | There is no such account in the key store                    |
| -32045 | `Not Unlocked`         | The account is not unlocked                                  |
| -32099 | `Unknown Error`        | An unknown error occurred                                    |
| -32602 | `Invalid Params`       | At least one of the parameters is invalid                    |

# List of methods

 * [ping](#ping)
 * [version](#version)
 * [commitHash](#commithash)
***
 * [chain_getBestBlockNumber](#chain_getbestblocknumber)
 * [chain_getBestBlockId](#chain_getbestblockid)
 * [chain_getBlockHash](#chain_getblockhash)
 * [chain_getBlockByNumber](#chain_getblockbynumber)
 * [chain_getBlockByHash](#chain_getblockbyhash)
 * [chain_getBlockTransactionCountByHash](#chain_getblocktransactioncountbyhash)
 * [chain_getTransaction](#chain_gettransaction)
 * [chain_getTransactionSigner](#chain_gettransactionsigner)
 * [chain_containsTransaction](#chain_containstransaction)
 * [chain_getSeq](#chain_getseq)
 * [chain_getBalance](#chain_getbalance)
 * [chain_getShardRoot](#chain_getshardroot)
 * [chain_getMinTransactionFee](#chain_getmintransactionfee)
 * [chain_getCommonParams](#chain_getcommonparams)
 * [chain_getTermMetadata](#chain_gettermmetadata)
 * [chain_getNetworkId](#chain_getnetworkid)
 * [chain_getPossibleAuthors](#chain_getpossibleauthors)
***
 * [mempool_sendSignedTransaction](#mempool_sendsignedtransaction)
 * [mempool_getErrorHint](#mempool_geterrorhint)
 * [mempool_getPendingTransactions](#mempool_getpendingtransactions)
 * [mempool_getPendingTransactionsCount](#mempool_getpendingtransactionscount)
 * [mempool_getBannedAccounts](#mempool_getbannedaccounts)
 * [mempool_unbanAccounts](#mempool_unbanaccounts)
 * [mempool_banAccounts](#mempool_banaccounts)
 * [mempool_registerImmuneAccounts](#mempool_registerimmuneaccounts)
 * [mempool_getRegisteredImmuneAccounts](#mempool_getregisteredimmuneaccounts)
 * [mempool_getMachineMinimumFees](#mempool_getmachineminimumfees)
***
 * [engine_getRecommendedConfirmation](#engine_getrecommendedconfirmation)
 * [engine_getCustomActionData](#engine_getcustomactiondata)
***
 * [miner_getWork](#miner_getwork)
 * [miner_submitWork](#miner_submitwork)
***
 * [net_localKeyFor](#net_localkeyfor)
 * [net_registerRemoteKeyFor](#net_registerremotekeyfor)
 * [net_connect](#net_connect)
 * [net_isConnected](#net_isconnected)
 * [net_disconnect](#net_disconnect)
 * [net_getPeerCount](#net_getpeercount)
 * [net_getEstablishedPeers](#net_getestablishedpeers)
 * [net_getPort](#net_getport)
 * [net_addToWhitelist](#net_addtowhitelist)
 * [net_removeFromWhitelist](#net_removefromwhitelist)
 * [net_addToBlacklist](#net_addtoblacklist)
 * [net_removeFromBlacklist](#net_removefromblacklist)
 * [net_enableWhitelist](#net_enablewhitelist)
 * [net_disableWhitelist](#net_disablewhitelist)
 * [net_enableBlacklist](#net_enableblacklist)
 * [net_disableBlacklist](#net_disableblacklist)
 * [net_getWhitelist](#net_getwhitelist)
 * [net_getBlacklist](#net_getblacklist)
 * [net_recentNetworkUsage](#net_recentnetworkusage)
***
 * [account_getList](#account_getlist)
 * [account_create](#account_create)
 * [account_importRaw](#account_importraw)
 * [account_unlock](#account_unlock)
 * [account_sign](#account_sign)
 * [account_sendTransaction](#account_sendtransaction)
 * [account_changePassword](#account_changepassword)
***
 * [devel_getStateTrieKeys](#devel_getstatetriekeys)
 * [devel_getStateTrieValue](#devel_getstatetrievalue)
 * [devel_snapshot](#devel_snapshot)
 * [devel_startSealing](#devel_startsealing)
 * [devel_stopSealing](#devel_stopsealing)
 * [devel_getBlockSyncPeers](#devel_getblocksyncpeers)
 * [devel_getPeerBestBlockHashes](#devel_getpeerbestblockhashes)
 * [devel_getTargetBlockHashes](#devel_gettargetblockhashes)

# Specification

## ping
Sends ping to check whether CodeChain's RPC server is responding or not.

### Params
No parameters

### Returns
`string` - "pong"

### Request Example
```
  curl \
    -H 'Content-Type: application/json' \
    -d '{"jsonrpc": "2.0", "method": "ping", "params": [], "id": null}' \
    localhost:8080
```

### Response Example
```
{
  "jsonrpc":"2.0",
  "result":"pong",
  "id":null
}
```

[Back to **List of methods**](#list-of-methods)

## version
Gets the version of CodeChain.

### Params
No parameters

### Returns
`string` - e.g. 0.1.0

### Request Example
```
  curl \
    -H 'Content-Type: application/json' \
    -d '{"jsonrpc": "2.0", "method": "version", "params": [], "id": null}' \
    localhost:8080
```

### Response Example
```
{
  "jsonrpc":"2.0",
  "result":"0.1.0",
  "id":null
}
```

[Back to **List of methods**](#list-of-methods)

## commitHash
Gets the commit hash of the repository upon which the CodeChain executable was built.

### Params
No parameters

### Returns
`string` - the commit hash

### Request Example
```
  curl \
    -H 'Content-Type: application/json' \
    -d '{"jsonrpc": "2.0", "method": "commitHash", "params": [], "id": null}' \
    localhost:8080
```

### Response Example
```
{
  "jsonrpc":"2.0",
  "result": "361a36fe20900f15e71148a615b25978652bfe90",
  "id":null
}
```

[Back to **List of methods**](#list-of-methods)

## chain_getBestBlockNumber
Gets the number of the best block.

### Params
No parameters

### Returns
`number`

### Request Example
```
  curl \
    -H 'Content-Type: application/json' \
    -d '{"jsonrpc": "2.0", "method": "chain_getBestBlockNumber", "params": [], "id": null}' \
    localhost:8080
```

### Response Example
```
{
  "jsonrpc":"2.0",
  "result":1,
  "id":null
}
```

[Back to **List of methods**](#list-of-methods)

## chain_getBestBlockId
Gets the number and the hash of the best block.

### Params
No parameters

### Returns
{ hash: `H256`, number: `number` }

### Request Example
```
  curl \
    -H 'Content-Type: application/json' \
    -d '{"jsonrpc": "2.0", "method": "chain_getBestBlockId", "params": [], "id": null}' \
    localhost:8080
```

### Response Example
```
{
  "jsonrpc":"2.0",
  "result":{
    "hash":"0x7f7104b580f9418d444560009e5a92a4573d42d2c51cd0c6045afdc761826249",
    "number":1
  },
  "id":null
}
```

[Back to **List of methods**](#list-of-methods)

## chain_getBlockHash
Gets the hash of the block with given number.

### Params
 1. n - `number`

### Returns
`null` | `H256`

Errors: `Invalid Params`

### Request Example
```
  curl \
    -H 'Content-Type: application/json' \
    -d '{"jsonrpc": "2.0", "method": "chain_getBlockHash", "params": [1], "id": null}' \
    localhost:8080
```

### Response Example
```
{
  "jsonrpc":"2.0",
  "result":"0x56642f04d519ae3262c7ba6facf1c5b11450ebaeb7955337cfbc45420d573077",
  "id":null
}
```

[Back to **List of methods**](#list-of-methods)

## chain_getBlockByNumber
Gets the block with the given number.

### Params
 1. number: `number`

### Returns
`null` | `Block`

Errors: `Invalid Params`

### Request Example
```
  curl \
    -H 'Content-Type: application/json' \
    -d '{"jsonrpc": "2.0", "method": "chain_getBlockByNumber", "params": [5], "id": null}' \
    http://localhost:8080
```

### Response Example
```
{
  "jsonrpc":"2.0",
  "result":{
    "author":"sccqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqz6sxn0",
    "extraData":[

    ],
    "hash":"0x0e9cbbe0ecc774de3b5d05827ffb5c541bc7b7ff63de253d17272cf0fea1b7af",
    "number":5,
    "transactions":[
      {
        "action":{
          "type":"pay",
          "quantity":"0x3b9aca00",
          "receiver":"sccqra5felweesff3epv9wfu05a47sxh89yuvzw7mqd"
        },
        "blockHash":"0x0e9cbbe0ecc774de3b5d05827ffb5c541bc7b7ff63de253d17272cf0fea1b7af",
        "blockNumber":5,
        "fee":"0x5f5e100",
        "hash":"0x3ff9b02427ac04c06260928168775bca5a3da96ae6995041e197d42e71ab68b6",
        "networkId":"sc",
        "seq": 4,
        "transactionIndex":0,
        "sig":"0x4621da0344d8888c5076cc0a3cc7fd7a7e3a761ba812c95f807c050a4e5ec6b7120fa99fdf502ed088ed61eb6d5fe44f44c280e97c7702d5127640d7a8a6d7e401"
      }
    ],
    "transactionsRoot":"0xa4a8229a90d91e9a38b17f95c9ac2d01f46b10553e62c68df5bbfe1cc5b3e164",
    "parentHash":"0xbc4f7e7b1dded863c500147243d78436ca297bfae64e1ec2d17396286cf14b6e",
    "seal":[

    ],
    "stateRoot":"0x4cdbde0340558aa7116975a170f004af3b6343f5bf0354dadd1815d22ed12da7",
    "timestamp":1536924583
  },
  "id":null
}
```

[Back to **List of methods**](#list-of-methods)

## chain_getBlockByHash
Gets the block with the given hash.

### Params
 1. hash: `H256`

### Returns
`null` | `Block`

Errors: `Invalid Params`

### Request Example
```
  curl \
    -H 'Content-Type: application/json' \
    -d '{"jsonrpc": "2.0", "method": "chain_getBlockByHash", "params": ["0xfc196ede542b03b55aee9f106004e7e3d7ea6a9600692e964b4735a260356b50"], "id": null}' \
    localhost:8080
```

### Response Example
```
{
  "jsonrpc":"2.0",
  "result":{
    "author":"cccqzzpxln6w5zrhmfju3zc53w6w4y6s95mf5lfasfn",
    "extraData":[

    ],
    "hash":"0xfc196ede542b03b55aee9f106004e7e3d7ea6a9600692e964b4735a260356b50",
    "number":5,
    "transactions":[
      {
        "action":{
          "type":"pay",
          "quantity":"0xa",
          "receiver": "cccqzn9jjm3j6qg69smd7cn0eup4w7z2yu9myd6c4d7"
        },
        "blockHash":"0xfc196ede542b03b55aee9f106004e7e3d7ea6a9600692e964b4735a260356b50",
        "blockNumber":5,
        "fee":"0xa",
        "hash":"0xdb7c705d02e8961880783b4cb3dc051c41e551ade244bed5521901d8de190fc6",
        "networkId":"cc",
        "seq": 4,
        "transactionIndex":0,
        "sig":"0x291d932e55162407eb01915923d68cf78df4815a25fc6033488b644bda44b02251123feac3a3c56a399a2b32331599fd50b7a39ec2c1a2325e37f383c6aeedc301"
      }
    ],
    "transactionsRoot":"0x0270d11d2bd21a0ec8e78d1c4e918103d7c4b02fdf734051231cb9eea90ae88e",
    "parentHash":"0xddf9fece0c6dee067a409e73a299bca21cec2d8300dff45739a5b76c680f378d",
    "seal":[

    ],
    "stateRoot":"0x898961f82629a47ade064f15d3902a455379cb082e62d3995f21050df3f553dc",
    "timestamp":1531583888
  }
  "id":null
}
```

[Back to **List of methods**](#list-of-methods)

## chain_getBlockTransactionCountByHash
Gets the number of transactions within a block that corresponds with the given hash.

### Params
 1. hash: `H256`

### Returns
`null` | `number`

Errors: `Invalid Params`

### Request Example
```
  curl \
    -H 'Content-Type: application/json' \
    -d '{"jsonrpc": "2.0", "method": "chain_getBlockTransactionCountByHash", "params": ["0xfc196ede542b03b55aee9f106004e7e3d7ea6a9600692e964b4735a260356b50"], "id": null}' \
    localhost:8080
```

### Response Example
```
{"jsonrpc":"2.0","result":1,"id":null}
```

[Back to **List of methods**](#list-of-methods)

## chain_getTransaction
Gets a transaction with the given hash.

### Params
 1. transaction hash - `H256`

### Returns
`null` or `Transaction`

Errors: `Invalid Params`

### Request Example
```
  curl \
    -H 'Content-Type: application/json' \
    -d '{"jsonrpc": "2.0", "method": "chain_getTransaction", "params": ["0xdb7c705d02e8961880783b4cb3dc051c41e551ade244bed5521901d8de190fc6"], "id": null}' \
    localhost:8080
```

### Response Example
```
{
    "jsonrpc": "2.0",
    "result": {
        "action": {
          "type":"pay",
          "quantity":"0xa",
          "receiver": "cccqzn9jjm3j6qg69smd7cn0eup4w7z2yu9myd6c4d7"
        },
        "blockHash": "0xfc196ede542b03b55aee9f106004e7e3d7ea6a9600692e964b4735a260356b50",
        "blockNumber": 5,
        "fee": "0xa",
        "hash": "0xdb7c705d02e8961880783b4cb3dc051c41e551ade244bed5521901d8de190fc6",
        "networkId": "cc",
        "seq": 4,
        "transactionIndex": 0,
        "sig":"0x291d932e55162407eb01915923d68cf78df4815a25fc6033488b644bda44b02251123feac3a3c56a399a2b32331599fd50b7a39ec2c1a2325e37f383c6aeedc301"
    }
    "id": null,
}
```

[Back to **List of methods**](#list-of-methods)

## chain_getTransactionSigner
Returns the signer of the given transaction hash.

It returns `null` if the transaction hash doesn't exist in the chain.

### Params
1. tx hash: `H256`

### Returns
`null` | `PlatformAddress`

### Request Example
```
  curl \
    -H 'Content-Type: application/json' \
    -d '{"jsonrpc": "2.0", "method": "chain_getTransactionSigner", "params": ["0xdb7c705d02e8961880783b4cb3dc051c41e551ade244bed5521901d8de190fc6"], "id": "who-is-authors"}' \
    localhost:8080
```

### Response Example
```
{
  "jsonrpc":"2.0",
  "result": "tccq94guhkrfndnehnca06dlkxcfuq0gdlamvw9ga4f",
  "id": "who-is-authors"
}
```

[Back to **List of methods**](#list-of-methods)

## chain_containsTransaction
Returns true if the transaction with the given hash is in the chain.

### Params
 1. transaction hash - `H256`

### Returns
`boolean`

Errors: `Invalid Params`

### Request Example
```
  curl \
    -H 'Content-Type: application/json' \
    -d '{"jsonrpc": "2.0", "method": "chain_containsTransaction", "params": ["0xad708d48755ac36685280a45ec213941e21c41644c781bf2f487fd6c7e4b2ebb"], "id": null}' \
    localhost:8080
```

### Response Example
```
{
  "jsonrpc":"2.0",
  "result": true,
  "id":null
}
```
[Back to **List of methods**](#list-of-methods)

## chain_getSeq
Gets a seq of an account of the given address, at state of the given blockNumber.

### Params
 1. address: `PlatformAddress`
 2. block number: `number` | `null`

### Returns
`null` | `number` - It returns null when the given block number is invalid.

Errors: `KVDB Error`, `Invalid Params`, `Invalid NetworkId`

### Request Example
```
  curl \
    -H 'Content-Type: application/json' \
    -d '{"jsonrpc": "2.0", "method": "chain_getSeq", "params": ["cccqzn9jjm3j6qg69smd7cn0eup4w7z2yu9myd6c4d7", null], "id": null}' \
    localhost:8080
```

### Response Example
```
{
  "jsonrpc":"2.0",
  "result": 84,
  "id":null
}
```

[Back to **List of methods**](#list-of-methods)

## chain_getBalance
Gets a balance of an account of the given address, at the state of the given blockNumber.

### Params
 1. address: `PlatformAddress`
 2. block number: `number` | `null`

### Returns
`null` | `U64` - It returns null when the given block number is invalid.

Errors: `KVDB Error`, `Invalid Params`, `Invalid NetworkId`

### Request Example
```
  curl \
    -H 'Content-Type: application/json' \
    -d '{"jsonrpc": "2.0", "method": "chain_getBalance", "params": ["cccqzn9jjm3j6qg69smd7cn0eup4w7z2yu9myd6c4d7", null], "id": null}' \
    localhost:8080
```

### Response Example
```
{
  "jsonrpc":"2.0",
  "result":"0xe8d4a50dd0",
  "id":null
}
```

[Back to **List of methods**](#list-of-methods)

# chain_getMinTransactionFee
Gets the min cost of the transaction.
It returns null if the first parameter is an invalid transaction type or the second parameter is larger than the current best block.

### Params
 1. transaction type - `string`
 2. block number - `number` | `null`

### Returns
`number` | `null`

Errors: `Invalid Params`

### Request Example
```
  curl \
    -H 'Content-Type: application/json' \
    -d '{"jsonrpc": "2.0", "method": "chain_getMinTransactionFee", "params": ["pay", 3], "id": 7}' \
    localhost:8080
```

### Response Example
```
{
  "jsonrpc":"2.0",
  "result":100,
  "id":7
}
```

[Back to **List of methods**](#list-of-methods)

# chain_getCommonParams
Gets the common parameters.
It returns null if the block number parameter is larger than the current best block.

### Params
 1. block number - `number` | `null`

### Returns
`CommonParams` | `null`

Errors: `Invalid Params`

### Request Example
```
  curl \
    -H 'Content-Type: application/json' \
    -d '{"jsonrpc": "2.0", "method": "chain_getCommonParams", "params": [3], "id": 7}' \
    localhost:8080
```

### Response Example
```
{
  "jsonrpc":"2.0",
  "result":{
    "maxExtraDataSize":"0x20",
    "maxTransferMetadataSize":"0x0100",
    "maxTextContentSize":"0x0200",
    "networkID":"tc",
    "minPayCost":10,
    "minCreateShardCost":10,
    "minSetShardOwnersCost":10,
    "minSetShardUsersCost":10,
    "minCustomCost":10,
    "maxBodySize":4194304,
    "snapshotPeriod":16384
  },
  "id":7
}
```

[Back to **List of methods**](#list-of-methods)

# chain_getTermMetadata
Gets the term metadata.
It returns null if the block number parameter is larger than the current best block.

### Params
 1. block number - `number` | `null`

### Returns
`[number, number]` | `null`

- The first item is the last block number that the term is closed. 
- The second item is the current term id.

Errors: `Invalid Params`

### Request Example
```
  curl \
    -H 'Content-Type: application/json' \
    -d '{"jsonrpc": "2.0", "method": "chain_getTermMetadata", "params": [53], "id": 7}' \
    localhost:8080
```

### Response Example
```
{
  "jsonrpc":"2.0",
  "result":[43,4],
  "id":7
}
```

[Back to **List of methods**](#list-of-methods)

# chain_getMetadataSeq
Gets the sequence of metadata.
It returns null if the block number parameter is larger than the current best block.

### Params
 1. block number - `number` | `null`

### Returns
`number` | `null`

### Request Example
```
  curl \
    -H 'Content-Type: application/json' \
    -d '{"jsonrpc": "2.0", "method": "chain_getMetadataSeq", "params": [53], "id": 7}' \
    localhost:8080
```

### Response Example
```
{
  "jsonrpc":"2.0",
  "result":43,
  "id":7
}
```

[Back to **List of methods**](#list-of-methods)

## chain_getNetworkId
Return the nework id that is used in this chain.

### Params
No parameters

### Returns
`number`

### Request Example
```
  curl \
    -H 'Content-Type: application/json' \
    -d '{"jsonrpc": "2.0", "method": "chain_getNetworkId", "params": [], "id": 6}' \
    localhost:8080
```

### Response Example
```
{
  "jsonrpc":"2.0",
  "result": 17,
  "id":6
}
```

[Back to **List of methods**](#list-of-methods)

## chain_getPossibleAuthors
Returns the list of accounts that can generate the blocks at the given block number.

It returns `null` if anyone can generate the block.
Only PoW and Solo chains can return `null`. Other chains never return `null`.

The possible authors of the genesis block are always in the list that contains only the author of the genesis block, regardless of the chain types.

### Params
1. block number: `number` | `null`

### Returns
`null` | `PlatformAddress[]`

### Request Example
```
  curl \
    -H 'Content-Type: application/json' \
    -d '{"jsonrpc": "2.0", "method": "chain_getPossibleAuthors", "params": [null], "id": "who-can-be-authors"}' \
    localhost:8080
```

### Response Example
```
{
  "jsonrpc":"2.0",
  "result": ["tccq94guhkrfndnehnca06dlkxcfuq0gdlamvw9ga4f", "tccq8p9hr53lnxnhzcn0d065lux7etz22azaca786tt", "tccq8fj6lxn9tchqdqqe93yaga6fzxh5rndzu8k2gdw", "tccq9y6e0k6af9058qq4h4ffpt9xmat2vkeyue23j8y"],
  "id": "who-can-be-authors"
}
```

[Back to **List of methods**](#list-of-methods)

## mempool_sendSignedTransaction
Sends a signed transaction, returning its hash.

### Params
 1. bytes: `hexadecimal string` - RLP encoded hex string of SignedTransaction

### Returns
`H256` - transaction hash

Errors: `Invalid RLP`, `Verification Failed`, `Already Imported`, `Not Enough Balance`, `Too Low Fee`, `Too Cheap to Replace`, `Invalid Seq`, `Invalid Params`, `Invalid NetworkId`

### Request Example
```
  curl \
    -H 'Content-Type: application/json' \
    -d '{"jsonrpc": "2.0", "method": "mempool_sendSignedTransaction", "params": ["0xf85e040a11d70294a6594b7196808d161b6fb137e781abbc251385d90ab841291d932e55162407eb01915923d68cf78df4815a25fc6033488b644bda44b02251123feac3a3c56a399a2b32331599fd50b7a39ec2c1a2325e37f383c6aeedc301"], "id": null}' \
    localhost:8080
```

### Response Example
```
{
  "jsonrpc":"2.0",
  "result":"0xdb7c705d02e8961880783b4cb3dc051c41e551ade244bed5521901d8de190fc6",
  "id":null
}
```

[Back to **List of methods**](#list-of-methods)

## mempool_getErrorHint
Gets a hint to find out why the transaction failed.

### Params
 1. transaction hash - `H256`

### Returns
`null` | `string` - `null` if there is no hint, `string` if the transaction failed.

Errors: `Invalid Params`

### Request Example
```
  curl \
    -H 'Content-Type: application/json' \
    -d '{"jsonrpc": "2.0", "method": "mempool_getErrorHint", "params": ["0x31de93320082d6d5f0026fca4fe513cb76197dd2ad99cb0802040801148ec717"], "id": null}' \
    localhost:8080
```

### Response Example
```
{
  "jsonrpc":"2.0",
  "result":"Text verification has failed: Invalid Signature",
  "id":null
}
```

[Back to **List of methods**](#list-of-methods)

## mempool_deleteAllPendingTransactions
Deletes all pending transactions in both current and future queues.

### Params
No parameters.

### Returns
`null`

### Request Example
```
  curl \
    -H 'Content-Type: application/json' \
    -d '{"jsonrpc": "2.0", "method": "mempool_deleteAllPendingTransactions", "params": [], "id": null}' \
    localhost:8080
```

### Response Example
```
{"jsonrpc":"2.0","result":null,"id":null}
```

[Back to **List of methods**](#list-of-methods)

## mempool_getPendingTransactions
Gets transactions that have insertion_timestamps within the given range from the current transaction queue.

### Params
 1. from: `number | null` - The lower bound of collected pending transactions. If null, there is no lower bound.
 2. to: `number | null` - The upper bound of collected pending transactions. If null, there is no upper bound.
 3. future_included: `boolean` -  The parameter to include future transactions. If true, future transactions are included.
### Returns
`{ transactions: Transaction[], lastTimestamp: number }`

### Request Example
```
  curl \
    -H 'Content-Type: application/json' \
    -d '{"jsonrpc": "2.0", "method": "mempool_getPendingTransactions", "params": [null, null,true], "id": null}' \
    localhost:8080
```

### Response Example
```
{
  "jsonrpc":"2.0",
  "result":{
    "lastTimestamp": null,
    "transactions": [{
      "blockHash":null,
      "blockNumber":null,
      "fee":"0xa",
      "hash":"0x8ae3363ccdcc02d8d662d384deee34fb89d1202124e8065f0d6c84ab31e68d8a",
      "networkId":"cc",
      "seq":"0x0",
      "transactionIndex":null,
      "r":"0x22605d6b9fb713d3a415e02eeed8b4a630e0d867c91bf7d9b7721f94159c0fe1",
      "s":"0x772f19f1c27f1db8b28289caa9e99ad756878fd56b2415c25cd47cc737f7e0c2",
      "transactions":[
        {
          "pay":{
            "seq": 1,
            "receiver": "cccqzn9jjm3j6qg69smd7cn0eup4w7z2yu9myd6c4d7",
            "value":"0x0"
          }
        }
      ],
      "v":0
    }]
  },
  "id":null
}
```

[Back to **List of methods**](#list-of-methods)

## mempool_getPendingTransactionsCount
Returns a count of the transactions that have insertion_timestamps within the given range from the transaction queues.

### Params
 1. from: `number | null` - The lower bound of collected pending transactions. If null, there is no lower bound.
 2. to: `number | null` - The upper bound of collected pending transactions. If null, there is no upper bound.
 3. future_included: `boolean` -  The parameter to count future transactions. If true, future transactions are also counted.
 
### Returns
`number`

### Request Example
```
  curl \
    -H 'Content-Type: application/json' \
    -d '{"jsonrpc": "2.0", "method": "mempool_getPendingTransactionsCount", "params": [null, null,true], "id": null}' \
    localhost:8080
```

### Response Example
```
{
    "jsonrpc":"2.0",
    "result":4,
    "id":null
}
```

[Back to **List of methods**](#list-of-methods)

## mempool_banAccounts
Register accounts to the mempool's banned account list. The mempool would not import the transactions from the users on the list.

### Params
 1. prisoner_list: `PlatformAccount[]`

### Returns
`null`

Errors: `Invalid params`

### Request Example
```
curl \
    -H 'Content-Type: application/json' \
    -d '{"jsonrpc": "2.0", "method": "mempool_getBannedAccounts", "params": [], "id": null}' \
    localhost:8080
```

### Response Example
```
{
  "jsonrpc": "2.0",
  "result": null,
  "id": null
}
```

[Back to **List of methods**](#list-of-methods)

## mempool_unbanAccounts
Release accounts from the mempool's banned account list.

### Params
 1. trusty_list: `PlatformAccount[]` 

### Returns
`null`

Errors: `Invalid params`

### Request Example
```
curl \
    -H 'Content-Type: application/json' \
    -d '{"jsonrpc": "2.0", "method": "mempool_unbanAccounts", "params": [["tccq8t6d5nxsd7pckgnswusmq6sdzu76kxa808t6m3gtygltrjqeeqncfggwh3"]], "id": null}' \
    localhost:8080
```

### Response Example
```
{
  "jsonrpc": "2.0",
  "result": null,
  "id": null
}
```

[Back to **List of methods**](#list-of-methods)

## mempool_getBannedAccounts
Returns accounts banned for propagating transactions which cause syntax errors or runtime errors.

### Params
No parameters

### Returns
`PlatformAddress[]`

Error: `Invalid params`

### Request Example
```
curl \
    -H 'Content-Type: application/json' \
    -d '{"jsonrpc": "2.0", "method": "mempool_getBannedAccounts", "params": [], "id": null}' \
    localhost:8080
```

### Response Example
```
{
  "jsonrpc": "2.0",
  "result": [
    "tccq8t6d5nxsd7pckgnswusmq6sdzu76kxa808t6m3gtygltrjqeeqncfggwh3"
  ],
  "id": null
}
```

[Back to **List of methods**](#list-of-methods)

## mempool_registerImmuneAccounts
Register accounts immune from getting banned. The trasactions from these accounts would never be rejected for the reason they are malicious.

### Params
 1. immune_user_list: `PlatformAccount[]`

### Returns
`null`

Error: `Invalid params`

### Request Example
```
curl \
    -H 'Content-Type: application/json' \
    -d '{"jsonrpc": "2.0", "method": "mempool_registerImmuneAccounts", "params": [["tccq8t6d5nxsd7pckgnswusmq6sdzu76kxa808t6m3gtygltrjqeeqncfggwh3"]], "id": null}' \
    localhost:8080
```

### Response Example
```
{
  "jsonrpc": "2.0",
  "result": null,
  "id": null
}
```

[Back to **List of methods**](#list-of-methods)

## mempool_getRegisteredImmuneAccounts
Gets immune accounts registered by `mempool_registerImmuneAccounts`.

### Params
No parameters

### Returns
`PlatformAccount[]`

Error: `Invalid params`

### Request Example
```
curl \
    -H 'Content-Type: application/json' \
    -d '{"jsonrpc": "2.0", "method": "mempool_getImmuneAccounts", "params": [], "id": null}' \
    localhost:8080
```

### Response Example
```
{
  "jsonrpc": "2.0",
  "result": [
    "tccq8t6d5nxsd7pckgnswusmq6sdzu76kxa808t6m3gtygltrjqeeqncfggwh3"
  ],
  "id": null
}
```

[Back to **List of methods**](#list-of-methods)

## mempool_getMachineMinimumFees
Get minimum fees configured by the machine.

### Params
No parameters

### Returns
{
  "minCreateShardTransactionCost":`number`,
  "minCustomTransactionCost":`number`,
  "minPayTransactionCost":`number`,
  "minSetShardOwnersTransactionCost":`number`,
  "minSetShardUsersTransactionCost":`number`,
}

### Request Example
```
curl \
    -H 'Content-Type: application/json' \
    -d '{"jsonrpc": "2.0", "method": "mempool_getMachineMinimumFees", "params": [], "id": null}' \
    localhost:8080
```

### Response Example
```
{
  "jsonrpc":"2.0",
  "result":{
    "minCreateShardTransactionCost":0,
    "minCustomTransactionCost":0,
    "minPayTransactionCost":0,
    "minSetShardOwnersTransactionCost":0,
    "minSetShardUsersTransactionCost":0,
    },
  "id":null
}

```

[Back to **List of methods**](#list-of-methods)

## engine_getCustomActionData
Gets custom action data for given custom action handler id and rlp encoded key.

### Params
 1. handlerId: `number`
 2. bytes: `string`
 3. blockNumber: `number` | `null`

### Returns
`string`

### Request Example
```
  curl \
    -H 'Content-Type: application/json' \
    -d '{"jsonrpc": "2.0", "method": "engine_getCustomActionData", "params": [1,"0xcd8c6d6574616461746120686974",null], "id": 411}' \
    localhost:8080
```

### Response Example
```
{
  "jsonrpc":"2.0",
  "result":"0c",
  "id":411
}
```

[Back to **List of methods**](#list-of-methods)

## miner_getWork
Returns the hash of the current block and score.

### Params
No parameters

### Returns
`Work`

Errors: `No Author`, `No Work Required`, `No Work Found`

### Request Example
```
  curl \
    -H 'Content-Type: application/json' \
    -d '{"jsonrpc": "2.0", "method": "miner_getWork", "params": [], "id": null}' \
    localhost:8080
```

### Response Example
```
{
  "jsonrpc":"2.0",
  "result":{
    "powHash":"0x56642f04d519ae3262c7ba6facf1c5b11450ebaeb7955337cfbc45420d573077",
    "target":100
  },
  "id":null
}
```

[Back to **List of methods**](#list-of-methods)

## miner_submitWork
Used for submitting a proof-of-work solution.

### Params
 1. powHash: `string`
 2. seal: `string[]`

### Returns
`boolean`

Errors: `No Work Required`, `Invalid Params`

### Request Example
```
  curl \
    -H 'Content-Type: application/json' \
    -d '{"jsonrpc": "2.0", "method": "miner_submitWork", "params": ["0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef", ["0x56642f04d519ae3262c7ba6facf1c5b11450ebaeb7955337cfbc45420d573077"]], "id": null}' \
    localhost:8080
```

### Response Example
```
{
  "jsonrpc":"2.0",
  "result":true,
  "id":6
}
```

[Back to **List of methods**](#list-of-methods)

## net_localKeyFor
Get a key to communicate with the given address

### Params
 1. address: `string`
 2. port: `number`

### Returns
The 256-bit public key.

Errors: `Invalid Params`

### Request Example
```
  curl \
    -H 'Content-Type: application/json' \
    -d '{"jsonrpc": "2.0", "method": "net_localKeyFor", "params": ["192.168.0.3", 3485], "id": 5}' \
    localhost:8080
```

### Response Example
```
{
  "jsonrpc":"2.0",
  "result": "0x0b3f1e817ced530a586f029e66831f4d47b8fffa5eef0ba118f0e9dc1dd9b698",
  "id":5
}
```

[Back to **List of methods**](#list-of-methods)

## net_registerRemoteKeyFor
Register the remote public key to communicate with the given address

### Params
 1. address: `string`
 2. port: `number`
 3. remote_public_key: `string`

### Returns
The 256-bit local public key.

Errors: `Invalid Params`

### Request Example
```
  curl \
    -H 'Content-Type: application/json' \
    -d '{"jsonrpc": "2.0", "method": "net_registerRemoteKeyFor", "params": ["192.168.0.3", 3485, "0x0b3f1e817ced530a586f029e66831f4d47b8fffa5eef0ba118f0e9dc1dd9b698"], "id": 5}' \
    localhost:8080
```

### Response Example
```
{
  "jsonrpc":"2.0",
  "result": "0x46f85ec82c7859c29b0e51a412a3842b1f360f8983a66038bc37b37872f144b1",
  "id":5
}
```

[Back to **List of methods**](#list-of-methods)

## net_connect
Connect to the given address.

### Params
 1. address: `string`
 2. port: `number`

### Returns
`null`

Errors: `Invalid Params`

### Request Example
```
  curl \
    -H 'Content-Type: application/json' \
    -d '{"jsonrpc": "2.0", "method": "net_connect", "params": ["192.168.0.3", 3485], "id": 5}' \
    localhost:8080
```

### Response Example
```
{
  "jsonrpc":"2.0",
  "result":null,
  "id":5
}
```

[Back to **List of methods**](#list-of-methods)

## net_isConnected
Check whether the connection is established.

### Params
 1. address: `string`
 2. port: `number`

### Returns
`bool`

Errors: `Invalid Params`

### Request Example
```
  curl \
    -H 'Content-Type: application/json' \
    -d '{"jsonrpc": "2.0", "method": "net_isConnected", "params": ["192.168.0.3", 3485], "id": 6}' \
    localhost:8080
```

### Response Example
```
{
  "jsonrpc":"2.0",
  "result":true,
  "id":6
}
```

[Back to **List of methods**](#list-of-methods)

## net_disconnect
Disconnect the connection from the given address.

### Params
 1. address: `string`
 2. port: `number`

### Returns
`null`

Errors: `Not Conntected`, `Invalid Params`

### Request Example
```
  curl \
    -H 'Content-Type: application/json' \
    -d '{"jsonrpc": "2.0", "method": "net_disconnect", "params": ["192.168.0.3", 3485], "id": 6}' \
    localhost:8080
```

### Response Example
```
{
  "jsonrpc":"2.0",
  "result":null,
  "id":6
}
```

[Back to **List of methods**](#list-of-methods)

## net_getPeerCount
Return the count of peers which the client is connected to.

### Params
No parameters

### Returns
`number`

### Request Example
```
  curl \
    -H 'Content-Type: application/json' \
    -d '{"jsonrpc": "2.0", "method": "net_getPeerCount", "params": [], "id": 6}' \
    localhost:8080
```

### Response Example
```
{
  "jsonrpc":"2.0",
  "result": 34,
  "id":6
}
```

[Back to **List of methods**](#list-of-methods)

## net_getEstablishedPeers
Return the socket addresses of established peers.

### Params
No parameters

### Returns
`string[]`

### Request Example
```
  curl \
    -H 'Content-Type: application/json' \
    -d '{"jsonrpc": "2.0", "method": "net_getEstablishedPeers", "params": [], "id": 3}' \
    localhost:8080
```

### Response Example
```
{
  "jsonrpc":"2.0",
  "result": ["1.2.3.4:3485", "1.2.3.5:3485"],
  "id":3
}
```

[Back to **List of methods**](#list-of-methods)

## net_getPort
Return the port number on which the client is listening for peers.

### Params
No parameters

### Returns
`number`

### Request Example
```
  curl \
    -H 'Content-Type: application/json' \
    -d '{"jsonrpc": "2.0", "method": "net_getPort", "params": [], "id": 6}' \
    localhost:8080
```

### Response Example
```
{
  "jsonrpc":"2.0",
  "result": 3485,
  "id":6
}
```

[Back to **List of methods**](#list-of-methods)

## net_addToWhitelist
Adds the CIDR block address to the whitelist.

### Params
 1. address: `string`
 2. tag: `null` | `string`

### Returns
`null`

### Request Example
```
  curl \
    -H 'Content-Type: application/json' \
    -d '{"jsonrpc": "2.0", "method": "net_addToWhitelist", "params": ["1.2.3.0/24", "tag"], "id": 6}' \
    localhost:8080
```

### Response Example
```
{
  "jsonrpc":"2.0",
  "result": null,
  "id":6
}
```

[Back to **List of methods**](#list-of-methods)

## net_removeFromWhitelist
Removes the CIDR block address from the whitelist.

### Params
 1. address: `string`

### Returns
`null`

### Request Example
```
  curl \
    -H 'Content-Type: application/json' \
    -d '{"jsonrpc": "2.0", "method": "net_removeFromWhitelist", "params": ["1.2.3.0/24"], "id": 6}' \
    localhost:8080
```

### Response Example
```
{
  "jsonrpc":"2.0",
  "result": null,
  "id":6
}
```

[Back to **List of methods**](#list-of-methods)

## net_addToBlacklist
Adds the CIDR block address to the blacklist.

### Params
 1. address: `string`
 2. tag: `null` | `string`

### Returns
`null`

### Request Example
```
  curl \
    -H 'Content-Type: application/json' \
    -d '{"jsonrpc": "2.0", "method": "net_addToBlacklist", "params": ["1.2.3.4", "tag"], "id": 6}' \
    localhost:8080
```

### Response Example
```
{
  "jsonrpc":"2.0",
  "result": null,
  "id":6
}
```

[Back to **List of methods**](#list-of-methods)

## net_removeFromBlacklist
Removes the CIDR block address from the blacklist.

### Params
 1. address: `string`

### Returns
`null`

### Request Example
```
  curl \
    -H 'Content-Type: application/json' \
    -d '{"jsonrpc": "2.0", "method": "net_removeFromBlacklist", "params": ["1.2.3.4"], "id": 6}' \
    localhost:8080
```

### Response Example
```
{
  "jsonrpc":"2.0",
  "result": null,
  "id":6
}
```

[Back to **List of methods**](#list-of-methods)

## net_enableWhitelist
Enables whitelist.

### Params
No parameters

### Returns
`null`

### Request Example
```
  curl \
    -H 'Content-Type: application/json' \
    -d '{"jsonrpc": "2.0", "method": "net_enableWhitelist", "params": [], "id": 6}' \
    localhost:8080
```

### Response Example
```
{
  "jsonrpc":"2.0",
  "result": null,
  "id":6
}
```

[Back to **List of methods**](#list-of-methods)

## net_disableWhitelist
Disables whitelist.

### Params
No parameters

### Returns
`null`

### Request Example
```
  curl \
    -H 'Content-Type: application/json' \
    -d '{"jsonrpc": "2.0", "method": "net_disableWhitelist", "params": [], "id": 6}' \
    localhost:8080
```

### Response Example
```
{
  "jsonrpc":"2.0",
  "result": null,
  "id":6
}
```

[Back to **List of methods**](#list-of-methods)

## net_enableBlacklist
Enables blacklist.

### Params
No parameters

### Returns
`null`

### Request Example
```
  curl \
    -H 'Content-Type: application/json' \
    -d '{"jsonrpc": "2.0", "method": "net_enableBlacklist", "params": [], "id": 6}' \
    localhost:8080
```

### Response Example
```
{
  "jsonrpc":"2.0",
  "result": null,
  "id":6
}
```

[Back to **List of methods**](#list-of-methods)

## net_disableBlacklist
Disables blacklist.

### Params
No parameters

### Returns
`null`

### Request Example
```
  curl \
    -H 'Content-Type: application/json' \
    -d '{"jsonrpc": "2.0", "method": "net_disableBlacklist", "params": [], "id": 6}' \
    localhost:8080
```

### Response Example
```
{
  "jsonrpc":"2.0",
  "result": null,
  "id":6
}
```

[Back to **List of methods**](#list-of-methods)

## net_getWhitelist
Gets the CIDR block addresses in the whitelist.

### Params
No parameters

### Returns
{ list: `string[][]`, enabled: `bool` }

### Request Example
```
  curl \
    -H 'Content-Type: application/json' \
    -d '{"jsonrpc": "2.0", "method": "net_getWhitelist", "params": [], "id": 6}' \
    localhost:8080
```

### Response Example
```
{
  "jsonrpc":"2.0",
  "result": { "list": [["1.2.3.0/24", "tag1"], ["1.2.3.5/32", "tag2"], ["1.2.3.6/32", "tag3"]], "enabled": true },
  "id":6
}
```

[Back to **List of methods**](#list-of-methods)

## net_getBlacklist
Gets the CIDR block addresses in the blacklist.

### Params
No parameters

### Returns
{ list: `string[][]`, enabled: `bool` }

### Request Example
```
  curl \
    -H 'Content-Type: application/json' \
    -d '{"jsonrpc": "2.0", "method": "net_getBlacklist", "params": [], "id": 6}' \
    localhost:8080
```

### Response Example
```
{
  "jsonrpc":"2.0",
  "result": { "list": [["1.2.3.0/22", "tag1"], ["1.2.3.5/32", "tag2"], ["1.2.3.6/32", "tag3"]], "enabled": false },
  "id":6
}
```

[Back to **List of methods**](#list-of-methods)

## net_recentNetworkUsage
Gets the recent network usage.
The return type is an object.
The key of the object is a string, but what the keys are depend on the implementation.
The value of the object is the size of bytes that the node sent in the recent period.
The exact timespan of the recent is also an implementation dependent.

### Params
No parameters

### Returns
{ `string`: `number` }

### Request Example
```
  curl \
    -H 'Content-Type: application/json' \
    -d '{"jsonrpc": "2.0", "method": "net_recentNetworkUsage", "params": [], "id": 6}' \
    localhost:8080
```

### Response Example
```
{
  "jsonrpc":"2.0",
  "result":{"::handshake":750,"::negotiation":2210,"block-propagation":13445,"discovery":1667,"tendermint":164},
  "id":6
}
```

[Back to **List of methods**](#list-of-methods)

## account_getList
Gets a list of accounts.

### Params
No parameters

### Returns
`PlatformAddress[]`

Errors: `Keystore Error`

### Request Example
```
curl \
    -H 'Content-Type: application/json' \
    -d '{"jsonrpc": "2.0", "method": "account_getList", "params": [], "id": 6}' \
    localhost:8080
```

### Response Example
```
{
  "jsonrpc":"2.0",
  "result":["cccqqccmmu8mrwq7lxzz72d4ukaxemzmv3tvues8uwy"],
  "id":6
}
```

[Back to **List of methods**](#list-of-methods)

## account_create
Creates a new account.

### Params
 1. password: `string` | `null`

### Returns
`PlatformAddress`

Errors: `Keystore Error`, `Invalid Params`

### Request Example
```
curl \
    -H 'Content-Type: application/json' \
    -d '{"jsonrpc": "2.0", "method": "account_create", "params": [], "id": 6}' \
    localhost:8080
```

### Response Example
```
{
  "jsonrpc":"2.0",
  "result":"cccqqccmmu8mrwq7lxzz72d4ukaxemzmv3tvues8uwy",
  "id":6
}
```

[Back to **List of methods**](#list-of-methods)

## account_importRaw
Imports a secret key and add the corresponding account.

### Params
 1. secret: `H512`
 2. password: `string` | `null`

### Returns
`PlatformAddress`

Errors: `Keystore Error`, `Key Error`, `Already Exists`, `Invalid Params`

### Request Example
```
curl \
    -H 'Content-Type: application/json' \
    -d '{"jsonrpc": "2.0", "method": "account_importRaw", "params": ["5c681224c650e9c96af5239991d38cc3ba2abba6b43926c35fc5c0439c7b9efa0b3f1e817ced530a586f029e66831f4d47b8fffa5eef0ba118f0e9dc1dd9b698"], "id": 6}' \
    localhost:8080
```

### Response Example
```
{
  "jsonrpc":"2.0",
  "result":"cccq99c90k2lmu3l5e6z5hajhvwsh57v60845sfdk74",
  "id":6
}
```

[Back to **List of methods**](#list-of-methods)

## account_unlock
Unlocks the specified account for use.

It will default to 300 seconds. Passing 0 unlocks the account indefinitely.

### Params
 1. account: `PlatformAddress`
 2. password: `string`
 3. duration: `number`  | `null`

### Returns
`null`

Errors: `Keystore Error`, `Wrong Password`, `No Such Account`, `Invalid Params`, `Invalid NetworkId`

### Request Example
```
curl \
    -H 'Content-Type: application/json' \
    -d '{"jsonrpc": "2.0", "method": "account_unlock", "params": ["cccqqccmmu8mrwq7lxzz72d4ukaxemzmv3tvues8uwy", "1234", 0], "id": 6}' \
    localhost:8080
```

### Response Example
```
{
  "jsonrpc":"2.0",
  "result": null,
  "id":6
}
```

[Back to **List of methods**](#list-of-methods)

## account_sign
Calculates the account's signature for a given message.

### Params
 1. message: `H256`
 2. account: `PlatformAddress`
 3. password: `string` | `null`

### Returns
`Signature`

Errors: `Keystore Error`, `Wrong Password`, `No Such Account`, `Not Unlocked`, `Invalid Params`, `Invalid NetworkId`

### Request Example
```
curl \
    -H 'Content-Type: application/json' \
    -d '{"jsonrpc": "2.0", "method": "account_sign", "params": ["0000000000000000000000000000000000000000000000000000000000000000", "cccqqfz3sx7fr7uxqa5kl63qjdw9zrntru5kcdsjywj"], "id": 6}' \
    localhost:8080
```

### Response Example
```
{
  "jsonrpc":"2.0",
  "result":"0xff7e8928f7758a64b9ea6c53f9945cdd223740675ac6ac6da625306d3966f8197523e00d56844ddb70631d44f045f4d83cc183a267c3182ab04c2f459c8289f501",
  "id":6
}
```

[Back to **List of methods**](#list-of-methods)

## account_sendTransaction
Sends a transaction by signing it with the account’s private key.
It automatically fills the seq if the seq is not given.

### Params
 1. transction: `UnsignedTransaction`
 2. account: `PlatformAddress`
 3. passphrase: `string` | `null`

### Returns
{ hash: `H256`, seq: `number` } - the hash and seq of the transaction

Errors: `Keystore Error`, `Wrong Password`, `No Such Account`, `Not Unlocked`, `Invalid Params`, `Invalid NetworkId`

### Request Example
```
curl \
    -H 'Content-Type: application/json' \
    -d '{"jsonrpc": "2.0", "method": "account_sendTransaction", "params": [{"action":{ "type":"pay", "quantity":"0x3b9aca00", "receiver":"sccqra5felweesff3epv9wfu05a47sxh89yuvzw7mqd" }, "fee":"0x5f5e100", "networkId":"sc", "seq": null}, "cccqqfz3sx7fr7uxqa5kl63qjdw9zrntru5kcdsjywj", null], "id": 6}' \
    localhost:8080
```


### Response Example
```
{
  "jsonrpc":"2.0",
  "result": {"seq": 999999999440, "hash":"0x8ae3363ccdcc02d8d662d384deee34fb89d1202124e8065f0d6c84ab31e68d8a"},
  "id":6
}
```

[Back to **List of methods**](#list-of-methods)

## account_changePassword
Changes the account's password.

### Params
 1. account: `PlatformAddress`
 2. old_password: `String`
 3. new_password: `String`

### Returns
`null`

Errors: `Keystore Error`, `Wrong Password`, `No Such Account`, `Invalid Params`, `Invalid NetworkId`

### Request Example
```
curl \
    -H 'Content-Type: application/json' \
    -d '{"jsonrpc": "2.0", "method": "account_changePassword", "params": ["cccqqccmmu8mrwq7lxzz72d4ukaxemzmv3tvues8uwy", "1234", "5678"], "id": 6}' \
    localhost:8080
```

### Response Example
```
{
  "jsonrpc":"2.0",
  "result":null,
  "id":6
}
```

[Back to **List of methods**](#list-of-methods)

## devel_getStateTrieKeys
Gets keys of the state trie with the given offset and limit.

### Params
 1. offset: `number`
 2. limit: `number`

### Returns
`H256[]` with maximum length _limit_

### Request Example
```
  curl \
    -H 'Content-Type: application/json' \
    -d '{"jsonrpc": "2.0", "method": "devel_getStateTrieKeys", "params": [0, 1], "id": null}' \
    localhost:8080
```

### Response Example
```
{
  "jsonrpc":"2.0",
  "result":[
    "0x00acf5cba5c53e11f1512b8b480521cb546e7a17a96235a9282f6253b90de043"
  ],
  "id":null
}
```

[Back to **List of methods**](#list-of-methods)

## devel_getStateTrieValue
Gets the value of the state trie with the given key.

### Params
 1. key: `string`

### Returns
`string[]` - each string is RLP encoded

### Request Example
```
  curl \
    -H 'Content-Type: application/json' \
    -d '{"jsonrpc": "2.0", "method": "devel_getStateTrieValue", "params": ["0x00acf5cba5c53e11f1512b8b480521cb546e7a17a96235a9282f6253b90de043"], "id": null}' \
    localhost:8080
```

### Response Example
```
{
  "jsonrpc":"2.0",
  "result":[
    "0x20d560025f3a1c6675cb32384355ae05b224a3473ae17d3d15b6aa164af7d717",
    "0xf84541a053000000000000002ab33f741ba153ff1ffdf1107845828637c864d5360e4932a00000000000000000000000000000000000000000000000000000000000000000c06f"
  ],
  "id":null
}
```

[Back to **List of methods**](#list-of-methods)

## devel_snapshot
Snapshot the state of the given block hash.

### Params
 1. key: `H256`

### Returns

### Request Example
```
  curl \
    -H 'Content-Type: application/json' \
    -d '{"jsonrpc": "2.0", "method": "devel_snapshot", "params": ["0xfc196ede542b03b55aee9f106004e7e3d7ea6a9600692e964b4735a260356b50"], "id": null}' \
    localhost:8080
```

### Response Example
```
{
  "jsonrpc":"2.0",
  "result":[],
  "id":null
}
```

[Back to **List of methods**](#list-of-methods)

## devel_startSealing
Starts and enables sealing blocks by the miner.

### Params
No parameters

### Returns
`null`

### Request Example
```
  curl \
    -H 'Content-Type: application/json' \
    -d '{"jsonrpc": "2.0", "method": "devel_startSealing", "params": [], "id": null}' \
    localhost:8080
```

### Response Example
```
{
  "jsonrpc":"2.0",
  "result":null,
  "id":null
}
```

[Back to **List of methods**](#list-of-methods)

## devel_stopSealing
Stops and disables sealing blocks by the miner.

### Params
No parameters

### Returns
`null`

### Request Example
```
  curl \
    -H 'Content-Type: application/json' \
    -d '{"jsonrpc": "2.0", "method": "devel_stopSealing", "params": [], "id": null}' \
    localhost:8080
```

### Response Example
```
{
  "jsonrpc":"2.0",
  "result":null,
  "id":null
}
```

[Back to **List of methods**](#list-of-methods)

## devel_getBlockSyncPeers

Get peers in Block Sync module.

### Params

No parameters

### Returns

`string[]`

### Request Example

```
  curl \
    -H 'Content-Type: application/json' \
    -d '{"jsonrpc": "2.0", "method": "devel_getBlockSyncPeers", "params": [], "id": 3}' \
    localhost:8080
```

### Response Example

```
{
  "jsonrpc":"2.0",
  "result": ["1.2.3.4:3485", "1.2.3.5:3485"],
  "id":3
}
```

[Back to **List of methods**](#list-of-methods)

## devel_getPeerBestBlockHashes

Get IP address and best block hash of each peer.

### Params

No parameters

### Returns

[ 'string', 'H256' ][]

### Request Example

```
  curl \
    -H 'Content-Type: application/json' \
    -d '{"jsonrpc": "2.0", "method": "devel_getPeerBestBlockHashes", "params": [], "id": 3}' \
    localhost:8080
```

### Response Example
```
{
  "jsonrpc":"2.0",
  "result": [
    ["1.2.3.4:3485", "0x56642f04d519ae3262c7ba6facf1c5b11450ebaeb7955337cfbc45420d573077"], 
    ["1.2.3.5:3485", "0x7f7104b580f9418d444560009e5a92a4573d42d2c51cd0c6045afdc761826249"]
  ],
  "id":3
}
```

[Back to **List of methods**](#list-of-methods)

## devel_getTargetBlockHashes

Get hashes of target blocks

### Params

No parameters

### Returns

'`H256[]`

### Request Example

```
  curl \
    -H 'Content-Type: application/json' \
    -d '{"jsonrpc": "2.0", "method": "devel_getTargetBlockHashes", "params": [], "id": 3}' \
    localhost:8080
```

### Response Example
```
{
  "jsonrpc":"2.0",
  "result": [
    "0x56642f04d519ae3262c7ba6facf1c5b11450ebaeb7955337cfbc45420d573077",
    "0x7f7104b580f9418d444560009e5a92a4573d42d2c51cd0c6045afdc761826249"
    ],
  "id":3
}
```

[Back to **List of methods**](#list-of-methods)

## devel_testTPS

Test TPS as the parameters.

### Params

1. count: `number` - Integer.
2. seed: `number` - Integer, only used in "payOrTransfer" option.
3. option: "payOnly" | "transferSingle" | "transferMultiple" | "payOrTransfer"

### Returns

`number`

### Request Example

```
  curl \
    -H 'Content-Type: application/json' \
    -d '{"jsonrpc": "2.0", "method": "devel_testTPS", "params": [{"count": 1000, "seed": 0, "option": "payOnly"}], "id": null}' \
    localhost:8080
```

### Response Example

```
{
  "jsonrpc":"2.0",
  "result":5000.0,
  "id":null
}
`````

[Back to **List of methods**](#list-of-methods)
