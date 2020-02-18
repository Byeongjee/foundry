const SDK = require("codechain-sdk");

const sdk = new SDK({
    server: process.env.CODECHAIN_RPC_HTTP || "http://localhost:8080",
    networkId: process.env.CODECHAIN_NETWORK_ID || "tc"
});

(async () => {
    // LocalKeyStore creates `keystore.db` file in the working directory.
    const keyStore = await sdk.key.createLocalKeyStore();
    const address = await sdk.key.createAssetAddress({
        type: "P2PKH", // It supports P2PKH(Pay to Public Key Hash) lock/unlock scripts.
        keyStore
    });
    // This type of address is used to receive assets when minting or transferring them.
    // Example: tcaqyqsrfw3cg4h4fgxcfj3lsw49jcqzcxs5qpqtxfjfp
    console.log(address.toString());
})().catch(console.error);
