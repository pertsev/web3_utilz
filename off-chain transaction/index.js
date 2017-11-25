var Tx = require('ethereumjs-tx');
const unsign = require('@warren-bank/ethereumjs-tx-unsign');
const util = require('ethereumjs-util');
const Web3 = require('web3');

var web3 = new Web3();

var privateKey = new Buffer('deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef', 'hex');

console.log('Private key:', util.bufferToHex(privateKey));
var publicKey = util.privateToPublic(privateKey);
console.log('Public key:', util.bufferToHex(publicKey));
var addr = util.privateToAddress(privateKey);
console.log('Address derived from private key:', util.bufferToHex(addr));
console.log('Address derived from public key: 0x' + util.bufferToHex(util.sha3(publicKey)).slice(26));

var rawTx = {
    nonce: web3.toHex(0), // for real network use web3.eth.getTransactionCount(web3.eth.coinbase)
    gasPrice: web3.toHex(20000000000),
    gasLimit: web3.toHex(100000),
    to: '0x687422eEA2cB73B5d3e242bA5456b782919AFc85',
    value: web3.toHex(1000), // Wei !
    data: web3.toHex('HACK') // msg.data here. Hint: use myContractInstance.myMethod.getData(param1 [, param2, ...])
                             // to call contract function.
};

console.log("\nRaw:\n", rawTx, "\n");

var tx = new Tx(rawTx);
tx.sign(privateKey);
var signed = tx.serialize().toString('hex');
console.log('Signed:\n0x' + signed, '\n');
// 0xf86b808504a817c800830186a094687422eea2cb73b5d3e242ba5456b782919afc858203e8844841434b1ca0c9664558cc015bd252269db0b1674c02ce622868cee4fbee00bda12611cb222ca02f48f366e3bd0ee7f7b063578e1a9229213f9ebb1a6649803e9334dd63935ce5

// Ok. Let's check this tx
var receivedTx = new Tx(signed);
if (receivedTx.verifySignature()) {
    console.log('Address from recieved transaction: ', util.bufferToHex(receivedTx.from));
    var decodedTx = unsign(signed, true, true, true);
    console.log("\nRaw:\n", decodedTx.txData);
    console.log("\nSignature:\n", decodedTx.signature);
    console.log('\nmsg.data:', web3.toAscii(decodedTx.txData.data));
}
