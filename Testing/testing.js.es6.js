const solc = require('solc');
const fs = require('fs');
const Web3 = require('web3');
const web3 = new Web3(new Web3.providers.HttpProvider('http://127.0.0.1:8545'));
//const web3 = new Web3(new Web3.providers.WebsocketProvider('wss://ropsten.infura.io/ws'));
const code = fs.readFileSync('./testable.sol');

async function deploy() {
    let output = solc.compile(code.toString(), 1);
    let TestableABI = output.contracts[Object.keys(output.contracts)[0]].interface;
    let TestableBytecode = output.contracts[Object.keys(output.contracts)[0]].bytecode;

    let Testable = new web3.eth.Contract(JSON.parse(TestableABI),{
        from: web3.eth.defaultAccount
    });

    let gasCount = await Testable.deploy({
        data: TestableBytecode
    }).estimateGas();

    Testable = await Testable.deploy({
        data: TestableBytecode
    }).send({
        gas: gasCount
    });

    return Testable;
}

async function main() {
    // when use unlocked account from node
    let defaultAccs = await web3.eth.getAccounts();
    web3.eth.defaultAccount = defaultAccs[0];

    // this is for known private key
    // web3.eth.accounts.wallet.add(privKey.key);

    let Testable = await deploy();

    human_test(Testable);
    callme_tx_status_test(Testable, 3);
    callme_event_test(Testable, 3);

    // let's got new instance
    Testable = await deploy();
    callme_storage_test(Testable, 5);

}

async function human_test(instance) {
    // let's test that contract has owner (human)
    // use "call" for public variables and constant methods
    let humanAddress = await instance.methods.human().call();
    if (humanAddress !== web3.eth.defaultAccount) {
        throw "✕ human address is wrong"
    } else {
        console.log("✔ human_test passed");
    }
}

async function callme_tx_status_test(instance, times) {
    // now we gonna "send" tx to change contract state, we need to know how many Gas will be used though
    let gasCount = await instance.methods.callme(times).estimateGas();
    let receipt = await instance.methods.callme(times).send({
        gas: gasCount
    });

    if (receipt.status) {
        console.log("✔ transaction has status 'success'");
    } else {
        throw "✕ transaction has status 'fail'"
    }
}

async function callme_event_test(instance, times) {

    let gasCount = await instance.methods.callme(times).estimateGas();
    let receipt = await instance.methods.callme(times).send({
        gas: gasCount
    });
    // you can subscribe on events explicitly or grab it from receipt
    // let event = await instance.events.CallmeLog();
    if (receipt.status && receipt.events["CallmeLog"]) {
        console.log("✔ event raised");
    } else {
        throw "✕ there is no CallmeLog event"
    }
}

async function callme_storage_test(instance, times) {

    let gasCount = await instance.methods.callme(times).estimateGas();
    let receipt = await instance.methods.callme(times).send({
        gas: gasCount
    });

    // is it possible to read private variable?
    // Easy! counter var is stored at second Storage cell
    let counter = await web3.eth.getStorageAt(instance.options.address, 1);
    if (parseInt(counter) === times) {
        console.log("✔ storage test passed");
    } else {
        throw "✕ counter has wrong value!"
    }
}

main();