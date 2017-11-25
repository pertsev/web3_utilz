const Web3 = require('web3');
const web3 = new Web3();

let account = web3.eth.accounts.create();

// change condition for your purpose
let lastByte = account.address.slice(account.address.length - 2, account.address.length );

while(lastByte !== '00' ){
    account = web3.eth.accounts.create();
    lastByte = account.address.slice(account.address.length - 2, account.address.length );
}

console.log('Specific account found!');
console.log('Address:', account.address);
console.log('Private key:', account.privateKey);
