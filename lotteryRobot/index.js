var Web3 = require('web3');
var math = require('mathjs');

web3 = new Web3(new Web3.providers.HttpProvider("http://localhost:8545"));

// don't forget change addresses
const ICO_CONTRACT_ADDRESS = "0x529164937917ca981db36e727727229a4a8887be";
const ROBOT = "0x3a0c7287b9aac3c71ee8b9048c5dfb989f2a4d54";

// and ABI
const abi_i = [{"constant":true,"inputs":[{"name":"","type":"address"}],"name":"desires","outputs":[{"name":"email","type":"string"},{"name":"active","type":"bool"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[{"name":"who","type":"address"}],"name":"isDesirous","outputs":[{"name":"","type":"bool"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[{"name":"who","type":"address"}],"name":"isWhitelisted","outputs":[{"name":"","type":"bool"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[{"name":"_newController","type":"address"}],"name":"changeController","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":false,"inputs":[{"name":"_email","type":"string"}],"name":"proposal","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":true,"inputs":[{"name":"","type":"address"}],"name":"whitelist","outputs":[{"name":"","type":"bool"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[],"name":"buy","outputs":[],"payable":true,"stateMutability":"payable","type":"function"},{"constant":true,"inputs":[],"name":"robotAddress","outputs":[{"name":"","type":"address"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[{"name":"_email","type":"string"}],"name":"changeEmail","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":false,"inputs":[{"name":"who","type":"address"}],"name":"addParticipant","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":true,"inputs":[],"name":"lotteryBlock","outputs":[{"name":"","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[],"name":"removeProposal","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":true,"inputs":[{"name":"","type":"uint256"}],"name":"players","outputs":[{"name":"","type":"address"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[],"name":"controller","outputs":[{"name":"","type":"address"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[{"name":"number","type":"uint256"}],"name":"spinLottery","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"inputs":[{"name":"hackAddress","type":"address"},{"name":"_robotAddress","type":"address"},{"name":"_whitelist","type":"address[]"},{"name":"_desires","type":"address[]"}],"payable":false,"stateMutability":"nonpayable","type":"constructor"},{"payable":true,"stateMutability":"payable","type":"fallback"},{"anonymous":false,"inputs":[{"indexed":true,"name":"who","type":"address"},{"indexed":false,"name":"email","type":"string"}],"name":"Proposal","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"name":"who","type":"address"}],"name":"RemoveProposal","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"name":"who","type":"address"}],"name":"AddParticipant","type":"event"},{"anonymous":false,"inputs":[{"indexed":false,"name":"who","type":"address"}],"name":"NewLotteryBet","type":"event"},{"anonymous":false,"inputs":[{"indexed":false,"name":"blockNumber","type":"uint256"}],"name":"NewLotteryRound","type":"event"}];

// init Digital Security ICO
var ico = web3.eth.contract(abi_i).at(ICO_CONTRACT_ADDRESS);

var lotteryBlock = ico.lotteryBlock.call().toNumber();
var round = 5;
var currBlock;

// grab latest block
web3.eth.filter('latest', function(error, result){
    if (currBlock !== web3.eth.blockNumber ){
        currBlock = web3.eth.blockNumber;
        console.log('New block', currBlock)
    }
    if (!error) {
        if (web3.eth.blockNumber - lotteryBlock > round) {
            console.log('\n-------Starting new lottery round at block' + web3.eth.blockNumber +'--------');

            var number = math.randomInt(math.pow(2, 256));
            var spinTx = ico.spinLottery(number, {from: ROBOT, gas: 300000});
            console.log('Sending '+number+' from controller by '+spinTx+' transaction');
            lotteryBlock = web3.eth.blockNumber;
        }
    } else {
        console.error(error)
    }
});

// grab success events
var eventNewLotteryRound = ico.NewLotteryRound({fromBlock: 0, toBlock: 'latest'});
eventNewLotteryRound.watch(function(error, result) {
    console.log('Round finished! New round at', result.args.blockNumber + round, 'block.');
    lotteryBlock = result.args.blockNumber;
});
