/* eslint-disable no-console */
const Web3 = require('web3')
const kovanPOA = 'https://kovan.poa.network'
const kovanInfura = 'https://kovan.infura.io/v3/c7463beadf2144e68646ff049917b716'
const mainnetInfura = 'https://mainnet.infura.io/v3/c7463beadf2144e68646ff049917b716' // does not work
const mainnetTrust = 'http://ethereum-rpc.trustwalletapp.com'
const mainnetMEW = 'https://api.mycryptoapi.com/eth'

const web3 = new Web3(mainnetTrust)

async function main() {
  const txHash = process.argv[2]
  const { to, input, from, value, gas, gasPrice } = await web3.eth.getTransaction(txHash)
  try {
    const result = await web3.eth.call({
      to,
      data: input,
      from,
      value,
      gas,
      gasPrice
    })
    console.log('Cannot reproduce the issue. Smart contract returns the next data', result)
  } catch (e) {
    console.log('RAW message:', e.message)
    const rawMessageData = JSON.parse(e.message.slice(12)).data.slice(9)
    const reason = web3.utils.hexToAscii(rawMessageData)
    console.log('\nDecoded reason:', reason.slice(4))
  }
}

main()
