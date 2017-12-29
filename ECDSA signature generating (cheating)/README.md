# Generating ECDSA signatures. 

## Description:
Example of generating valid and different ECDSA signatures for same msg. If you have no idea about ECDSA, check [this](http://andrea.corbellini.name/2015/05/30/elliptic-curve-cryptography-ecdh-and-ecdsa/) wonderful blog of Andrea Corbellini

### Legend:
The simple dice game with [Signidice](https://github.com/gluk256/misc/blob/master/rng4ethereum/signidice.md) algorithm entropy. 

tl;dr: Player should submit his(her) seed to smart contact, then Casino sign seed and send signature to smart contract also. 
Smart contract use signature as seed for PRNG.

*Inspired by [DAO.casino.](https://github.com/DaoCasino/DiceGame) DAO Casino team aware of this bug and develop [solution](https://medium.com/@dao.casino/dao-casino-development-update-november-december-2017-d0d3180bb36b).

### To reproduce:

0. Setup local Ethereum node (geth e.g.), initialize private blockchain and run node with rpc interface.
1. Copy-paste `diceGame.sol` to remix (or use `Connect to localhost` feature) and deploy `DiceGame` contract to your blockchain. Replace contract addr.
2. Install python3 dependencies:
    * [web3.py](https://github.com/ethereum/web3.py)
    * [pyethereum](https://github.com/ethereum/pyethereum)
3. Run `python3 main.py`
4. Call `roll` func with some `seed` by Remix
5. See at console:

```
----------- New Game -------------

Seed is: 0x45ba4b90ca3f2ff02e2709129923dfa7b0711094be564bfa7bd5e95c5
Let's sign it!

k:  115433431399989491552061112962239315549007110697159927139679546307505360518949
Sum of dice is  11
[-] Bad signature :( Let's resign

k:  93278433122773886113119707795179240813013144806854869846077853441663942511613
Sum of dice is  11
[-] Bad signature :( Let's resign

k:  92339396429033418382044357475624065598320635886049346443913862088785374794025
Sum of dice is  8
[-] Bad signature :( Let's resign

k:  85327741194793567237418128956083772871496095079956234995149018676129068127530
Sum of dice is  2
[+] Good signature found!
s : 0x6218cc3f5f86c8e733af678c5d1fb942194103c028911438c43dd3b4b111560a
Send it by : 0x8142b2d2364750b810fe12baa3a7db0f905252553ed1c423abda310a87f1d877

----------- Success! Casino won! -------------
```