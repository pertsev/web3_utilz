## Solidity revert reason 
The script allows to get the revert reason for past transactions.

## Usage
1. `npm i`
2. `node index.js <TX_HASH>` 

## Example
```
node index.js 0x45df3ce73e04db535ebd4e5d96c9222699fe0a5ae1efdf46b502678af3aa879c

> RAW message: Node error: {"message":"VM execution error.","code":-32015,"data":"Reverted 0x08c379a0000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000066e6f206665650000000000000000000000000000000000000000000000000000"}

> Decoded reason:  no fee

```

## Note
1. It may not work if the smart contract state or state of the caller has been changed somehow. For reliable results, you need your own node synced up to the block of failed tx.
2. It obviously does not work if the contract does not emit any reason (Old contracts).
3. It does not work for `Out of gas`, `Bad Instruction` cases.
