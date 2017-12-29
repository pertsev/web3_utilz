#!/usr/bin/python3

from ethereum import utils
from secp256k1 import ecdsa_raw_sign, ecdsa_raw_sign_with_random_k
from web3 import Web3, HTTPProvider
import time

def is_casino_win(s):
    print("Sum of dice is ", s % 12)
    return s % 12 <= 3


def new_game(event_obj):
    print("\n----------- New Game -------------\n")
    msg = event_obj['args']['seed']
    print("Seed is: 0x" + utils.encode_hex(msg))
    print("Let's sign it!\n")

    v, r, s = ecdsa_raw_sign_with_random_k(msg, key)
    while not is_casino_win(s):
        print("[-] Bad signature :( Let's resign\n")
        v, r, s = ecdsa_raw_sign_with_random_k(msg, key)

    print("[+] Good signature found! ")
    print("s :", utils.int_to_hex(s))
    tx = contract_instance.transact({'from': web3.eth.coinbase}).confirm(msg, v, utils.encode_int32(r), utils.encode_int32(s))
    print("Send it by : 0x" + utils.encode_hex(tx))
    time.sleep(2)


def one_more_lose(event_obj):
    game_id = event_obj['args']['seed']
    game = contract_instance.call({'from': web3.eth.coinbase}).listGames(game_id)

    assert game[3] == 2, "Something goes wrong! Game state is %s" % game[3]

    print("\n----------- Success! Casino won! -------------")


if __name__ == '__main__':
    key = utils.decode_hex("9a596376b73bbdfeac7aa1a8ff6e18424d0413d69bad8569425d440b89ddebcf")

    web3 = Web3(HTTPProvider('http://192.168.0.100:8545'))

    contract_addr = "0xEa7013F33d9B4844D00ec4cF145393cB16B81548"
    contract_ABI = [{"constant": False,"inputs": [{"name": "seed","type": "bytes32"}],"name": "roll","outputs": [],"payable": True,"stateMutability": "payable","type": "function"},{"constant": True,"inputs": [],"name": "owner","outputs": [{"name": "","type": "address"}],"payable": False,"stateMutability": "view","type": "function"},{"constant": True,"inputs": [],"name": "testResult","outputs": [{"name": "","type": "uint256"}],"payable": False,"stateMutability": "view","type": "function"},{"constant": True,"inputs": [{"name": "","type": "bytes32"}],"name": "listGames","outputs": [{"name": "player","type": "address"},{"name": "bet","type": "uint256"},{"name": "seed","type": "bytes32"},{"name": "state","type": "uint8"},{"name": "result","type": "uint256"}],"payable": False,"stateMutability": "view","type": "function"},{"constant": False,"inputs": [{"name": "seed","type": "bytes32"},{"name": "_v","type": "uint8"},{"name": "_r","type": "bytes32"},{"name": "_s","type": "bytes32"}],"name": "confirm","outputs": [],"payable": False,"stateMutability": "nonpayable","type": "function"},{"payable": True,"stateMutability": "payable","type": "fallback"},{"anonymous": False,"inputs": [{"indexed": False,"name": "seed","type": "bytes32"}],"name": "LogNewGame","type": "event"},{"anonymous": False,"inputs": [{"indexed": False,"name": "seed","type": "bytes32"}],"name": "LogPlayerLose","type": "event"},{"anonymous": False,"inputs": [{"indexed": False,"name": "seed","type": "bytes32"}],"name": "LogPlayerWon","type": "event"}]

    contract_instance = web3.eth.contract(abi=contract_ABI, address=contract_addr)

    new_game_event = contract_instance.eventFilter('LogNewGame')
    player_lose_event = contract_instance.eventFilter('LogPlayerLose')

    while 1:
        for event in new_game_event.get_new_entries():
            new_game(event)
            for lose in player_lose_event.get_new_entries():
                one_more_lose(lose)
        time.sleep(2)
