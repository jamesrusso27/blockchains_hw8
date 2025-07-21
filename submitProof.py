import eth_account
import random
import string
import json
from pathlib import Path
from web3 import Web3
from web3.middleware import ExtraDataToPOAMiddleware
from web3.exceptions import TransactionFailed

def merkle_assignment():
    num_of_primes = 8192
    primes = generate_primes(num_of_primes)
    leaves = convert_leaves(primes)
    tree = build_merkle(leaves)
    random_leaf_index = find_unclaimed_leaf(primes, leaves)
    proof = prove_merkle(tree, random_leaf_index)
    challenge = ''.join(random.choice(string.ascii_letters) for i in range(32))
    addr, sig = sign_challenge(challenge)
    if sign_challenge_verify(challenge, addr, sig):
        tx_hash = send_signed_msg(proof, leaves[random_leaf_index])
    return addr, sig, tx_hash

def generate_primes(num_primes):
    def is_prime(n):
        if n < 2:
            return False
        for i in range(2, int(n ** 0.5) + 1):
            if n % i == 0:
                return False
        return True
    primes_list = []
    n = 2
    while len(primes_list) < num_primes:
        if is_prime(n):
            primes_list.append(n)
        n += 1
    return primes_list

def convert_leaves(primes_list):
    return [Web3.to_bytes(int.to_bytes(prime, 32, 'big')) for prime in primes_list]

def build_merkle(leaves):
    tree = [leaves]
    while len(tree[-1]) > 1:
        level = []
        for i in range(0, len(tree[-1]), 2):
            if i + 1 < len(tree[-1]):
                level.append(hash_pair(tree[-1][i], tree[-1][i + 1]))
            else:
                level.append(tree[-1][i])
        tree.append(level)
    return tree

def prove_merkle(merkle_tree, random_indx):
    merkle_proof = []
    index = random_indx
    for level in merkle_tree[:-1]:
        sibling_index = index + 1 if index % 2 == 0 else index - 1
        if 0 <= sibling_index < len(level):
            merkle_proof.append(level[sibling_index])
        index //= 2
    return merkle_proof

def find_unclaimed_leaf(primes, leaves):
    chain = 'bsc'
    w3 = connect_to(chain)
    address, abi = get_contract_info(chain)
    contract = w3.eth.contract(address=address, abi=abi)
    for i in range(len(primes)):
        owner = contract.functions.getOwnerByPrime(primes[i]).call()
        if owner == '0x0000000000000000000000000000000000000000':
            return i
    raise ValueError("No unclaimed leaves found")

def sign_challenge(challenge):
    acct = get_account()
    addr = acct.address
    eth_sk = acct.key
    eth_encoded_msg = eth_account.messages.encode_defunct(text=challenge)
    eth_sig_obj = eth_account.Account.sign_message(eth_encoded_msg, eth_sk)
    return addr, eth_sig_obj.signature.hex()

def send_signed_msg(proof, random_leaf):
    chain = 'bsc'
    acct = get_account()
    address, abi = get_contract_info(chain)
    w3 = connect_to(chain)
    contract = w3.eth.contract(address=address, abi=abi)
    nonce = w3.eth.get_transaction_count(acct.address)
    gas_price = w3.eth.gas_price
    tx = contract.functions.submit(proof, random_leaf).build_transaction({
        'from': acct.address,
        'nonce': nonce,
        'gas': 3000000,
        'gasPrice': int(gas_price * 1.1),
        'chainId': 97
    })
    signed_tx = w3.eth.account.sign_transaction(tx, acct.key)
    try:
        tx_hash = w3.eth.send_raw_transaction(signed_tx.raw_transaction)
        print(f"Transaction sent: {tx_hash.hex()}")
        w3.eth.wait_for_transaction_receipt(tx_hash)
        return tx_hash.hex()
    except TransactionFailed as e:
        print(f"Transaction failed: {e}")
        return None

def connect_to(chain):
    if chain not in ['avax','bsc']:
        print(f"{chain} is not a valid option for 'connect_to()'")
        return None
    if chain == 'avax':
        api_url = f"https://api.avax-test.network/ext/bc/C/rpc"
    else:
        api_url = f"https://data-seed-prebsc-1-s1.binance.org:8545/"
    w3 = Web3(Web3.HTTPProvider(api_url))
    w3.middleware_onion.inject(ExtraDataToPOAMiddleware, layer=0)
    return w3

def get_account():
    cur_dir = Path(__file__).parent.absolute()
    with open(cur_dir.joinpath('sk.txt'), 'r') as f:
        sk = f.readline().rstrip()
    if sk[0:2] == "0x":
        sk = sk[2:]
    return eth_account.Account.from_key(sk)

def get_contract_info(chain):
    contract_file = Path(__file__).parent.absolute() / "contract_info.json"
    if not contract_file.is_file():
        contract_file = Path(__file__).parent.parent.parent / "tests" / "contract_info.json"
    with open(contract_file, "r") as f:
        d = json.load(f)
        d = d[chain]
    return d['address'], d['abi']

def sign_challenge_verify(challenge, addr, sig):
    eth_encoded_msg = eth_account.messages.encode_defunct(text=challenge)
    if eth_account.Account.recover_message(eth_encoded_msg, signature=sig) == addr:
        print(f"Success: signed the challenge {challenge} using address {addr}!")
        return True
    else:
        print(f"Failure: The signature does not verify!")
        print(f"signature = {sig}\naddress = {addr}\nchallenge = {challenge}")
        return False

def hash_pair(a, b):
    if a < b:
        return Web3.solidity_keccak(['bytes32', 'bytes32'], [a, b])
    else:
        return Web3.solidity_keccak(['bytes32', 'bytes32'], [b, a])

if __name__ == "__main__":
    merkle_assignment()