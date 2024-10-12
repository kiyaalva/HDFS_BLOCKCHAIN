from web3 import Web3
from solcx import compile_source

# Connect to local Ethereum node (Ganache)
w3 = Web3(Web3.HTTPProvider('http://127.0.0.1:7545'))  # Adjust if your Ganache settings are different

# Check if connected
if not w3.isConnected():
    print("Failed to connect to the Ethereum node!")
    exit()

# Compile the Solidity contract
compiled_sol = compile_source(
    '''
    pragma solidity ^0.8.0;

    contract Verify {
        string public merkleRoot;

        function setMerkleRoot(string memory _merkleRoot) public {
            merkleRoot = _merkleRoot;
        }

        function getMerkleRoot() view public returns (string memory) {
            return merkleRoot;
        }
    }
    '''
)

contract_interface = compiled_sol['<stdin>:Verify']

# Set up account (make sure to unlock your account if needed)
account = w3.eth.accounts[0]  # Use the first account for deployment

# Deploy the contract
Verify = w3.eth.contract(abi=contract_interface['abi'], bytecode=contract_interface['bin'])

# Build transaction
tx_hash = Verify.constructor().transact({'from': account})

# Wait for transaction receipt
tx_receipt = w3.eth.waitForTransactionReceipt(tx_hash)

# Contract address
print(f"Contract deployed at address: {tx_receipt.contractAddress}")

# Interact with the deployed contract
contract_instance = w3.eth.contract(address=tx_receipt.contractAddress, abi=contract_interface['abi'])

# Set the Merkle root (replace "your_merkle_root_here" with the actual root)
tx_hash = contract_instance.functions.setMerkleRoot("your_merkle_root_here").transact({'from': account})
w3.eth.waitForTransactionReceipt(tx_hash)

# Get the Merkle root
merkle_root = contract_instance.functions.getMerkleRoot().call()
print(f"Merkle Root: {merkle_root}")
