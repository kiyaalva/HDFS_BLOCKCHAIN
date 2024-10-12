# Import necessary modules
from web3 import Web3
from solcx import compile_source, install_solc, get_installed_solc_versions,set_solc_version
import merkletools
import hashlib
from hdfs import InsecureClient
import json
from solcx import install_solc

# Install a specific version of the Solidity compiler
install_solc('0.8.19')  # Replace '0.8.6' with the desired version
set_solc_version('0.8.19')


# HDFS client setup (Replace 'localhost' with your HDFS namenode IP if running remotely)
hdfs_client = InsecureClient('http://localhost:9870', user='kiran')  # Ensure Hadoop is running

# Function to build a Merkle tree from data
def build_merkle_tree(data):
    """
    Builds a Merkle tree from the provided data dictionary.
    :param data: Dictionary of key-value pairs to build the Merkle tree from.
    :return: MerkleTools object containing the constructed Merkle tree.
    """
    mt = merkletools.MerkleTools(hash_type='sha256')  # Initialize MerkleTools with SHA256 hashing
    for v in data.values():
        mt.add_leaf(v, True)  # Add each value as a leaf to the Merkle tree
    mt.make_tree()  # Build the Merkle tree
    return mt

# Function to store data in HDFS
def store_data_in_hdfs(data, hdfs_path="/data/project3/data.json"):
    """
    Stores a given dictionary as a JSON file in the specified HDFS path.
    :param data: Dictionary containing the data to store.
    :param hdfs_path: HDFS path where data should be stored.
    """
    json_data = json.dumps(data)  # Convert dictionary to JSON format
    with hdfs_client.write(hdfs_path, overwrite=True, encoding='utf-8') as writer:
        writer.write(json_data)  # Write the JSON data to HDFS
    print(f"Data successfully stored in HDFS at: {hdfs_path}")

# Function to query value by key from HDFS
def query_value_by_key_from_hdfs(key, hdfs_path="/data/project3/data.json"):
    """
    Retrieves a specific value by key from a JSON file stored in HDFS.
    :param key: Key to search for in the JSON data.
    :param hdfs_path: HDFS path where the JSON data is stored.
    :return: Value associated with the given key, or None if key is not found.
    """
    with hdfs_client.read(hdfs_path, encoding='utf-8') as reader:
        data = json.load(reader)  # Load the JSON data from HDFS
    return data.get(key, None)  # Retrieve value by key

# Function to get all data from HDFS
def get_all_data_from_hdfs(hdfs_path="/data/project3/data.json"):
    """
    Retrieves all data from a JSON file stored in HDFS.
    :param hdfs_path: HDFS path where the JSON data is stored.
    :return: Dictionary containing all the data from HDFS.
    """
    with hdfs_client.read(hdfs_path, encoding='utf-8') as reader:
        data = json.load(reader)  # Load the entire JSON data
    return data  # Return the data as a dictionary

# Function to retrieve and build a Merkle tree from HDFS data
def get_merkle_tree_from_hdfs(hdfs_path="/data/project3/data.json", key_index=None):
    """
    Retrieves data from HDFS and constructs a Merkle tree.
    :param hdfs_path: HDFS path where the JSON data is stored.
    :param key_index: Optional dictionary to sort the data before constructing the Merkle tree.
    :return: MerkleTools object containing the constructed Merkle tree.
    """
    data = get_all_data_from_hdfs(hdfs_path)  # Retrieve all data from HDFS
    if key_index:
        # Sort the data by the provided key index mapping
        data = {k: data[k] for k in sorted(data.keys(), key=lambda k: key_index.get(k, 0))}
    merkle_tree = build_merkle_tree(data)  # Build and return the Merkle tree
    return merkle_tree

def malicious_attempt_hdfs(key, new_value, hdfs_path="/data/project3/data.json"):
    """
    Simulates a malicious attempt by modifying a specific value in the HDFS data.
    :param key: Key of the data to be modified.
    :param new_value: New value to replace the original value.
    :param hdfs_path: HDFS path where the JSON data is stored.
    """
    with hdfs_client.read(hdfs_path, encoding='utf-8') as reader:
        data = json.load(reader)  # Load the existing data from HDFS

    # Simulate a malicious attempt by modifying the value for the given key
    if key in data:
        print(f"Before malicious attempt: {key} = {data[key]}")
        data[key] = new_value  # Modify the value
        print(f"After malicious attempt: {key} = {data[key]}")

    # Store the modified data back in HDFS
    with hdfs_client.write(hdfs_path, overwrite=True, encoding='utf-8') as writer:
        writer.write(json.dumps(data))  # Write the modified data back to HDFS

    print(f"Malicious attempt: Value of {key} modified in HDFS.")

def validate_merkle_proof(value, merkle_proof, merkle_root):
    """
    Validates the Merkle proof for a given value and Merkle root.
    :param value: The value to validate.
    :param merkle_proof: The Merkle proof associated with the value.
    :param merkle_root: The Merkle root to validate against.
    :return: Boolean indicating whether the proof is valid.
    """
    mt = merkletools.MerkleTools(hash_type='sha256')
    mt.merkle_root = merkle_root
    return mt.validate_proof(merkle_proof, hashlib.sha256(value.encode()).hexdigest(),merkle_root)



# Example usage:
if __name__ == '__main__':
    # Original data to be stored in HDFS
    ori_data = {
        'A': '10',
        'B': '20',
        'C': '30',
        'D': '40'
    }

    # Store original data in HDFS
    store_data_in_hdfs(ori_data)

    # Key-index mapping for data sorting
    key_index = {'A': 0, 'B': 1, 'C': 2, 'D': 3}

    # Retrieve and build Merkle Tree from HDFS data
    merkle_tree = get_merkle_tree_from_hdfs(key_index=key_index)

    # Print the Merkle root to verify
    print("Merkle Root:", merkle_tree.get_merkle_root())  # Merkle root for verification

    # Query a value by key from HDFS
    queried_value = query_value_by_key_from_hdfs('B')
    print(f"Queried value for key 'B': {queried_value}")


# Ensure the desired Solidity version is installed
    solc_version = "0.8.19"
    install_solc(solc_version)

    # Check if the version is installed
    if solc_version not in [str(version) for version in get_installed_solc_versions()]:
        print(f"Solidity version {solc_version} is not installed.")
        exit()


    # Compile Solidity contract
    compiled_sol = compile_source(
        '''
        pragma solidity >0.5.0;
        contract Verify{
            string public merkleRoot;

            function setMerkleRoot(string memory _merkleRoot) public {
                merkleRoot = _merkleRoot;
            }

            function getMerkleRoot() view public returns (string memory){
                return merkleRoot;
            }
        }
        ''',
        output_values=['abi', 'bin']
    )

    contract_id, contract_interface = compiled_sol.popitem()
    bytecode = contract_interface['bin']
    abi = contract_interface['abi']

    # Connect to Ethereum node
    w3 = Web3(Web3.HTTPProvider('http://127.0.0.1:8545'))  # Ensure Ethereum node is running
    w3.eth.default_account = w3.eth.accounts[0]  # Set default account

    # Deploy contract
    Verify = w3.eth.contract(abi=abi, bytecode=bytecode)
    deploy_tx_hash = Verify.constructor().transact()
    deploy_tx_receipt = w3.eth.wait_for_transaction_receipt(deploy_tx_hash)
    verify_contract = w3.eth.contract(
        address=deploy_tx_receipt.contractAddress,
        abi=abi
    )

    # Set Merkle root in contract
    merkle_root = merkle_tree.get_merkle_root()
    set_tx_hash = verify_contract.functions.setMerkleRoot(merkle_root).transact()
    w3.eth.wait_for_transaction_receipt(set_tx_hash)

   # Retrieve and print the Merkle root stored in the Ethereum contract
    merkle_root_from_contract = verify_contract.functions.getMerkleRoot().call()
    print("Merkle Root from Ethereum contract before malicious attempt:", merkle_root_from_contract)

    # Simulate a malicious attempt - modify the value of key 'B'
    #malicious_attempt_hdfs('B', '100')

    # Query the modified value from HDFS
    modified_value = query_value_by_key_from_hdfs('B')
    #print(f"Queried value after malicious attempt for key 'B': {modified_value}")

    # Rebuild Merkle Tree from the modified HDFS data
    merkle_tree_after_modification = get_merkle_tree_from_hdfs(key_index=key_index)
    merkle_root_after_modification = merkle_tree_after_modification.get_merkle_root()
    #print("Merkle Root after malicious attempt:", merkle_root_after_modification)

    # Get Merkle proof for key 'B'
    index = key_index['B']
    merkle_proof = merkle_tree_after_modification.get_proof(index)

    # Validate the Merkle proof
    is_valid = validate_merkle_proof(modified_value, merkle_proof, merkle_root_after_modification)
    print(f"Is the modified data valid? {is_valid}")

    # Compare the Merkle root from Ethereum contract and the one after the malicious attempt
    print("Merkle Root from Ethereum contract:", merkle_root_from_contract)
    print("Merkle Root from HDFS after malicious attempt:", merkle_root_after_modification)

    # Check if the roots are different (which they should be after the malicious attempt)
    if merkle_root_from_contract == merkle_root_after_modification:
        print("The Merkle roots match, no tampering detected.")
    else:
        print("The Merkle roots do not match, tampering detected.")
