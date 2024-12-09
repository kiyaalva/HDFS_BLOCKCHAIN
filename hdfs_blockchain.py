from web3 import Web3
from solcx import compile_source, install_solc, set_solc_version
from hdfs import InsecureClient
import hashlib
import json

# HDFS client setup
hdfs_client = InsecureClient('http://localhost:9870', user='kiran')

# Ethereum setup
install_solc('0.8.19')
set_solc_version('0.8.19')
w3 = Web3(Web3.HTTPProvider('http://127.0.0.1:8545'))
w3.eth.default_account = w3.eth.accounts[0]

# Deploy the Ethereum smart contract
compiled_sol = compile_source('''
pragma solidity ^0.8.19;
contract Verify {
    mapping(string => string) public fileHashes;

    function storeHash(string memory filePath, string memory hashValue) public {
        fileHashes[filePath] = hashValue;
    }

    function getHash(string memory filePath) public view returns (string memory) {
        return fileHashes[filePath];
    }
}
''', output_values=['abi', 'bin'])

contract_id, contract_interface = compiled_sol.popitem()
contract_abi = contract_interface['abi']
contract_bytecode = contract_interface['bin']

contract = w3.eth.contract(abi=contract_abi, bytecode=contract_bytecode)
tx_hash = contract.constructor().transact()
tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
verify_contract = w3.eth.contract(
    address=tx_receipt.contractAddress,
    abi=contract_abi
)


def generate_metadata_hash(file_path):
    """
    Generate a SHA-256 hash for a file's metadata in HDFS.
    """
    metadata = hdfs_client.status(file_path)
    metadata_json = json.dumps(metadata, sort_keys=True)
    return hashlib.sha256(metadata_json.encode()).hexdigest()


def store_hash_in_blockchain(file_path, metadata_hash):
    """
    Store the metadata hash in the Ethereum smart contract.
    """
    tx_hash = verify_contract.functions.storeHash(file_path, metadata_hash).transact()
    w3.eth.wait_for_transaction_receipt(tx_hash)
    print(f"Stored hash for {file_path} in the blockchain.")


def get_hash_from_blockchain(file_path):
    """
    Retrieve the metadata hash for a file from the blockchain.
    """
    return verify_contract.functions.getHash(file_path).call()


def detect_tampered_files(directory_path):
    """
    Detect tampered files in an HDFS directory by comparing metadata hashes.
    """
    file_statuses = hdfs_client.list(directory_path, status=True)
    tampered_files = []

    for file_info in file_statuses:
        file_path = f"{directory_path}/{file_info[0]}"
        current_hash = generate_metadata_hash(file_path)
        stored_hash = get_hash_from_blockchain(file_path)

        if not stored_hash:
            print(f"File {file_path} is not tracked in the blockchain.")
        elif current_hash != stored_hash:
            tampered_files.append(file_path)

    return tampered_files


def ensure_directory_exists(directory_path):
    """
    Ensure the specified HDFS directory exists. Create it if it doesn't.
    """
    try:
        hdfs_client.list(directory_path)
    except Exception:
        print(f"Directory {directory_path} does not exist. Creating it...")
        hdfs_client.makedirs(directory_path)


def generate_directory_hash(directory_path):
    """
    Generate a Merkle root hash for a directory by combining the metadata hashes of its files.
    """
    file_statuses = hdfs_client.list(directory_path, status=True)
    file_hashes = []

    for file_info in file_statuses:
        file_path = f"{directory_path}/{file_info[0]}"
        file_hash = generate_metadata_hash(file_path)
        file_hashes.append(file_hash)

    # Compute Merkle root hash from file hashes
    if not file_hashes:
        return None  # Empty directory
    return compute_merkle_root(file_hashes)


def compute_merkle_root(hashes):
    """
    Compute the Merkle root hash from a list of hashes.
    """
    if len(hashes) == 1:
        return hashes[0]

    new_level = []
    for i in range(0, len(hashes), 2):
        left = hashes[i]
        right = hashes[i + 1] if i + 1 < len(hashes) else hashes[i]
        new_level.append(hashlib.sha256((left + right).encode()).hexdigest())

    return compute_merkle_root(new_level)


def store_directory_hash_in_blockchain(directory_path, directory_hash):
    """
    Store the directory-level hash in the Ethereum smart contract.
    """
    tx_hash = verify_contract.functions.storeHash(directory_path, directory_hash).transact()
    w3.eth.wait_for_transaction_receipt(tx_hash)
    print(f"Stored directory hash for {directory_path} in the blockchain.")


def detect_directory_tampering(directory_path):
    """
    Detect if the directory's integrity is compromised by comparing the Merkle root hash.
    """
    current_hash = generate_directory_hash(directory_path)
    stored_hash = get_hash_from_blockchain(directory_path)

    if not stored_hash:
        print(f"Directory {directory_path} is not tracked in the blockchain.")
        return False

    if current_hash != stored_hash:
        print(f"Tampering detected in directory {directory_path}.")
        print("Possible causes of tampering:")
        print(" - A file was deleted.")
        print(" - A file was added.")
        print(" - A file was modified.")
        return True

    print(f"Directory {directory_path} integrity verified.")
    return False


def simulate_add_file(directory_path, file_name, content="This is a malicious file."):
    """
    Simulates a malicious attempt by adding a new file to the directory in HDFS.
    """
    file_path = f"{directory_path}/{file_name}"
    with hdfs_client.write(file_path, overwrite=True, encoding='utf-8') as writer:
        writer.write(content)
    print(f"Malicious file {file_name} added to {directory_path}.")

def malicious_attempt(file_path):
    """
    Simulates a malicious attempt by modifying the file's metadata in HDFS.
    :param file_path: Path to the file in HDFS.
    """
    metadata = hdfs_client.status(file_path)
    print(f"Original metadata for {file_path}: {metadata}")

    with hdfs_client.write(file_path, overwrite=True, encoding='utf-8') as writer:
        writer.write("This is malicious content!") 
    print(f"Malicious attempt made on {file_path}.")


if __name__ == '__main__':
    hdfs_directory = "/data/project3"
    ensure_directory_exists(hdfs_directory)

    # Generate and store hashes for individual files
    file_statuses = hdfs_client.list(hdfs_directory, status=True)
    for file_info in file_statuses:
        file_path = f"{hdfs_directory}/{file_info[0]}"
        metadata_hash = generate_metadata_hash(file_path)
        store_hash_in_blockchain(file_path, metadata_hash)

    # Generate and store directory-level hash
    directory_hash = generate_directory_hash(hdfs_directory)
    if directory_hash:
        store_directory_hash_in_blockchain(hdfs_directory, directory_hash)
    else:
        print(f"No files in directory {hdfs_directory} to generate hash.")

    # Simulate a malicious file addition
    simulate_add_file(hdfs_directory, "malicious_file.txt")

    # Detect tampering at the directory level
    if detect_directory_tampering(hdfs_directory):
        print(f"Tampering detected in directory {hdfs_directory}.")
    else:
        print(f"Directory {hdfs_directory} is secure.")

    # Simulate a malicious attempt
    malicious_file_path = f"{hdfs_directory}/test.csv"
    malicious_attempt(malicious_file_path)

    # Detect tampered files individually
    tampered_files = detect_tampered_files(hdfs_directory)
    if tampered_files:
        print("Tampered files detected:")
        for file in tampered_files:
            print(f" - {file}")
    else:
        print("No tampered files detected.")
