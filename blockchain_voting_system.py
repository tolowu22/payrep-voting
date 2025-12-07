import hashlib
import json
from time import time

class Blockchain:
    def __init__(self):
        self.chain = []
        self.pending_votes = []
        # Create the genesis block (the first block in the chain)
        self.new_block(previous_hash='1', proof=100)

    def new_block(self, proof, previous_hash=None):
        """
        Create a new Block in the Blockchain
        :param proof: <int> The proof given by the Proof of Work algorithm
        :param previous_hash: (Optional) <str> Hash of previous Block
        :return: <dict> New Block
        """
        block = {
            'index': len(self.chain) + 1,
            'timestamp': time(),
            'votes': self.pending_votes,
            'proof': proof,
            'previous_hash': previous_hash or self.hash(self.chain[-1]),
        }

        # Reset the list of pending votes
        self.pending_votes = []
        self.chain.append(block)
        return block

    def new_vote(self, voter_id, candidate):
        """
        Creates a new vote to go into the next mined Block
        :param voter_id: <str> Unique ID of the voter
        :param candidate: <str> The candidate being voted for
        :return: <int> The index of the Block that will hold this vote
        """
        self.pending_votes.append({
            'voter_id': voter_id,
            'candidate': candidate,
        })
        return self.last_block['index'] + 1

    @property
    def last_block(self):
        return self.chain[-1]

    @staticmethod
    def hash(block):
        """
        Creates a SHA-256 hash of a Block
        :param block: <dict> Block
        :return: <str>
        """
        # We must make sure the Dictionary is Ordered, or we'll have inconsistent hashes
        block_string = json.dumps(block, sort_keys=True).encode()
        return hashlib.sha256(block_string).hexdigest()

    def proof_of_work(self, last_proof):
        """
        Simple Proof of Work Algorithm:
         - Find a number p' such that hash(pp') contains leading 4 zeroes
         - p is the previous proof, and p' is the new proof
        :param last_proof: <int>
        :return: <int>
        """
        proof = 0
        while self.valid_proof(last_proof, proof) is False:
            proof += 1
        return proof

    @staticmethod
    def valid_proof(last_proof, proof):
        """
        Validates the Proof: Does hash(last_proof, proof) contain 4 leading zeroes?
        :param last_proof: <int> Previous Proof
        :param proof: <int> Current Proof
        :return: <bool> True if correct, False if not.
        """
        guess = f'{last_proof}{proof}'.encode()
        guess_hash = hashlib.sha256(guess).hexdigest()
        return guess_hash[:4] == "0000"


# --- DRIVER CODE (To test it works) ---
print("Starting the Voting Blockchain...")
blockchain = Blockchain()

# 1. Add some votes
print("Adding votes...")
blockchain.new_vote("Voter123", "Candidate A")
blockchain.new_vote("Voter456", "Candidate B")
blockchain.new_vote("Voter789", "Candidate A")

# 2. Mine a block (Seal these votes into the chain)
print("Mining block (calculating proof of work)...")
last_block = blockchain.last_block
last_proof = last_block['proof']
proof = blockchain.proof_of_work(last_proof)

# 3. Add the block to the chain
previous_hash = blockchain.hash(last_block)
block = blockchain.new_block(proof, previous_hash)

print("\n--- Blockchain Status ---")
print(json.dumps(blockchain.chain, indent=4))