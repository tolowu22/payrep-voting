import hashlib
import json
import hmac
from time import time

class Blockchain:
    def __init__(self, chain=None, pending_votes=None):
        self.chain = chain if chain is not None else []
        self.pending_votes = pending_votes if pending_votes is not None else []
        if not self.chain:
            # Create the genesis block when no chain exists yet.
            self.new_block(previous_hash='1', proof=100)

    @classmethod
    def load_state(cls, filename):
        """Load blockchain state from JSON file"""
        try:
            with open(filename, 'r') as f:
                data = json.load(f)
                return cls(chain=data.get('chain', []), pending_votes=data.get('pending_votes', []))
        except (FileNotFoundError, json.JSONDecodeError):
            return cls()

    def save_state(self, filename):
        """Save blockchain state to JSON file"""
        try:
            data = {
                'chain': self.chain,
                'pending_votes': self.pending_votes
            }
            with open(filename, 'w') as f:
                json.dump(data, f, indent=4)
        except Exception as e:
            print(f"Warning: Could not save blockchain state to {filename} ({type(e).__name__}: {e})")

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
        # SECURITY CHECK: Prevent Double Voting
        if self.has_voted(voter_id):
            return False
        vote_data = {
            'voter_id': voter_id,
            'candidate': candidate,
            'timestamp': time(),
        }
        # Add digital signature
        vote_data['signature'] = self.sign_vote(vote_data)
        self.pending_votes.append(vote_data)
        return self.last_block['index'] + 1

    def sign_vote(self, vote_data):
        """Create a digital signature for the vote"""
        secret_key = b'blockchain_voting_secret_key'  # In production, use proper key management
        message = json.dumps(vote_data, sort_keys=True).encode()
        return hmac.new(secret_key, message, hashlib.sha256).hexdigest()

    def verify_vote_signature(self, vote):
        """Verify the digital signature of a vote"""
        signature = vote.pop('signature', None)
        if not signature:
            return False
        expected_signature = self.sign_vote(vote)
        vote['signature'] = signature  # Restore
        return hmac.compare_digest(signature, expected_signature)

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

    def has_voted(self, voter_id):
        # 1. Check Pending Mempool
        for vote in self.pending_votes:
            if vote['voter_id'] == voter_id: return True
        # 2. Check Mined Blocks
        for block in self.chain:
            if 'votes' in block:
                for vote in block['votes']:
                    if isinstance(vote, dict) and vote.get('voter_id') == voter_id:
                        return True
        return False

    def tally_votes(self, official_candidates):
        results = {candidate: 0 for candidate in official_candidates}
        for block in self.chain:
            if 'votes' in block:
                for vote in block['votes']:
                    candidate = vote['candidate']
                    if candidate in results: results[candidate] += 1
        # Include pending votes in live tally
        for vote in self.pending_votes:
            candidate = vote['candidate']
            if candidate in results: results[candidate] += 1
        return results

    def is_chain_valid(self, chain):
        last_block = chain[0]
        current_index = 1
        while current_index < len(chain):
            block = chain[current_index]
            if block['previous_hash'] != self.hash(last_block): return False
            if not self.valid_proof(last_block['proof'], block['proof']): return False
            last_block = block
            current_index += 1
        return True

    @classmethod
    def load_from_file(cls, filename):
        """Load blockchain state from JSON file"""
        try:
            with open(filename, 'r') as f:
                data = json.load(f)
                return cls(chain=data.get('chain', []), pending_votes=data.get('pending_votes', []))
        except (FileNotFoundError, json.JSONDecodeError):
            return cls()

    def save_to_file(self, filename):
        """Save blockchain state to JSON file"""
        data = {
            'chain': self.chain,
            'pending_votes': self.pending_votes
        }
        with open(filename, 'w') as f:
            json.dump(data, f, indent=4)