import json
import logging
import os
from typing import Dict, Any

import requests
import json
import hashlib
from base64 import b64decode

from deoracle_proof.models.proof_response import ProofResponse

networks = {
    "eth": "https://mainnet.infura.io/v3/0822174983b6479ca10ad18f6a5a518c",
    "base": "https://base-mainnet.infura.io/v3/0822174983b6479ca10ad18f6a5a518c",
    "vana": "https://rpc.vana.org",
    "solana": "https://alien-side-emerald.solana-mainnet.quiknode.pro/a9c0f414bbd654569d77f8cfec805701a08b5f03",
}
api_url = "https://deoracle.io/api/token/verify"
TOTAL_SUPPLY_METHOD = "0x18160ddd"

class Proof:
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.proof_response = ProofResponse(dlp_id=config['dlp_id'])

    def generate(self) -> ProofResponse:
        """Generate proofs for all input files."""
        logging.info("Starting proof generation")

        # Iterate through files and calculate data validity
        account_email = ""
        data_chain = ""
        data_contract = ""
        data_reason = ""
        try:
            for input_filename in os.listdir(self.config['input_dir']):
                input_file = os.path.join(self.config['input_dir'], input_filename)
                if input_filename.lower() == 'decrypted_file.zip':
                    with open(input_file, 'r') as f:
                        input_data = json.load(f)
                        account_email = input_data.get('email', "")
                        data_chain = input_data.get('chain', "")
                        data_contract = input_data.get('contract', "")
                        data_reason = input_data.get('reason', "")
                        break
        except Exception as e:
            logging.error("parse json error: %s", str(e), exc_info=True)

        email_matches = self.config['user_email'] == account_email
        ownership = 1 if email_matches else 0
        total_supply = 0

        if ownership and data_contract != "":
            data_chain = data_chain.lower()
            if data_chain == "solana":
                if len(data_contract) == 44:
                    total_supply = get_total_supply_solana(networks[data_chain], data_contract)
                    logging.info("sol supply {}".format(total_supply))
            elif data_chain == "eth" or data_chain == "base" or data_chain == "vana" :
                if len(data_contract) == 42:
                    total_supply = get_total_supply_evm(networks[data_chain], data_contract)
                    
        logging.info( "{} on {} supply {}".format(data_contract, data_chain, total_supply))
        data_reason = data_reason.strip();

        authenticity = 1 if total_supply > 0 else 0
        quality = 1 if len(data_reason) >= 15 else 0.5

        uniqueness = 0
        if ownership and authenticity:
            hash_string = f"{account_email}-{data_chain}-{data_contract}"
            hash_object = hashlib.sha256(hash_string.encode('utf-8'))
            is_repeat = check_hash_repeat(api_url, hash_object.hexdigest())
            if not is_repeat:
                uniqueness = 1

        self.proof_response.ownership = ownership
        self.proof_response.quality = quality
        self.proof_response.authenticity = authenticity
        self.proof_response.uniqueness = uniqueness

        # Calculate overall score and validity
        total_score = quality * (1 if uniqueness else 0.2) * ownership * authenticity
        self.proof_response.score = total_score
        self.proof_response.valid = ownership and total_score >= 0

        # Additional (public) properties to include in the proof about the data
        self.proof_response.attributes = {
            'total_score': total_score,
            'score_threshold': quality,
            'email_verified': email_matches,
        }

        # Additional metadata about the proof, written onchain
        self.proof_response.metadata = {
            'dlp_id': self.config['dlp_id'],
        }

        return self.proof_response

def get_total_supply_evm(rpc_url, token_address):
    payload = {
        "jsonrpc": "2.0",
        "method": "eth_call",
        "params": [
            {
                "to": token_address, 
                "data": TOTAL_SUPPLY_METHOD, 
            },
            "latest", 
        ],
        "id": 1,
    }

    try:
        response = requests.post(rpc_url, json=payload, timeout=3)
        response.raise_for_status()
        result = response.json()

        total_supply_hex = result.get("result")
        if total_supply_hex:
            total_supply = int(total_supply_hex, 16)
            return total_supply
        else:
            return 0
    except Exception as e:
        logging.error("request error: %s", str(e), exc_info=True)
        return 0
    
def get_total_supply_solana(rpc_url, token_mint_address):
    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "getAccountInfo",
        "params": [
            token_mint_address, 
            {"encoding": "base64"},  
        ],
    }
    try:
        response = requests.post(rpc_url, json=payload, timeout=3)
        response.raise_for_status()
        result = response.json()

        account_info = result.get("result", {}).get("value")
        if account_info is None:
            logging.error( f"Error: Mint account {token_mint_address} not found.")
            return 0

        account_data = account_info["data"][0]
        decoded_data = b64decode(account_data)

        # Mint Account 
        mint_supply = int.from_bytes(decoded_data[36:44], "little") 
        # decimals = decoded_data[44] 
        # total_supply = mint_supply / (10 ** decimals)
        # return total_supply
        return mint_supply
    except Exception as e:
        logging.error("request error: %s", str(e), exc_info=True)
        return 0
  
def check_hash_repeat(rpc_url, hash):
    payload = {
        "hash": hash,
    }
    try:
        response = requests.post(rpc_url, json=payload, timeout=3)
        response.raise_for_status()
        result = response.json()

        result_data = bool(result.get("data", False))

        return not result_data
    
    except Exception as e:
        logging.error("request error: %s", str(e), exc_info=True)
        return True