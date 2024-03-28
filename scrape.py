import asyncio
import sys
import websockets
import json
from solana.rpc.api import Client
from solders.pubkey import Pubkey  # type: ignore
from solders.signature import Signature  # type: ignore
import pandas as pd
from tabulate import tabulate
from portalocker import Lock, unlock
import os
import time  # Add this import for time.sleep

wallet_address = "675kPX9MHTjS2zt1qfr1NYHuzeLXfQM9H24wFSUt1Mp8"
seen_signatures = set()
solana_client = Client("https://api.mainnet-beta.solana.com")

def lock_file(file_path):
    lock_file_path = file_path + ".lock"
    lock = Lock(lock_file_path)
    lock.acquire()

def unlock_file(file_path):
    lock_file_path = file_path + ".lock"
    with open(lock_file_path, "w") as lock_file:
        unlock(lock_file)

def save_token_address(token_address):
    with open('token_address.txt', 'w') as file:
        file.write(str(token_address))

async def getTokensWithBackoff(str_signature):
    retries = 5  # Maximum number of retries
    for i in range(retries):
        try:
            return await getTokens(str_signature)
        except Exception as e:
            print(f"Error: {e}. Retrying in {2**i} seconds...")
            time.sleep(2**i)
    raise Exception("Exceeded maximum retries. Unable to get tokens.")

async def getTokens(str_signature):
    signature = Signature.from_string(str_signature)
    transaction = solana_client.get_transaction(
        signature, encoding="jsonParsed", max_supported_transaction_version=0).value
    instruction_list = transaction.transaction.transaction.message.instructions
    for instructions in instruction_list:
        if instructions.program_id == Pubkey.from_string(wallet_address):
            print("============NEW POOL DETECTED====================")
            Token0 = instructions.accounts[8]
            Token1 = instructions.accounts[9]
            # Your data
            data = {'Token_Index': ['Token0', 'Token1'],
                    'Account Public Key': [Token0, Token1]}
            df = pd.DataFrame(data)
            table = tabulate(df, headers='keys', tablefmt='fancy_grid')
            print(table)
            token_address = Token0 if Token0 != wallet_address else Token1
            save_token_address(token_address)
            print(f"Token address saved to token_address.txt")

async def run():
    uri = "wss://api.mainnet-beta.solana.com"
    async with websockets.connect(uri) as websocket:
        # Send subscription request
        await websocket.send(json.dumps({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "logsSubscribe",
            "params": [
                {"mentions": [wallet_address]},
                {"commitment": "finalized"}
            ]
        }))
        first_resp = await websocket.recv()
        response_dict = json.loads(first_resp)
        if 'result' in response_dict:
            print("Subscription successful. Subscription ID: ", response_dict['result'])
        # Continuously read from the WebSocket
        async for response in websocket:
            response_dict = json.loads(response)
            if response_dict['params']['result']['value']['err'] is None:
                signature = response_dict['params']['result']['value']['signature']
                if signature not in seen_signatures:
                    seen_signatures.add(signature)
                    log_messages_set = set(response_dict['params']['result']['value']['logs'])
                    search = "initialize2"
                    if any(search in message for message in log_messages_set):
                        print(f"True, https://solscan.io/tx/{signature}")
                        await getTokensWithBackoff(signature)
                    else:
                        pass

async def main():
    await run()

if __name__ == "__main__":
    asyncio.run(main())
