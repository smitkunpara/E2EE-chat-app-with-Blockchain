from web3 import Web3
import json

contract_abi = abi=json.loads('''[
	{
		"inputs": [
			{
				"internalType": "address",
				"name": "newOwner",
				"type": "address"
			}
		],
		"name": "changeOwner",
		"outputs": [],
		"stateMutability": "nonpayable",
		"type": "function"
	},
	{
		"inputs": [
			{
				"internalType": "string",
				"name": "username",
				"type": "string"
			},
			{
				"internalType": "string",
				"name": "user_password",
				"type": "string"
			}
		],
		"name": "setUser",
		"outputs": [],
		"stateMutability": "nonpayable",
		"type": "function"
	},
	{
		"inputs": [],
		"stateMutability": "nonpayable",
		"type": "constructor"
	},
	{
		"inputs": [
			{
				"internalType": "string",
				"name": "username",
				"type": "string"
			},
			{
				"internalType": "string",
				"name": "newPublickey",
				"type": "string"
			},
			{
				"internalType": "uint256",
				"name": "time",
				"type": "uint256"
			}
		],
		"name": "updateUser",
		"outputs": [],
		"stateMutability": "nonpayable",
		"type": "function"
	},
	{
		"inputs": [
			{
				"internalType": "string",
				"name": "username",
				"type": "string"
			}
		],
		"name": "getUserData",
		"outputs": [
			{
				"internalType": "string",
				"name": "",
				"type": "string"
			},
			{
				"internalType": "string",
				"name": "",
				"type": "string"
			},
			{
				"internalType": "string",
				"name": "",
				"type": "string"
			},
			{
				"internalType": "uint256",
				"name": "",
				"type": "uint256"
			}
		],
		"stateMutability": "view",
		"type": "function"
	},
	{
		"inputs": [],
		"name": "owner",
		"outputs": [
			{
				"internalType": "address",
				"name": "",
				"type": "address"
			}
		],
		"stateMutability": "view",
		"type": "function"
	},
	{
		"inputs": [
			{
				"internalType": "string",
				"name": "",
				"type": "string"
			}
		],
		"name": "userDataByUsername",
		"outputs": [
			{
				"internalType": "string",
				"name": "username",
				"type": "string"
			},
			{
				"internalType": "string",
				"name": "user_password",
				"type": "string"
			},
			{
				"internalType": "string",
				"name": "publickey",
				"type": "string"
			},
			{
				"internalType": "uint256",
				"name": "current_time",
				"type": "uint256"
			}
		],
		"stateMutability": "view",
		"type": "function"
	}
]''')

web3 = Web3(Web3.HTTPProvider('HTTP://127.0.0.1:8545'))
web3.eth.default_account=web3.eth.accounts[0]
contract_address = '0x126FAE1B3544D9b8A819d31FAB1fe196B11412b2'
contract = web3.eth.contract(address=contract_address, abi=contract_abi)
account = '0xc984C2244Eb805dADFd03E73e7E73Ad5557748D9'
private_key = '0x63b08d56d9cdd782ef49f80ca91050fbc510709f2515ab8e47c76782eaf01e3f'

def set_user_data(username, user_password,):
	try:
		txn_dict = contract.functions.setUser(username, user_password).build_transaction(
			{
				'from': account,
				'gas': 3000000,
				'gasPrice': web3.to_wei('1', 'gwei'),
				'nonce': web3.eth.get_transaction_count(account),
			}
		)
		signed_txn = web3.eth.account.sign_transaction(txn_dict, private_key=private_key)
		result = web3.eth.send_raw_transaction(signed_txn.rawTransaction)
		return result.hex()
	except Exception as e:
		print(e)
		return None

def get_user_data(username):
	try:
		result = contract.functions.getUserData(username).call()
		return result
	except Exception as e:
		return None

def update_user_data(username,pubkey,time):
	try:
		nonce = web3.eth.get_transaction_count(account)
		txn_dict = contract.functions.updateUser(username, pubkey, time).build_transaction(
			{
				'from': account,
				'gas': 3000000,
				'gasPrice': web3.to_wei('1', 'gwei'),
				'nonce': nonce,
			}
		)
		signed_txn = web3.eth.account.sign_transaction(txn_dict, private_key=private_key)
		result = web3.eth.send_raw_transaction(signed_txn.rawTransaction)
	except Exception as e:
		print(e)
		return None




# set_user_data("smit","smit")
# set_user_data("user2","pass2")
# set_user_data("user3","pass3")

# print(get_user_data("user1"))
# print(get_user_data("user2"))
# print(get_user_data("user3"))

# update_user_data("user1","pubkey1",1)
# update_user_data("user2","pubkey2",2)
# update_user_data("user3","pubkey3",3)

# print(get_user_data("user1"))
# print(get_user_data("user2"))
# print(get_user_data("user3"))