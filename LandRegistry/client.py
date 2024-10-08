import argparse
import json
import os
import hashlib
import requests
import base64
from sawtooth_signing import create_context
from sawtooth_signing import CryptoFactory
from sawtooth_signing import ParseError
from sawtooth_signing.secp256k1 import Secp256k1PrivateKey
from sawtooth_sdk.protobuf.transaction_pb2 import TransactionHeader, Transaction
from sawtooth_sdk.protobuf.batch_pb2 import Batch, BatchHeader, BatchList
import time
import pickle

NAMESPACE = hashlib.sha512('LandRegistry'.encode('utf-8')).hexdigest()[0:6]
URL='http://rest-api:8008'


def _hash(data):
        '''Compute the SHA-512 hash and return the result as hex characters.'''
        return hashlib.sha512(data).hexdigest()


def _get_keyfile(customerName):
    '''Get the private key for a customer.'''
    home = os.path.expanduser("~")
    key_dir = os.path.join(home, ".sawtooth", "keys")
    key_file = '{}/{}.priv'.format(key_dir, customerName)

    if not os.path.exists(key_file):
        return None 
    return key_file

def create_LandRegistry(reg_no, det, owner, private_key, url):
    # Prepare the transaction payload
    hashed_private_key=_hash(private_key.encode('utf-8'))[0:64]
    payload = {
    
        'operation':'register',
        'reg_no': reg_no,
        'det': det,
        'owner': owner,
        'price': -1,
        'private_key':hashed_private_key,
        'hash_value':None,
        'destination_owner':None,
        'time_limit':0,
        'lock_status':False
    }
    #checking the registry number already existed or not
    if get_LandRegistry(reg_no,URL) is not None:
            print(f"Registry no. {reg_no} already exists for owner {owner}")
            
    else:
         
        reg_no=_hash(reg_no.encode('utf-8'))[0:64]
        client_file=_get_keyfile(private_key)
        if client_file is None:
            print("User is not existed in the blockchain network,please generate private and public keys")
            return
        file_temp= open(_get_keyfile(private_key))
        privateKeyStr= file_temp.read().strip()
        privateKey = Secp256k1PrivateKey.from_hex(privateKeyStr)
        signer = CryptoFactory(create_context('secp256k1')) \
                .new_signer(privateKey)
        publicKey = signer.get_public_key().as_hex()

        file_temp= open(_get_keyfile("client"))
        #file_temp= open(_get_keyfile(owner))
        privateKeyStr= file_temp.read().strip()
        private_temp = Secp256k1PrivateKey.from_hex(privateKeyStr)
        signer_temp = CryptoFactory(create_context('secp256k1')) \
                .new_signer(private_temp)
        publicKey_temp = signer_temp.get_public_key().as_hex()

        transaction_id=None
        # Create a transaction header
        transaction_header = TransactionHeader(
            signer_public_key=publicKey,
            family_name='LandRegistry',
            family_version='1.0',
            inputs=[NAMESPACE + reg_no],
            outputs=[NAMESPACE + reg_no],
            dependencies=[],
            payload_sha512=hashlib.sha512(json.dumps(payload).encode()).hexdigest(),
            batcher_public_key=publicKey_temp,
            nonce='').SerializeToString()

        # Create a transaction
        transaction = Transaction(
            header=transaction_header,
            payload=json.dumps(payload).encode(),
            header_signature=signer.sign(transaction_header))
        # Create a batch header
        batch_header = BatchHeader(
            signer_public_key=publicKey_temp,
            transaction_ids=[transaction.header_signature]).SerializeToString()
        #ransaction_id=batch_header[transaction_ids]
            

        # Create a batch
        batch = Batch(
            header=batch_header,
            transactions=[transaction],
            header_signature=signer_temp.sign(batch_header))
            
            
        batch_list = BatchList(batches=[batch])

        
        batch_list_bytes = batch_list.SerializeToString()
        #batch_signature = signer_temp.sign(batch_list_bytes)
        #batch.header_signature = batch_signature
        # Update the batch header signature
        

        # Submit the batch to the validator
        #print("batcher_publickey:",publicKey_temp)
        #print("transaction details:",transaction)
        print("Land Registered successfully in LandRegistry")
        print("Transaction_Header id:",transaction_id)
        submit_batch(url, batch_list_bytes)


def setPrice_LandRegistry(reg_no, price,owner, private_key, url):
    # Prepare the transaction payload
    payload = {
        'operation':'setPrice',    
        'reg_no': reg_no,
        'setPrice': price
    }
    LandRegistry = get_LandRegistry(reg_no, URL)
    #print("LandRegistry:",LandRegistry['key'],"privatekey:",private_key)
    if LandRegistry['private_key']!=_hash(private_key.encode('utf-8'))[0:64]:
        print("Unauthorized Access")
        return
    
    reg_no=_hash(reg_no.encode('utf-8'))[0:64]
    file_temp= open(_get_keyfile(private_key))
    privateKeyStr= file_temp.read().strip()
    privateKey = Secp256k1PrivateKey.from_hex(privateKeyStr)
    signer = CryptoFactory(create_context('secp256k1')) \
            .new_signer(privateKey)
    publicKey = signer.get_public_key().as_hex()
    
    file_temp= open(_get_keyfile("client"))
    #file_temp= open(_get_keyfile(owner))
    privateKeyStr= file_temp.read().strip()
    private_temp = Secp256k1PrivateKey.from_hex(privateKeyStr)
    signer_temp = CryptoFactory(create_context('secp256k1')) \
            .new_signer(private_temp)
    publicKey_temp = signer_temp.get_public_key().as_hex()

    # Create a transaction header
    transaction_header = TransactionHeader(
        signer_public_key=publicKey,
        family_name='LandRegistry',
        family_version='1.0',
        inputs=[NAMESPACE + reg_no],
        outputs=[NAMESPACE + reg_no],
        dependencies=[],
        payload_sha512=hashlib.sha512(json.dumps(payload).encode()).hexdigest(),
        batcher_public_key=publicKey_temp,
        nonce='').SerializeToString()

    # Create a transaction
    transaction = Transaction(
        header=transaction_header,
        payload=json.dumps(payload).encode(),
        header_signature=signer.sign(transaction_header))

    # Create a batch header
    batch_header = BatchHeader(
        signer_public_key=publicKey_temp,
        transaction_ids=[transaction.header_signature]).SerializeToString()

    # Create a batch
    batch = Batch(
        header=batch_header,
        transactions=[transaction],
        header_signature=signer_temp.sign(batch_header))
        
        
    batch_list = BatchList(batches=[batch])

    
    batch_list_bytes = batch_list.SerializeToString()
    #batch_signature = signer_temp.sign(batch_list_bytes)
    #batch.header_signature = batch_signature
    # Update the batch header signature
    

    # Submit the batch to the validator
    #print(NAMESPACE + reg_no)
    print("price updated successfully")
    submit_batch(url, batch_list_bytes)

def buyPrice_LandRegistry(reg_no, price,new_owner, private_key, url):
    # Prepare the transaction payload
    payload = {
        'operation':'buyPrice',    
        'reg_no': reg_no,
        'new_owner': new_owner,
        'price':price,
        'private_key':private_key
    }
    LandRegistry = get_LandRegistry(reg_no, URL)
    print("land details:",LandRegistry)
    if LandRegistry['price']==-1:
         print("Land price is not set by the owner")
         return
    if LandRegistry['price']>price:
        print("Price not met")
        return
    print(f"Land being transafered successfully to {new_owner}")
    reg_no=_hash(reg_no.encode('utf-8'))[0:64]
    file_temp= open(_get_keyfile(private_key))
    privateKeyStr= file_temp.read().strip()
    privateKey = Secp256k1PrivateKey.from_hex(privateKeyStr)
    signer = CryptoFactory(create_context('secp256k1')) \
            .new_signer(privateKey)
    publicKey = signer.get_public_key().as_hex()

    file_temp= open(_get_keyfile("client"))
    #file_temp= open(_get_keyfile(new_owner))
    privateKeyStr= file_temp.read().strip()
    private_temp = Secp256k1PrivateKey.from_hex(privateKeyStr)
    signer_temp = CryptoFactory(create_context('secp256k1')) \
            .new_signer(private_temp)
    publicKey_temp = signer_temp.get_public_key().as_hex()

    # Create a transaction header
    transaction_header = TransactionHeader(
        signer_public_key=publicKey,
        family_name='LandRegistry',
        family_version='1.0',
        inputs=[NAMESPACE + reg_no],
        outputs=[NAMESPACE + reg_no],
        dependencies=[],
        payload_sha512=hashlib.sha512(json.dumps(payload).encode()).hexdigest(),
        batcher_public_key=publicKey_temp,
        nonce='').SerializeToString()

    # Create a transaction
    transaction = Transaction(
        header=transaction_header,
        payload=json.dumps(payload).encode(),
        header_signature=signer.sign(transaction_header))

    # Create a batch header
    batch_header = BatchHeader(
        signer_public_key=publicKey_temp,
        transaction_ids=[transaction.header_signature]).SerializeToString()

    # Create a batch
    batch = Batch(
        header=batch_header,
        transactions=[transaction],
        header_signature=signer_temp.sign(batch_header))
        
        
    batch_list = BatchList(batches=[batch])

    
    batch_list_bytes = batch_list.SerializeToString()
    #batch_signature = signer_temp.sign(batch_list_bytes)
    #batch.header_signature = batch_signature
    # Update the batch header signature
    

    # Submit the batch to the validator
    #print(NAMESPACE + reg_no)
    submit_batch(url, batch_list_bytes)

#########My code starts####################
def LockAsset_LandRegistry(reg_no, owner, private_key,destination_owner, hash_value,time_limit,url):
    # Prepare the transaction payload
    payload = {
        'operation':'LockAsset',    
        'reg_no': reg_no,
        'owner': owner,
        'private_key':_hash(private_key.encode('utf-8'))[0:64],
        'destination_owner':destination_owner,
        'hash_value':_hash(hash_value.encode('utf-8'))[0:64],
        'time_limit':time_limit,
    }
    LandRegistry = get_LandRegistry(reg_no, URL)
    #print("land details:",LandRegistry)

    if LandRegistry is None:
        print("LandRegistry not found")
        return
    if LandRegistry['private_key']!=_hash(private_key.encode('utf-8'))[0:64]:
         print("Unauthorized Access")
         return
    print(f"Land being locked successfully by {owner}")
    reg_no=_hash(reg_no.encode('utf-8'))[0:64]
    file_temp= open(_get_keyfile(private_key))
    privateKeyStr= file_temp.read().strip()
    privateKey = Secp256k1PrivateKey.from_hex(privateKeyStr)
    signer = CryptoFactory(create_context('secp256k1')) \
            .new_signer(privateKey)
    publicKey = signer.get_public_key().as_hex()

    file_temp= open(_get_keyfile("client"))
    #file_temp= open(_get_keyfile(new_owner))
    privateKeyStr= file_temp.read().strip()
    private_temp = Secp256k1PrivateKey.from_hex(privateKeyStr)
    signer_temp = CryptoFactory(create_context('secp256k1')) \
            .new_signer(private_temp)
    publicKey_temp = signer_temp.get_public_key().as_hex()

    # Create a transaction header
    transaction_header = TransactionHeader(
        signer_public_key=publicKey,
        family_name='LandRegistry',
        family_version='1.0',
        inputs=[NAMESPACE + reg_no],
        outputs=[NAMESPACE + reg_no],
        dependencies=[],
        payload_sha512=hashlib.sha512(json.dumps(payload).encode()).hexdigest(),
        batcher_public_key=publicKey_temp,
        nonce='').SerializeToString()

    # Create a transaction
    transaction = Transaction(
        header=transaction_header,
        payload=json.dumps(payload).encode(),
        header_signature=signer.sign(transaction_header))

    # Create a batch header
    batch_header = BatchHeader(
        signer_public_key=publicKey_temp,
        transaction_ids=[transaction.header_signature]).SerializeToString()

    # Create a batch
    batch = Batch(
        header=batch_header,
        transactions=[transaction],
        header_signature=signer_temp.sign(batch_header))
        
        
    batch_list = BatchList(batches=[batch])

    
    batch_list_bytes = batch_list.SerializeToString()
    #batch_signature = signer_temp.sign(batch_list_bytes)
    #batch.header_signature = batch
    submit_batch(url, batch_list_bytes)


def ClaimAsset_LandRegistry(reg_no, new_owner, private_key, secret_key,url):
    # Prepare the transaction payload
    payload = {
        'operation':'ClaimAsset',
        'reg_no': reg_no,
        'new_owner': new_owner,
        'private_key':_hash(private_key.encode('utf-8'))[0:64],
        'secret_key':_hash(secret_key.encode('utf-8'))[0:64],
    }
    LandRegistry = get_LandRegistry(reg_no, URL)
    if LandRegistry is None:
         print("LandRegistry not found")
         return
    print("Request sent to Validator for Claiming the Asset,check the status by getDetails function")
    reg_no=_hash(reg_no.encode('utf-8'))[0:64]
    file_temp= open(_get_keyfile(private_key))
    privateKeyStr= file_temp.read().strip()
    privateKey = Secp256k1PrivateKey.from_hex(privateKeyStr)
    signer = CryptoFactory(create_context('secp256k1')) \
            .new_signer(privateKey)
    publicKey = signer.get_public_key().as_hex()

    file_temp= open(_get_keyfile("client"))
    #file_temp= open(_get_keyfile(new_owner))
    privateKeyStr= file_temp.read().strip()
    private_temp = Secp256k1PrivateKey.from_hex(privateKeyStr)
    signer_temp = CryptoFactory(create_context('secp256k1')) \
            .new_signer(private_temp)
    publicKey_temp = signer_temp.get_public_key().as_hex()

    # Create a transaction header
    transaction_header = TransactionHeader(
        signer_public_key=publicKey,
        family_name='LandRegistry',
        family_version='1.0',
        inputs=[NAMESPACE + reg_no],
        outputs=[NAMESPACE + reg_no],
        dependencies=[],
        payload_sha512=hashlib.sha512(json.dumps(payload).encode()).hexdigest(),
        batcher_public_key=publicKey_temp,
        nonce='').SerializeToString()

    # Create a transaction
    transaction = Transaction(
        header=transaction_header,
        payload=json.dumps(payload).encode(),
        header_signature=signer.sign(transaction_header))

    # Create a batch header
    batch_header = BatchHeader(
        signer_public_key=publicKey_temp,
        transaction_ids=[transaction.header_signature]).SerializeToString()

    # Create a batch
    batch = Batch(
        header=batch_header,
        transactions=[transaction],
        header_signature=signer_temp.sign(batch_header))
        
        
    batch_list = BatchList(batches=[batch])

    
    batch_list_bytes = batch_list.SerializeToString()
    submit_batch(url, batch_list_bytes)


def RefundAsset_LandRegistry(reg_no, new_owner, private_key,secret_key,url):
    # Prepare the transaction payload
    payload = {
        'operation':'RefundAsset',    
        'reg_no': reg_no,
        'new_owner': new_owner,
        'private_key':_hash(private_key.encode('utf-8'))[0:64],
        'secret_key':_hash(secret_key.encode('utf-8'))[0:64],
    }
    LandRegistry = get_LandRegistry(reg_no, URL)
    if LandRegistry is None:
         print("LandRegistry not found")
         return
    print("Request sent to Validator for Refunding the Asset,check the status by getDetails function")
    reg_no=_hash(reg_no.encode('utf-8'))[0:64]
    file_temp= open(_get_keyfile(private_key))
    privateKeyStr= file_temp.read().strip()
    privateKey = Secp256k1PrivateKey.from_hex(privateKeyStr)
    signer = CryptoFactory(create_context('secp256k1')) \
            .new_signer(privateKey)
    publicKey = signer.get_public_key().as_hex()

    file_temp= open(_get_keyfile("client"))
    #file_temp= open(_get_keyfile(new_owner))
    privateKeyStr= file_temp.read().strip()
    private_temp = Secp256k1PrivateKey.from_hex(privateKeyStr)
    signer_temp = CryptoFactory(create_context('secp256k1')) \
            .new_signer(private_temp)
    publicKey_temp = signer_temp.get_public_key().as_hex()

    # Create a transaction header
    transaction_header = TransactionHeader(
        signer_public_key=publicKey,
        family_name='LandRegistry',
        family_version='1.0',
        inputs=[NAMESPACE + reg_no],
        outputs=[NAMESPACE + reg_no],
        dependencies=[],
        payload_sha512=hashlib.sha512(json.dumps(payload).encode()).hexdigest(),
        batcher_public_key=publicKey_temp,
        nonce='').SerializeToString()

    # Create a transaction
    transaction = Transaction(
        header=transaction_header,
        payload=json.dumps(payload).encode(),
        header_signature=signer.sign(transaction_header))

    # Create a batch header
    batch_header = BatchHeader(
        signer_public_key=publicKey_temp,
        transaction_ids=[transaction.header_signature]).SerializeToString()

    # Create a batch
    batch = Batch(
        header=batch_header,
        transactions=[transaction],
        header_signature=signer_temp.sign(batch_header))
        
        
    batch_list = BatchList(batches=[batch])

    
    batch_list_bytes = batch_list.SerializeToString()
    submit_batch(url, batch_list_bytes)





# Get transaction details
def get_transaction_details(transaction_id, url):
    response = requests.get(f'{url}/transactions/{transaction_id}')
    data = response.json()

    if 'data' in data:
        # Decode the base64 encoded payload
        payload = base64.b64decode(data['data']['payload']).decode('utf-8')
        # Load the payload as JSON
        payload = json.loads(payload)
        return payload
    else:
        return None
    


#########My code ends####################


def get_LandRegistry(reg_no, url):
    reg_no=_hash(reg_no.encode('utf-8'))[0:64]
    response = requests.get(f'{url}/state/{NAMESPACE}{reg_no}')
    data = response.json()
    
    if 'data' in data:
        state_data = base64.b64decode(data['data']).decode()
        #print(json.loads(state_data))
        return json.loads(state_data)
    else:
        return None


def submit_batch(url, batch_list_bytes):
    headers = {'Content-Type': 'application/octet-stream'}
    data=batch_list_bytes
    url='http://rest-api:8008/batches'
    try:
            if data is not None:
                result = requests.post(url, headers=headers, data=data)
            else:
                result = requests.get(url, headers=headers)

            if not result.ok:
                raise Exception("Error {}: {}".format(
                    result.status_code, result.reason))
    except requests.ConnectionError as err:
            raise Exception('Failed to connect to {}: {}'.format(url, str(err)))
    except BaseException as err:
            raise Exception(err)
    

def main():
    parser = argparse.ArgumentParser(description='LandRegistry Client')
    parser.add_argument('action', choices=['register', 'setPrice','buyPrice', 'getDetails','LockAsset','ClaimAsset','RefundAsset','getByTxnId'], help='LandRegistry action')
    parser.add_argument('--reg-no', help='registry no.')
    parser.add_argument('--det', help='Land details no.')    
    parser.add_argument('--owner', help='Owner')
    parser.add_argument('--new-owner', help='New owner')
    parser.add_argument('--private-key', help='Private key')
    parser.add_argument('--destination-owner', help='Destination owner')
    parser.add_argument('--secret-key', help='Secret key')
    parser.add_argument('--hash-value', help='Hash value')
    parser.add_argument('--time-limit', help='Time limit for the transaction')
    parser.add_argument('--price',help='Buy/Sell at price')
    parser.add_argument('--govt',help='Government password')
    parser.add_argument('--transaction-id', help='Transaction ID')
    parser.add_argument('--url', default='http://rest-api:8008', help='Sawtooth REST API URL')
    args = parser.parse_args()
    #print("argments are :",args)
    if args.action == 'register':
        if args.govt == 'qwerty':
            create_LandRegistry(args.reg_no, args.det, args.owner, args.private_key, args.url)
        else:
            print("Need govt approval")
            print("Do not have access to register new Lands")            
    elif args.action == 'setPrice':

        setPrice_LandRegistry(args.reg_no, args.price,args.owner, args.private_key, args.url)
    elif args.action == 'buyPrice':
        buyPrice_LandRegistry(args.reg_no, args.price,args.new_owner, args.private_key, args.url)        
    elif args.action == 'getDetails':
        LandRegistry = get_LandRegistry(args.reg_no, args.url)
        if LandRegistry:
            #print(f"comple details in json form: {LandRegistry}")
            print("Land Registry num: ",LandRegistry['reg_no'])
            print("Owner: ",LandRegistry['owner'])
            print("Land Details: ",LandRegistry['det'])
            print("Price: ",LandRegistry['price'])                                
        else:
            print("LandRegistry not found.")
            print("check registration num proporly")
    ### my functions starts
    
    elif args.action == 'LockAsset':
        
        LockAsset_LandRegistry(args.reg_no, args.owner,args.private_key,args.destination_owner,args.hash_value,args.time_limit,args.url)
        
    elif args.action == 'ClaimAsset':
        
        ClaimAsset_LandRegistry(args.reg_no, args.new_owner,args.private_key,args.secret_key,args.url)
    elif args.action == 'RefundAsset':
        
        RefundAsset_LandRegistry(args.reg_no, args.new_owner, args.private_key,args.secret_key,args.url)


    elif args.action == 'getByTxnId':
        transaction = get_transaction_details(args.transaction_id, args.url)
        if transaction:
            print(transaction)
        else:
            print("No transaction found for the given transaction ID.")

    
    ### my functions ends
        


if __name__ == '__main__':
    #print("Hello")
    main()


