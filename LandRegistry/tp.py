import hashlib
import json
import logging
import sys
import traceback
from sawtooth_sdk.processor.handler import TransactionHandler
from sawtooth_sdk.processor.core import TransactionProcessor
from sawtooth_sdk.protobuf.transaction_pb2 import TransactionHeader
from sawtooth_sdk.protobuf.transaction_pb2 import Transaction
from sawtooth_sdk.protobuf.transaction_receipt_pb2 import StateChangeList
from sawtooth_sdk.protobuf.transaction_receipt_pb2 import StateChange
from sawtooth_sdk.protobuf.state_context_pb2 import TpStateEntry
from sawtooth_sdk.protobuf.state_context_pb2 import TpStateGetResponse
from sawtooth_sdk.protobuf.transaction_pb2 import TransactionHeader
from sawtooth_sdk.protobuf.batch_pb2 import Batch
from sawtooth_sdk.protobuf.batch_pb2 import BatchHeader
from sawtooth_sdk.protobuf.batch_pb2 import BatchList
from sawtooth_sdk.processor.exceptions import InvalidTransaction
#user modules
import time

RETRY_TIMES = 5  # Number of retries
RETRY_DELAY = 5  # Delay between retries in seconds

LOGGER = logging.getLogger(__name__)

# Define the LandRegistry transaction family
FAMILY_NAME = 'LandRegistry'
FAMILY_VERSIONS = ['1.0']

# Define the LandRegistry transaction prefixes
NAMESPACE = hashlib.sha512(FAMILY_NAME.encode('utf-8')).hexdigest()[0:6]

def _hash(data):
    '''Compute the SHA-512 hash and return the result as hex characters.'''
    return hashlib.sha512(data).hexdigest()

class LandRegistryTransactionHandler(TransactionHandler):
    def __init__(self, namespace_prefix):
        self._namespace_prefix = namespace_prefix
        #for locking all the transactions
        self.locks=[]

    @property
    def family_name(self):
        return FAMILY_NAME

    @property
    def family_versions(self):
        return ['1.0']

    @property
    def namespaces(self):
        return [self._namespace_prefix]

    def apply(self, transaction, context):
        header = transaction.header
        payload = transaction.payload.decode('utf-8')
        data = json.loads(payload)

        LOGGER.info(f"Applying transaction: {data}")

        if data['operation'] == 'register':
            self._create_LandRegistry(payload, context)
        elif data['operation'] == 'setPrice':
            self.setPrice_LandRegistry(payload, context)
        elif data['operation'] == 'buyPrice':
            self.buyPrice_LandRegistry(payload, context)
        elif data['operation'] =='LockAsset':
            self.LockAsset_LandResgistry(payload, context)
        elif data['operation'] =='ClaimAsset':
            self.ClaimAsset_LandResgistry(payload, context)
        elif data['operation'] =='RefundAsset':
            self.RefundAsset_LandResgistry(payload, context)
        else:
            raise InvalidTransaction('Invalid transaction type')

    def _create_LandRegistry(self, payload, context):
        data = json.loads(payload)
        reg_no = data['reg_no']
        owner = data['owner']


        LOGGER.info(f"Creating LandRegistry: reg_no={reg_no}, owner={owner}")

        if _get_LandRegistry(context, reg_no) is not None:
            raise InvalidTransaction(f"Registry no. {reg_no} already exists for owner {owner}")
        
        _set_LandRegistry(context, reg_no, data)
    
    def setPrice_LandRegistry(self, payload, context):
        
        data = json.loads(payload)
        reg_no = data['reg_no']
        price = data['setPrice']
        
        LOGGER.info(f"Setting price for LandRegistry {reg_no} of {price}")

        LandRegistry = _get_LandRegistry(context, reg_no)
        if LandRegistry is None:
            raise InvalidTransaction(f"Registry no. {reg_no} does not exist")
        LOGGER.info(f"LandRegistry details: {LandRegistry}")
        LandRegistry['price'] = price
        _set_LandRegistry(context, reg_no, LandRegistry)

    def buyPrice_LandRegistry(self, payload, context):
        data = json.loads(payload)
        reg_no = data['reg_no']
        price = data['price']
        new_owner = data['new_owner']   
        key = data['private_key']
        #calling smart contract        
        #transferOwnership(self, payload, context)

        LOGGER.info(f"Buying LandRegistry {reg_no} for price {price} by {new_owner}")

        LandRegistry = _get_LandRegistry(context, reg_no)
        if LandRegistry is None:
            raise InvalidTransaction(f"Registry no. {reg_no} does not exist")
        
        LandRegistry['price'] = -1
        LandRegistry['owner'] = new_owner
        LandRegistry['key'] = key
        _set_LandRegistry(context, reg_no, LandRegistry)




###########My code starts#################
    def LockAsset_LandResgistry(self,payload,context):

        #required information
        data = json.loads(payload)
        reg_no = data['reg_no']
        owner = data['owner']
        private_key = data['private_key']
        hash_value1 = data['hash_value1']
        hash_value2= data['hash_value2']
        #whom want to send the asset(destination_Owner)
        destination_owner = data['destination_owner']

        #calculating total time for locking the asset
        current_time=int(time.time())
        time_limit=data['time_limit']
        total_time=current_time+int(time_limit)


        LOGGER.info("Locking the asset")
        LandRegistry = _get_LandRegistry(context, reg_no)
        #check LandRegistry is exist or not
        for _ in range(RETRY_TIMES):
            try:
                LandRegistry = _get_LandRegistry(context, reg_no)
                # Check LandRegistry is exist or not
                if LandRegistry is None:
                    raise InvalidTransaction(f"Registry no. {reg_no} does not exist")
                break  # If the request is successful, break the loop
            except Exception as e:
                LOGGER.error(f"Error getting LandRegistry: {e}")
                time.sleep(RETRY_DELAY)  # Wait before retrying
        else:
            raise InvalidTransaction(f"Failed to get LandRegistry after {RETRY_TIMES} retries")
        
        
        #checking the asset is already locked or not
        if LandRegistry['lock_status']==True:
            raise InvalidTransaction(f"Asset is already locked")
        
        #changes the ownership of the asset and Locking the asset for given time
        LandRegistry['hash_value1']=hash_value1
        if hash_value2 is not None:
            LandRegistry['hash_value2']=hash_value2
        LandRegistry['time_limit']=total_time
        LandRegistry['owner'] = "No owner,smart contract Locked this asset"
        LandRegistry['destination_owner']=destination_owner
        LandRegistry['private_key'] = None
        LandRegistry['lock_status'] = True
        LOGGER.info(f"Asset reg No:{reg_no} locked of the {owner}")
        _set_LandRegistry(context, reg_no, LandRegistry)


    #claim the asset by the owner
    def ClaimAsset_LandResgistry(self,payload,context):
        data = json.loads(payload)
        #required information
        reg_no = data['reg_no']
        new_owner = data['new_owner']
        secret_key1 = data['secret_key1']
        secret_key2 = data['secret_key2']
        private_key = data['private_key']
        
        #calculating the current time
        current_time=int(time.time())


        LandRegistry = _get_LandRegistry(context, reg_no)
        if LandRegistry is None:
            raise InvalidTransaction(f"Registry no. {reg_no} does not exist")
        
        #checking the asset is  locked or not
        if LandRegistry['lock_status']==False:
            LOGGER.info(f"Asset is not locked by orginal owner")
            return
        #checking the secret key is matching or not
        if LandRegistry['hash_value1']!=secret_key1:
            LOGGER.info(f"secret key1 is not matching")
            return
        if LandRegistry['hash_value2'] is not None:
            if secret_key2 is None:
                LOGGER.info(f"secret key2 is not provided,please give along with secret key1")
                return
            elif LandRegistry['hash_value2']!=secret_key2:
                LOGGER.info(f"secret key2 is not matching")
                return
            
        #checking the destination owner is same as new owner
        if LandRegistry['destination_owner']!=new_owner:
            LOGGER.info(f"destination owner is not matching")
            return
        #checking the time limit exceed or not
        if LandRegistry['time_limit']<current_time:
            LOGGER.info(f"Time limit exceed")
            return
        
        LandRegistry['hash_value']=None
        LandRegistry['owner'] = new_owner
        LandRegistry['destination_owner']=None
        LandRegistry['private_key'] = private_key
        LandRegistry['time_limit']=0
        LandRegistry['orginal_owner']=new_owner
        LandRegistry['lock_status'] = False
        LOGGER.info(f"Asset reg No:{reg_no} claimed by the {new_owner} successfully")
        _set_LandRegistry(context, reg_no, LandRegistry)

    
   #refund the asset to the owner
    def RefundAsset_LandResgistry(self,payload,context):
        data = json.loads(payload)
        #required information
        reg_no = data['reg_no']
        private_key = data['private_key']
    
        #calculating the current time
        current_time=int(time.time())


        LandRegistry = _get_LandRegistry(context, reg_no)
        if LandRegistry is None:
            raise InvalidTransaction(f"Registry no. {reg_no} does not exist")
        
        #checking the asset is  locked or not
        if LandRegistry['lock_status']==False:
            LOGGER.info(f"Asset is not locked by orginal owner")
            return
    
        #checking time limit exceed or not
        if LandRegistry['time_limit']>current_time:
            LOGGER.info(f"not possible to refund the asset before time limit exceed.")
            return
        
        #transfering the ownership
        LandRegistry['hash_value']=None
        LandRegistry['owner'] = LandRegistry['orginal_owner']
        LandRegistry['destination_owner']=None
        LandRegistry['private_key'] = private_key
        LandRegistry['time_limit']=0
        LandRegistry['lock_status'] = False
        LOGGER.info(f"Asset reg No:{reg_no} Refunded to the {LandRegistry['orginal_owner']} successfully")
        _set_LandRegistry(context, reg_no, LandRegistry)
        

 
#################MY CODE ENDS#################


def _get_LandRegistry(context, reg_no):
    reg_no = _hash(reg_no.encode('utf-8'))[0:64]
    state_entries = context.get_state([NAMESPACE + reg_no])
    #LOGGER.info(f"Getting Land registry details")
    if state_entries:    
        data = state_entries[0].data
        LandRegistry = json.loads(data)
        return LandRegistry
    return None

def _set_LandRegistry(context, reg_no, LandRegistry):
    state_change = StateChange()
    reg_no = _hash(reg_no.encode('utf-8'))[0:64]
    state_change.address = NAMESPACE + reg_no
    state_change.value = json.dumps(LandRegistry).encode()

    context.set_state({state_change.address: state_change.value})



def setup_loggers():
    logging.basicConfig()
    logging.getLogger().setLevel(logging.DEBUG)

def main():
    '''Entry-point function for the LandRegistry transaction processor.'''
    setup_loggers()
    try:
        # Register the transaction handler and start it.
        processor = TransactionProcessor(url='tcp://validator:4004')
        LOGGER.info("Transaction processor started")

        handler = LandRegistryTransactionHandler(NAMESPACE)

        processor.add_handler(handler)

        processor.start()

    except KeyboardInterrupt:
        pass
    except SystemExit as err:
        raise err
    except BaseException as err:
        traceback.print_exc(file=sys.stderr)
        sys.exit(1)

if __name__ == '__main__':
    main()
