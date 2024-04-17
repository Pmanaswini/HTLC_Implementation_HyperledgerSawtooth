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
        self.start_time=0
        self.end_time=0
        self.h=""
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
        else:
            raise InvalidTransaction('Invalid transaction type')

    def _create_LandRegistry(self, payload, context):
        data = json.loads(payload)
        reg_no = data['reg_no']
        owner = data['owner']
        #data['owner']="Neha"

        LOGGER.info(f"Creating LandRegistry: reg_no={reg_no}, owner={owner}")

        if _get_LandRegistry(context, reg_no) is not None:
            raise InvalidTransaction(f"Registry no. {reg_no} already exists for owner {owner}")
        #setting time
        #self.start_time=time.time()
        #LOGGER.info(f"time starts at:{time.strftime("%H:%M:%S")}")
        LOGGER.info(f"time starts at:{self.start_time}")

        _set_LandRegistry(context, reg_no, data)
    
    def setPrice_LandRegistry(self, payload, context):
        #checking price updation happening within preiod of time or not
        self.end_time=time.time()
        #LOGGER.info(f"time end at:{self.end_time}")
        #if self.start_time-self.end_time>0.2:
            #raise InvalidTransaction(f"Time Limit exceed you have to perform price update within 20 seconds,you used time:{self.start_time-self.end_time}")
        data = json.loads(payload)
        reg_no = data['reg_no']
        price = data['setPrice']
        
        LOGGER.info(f"Setting price for LandRegistry {reg_no} to {price}")

        LandRegistry = _get_LandRegistry(context, reg_no)
        if LandRegistry is None:
            raise InvalidTransaction(f"Registry no. {reg_no} does not exist")

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
        data = json.loads(payload)
        reg_no = data['reg_no']
        owner = data['owner']
        key = data['private_key']
        LOGGER.info("Locking the asset")
        LandRegistry = _get_LandRegistry(context, reg_no)
        if LandRegistry is None:
            raise InvalidTransaction(f"Registry no. {reg_no} does not exist")
        self.h=hashlib.sha256(key.encode('utf-8')).hexdigest()
        LOGGER.info(f"Asset reg No:{reg_no} locked of the {owner}")

    def ClaimAsset_LandResgistry(self,payload,context):
        data = json.loads(payload)
        reg_no = data['reg_no']
        new_owner = data['new_owner']
        key = data['secret_key']
        private_key = data['private_key']
        #private_key = data['private_key']
        LandRegistry = _get_LandRegistry(context, reg_no)
        if LandRegistry is None:
            raise InvalidTransaction(f"Registry no. {reg_no} does not exist")
        #checking the given secret key is correct or not
        if self.h==hashlib.sha256(key.encode('utf-8')).hexdigest():
            LandRegistry['owner'] = new_owner
            LandRegistry['private_key'] = private_key
            LOGGER.info(f"Asset reg No:{reg_no} claimed by the {new_owner}")
            _set_LandRegistry(context, reg_no, LandRegistry)
        else:
            LOGGER.info(f"Asset reg No:{reg_no} not claimed by the {new_owner}")

#################MY CODE ENDS#################


def _get_LandRegistry(context, reg_no):
    reg_no = _hash(reg_no.encode('utf-8'))[0:64]
    state_entries = context.get_state([NAMESPACE + reg_no])
    LOGGER.info(f"Getting Land registry details")
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



def transferOwnership(self, payload, context):
        data = json.loads(payload)
        reg_no = data['reg_no']
        new_owner = data['new_owner']
        private_key = data['private_key']

        LandRegistry = _get_LandRegistry(context, reg_no)
        if LandRegistry is None:
            raise InvalidTransaction(f"Registry no. {reg_no} does not exist")

        # Verify ownership
        if LandRegistry['owner'] != private_key:
            raise InvalidTransaction("Unauthorized access")

        # Update owner
        LandRegistry['owner'] = new_owner
        _set_LandRegistry(context, reg_no, LandRegistry)



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
