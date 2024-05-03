import unittest
import json
from tp import LandRegistryTransactionHandler, NAMESPACE, _hash, Transaction, TpStateEntry
import time

class MockContext:
    def __init__(self):
        self.state = {}

    def get_state(self, addresses):
        return [TpStateEntry(address=a, data=self.state[a]) for a in addresses if a in self.state]

    def set_state(self, state_dict):
        self.state.update(state_dict)


class TestLandRegistryTransactionHandler(unittest.TestCase):
    def setUp(self):
        self.handler = LandRegistryTransactionHandler(NAMESPACE)
        self.context = MockContext()

    def test_LockAsset_LandResgistry(self):
        # Create a mock transaction
        transaction = Transaction()
        transaction.payload = json.dumps({
            'operation': 'LockAsset',
            'reg_no': '123',
            'owner': 'Alice',
            'private_key': 'alice_private_key',
            'hash_value1': 'hash_value1',
            'hash_value2': 'hash_value2',
            'destination_owner': 'Bob',
            'time_limit': '1000'
        }).encode('utf-8')

        # Create a mock LandRegistry
        reg_no_hash = _hash('123'.encode('utf-8'))[0:64]
        self.context.state[NAMESPACE + reg_no_hash] = json.dumps({
            'owner': 'Alice',
            'lock_status': False
        }).encode('utf-8')

        # Apply the transaction
        self.handler.apply(transaction, self.context)

        # Check the state changes
        LandRegistry = json.loads(self.context.state[NAMESPACE + reg_no_hash])
        current_time = int(time.time())
        expected_time_limit = current_time + 1000
        self.assertEqual(LandRegistry['owner'], "No owner,smart contract Locked this asset")
        self.assertEqual(LandRegistry['destination_owner'], 'Bob')
        self.assertEqual(LandRegistry['private_key'], None)
        self.assertEqual(LandRegistry['lock_status'], True)
        self.assertEqual(LandRegistry['time_limit'], expected_time_limit)

if __name__ == '__main__':
    unittest.main()
