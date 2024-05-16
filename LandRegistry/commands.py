import subprocess
import time

def execute_command(command):
    try:
        subprocess.run(command, shell=True, check=True)
    except subprocess.CalledProcessError as e:
        print(f"Command '{command}' failed with error code {e.returncode}")

# List of commands to execute
commands = [
    "sawtooth keygen owner1",
    "sawtooth keygen owner2",
    "sawtooth keygen client",
    "sawtooth block list --url http://rest-api:8008",
    "python3 client.py register --reg-no 12 --det 'plot 72, 100sqmts,...' --owner owner1 --private-key owner1 --govt 'qwerty'",
    "python3 client.py getDetails --reg-no 12",
    "python3 client.py setPrice --reg-no 12 --price 10234 --owner owner1 --private-key owner1",
    "python3 client.py getDetails --reg-no 12",
    "sawtooth block list --url http://rest-api:8008",
    "python3 client.py LockAsset --reg-no 12 --owner owner1 --private-key owner1 --destination-owner owner2 --hash-value1 pitla --time-limit 100 --hash-value2 bitla",
    "python3 client.py getDetails --reg-no 12",
    "python3 client.py ClaimAsset --reg-no 12 --new-owner owner2 --private-key owner2  --secret-key1 pitla --secret-key2 bitla",
    "python3 client.py getDetails --reg-no 12",
    "python3 client.py RefundAsset --reg-no 12 --private-key owner1 ",
    "python3 client.py getDetails --reg-no 12"
]

if __name__ == "__main__":
    for command in commands:
        execute_command(command)
        time.sleep(7)
