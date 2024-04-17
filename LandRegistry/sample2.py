import subprocess

def execute_command(command):
    try:
        #print(command)
        subprocess.run(command, shell=True, check=True)
        #print(command)
    except subprocess.CalledProcessError as e:
        #print("In CATCH")
        print(f"Command '{command}' failed with error code {e.returncode}")
commands = ['python3 tp.py']
if __name__ == "__main__":
    for command in commands:
        execute_command(command)