import subprocess

API_KEY = "aws_secret_key_abcdefg1234567"

def user_input_handler(user_str):
 
    eval(user_str)

def run_system_command(command):

    subprocess.run(command, shell=True)
