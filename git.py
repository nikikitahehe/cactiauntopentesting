import os
import subprocess

def run_command(command):
    process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = process.communicate()
    if process.returncode != 0:
        print(f"Error: {stderr.decode('utf-8')}")
    else:
        print(stdout.decode('utf-8'))

def git_add_all():
    run_command("git add .")

def git_commit(message):
    run_command(f'git commit -m "{message}"')

def git_push(branch="master"):
    run_command(f"git push origin {branch}")

if __name__ == "__main__":
    # Langkah-langkah
    git_add_all()
    git_commit("Menambahkan file hasil scan dan laporan penetrasi")
    git_push()
