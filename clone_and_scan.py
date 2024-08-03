# clone_and_scan.py
import os
import git

repo_url = 'https://github.com/pavankalyanvarikolu/terraform-infra.git'
local_path = 'terraform-infra'

if os.path.exists(local_path):
    print(f'Repository already cloned at {local_path}. Pulling latest changes...')
    git_repo = git.Repo(local_path)
    git_repo.remote().pull()
else:
    print(f'Cloning repository from {repo_url} into {local_path}...')
    git.Repo.clone_from(repo_url, local_path)
