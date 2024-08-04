import os
import subprocess
import sys
import shutil

def install_checkov():
    try:
        # Install Checkov using pip
        subprocess.check_call([sys.executable, "-m", "pip", "install", "checkov"])
        print("Checkov installed successfully.")
    except subprocess.CalledProcessError as e:
        print("Failed to install Checkov.")
        raise e

def run_checkov():
    # Define the directory containing the Terraform files
    terraform_directory = "./terraform_thesis"

    # Define the output file path
    output_file = "./results/vulnerability_report.json"

    # Locate the Checkov executable
    checkov_path = shutil.which("checkov")

    if not checkov_path:
        print("Checkov executable not found. Please ensure Checkov is installed correctly.")
        return

    # Check if the output file already exists
    if os.path.exists(output_file):
        print(f"Output file {output_file} already exists. Deleting it to avoid conflict.")
        os.remove(output_file)

    try:
        # Run Checkov and save the result in a JSON file
        subprocess.check_call([
            checkov_path,
            "-d", terraform_directory,
            "--output-file-path", output_file,
            "--output", "json"
        ])
        print(f"Checkov scan completed. Results saved to {output_file}.")
    except subprocess.CalledProcessError as e:
        print("Failed to run Checkov.")
        raise e
    except FileNotFoundError as e:
        print("Checkov executable not found. Please ensure Checkov is installed correctly.")
        raise e

if __name__ == "__main__":
    install_checkov()
    run_checkov()
