import json
import os

remediation_dir = 'remediations'
os.makedirs(remediation_dir, exist_ok=True)

with open('checkov_report.json', 'r') as f:
    vulnerabilities = json.load(f)

def determine_remediation(vulnerability):
    check_id = vulnerability.get('check_id', '')
    remediation_steps = ''

    if check_id == 'CKV_AWS_3':
        remediation_steps = (
            '1. Enable encryption at rest for your S3 bucket.\n'
            '2. Update the Terraform configuration to include `server_side_encryption_configuration`.\n'
        )
    elif check_id == 'CKV_AWS_41':
        remediation_steps = (
            '1. Restrict the security group ingress rule to specific IP addresses instead of 0.0.0.0/0.\n'
            '2. Update the Terraform configuration to limit access to port 22 (SSH) only to trusted IP addresses.\n'
        )
    else:
        remediation_steps = 'No specific remediation steps found for this vulnerability.'

    return remediation_steps

for i, vulnerability in enumerate(vulnerabilities):
    remediation = determine_remediation(vulnerability)
    remediation_file = os.path.join(remediation_dir, f'remediation_{i+1}.txt')

    with open(remediation_file, 'w') as f:
        f.write(f'Vulnerability: {vulnerability.get("check_name")}\n')
        f.write(f'Resource: {vulnerability.get("resource")}\n')
        f.write(f'File: {vulnerability.get("file_path")}\n')
        f.write(f'Severity: {vulnerability.get("severity")}\n\n')
        f.write('Remediation Steps:\n')
        f.write(remediation)

print(f'Remediation actions have been saved to the {remediation_dir} directory.')
