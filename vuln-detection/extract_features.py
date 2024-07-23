import os
import subprocess
import json
import pandas as pd

# Print the current working directory
print("Current Working Directory:", os.getcwd())

# List of Docker images to pull and scan
images = [
    'ubuntu:latest',
    'alpine:latest',
    'node:latest',
    'mysql:latest',
    'nginx:latest',
    'redis:latest',
    'python:latest',
    'postgres:latest',
    'jenkins/jenkins:lts',
    'wordpress:latest'
]

# Ensure Trivy is installed
def install_trivy():
    print("Checking if Trivy is installed...")
    if subprocess.run(["trivy", "--version"]).returncode != 0:
        print("Trivy is not installed. Installing Trivy...")
        subprocess.run(["brew", "install", "trivy"])
    else:
        print("Trivy is already installed.")

install_trivy()

# Pull Docker images and scan with Trivy
vulnerabilities = []
for image in images:
    print(f"Pulling image: {image}")
    pull_result = subprocess.run(["docker", "pull", image])
    if pull_result.returncode != 0:
        print(f"Failed to pull image: {image}")
        continue
    print(f"Scanning image: {image}")
    scan_result = subprocess.run(["trivy", "image", "--format", "json", "-o", "trivy_output.json", image], capture_output=True)
    if scan_result.returncode != 0:
        print(f"Failed to scan image: {image}")
        continue
    with open("trivy_output.json") as f:
        data = json.load(f)
        for result in data['Results']:
            if 'Vulnerabilities' in result:
                for vuln in result['Vulnerabilities']:
                    vulnerabilities.append({
                        'Image': image,
                        'VulnerabilityID': vuln['VulnerabilityID'],
                        'PkgName': vuln['PkgName'],
                        'InstalledVersion': vuln['InstalledVersion'],
                        'Severity': vuln['Severity']
                    })
    print(f"Finished scanning image: {image}")

# Check if vulnerabilities list is empty
if not vulnerabilities:
    print("No vulnerabilities found.")
else:
    # Convert vulnerabilities to DataFrame and save to CSV
    df = pd.DataFrame(vulnerabilities)
    df.to_csv('vulnerabilities.csv', index=False)
    print("Vulnerability data saved to vulnerabilities.csv")
