import boto3
from botocore.config import Config
import json
import os
import re
import argparse

# Sensitive regex patterns
suspicious_patterns = {
    "AWS Access Key": r"AKIA[0-9A-Z]{16}",
    "AWS Secret Key": r"(?i)aws.+['\"][0-9a-zA-Z/+]{40}['\"]",
    "Password Field": r"(?i)(password|pwd)['\"]?\s*[:=]\s*['\"].+?['\"]",
    "API Key": r"(?i)(api[_-]?key)['\"]?\s*[:=]\s*['\"].+?['\"]",
    "JWT": r"eyJ[a-zA-Z0-9-_]+\.[a-zA-Z0-9-_]+\.[a-zA-Z0-9-_]+"
}

# Arg parser
parser = argparse.ArgumentParser(description="Download S3 and/or Secrets data with scanning")
parser.add_argument("--buckets", action="store_true", help="Only download S3 bucket files")
parser.add_argument("--secrets", action="store_true", help="Only download Secrets Manager secrets")
args = parser.parse_args()

# If neither flag is set, do both
do_buckets = args.buckets or not (args.buckets or args.secrets)
do_secrets = args.secrets or not (args.buckets or args.secrets)

# Proxy config
proxy_config = Config(proxies={'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'})

# AWS setup
access_key = '[access-key]'
secret_access_key = '[secret-key]'
region = 'us-east-1'
bucket = 'hl-data-download'

session = boto3.Session(
    aws_access_key_id=access_key,
    aws_secret_access_key=secret_access_key,
    region_name=region
)

s3_client = session.client("s3", config=proxy_config)
sts_client = session.client("sts", config=proxy_config)
secrets_client = session.client("secretsmanager", config=proxy_config)
iam_client = session.client("iam", config=proxy_config)

# Caller identity
sts_caller_info = sts_client.get_caller_identity()
if sts_caller_info:
    print(f"UserId: {sts_caller_info['UserId']}")
    print(f"Account: {sts_caller_info['Account']}")
    print(f"ARN: {sts_caller_info['Arn']}")

# Main output directory
output_dir = bucket
os.makedirs(output_dir, exist_ok=True)

# Download from S3
if do_buckets:
    print("\nDownloading S3 objects...")
    bucket_objects = s3_client.list_objects_v2(Bucket=bucket)
    for obj in bucket_objects.get("Contents", []):
        file_key = obj["Key"]
        print(f"File {file_key} found!")

        local_path = os.path.join(output_dir, file_key)
        os.makedirs(os.path.dirname(local_path), exist_ok=True)

        with open(local_path, "wb") as file:
            s3_client.download_fileobj(bucket, file_key, file)
            print(f"Downloaded {file_key} to {local_path}")

# Download and scan secrets
if do_secrets:
    print("\nSearching for secrets...")
    paginator = secrets_client.get_paginator('list_secrets')
    for page in paginator.paginate():
        for secret in page.get('SecretList', []):
            secret_name = secret['Name']
            print(f"\nSecret found: {secret_name}")
            try:
                secret_value = secrets_client.get_secret_value(SecretId=secret_name)
                secret_string = secret_value.get('SecretString', '')

                if not secret_string:
                    print("Secret has no string content.")
                    continue

                # Scan for suspicious content
                found = False
                for label, pattern in suspicious_patterns.items():
                    match = re.search(pattern, secret_string)
                    if match:
                        found = True
                        print(f"Possible {label} detected in {secret_name}")
                        print(f"    ➜ Value: {match.group()}")

                # Save to file named after the secret
                safe_name = secret_name.replace("/", "_")
                path = os.path.join(output_dir, f"{safe_name}.txt")
                with open(path, "w") as f:
                    f.write(secret_string)
                print(f"Saved secret {secret_name} to {path}")

            except Exception as e:
                print(f"Failed to get secret {secret_name}: {e}")
