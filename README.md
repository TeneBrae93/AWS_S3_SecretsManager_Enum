# AWS Boto3 Credential & Secrets Extractor

I created this Python script while working through the Understand Authentication Mechanisms Using Boto3 lab on Pwned Labs. It's a free lab - check it out!

https://pwnedlabs.io/labs/understand-authentication-mechanisms-using-boto3

### Features
- Files from an S3 bucket
- Secrets from AWS Secrets Manager
- Auto-scanning secrets for sensitive data like passwords, keys, and tokens


---


## Usage

```bash
python3 secretfinder.py [--buckets] [--secrets]
```

If no flags are specified, the script will do **both** (download from S3 and Secrets Manager).
