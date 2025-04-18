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

### Options

| Flag        | Description                               |
|-------------|-------------------------------------------|
| `--buckets` | Only download S3 bucket files             |
| `--secrets` | Only download and scan secrets            |

---

## Example

```bash
python3 script.py --secrets
```

```
UserId: AIDAWHEOTHRF7MLFMRGYH
Account: 427648302155
ARN: arn:aws:iam::427648302155:user/data-bot

Searching for secrets...

Secret found: ext/cost-optimization
⚠️  Possible Password Field detected in ext/cost-optimization
    ➜ Value: password = "hunter2"
💾 Saved secret ext/cost-optimization to hl-data-download/ext_cost-optimization.txt
```

---

## Secret Scanning

Secrets are scanned for sensitive patterns, including:

- AWS Access Keys
- AWS Secret Keys
- API Keys
- Password fields
- JWTs

---
