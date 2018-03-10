# AWS Forensics & Incident Response

Tools for IR & Forensic data gathering in AWS

What do you do when you get that dreaded "We've detected fraudulent activity" or "We've found your access keys on github" messages from AWS?

Hopefully you've already enabled CloudTrail, don't use root and root AWS Access keys, and other AWS Best practices around AWS Account Hygiene. If not, and you found this repo by Googling "What do I do when my AWS Account is hacked", hopefully this is of use to you.


## Tools and documents included

### Documents
* [How to prepare and secure your AWS Account](Prepare.md)
* [How to monitor for an AWS Account compromise](Detect.md)
* [What to do immediately after being notified of a compromise](Response-Runbook.md)
* [Cleanup Tasks](Remediate-Runbook.md)

### Tools
* Cloud Formation template to create an [immutable evidence bucket](cloudformation/EvidenceBucket.yaml)
* Capture [CloudTrail Events]
* Capture [S3 Bucket Policies]
* Capture [EC2 Instance & Volume Info](bin/inventory_assets.py)
* Capture [IAM User Activity](bin/audit_iam.py)


## Getting Started
These tools assume a few things:
1. You have a profile configured via the AWS CLI with credentials to the compromised (aka Target) account
2. You have an AWS Account that is not the target account for storing evidence and doing forensic analysis. This is the Forensic Account.
3. An [evidence bucket] is deployed in the forensic AWS Account. Files created will be immediately pushed to the evidence bucket and tagged with the IAM Role of the person collecting the data.