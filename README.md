# AWS Resource Scanner

## Overview

This script scans and displays information about various AWS resources across two specified regions: `us-east-1` and `us-west-1`. The resources include:

* EC2 instances, unattached EBS volumes, NAT Gateways, Internet Gateways, and Elastic IP addresses
* S3 buckets
* RDS instances
* ECS clusters and services
* EKS clusters
* Lambda functions
* ALB/NLB (ELBv2)
* API Gateway (v1 REST and v2 HTTP/WebSocket)
* DynamoDB tables

## Usage

1. Ensure you have the necessary AWS credentials configured (e.g., `~/.aws/credentials` file).
2. Install the required libraries by running `pip install boto3 tabulate` in your terminal.
3. Execute the script using Python: `python main.py`
4. The script will print the gathered AWS resource information in a tabulated format.

## Notes

* This script only scans resources in the `us-east-1` and `us-west-1` regions. Modify the `REGIONS` list in `main.py` to include additional regions as needed.
* Ensure you have the necessary permissions to access the AWS resources being scanned.
