#!/usr/bin/env python3

import boto3
from botocore.exceptions import ClientError, WaiterError
import json
import sys
import datetime
from pprint import pprint
import csv



def get_investgator_identity():
    client = boto3.client('sts')
    response = client.get_caller_identity()
    return(response['Arn'])

def get_compromised_account_id(compromised_account_session):
    client = compromised_account_session.client('sts')
    response = client.get_caller_identity()
    return(response['Account'])

def get_regions(compromised_account_session):
    ec2 = compromised_account_session.client('ec2')
    response = ec2.describe_regions()
    output = ['us-east-1']
    for r in response['Regions']:
        if r['RegionName'] == "us-east-1":
            continue
        output.append(r['RegionName'])
    return(output)