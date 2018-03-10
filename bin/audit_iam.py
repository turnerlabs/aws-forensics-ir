#!/usr/bin/env python3

import boto3
from botocore.exceptions import ClientError, WaiterError
import json
import sys
import datetime
from pprint import pprint
import csv



def main(args):

    compromised_account_session = boto3.session.Session(profile_name=args.compromised_profile)
    chain_of_custody = {
        'investigator': get_investgator_identity(),
        'compromised_account_id': get_compromised_account_id(compromised_account_session),
        'boto3_version': boto3.__version__,
    }

    s3 = boto3.resource('s3')
    forensic_bucket = s3.Bucket(args.bucket)

    trusted_entities = inventory_roles(compromised_account_session)

    print("Account {}({}) has the following trusted entities:".format(args.compromised_profile, chain_of_custody['compromised_account_id']))
    print("AWS Accounts: {}".format("\n\t".join(trusted_entities['Accounts'])))
    print("AWS Services: {}".format("\n\t".join(trusted_entities['Service'])))


def inventory_roles(compromised_account_session):
    principals = {
        "Service": set(),
        "Accounts": set()
    }
    iam_client = compromised_account_session.client('iam')

    response = iam_client.list_roles(MaxItems=123)

    for r in response['Roles']:
        arpd = r['AssumeRolePolicyDocument']
        # print(arpd)
        for s in arpd['Statement']:
            p = s['Principal']
            if "Service" in p:
                if type(p['Service']) is list:
                    for s in p['Service']:
                        principals['Service'].add(s)
                else:
                    principals['Service'].add(p['Service'])
            if "AWS" in p:
                if type(p['AWS']) is list:
                    for a in p['AWS']:
                        principals['Accounts'].add(a)
                else:
                    principals['Accounts'].add(p['AWS'])


    # print(principals)
    return(principals)


def get_credential_report(iam_client):
    resp1 = iam_client.generate_credential_report()
    if resp1['State'] == 'COMPLETE' :
        try:
            response = iam_client.get_credential_report()
            credential_report_csv = response['Content'].decode('ascii')
            # print(credential_report_csv)
            reader = csv.DictReader(credential_report_csv.splitlines())
            # print(reader)
            # print(reader.fieldnames)
            credential_report = []
            for row in reader:
                credential_report.append(row)
            return(credential_report)
        except ClientError as e:
            print("Unknown error getting Report: " + e.message)
    else:
        sleep(2)
        return get_credential_report(iam_client)


#####

def get_investgator_identity():
    client = boto3.client('sts')
    response = client.get_caller_identity()
    return(response['Arn'])

def get_compromised_account_id(compromised_account_session):
    client = compromised_account_session.client('sts')
    response = client.get_caller_identity()
    return(response['Account'])


def do_args():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--debug", help="print debugging info", action='store_true')
    parser.add_argument("--error", help="print error info only", action='store_true')

    parser.add_argument("--compromised_profile", help="Profile of the compromised account", required=True)
    parser.add_argument("--investigation_id", help="Free text investigation id", required=True)
    parser.add_argument("--bucket", help="S3 Bucket to dump json", required=True)
    parser.add_argument("--prefix", help="S3 Prefix to dump json", required=True)

    args = parser.parse_args()
    return(args)

if __name__ == '__main__':

    args = do_args()
    main(args)