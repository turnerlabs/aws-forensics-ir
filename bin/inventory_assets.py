#!/usr/bin/env python3

import boto3
from botocore.exceptions import ClientError, WaiterError
import json
import sys
import datetime


def main(args):
    compromised_account_session = boto3.session.Session(profile_name=args.compromised_profile)

    chain_of_custody = {
        'investigator': get_investgator_identity(),
        'compromised_account_id': get_compromised_account_id(compromised_account_session),
        'boto3_version': boto3.__version__,
    }

    s3 = boto3.resource('s3')
    forensic_bucket = s3.Bucket(args.bucket)

    if args.region is None:
        regions = get_regions(compromised_account_session)
    else:
        regions = [args.region]

    for r in regions:
        print("Region: {}".format(r))
        ami_list = get_instances(r, compromised_account_session, forensic_bucket, args, chain_of_custody)
        print(ami_list)
        if len(ami_list) > 0:
            get_amis(r, ami_list, compromised_account_session, forensic_bucket, args, chain_of_custody)
        get_key_pairs(r, compromised_account_session, forensic_bucket, args, chain_of_custody)
        vols = get_volumes(r, compromised_account_session, forensic_bucket, args, chain_of_custody)
        print("{} has {} volumes".format(r, len(vols)))

    exit(0)


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


def get_key_pairs(region, compromised_account_session, forensic_bucket, args, chain_of_custody):
    output = []
    ec2_client = compromised_account_session.client('ec2', region_name = region)
    response = ec2_client.describe_key_pairs()

    key = "{}/{}-keypairs.json".format(args.prefix, region)
    chain_of_custody['date_captured'] = str(datetime.datetime.now())

    object = forensic_bucket.put_object(
        ACL='private',
        Body=json.dumps(response, sort_keys=True, default=str, indent=2),
        ContentType='application/json',
        Key=key,
        Metadata=chain_of_custody,
        # Default Encryption should be enabled, so I don't need to worry about this.
        # ServerSideEncryption='aws:kms',
        # SSEKMSKeyId='string',
    )
    print("{} key-pair info saved as s3://{}/{} with etag {}".format(region, forensic_bucket.name, key, object.e_tag))
    return(output)

def get_amis(region, ami_list, compromised_account_session, forensic_bucket, args, chain_of_custody):
    output = []
    ec2_client = compromised_account_session.client('ec2', region_name = region)
    response = ec2_client.describe_images(ImageIds=ami_list )

    for i in response['Images']:
        key = "{}/{}.json".format(args.prefix, i['ImageId'])
        chain_of_custody['date_captured'] = str(datetime.datetime.now())

        object = forensic_bucket.put_object(
            ACL='private',
            Body=json.dumps(i, sort_keys=True, default=str, indent=2),
            ContentType='application/json',
            Key=key,
            Metadata=chain_of_custody,
            # Default Encryption should be enabled, so I don't need to worry about this.
            # ServerSideEncryption='aws:kms',
            # SSEKMSKeyId='string',
        )
        print("{} saved as s3://{}/{} with etag {}".format(i['ImageId'], forensic_bucket.name, key, object.e_tag))
    return(output)

def get_instances(region, compromised_account_session, forensic_bucket, args, chain_of_custody):
    output = []
    ec2_client = compromised_account_session.client('ec2', region_name = region)
    response = ec2_client.describe_instances(MaxResults=123 )

    for r in response['Reservations']:
        for i in r['Instances']:
            output.append(i['ImageId']) # we need to return the list of used AMIs

            key = "{}/{}.json".format(args.prefix, i['InstanceId'])
            chain_of_custody['date_captured'] = str(datetime.datetime.now())

            object = forensic_bucket.put_object(
                ACL='private',
                Body=json.dumps(i, sort_keys=True, default=str, indent=2),
                ContentType='application/json',
                Key=key,
                Metadata=chain_of_custody,
                # Default Encryption should be enabled, so I don't need to worry about this.
                # ServerSideEncryption='aws:kms',
                # SSEKMSKeyId='string',
            )

            print("{} saved as s3://{}/{} with etag {}".format(i['InstanceId'], forensic_bucket.name, key, object.e_tag))
    return(output)

def get_volumes(region, compromised_account_session, forensic_bucket, args, chain_of_custody):
    output = []
    ec2_client = compromised_account_session.client('ec2', region_name = region)
    response = ec2_client.describe_volumes(MaxResults=123 )

    for v in response['Volumes']:
        output.append(v['VolumeId'])
        key = "{}/{}.json".format(args.prefix, v['VolumeId'])
        chain_of_custody['date_captured'] = str(datetime.datetime.now())

        object = forensic_bucket.put_object(
            ACL='private',
            Body=json.dumps(v, sort_keys=True, default=str, indent=2),
            ContentType='application/json',
            Key=key,
            Metadata=chain_of_custody,
            # Default Encryption should be enabled, so I don't need to worry about this.
            # ServerSideEncryption='aws:kms',
            # SSEKMSKeyId='string',
        )
        print("{} saved as s3://{}/{} with etag {}".format(v['VolumeId'], forensic_bucket.name, key, object.e_tag))

    return(output)

###################

def do_args():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--debug", help="print debugging info", action='store_true')
    parser.add_argument("--error", help="print error info only", action='store_true')

    parser.add_argument("--compromised_profile", help="Profile of the compromised account", required=True)
    parser.add_argument("--investigation_id", help="Free text investigation id", required=True)
    parser.add_argument("--bucket", help="S3 Bucket to dump json", required=True)
    parser.add_argument("--prefix", help="S3 Prefix to dump json", required=True)

    parser.add_argument("--region", help="Only process this region")

    args = parser.parse_args()
    return(args)

if __name__ == '__main__':

    args = do_args()
    main(args)