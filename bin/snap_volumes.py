#!/usr/bin/env python3

import boto3
from botocore.exceptions import ClientError, WaiterError
import json


def main(args):

    # boto3.setup_default_session(profile_name=args.compromised_profile)
    compromised_account_session = boto3.session.Session(profile_name=args.compromised_profile)

    if args.region is None:
        regions = get_regions(compromised_account_session)
    else:
        regions = [args.region]

    for r in regions:
        vols = get_volumes(r, compromised_account_session)
        print("{} has {} volumes".format(r, len(vols)))

        for v in vols:
            snap_id = snap_and_share_volume(v, r, args, compromised_account_session)
            if snap_id is not None:
                forensic_snap = copy_snapshot_to_forensic_master(snap_id, r, args)
                print("Captured Forensic Snapshot {} in {}".format(forensic_snap.id, r))
            # return() # abort after 1

    exit(0)

def get_regions(compromised_account_session):
    ec2 = compromised_account_session.client('ec2')
    response = ec2.describe_regions()
    output = ['us-east-1']
    for r in response['Regions']:
        if r['RegionName'] == "us-east-1":
            continue
        output.append(r['RegionName'])
    return(output)

def get_volumes(region, compromised_account_session):
    output = []
    ec2_client = compromised_account_session.client('ec2', region_name = region)
    response = ec2_client.describe_volumes(MaxResults=123)

    for v in response['Volumes']:
        output.append(v['VolumeId'])
    return(output)

def snap_and_share_volume(original_volume_id, region, args, compromised_account_session):

    ec2 = compromised_account_session.resource("ec2", region_name = region)
    ec2_client = compromised_account_session.client("ec2", region_name = region)

    waiter_snapshot_complete = ec2_client.get_waiter("snapshot_completed")
    waiter_volume_available = ec2_client.get_waiter("volume_available")
    waiter_volume_in_use = ec2_client.get_waiter("volume_in_use")

    original_volume=ec2.Volume(original_volume_id)

    volume_description = "Snapshot of volume ({}) from {}:{} - Investigation: {}".format(original_volume_id,
                original_volume.attachments[0][u'InstanceId'], original_volume.attachments[0][u'Device'], args.investigation_id)

    """ Step 1: Take snapshot of volume """
    print("Create snapshot of volume ({}) from {}:{} (size: {}GB)".format(original_volume_id,
        original_volume.attachments[0][u'InstanceId'], original_volume.attachments[0][u'Device'], original_volume.size))

    try:
        snapshot = ec2.create_snapshot(
            VolumeId=original_volume_id,
            Description=volume_description,
            DryRun=args.test
        )
    except ClientError as e:
        print("ERROR creating snapshot for {}: {}".format(original_volume_id, e))
        return(None)

    try:
        waiter_snapshot_complete.wait( SnapshotIds=[snapshot.id])
    except WaiterError as e:
        snapshot.delete()
        print("TIMEOUT creating snapshot for {}: {}".format(original_volume_id, e))
        return(None)

    # Now share it to the forensic account
    try:
        response = snapshot.modify_attribute(
            Attribute='createVolumePermission',
            OperationType='add',
            UserIds=[args.forensic_account_id ],
            DryRun=args.test
        )
    except ClientError as e:
        print("ERROR sharing snapshot for {} to {}: {}".format(original_volume_id, args.forensic_account_id, e))
        return(None)

    print("Snapshot complete")
    return(snapshot)
    # end snap_and_share_volume()

def copy_snapshot_to_forensic_master(snapshot, region, args):

    description = "Encrypted Forensic Copy of {}".format(snapshot.description)

    ec2 = boto3.resource("ec2")
    ec2_client = boto3.client('ec2') # This should copy from original region to us-east-1
    waiter_snapshot_complete = ec2_client.get_waiter("snapshot_completed")

    print("Creating {}".format(description))

    try:
        response = ec2_client.copy_snapshot(
            Description=description,
            Encrypted=True,
            KmsKeyId=args.kms_key_alias,
            SourceRegion=region,
            SourceSnapshotId=snapshot.id
        )
        new_id = response['SnapshotId']
        new_snapshot = ec2.Snapshot(new_id)
    except ClientError as e:
        print("ERROR copying snapshot for {}: {}".format(snapshot.id, e))
        return(None)

    try:
        print("Waiting for copy of {} to forensic account {} to complete".format(snapshot.id, new_id))
        waiter_snapshot_complete.wait( SnapshotIds=[new_snapshot.id])
    except WaiterError as e:
        new_snapshot.delete()
        print("TIMEOUT copying snapshot for {}: {}".format(new_snapshot.id, e))
        return(None)
    return(new_snapshot)

###################

def do_args():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--debug", help="print debugging info", action='store_true')
    parser.add_argument("--error", help="print error info only", action='store_true')
    parser.add_argument("--test", help="Dry-Run all change commands", action='store_true')

    parser.add_argument("--forensic_account_id", help="Account Id to share snapshots to", required=True)
    parser.add_argument("--compromised_profile", help="Profile of the compromised account", required=True)

    parser.add_argument("--investigation_id", help="Free text investigation id", required=True)
    parser.add_argument("--kms-key-alias", help="KMS Key Alias for encrypting Forensic Snapshots", required=True)

    parser.add_argument("--region", help="Only do this region")


    args = parser.parse_args()

    # if not hasattr(args, 'environment_id'):
    #     print("Must specify --environment_id")
    #     exit(1)

    return(args)

def validate_args(args):
    # 1 - validate the S3 Bucket
    # 2 - Validate the KMS Key exists.
    # 3 - Validate access via the compromised_profile

    return(True)

if __name__ == '__main__':

    args = do_args()
    validate_args(args)
    main(args)