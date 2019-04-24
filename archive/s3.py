#!/usr/bin/env python3
#############################################
# Copyright 2019 NoelMcloughlin
#############################################

import sys, os, getopt, boto3, botocore
import subprocess
import uuid

s3_region_name='eu-west-1'

########### FUNCTIONS ############

def usage():
    print("\n%s Usage:" % os.path.basename(__file__))
    print("\n\t -a --action\tstart|clean\tInteract with S3 bucket")
    print("\n\t -n --bucket\tbucketname\tYour bucket name")
    print("\n\t -f --object\tfilename\tRelative filename to put in bucket")
    print("\n")
    sys.exit(2)

def handle(error=None, resource=None):
    try:
        if "NotFound" in error.response['Error']['Code'] or "DryRunOperation" in error.response['Error']['Code']:
            return  
        elif "InvalidParameterValue" in error.response['Error']['Code']:
            return  
        elif error.response['Error']['Code'] in ('DependencyViolation', 'VpcLimitExceeded', 'UnauthorizedOperation', 'ParamValidationError', 'AddressLimitExceeded',):
            print('Failed (%s)' % error.response['Error']['Code'])
            if resource == 'vpc':
                return  
        else:   
            print("Failed with %s" % error)
    except AttributeError as err:
        print('Something went wrong %s %s' % (error, err))
    exit(1)

##################
### S3 BUCKETS ###
##################

def create_bucket_name(prefix):
    ### Generate bucket name with uuid
    return 'prefix' + ''.join([bucket_prefix, str(uuid.uuid4())])


def create_bucket(client, acl, bucket, location, dry=False):
    """
    Create a S3 bucket
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/s3.html#S3.Client.create_bucket
    """
    try:
        response = client.create_bucket( ACL=acl, Bucket=bucket, CreateBucketConfiguration={'LocationConstraint': location})
        print('Created bucket %s' % ('(dry)' if dry else ''))
        return response
    except Exception as err:
        handle(err)
    return None

def delete_bucket(client, bucket, dry=False):
    """
    Delete a virtual private cloud.
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/s3.html#S3.Client.delete_bucket
    """
    try:
        response = client.delete_bucket(Bucket=bucket, DryRun=dry)
        print('Deleted %s %s' % (bucket, ('(dry)' if dry else '')))
        return response
    except Exception as err:
        handle(err, 'bucket')

###############
### OBJECTS ###
###############

def put_object(s3, bucket, object_name, dry=False):
    """
    Put object in bucket
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/s3.html#S3.Client.put_object
    """
    try:
        response = s3.Object(bucket, object_name).put(Body=open(object_name, 'rb'))
        print('Put %s in bucket %s %s' % (object_name, bucket, '(dry)' if dry else ''))
        #return response
    except Exception as err:
        handle(err)

def delete_object(client, bucket, key, dry=False):
    """
    Delete object from bucket
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/s3.html#S3.Client.delete_object
    """
    try:
        response = client.delete_object( Bucket=bucket, Delete={'Objects': object, 'Quiet': quiet}, )
        print('Deleted object %s %s' % (key, ('(dry)' if dry else '')))
        return response
    except Exception as err:
        handle(err)

def delete_objects(client, bucket, objects, quiet=False, dry=False):
    """
    Delete objects from bucket.
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/s3.html#S3.Client.delete_objects
    """
    try:
        response = client.delete_objects( Bucket=bucket, Delete={'Objects': objects, 'Quiet': quiet}, )
        print('Deleted objects %s' % ('(dry)' if dry else ''))
        return response
    except Exception as err:
        handle(err)

def list_objects(client, bucket, dry=False):
    """
    List objects in bucket
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/s3.html#S3.Client.list_objects
    """
    try:
        response = client.list_objects( Bucket=bucket )
        print('Deleted objects %s' % ('(dry)' if dry else ''))
        return response
    except Exception as err:
        handle(err)


##########################
#### Create resources ####
##########################
def start(s3, client, bucket, object_name, dry=False):
    try:
        s3_bucket = create_bucket(client, 'public-read-write', bucket, s3_region_name, dry)
        if s3_bucket:
            print(s3_bucket['Location'])
            response = put_object(s3, bucket, object_name, dry)
            if response:
                print(list_objects(client, s3_bucket))

    except Exception as err:
        handle(err)
    return(0)

def clean(s3, client):
    try:
        delete_bucket(client, bucket)
    except Exception as err:
        handle(err)
    return(0)

#############
### MAIN ####
#############

def main(argv):
    try:
        opts, args = getopt.getopt(argv, "a:f:n:l", ["action=", "file=", "name=", "list="])
    except getopt.GetoptError as e:
        handle(e)

    ### command line arguments ###
    if not opts:
        usage()

    name = filename = action = ""
    for opt, arg in opts:
        if opt in ("-l", "--list",):
            action = "list"
        elif opt in ("-n", "--name",):
            name = arg.lower()
        elif opt in ("-a", "--action",):
            action = arg.lower()
        elif opt in ("-f", "--file"):
            filename = arg.lower()
        else:
            usage()

    client = boto3.client('s3')
    s3 = boto3.resource('s3')

    ### workflow ###
    if action == "start" and name and filename:
        start(s3, client, name, filename)
    elif action == "clean" and name:
        clean(s3, client, name)
    elif action == "list":
        client.list_buckets()
    else:
        usage()

if __name__ == "__main__":
   try:
       main(sys.argv[1:])
   except Exception as err:
       handle(err)
exit(0)
