#!/usr/bin/env python3

import sys
import os
import getopt
import boto3
import botocore
sys.path.append('./lib')
import globals as g

### BEGIN ####

def usage():
    print("\n%s Usage:" % os.path.basename(__file__))
    print("\n\t  -a --action\tstart | clean_all ")
    print("\n\t[ -t --target\tec2 ]")
    print("\n")
    sys.exit(2)

def handle(error):
    if error.response:
        if error.response['Error']['Code'] in ('DependencyViolation', 'InvalidGroup.NotFound', 'VpcLimitExceeded', 'UnauthorizedOperation', 'ParamValidationError', 'AddressLimitExceeded',):
            print('Failed (%s)' % error.response['Error']['Code'])
        elif error.response['Error']['Code'] in ('CannotDelete',):
            print('Failed (%s)' % error.response['Error']['Code'])
            return
        elif error.response['Error']['Code'] in ('DryRunOperation',):
            return
    print("Failed with %s" % error)
    exit (1)

############
### VPCS ###
############

def create_vpc(client, name=g.ec2_project_name, cidr_ipv4=g.ec2_cidr_block, autoipv6=False, tenancy=g.ec2_tenancy, mode=True):
    """
    Create a virtual private cloud.
    See https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.create_vpc
    """
    try:
        vpc = client.create_vpc(CidrBlock=g.ec2_cidr_block, AmazonProvidedIpv6CidrBlock=True, InstanceTenancy=tenancy, DryRun=mode)
        return vpc
    except Exception as err:
        handle(err)
    return None

def delete_vpc(client, vpc_id=g.ec2_vpc_id, mode=True):
    """
    Delete a virtual private cloud.
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.delete_vpc
    """
    try:
        print('Deleting %s %s' % (vpc_id, '(dryrun)' if mode else ''))
        return client.delete_vpc(VpcId=vpc_id, DryRun=mode)
    except Exception as err:
        handle(err)

def get_vpcs(client, tagname='tag:project', tagvalue=g.ec2_project_name, mode=True):
    """
    Get VPC(s) by tag.
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.describe_vpcs
    """
    try:
        return client.describe_vpcs(Filters=[{'Name': tagname, 'Values': [tagvalue,]},], DryRun=mode)
    except Exception as err:
        handle(err)

##############
### SUBNET ###
##############

def create_subnet(client, name=g.ec2_project_name, cidr_ipv4=g.ec2_cidr_block, vpc=g.ec2_vpc_id, mode=True):
    """
    Create a subnet.
    See https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.create_subnet
    """
    try:
        subnet = client.create_subnet(CidrBlock=g.ec2_cidr_block, VpcId=g.ec2_vpc_id, DryRun=mode)
        #not working#subnet.create_tags(Tags=[{"Key": "project", "Value": g.ec2_project_name}])
        return subnet
    except Exception as err:
        handle(err)
    return None

def delete_subnet(client, subnet=g.ec2_subnet_id, mode=True):
    """
    Delete a subnet.
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.delete_subnet
    """
    try:
        print('Deleting %s %s' % (subnet, '(dryrun)' if mode else ''))
        return client.delete_subnet(SubnetId=subnet, DryRun=mode)
    except Exception as err:
        handle(err)

def get_subnets(client, tagname='tag:project', tagvalue=g.ec2_project_name, mode=True):
    """
    Get VPC(s) by tag (note: create_tags not working via client api, use cidr or object_id instead )
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.describe_subnets
    """
    try:
        return client.describe_subnets(Filters=[{'Name': tagname, 'Values': [tagvalue,]},], DryRun=mode)
    except Exception as err:
        handle(err)

#######################
### SECURITY GROUPS ###
#######################

def create_sg(client, desc=g.ec2_project_name, groupname=g.ec2_group_name, vpc=g.ec2_vpc_id, mode=True):
    """
    Create security group.
    See https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.create_security_group
    """
    try:
        return client.create_security_group( Description=desc, GroupName=groupname, VpcId=vpc, DryRun=mode)
    except Exception as err:
        handle(err)

def delete_sg(client, groupid=g.ec2_sg_id, mode=True):
    """
    Delete a security group.
    See https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.delete_security_group
    """
    try:
        print('Deleting %s %s' % (groupid, '(dryrun)' if mode else ''))
        return client.delete_security_group( GroupId=groupid, DryRun=mode)
    except Exception as err:
        handle(err)

def get_sgs(client, name='tag:project', value=g.ec2_project_name, groupname=g.ec2_group_name, mode=True):
    """
    Get Security Groups by searching for VPC Id.
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.describe_security_groups
    """
    try:
        return client.describe_security_groups(Filters=[{'Name': name, 'Values': [value,]}, {'Name': 'group-name', 'Values': [groupname,]},], DryRun=mode)
    except Exception as err:
        handle(err)

def add_sg_ingress(client, fromport=80, toport=80, ipprotocol='TCP', ipranges=[{'CidrIp': '0.0.0.0/0'},], ipv6ranges=[{'CidrIpv6', '::/0'},], groupid=g.ec2_sg_id, mode=True):
    """
    Adds one or more ingress rules to a security group.
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.authorize_security_group_ingress
    """
    try:
        return client.authorize_security_group_ingress(IpPermissions=[{'FromPort': fromport, 'ToPort': toport, 'IpProtocol': ipprotocol, 'IpRanges': ipranges, 'Ipv6Ranges': ipv6ranges},], GroupId=groupid, DryRun=mode)
    except Exception as err:
        handle(err)

###################
### ELASTIC IPS ###
###################

def create_elastic_ip(client, domain='vpc', mode=True):
    """
    Create elastic ip.
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.allocate_address
    """
    try:
        return client.allocate_address( Domain=domain, DryRun=mode)
    except Exception as err:
        handle(err)

def associate_elastic_ip(client, allocation_id=g.ec2_elastic_ip_allocation_id, instance_id=g.ec2_instance_id, mode=True):
    """
    Associate elastic ip.
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.associate_address
    """
    try:
        return client.associate_address( AllocationId=allocation_id, InstanceId=instance_id, DryRun=mode)
    except Exception as err:
        handle(err)

def delete_elastic_ip(client, allocation_id=g.ec2_elastic_ip_allocation_id, public_ip='', mode=True):
    """
    Delete a elastic ip.
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.release_address
    """
    try:
        print('Deleting %s %s %s' % (allocation_id, public_ip, '(dryrun)' if mode else ''))
        client.release_address( AllocationId=allocation_id, DryRun=mode)
    except Exception as err:
        handle(err)

def get_elastic_ips(client, name='domain', value='vpc', allocation_id=g.ec2_elastic_ip_allocation_id, instance_id=g.ec2_instance_id, mode=True):
    """
    Get Elastic IPs by searching for stuff
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.describe_addresses
    """
    try:
        if allocation_id:
            return client.describe_addresses(Filters=[{'Name': name, 'Values': [value,]},], AllocationIds=[allocation_id,], DryRun=mode)
        elif instance_id:
            return client.describe_addresses(Filters=[{'Name': name, 'Values': [value,]}, {'Name': 'instance-id', 'Values': [instance_id,]},], DryRun=mode)
        else:
            return client.describe_addresses(Filters=[{'Name': name, 'Values': [value,]},], DryRun=mode)
    except Exception as err:
        handle(err)


########################
### INTERNET GATEWAY ###
########################

def create_internet_gateway(client, mode=True):
    """
    Create internet gateway.
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.create_internet_gateway
    """
    try:
        return client.create_internet_gateway(DryRun=mode)
    except Exception as err:
        handle(err)

def delete_internet_gateway(client, gateway_id=g.ec2_internet_gateway_id, mode=True):
    """
    Delete a internet gateway.
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.delete_internet_gateway
    """
    try:
        print('Deleting %s %s' % (gateway_id, '(dryrun)' if mode else ''))
        return client.delete_internet_gateway( InternetGatewayId=gateway_id, DryRun=mode)
    except Exception as err:
        handle(err)

def get_internet_gateways(client, name='attachment.vpc-id', value=g.ec2_vpc_id, mode=True):
    """
    Get internet gateways IPs by searching for stuff
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.describe_internet_gateways
    """
    try:
        return client.describe_internet_gateways(Filters=[{'Name': name, 'Values': [value,]},], DryRun=mode)
    except Exception as err:
        handle(err)

def attach_internet_gateway(client, gateway_id=g.ec2_internet_gateway_id, vpc_id=g.ec2_vpc_id, mode=True):
    """
    Attaches an internet gateway to a VPC
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.attach_internet_gateway
    """
    try:
        print('Attaching %s to %s %s' % ( gateway_id, vpc_id, '(dryrun)' if mode else '' ))
        client.attach_internet_gateway( InternetGatewayId=gateway_id, VpcId=vpc_id, DryRun=mode)
    except Exception as err:
        handle(err)

def detach_internet_gateway(client, gateway_id=g.ec2_internet_gateway_id, vpc_id=g.ec2_vpc_id, mode=True):
    """
    Attaches an internet gateway to a VPC
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.detach_internet_gateway
    """
    try:
        print('Detaching %s from %s %s' % ( gateway_id, vpc_id, '(dryrun)' if mode else '' ))
        client.detach_internet_gateway( InternetGatewayId=gateway_id, VpcId=vpc_id, DryRun=mode)
    except Exception as err:
        handle(err)


####################
### EC2 RESOURCE ###
####################

def create_instance(image_id=g.ec2_ami, image_type=g.ec2_ami_type, sg_id=g.ec2_sg_id, sn_id=g.ec2_subnet_id, userdata='', mode=True):
    """
    Create and launch a new Amazon EC2 micro instance with boto3.
    Launch a free tier Amazon Linux AMI using your Amazon credentials.
    """
    try:
        print('Creating instance %s' % '(dryrun)' if mode else '' )
        return ec2.create_instances(ImageId=image_id, MaxCount=1, MinCount=1, InstanceType=image_type, SecurityGroupIds=[sg_id,], SubnetId=sn_id, UserData=userdata, DryRun=mode)
    except Exception as err:
        handle(err)

def delete_instance(instance, instance_id=g.ec2_instance_id, mode=True):
    """
    Delete a ec2 instance
    See https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.delete_security_group
    """
    try:
        print('Terminating instance %s' % '(dryrun)' if mode else '' )
        instance.terminate(DryRun=mode)
        instance.wait_until_terminated(Filters=[{'Name': 'instance-id', 'Values': [instance_id,]},], DryRun=mode)
    except Exception as err:
        handle(err)

def get_instances(client, name='tag:project', value=g.ec2_project_name, running=False, mode=True):
    """
    Get EC2 instances by searching for stuff
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.describe_instances
    """
    try:
        if running:
            return client.describe_instances(Filters=[{'Name': name, 'Values': [value,]}, {'Name': 'instance-state-name', 'Values': [running,]},], DryRun=mode)
        else:
            return client.describe_instances(Filters=[{'Name': name, 'Values': [value,]},], DryRun=mode)
    except Exception as err:
        handle(err)


client = boto3.client('ec2', region_name=g.ec2_region_name)
ec2 = boto3.resource('ec2')

################################
#### cleanup all resources #####
################################
def clean_ec2():
    for mode in (True, False):
        try:
            #### VPC ####
            print("\nCLEAN DOWN E2C ENVIRON %s" % ('dryrun' if mode else 'for real, please be patient'))
            vpcs = get_vpcs(client, 'cidr', g.ec2_cidr_block, mode)
            if vpcs:
                for vpc in vpcs['Vpcs']:
                    g.ec2_vpc_id = vpc['VpcId'] 

                    ### EC2 INSTANCES ###
                    instances = get_instances(client, 'vpc-id', g.ec2_vpc_id, False, mode)
                    if instances and "Reservations" in instances and instances['Reservations']:
                        for v in instances['Reservations'][0]['Instances']:
                            delete_instance(ec2.Instance(v['InstanceId']), v['InstanceId'], mode)

                            ### ELASTIC IPS ###
                            eips = get_elastic_ips(client, 'domain', 'vpc', None, v['InstanceId'], mode)
                            if eips:
                                for ip in eips['Addresses']:
                                    delete_elastic_ip(client, ip['AllocationId'], ip['PublicIp'], mode)

                    ### SUBNETS ###
                    subnets = get_subnets(client, 'vpc-id', g.ec2_vpc_id, mode)
                    if subnets:
                        for sn in subnets['Subnets']:
                            delete_subnet(client, sn['SubnetId'], mode)

                    ### INTERNET GATEWAY ###
                    gateways = get_internet_gateways(client, 'attachment.vpc-id', g.ec2_vpc_id, mode)
                    if gateways:
                        for v in gateways['InternetGateways']:
                            detach_internet_gateway(client, v['InternetGatewayId'], g.ec2_vpc_id, mode) 
                            delete_internet_gateway(client, v['InternetGatewayId'], mode)

                    ### SECURITY GROUPS ###
                    sgs = get_sgs(client, 'vpc-id', g.ec2_vpc_id, g.ec2_group_name, mode)
                    if sgs and "SecurityGroups" in sgs and sgs["SecurityGroups"]:
                        for sg in sgs['SecurityGroups']:
                            delete_sg(client, sg['GroupId'], mode)

                    ### VPC ###
                    delete_vpc(client, g.ec2_vpc_id, mode)
        except Exception as err:
            handle(err)
        return(0)

##########################
#### Create resources ####
##########################
def start_ec2():
    for mode in (True, False):
        try:
            print("\nCREATE E2C ENVIRON %s" % ('dryrun' if mode else 'for real, please be patient'))
            g.ec2_vpc_id = create_vpc(client, g.ec2_project_name, g.ec2_cidr_block, True, g.ec2_tenancy, mode)
            if g.ec2_vpc_id:
                g.ec2_vpc_id = g.ec2_vpc_id['Vpc']['VpcId']

                ### INTERNET GATEWAY
                g.ec2_gateway_id = create_internet_gateway(client, mode)
                if g.ec2_gateway_id:
                    g.ec2_gateway_id = g.ec2_gateway_id['InternetGateway']['InternetGatewayId']
                    attach_internet_gateway(client, g.ec2_gateway_id, g.ec2_vpc_id, mode) 

                ### SUBNET ###
                g.ec2_subnet_id = create_subnet(client, g.ec2_project_name, g.ec2_cidr_block, g.ec2_vpc_id, mode)
                if g.ec2_subnet_id:
                    g.ec2_subnet_id = g.ec2_subnet_id['Subnet']['SubnetId']

                ### SECURITY GROUP ###
                g.ec2_sg_id = create_sg(client, g.ec2_project_name, g.ec2_group_name, g.ec2_vpc_id, mode)
                if g.ec2_sg_id:
                    g.ec2_sg_id = g.ec2_sg_id['GroupId']
                    add_sg_ingress(client, 22, 22, 'TCP', [{'CidrIp': '0.0.0.0/0'},], [{'CidrIpv6': '::/0'},], g.ec2_sg_id, mode)
                    add_sg_ingress(client, 80, 80, 'TCP', [{'CidrIp': '0.0.0.0/0'},], [{'CidrIpv6': '::/0'},], g.ec2_sg_id, mode)
                    add_sg_ingress(client, 443, 443, 'TCP', [{'CidrIp': '0.0.0.0/0'},], [{'CidrIpv6': '::/0'},], g.ec2_sg_id, mode)

                ### ELASTIC IP ###
                g.ec2_elastic_ip_allocation_id = create_elastic_ip(client, 'vpc', mode)
                if g.ec2_elastic_ip_allocation_id:
                    g.ec2_elastic_ip_allocation_id = g.ec2_elastic_ip_allocation_id['AllocationId']

                ### EC2 INSTANCE ###
                instance = create_instance(g.ec2_ami, g.ec2_ami_type, g.ec2_sg_id, g.ec2_subnet_id, g.ec2_userdata, mode)
                if instance and instance[0]:
                    g.ec2_instance_id = instance[0].id
                    if g.ec2_instance_id:
                        instance = ec2.Instance(g.ec2_instance_id)
                        instance.wait_until_running(Filters=[{'Name': 'instance-id', 'Values': [g.ec2_instance_id,]},], DryRun=mode)

                        #### ELASTIC IP ASSOCIATION  ####
                        g.ec2_elastic_ip_association_id = associate_elastic_ip(client, g.ec2_elastic_ip_allocation_id, g.ec2_instance_id, mode)
                        if g.ec2_elastic_ip_association_id:
                            g.ec2_elastic_ip_association_id = g.ec2_elastic_ip_association_id['AssociationId']

            print('created VPC %s' % ('(dryrun)' if mode else g.ec2_vpc_id))
            print('created Subnet %s' % ('(dryrun)' if mode else g.ec2_subnet_id))
            print('created Security Group %s' % ('(dryrun)' if mode else g.ec2_sg_id))
            print('created Instance %s' % ('(dryrun)' if mode else g.ec2_instance_id))
        except Exception as err:
            handle(err)
    return(0)

#############
### MAIN ####
#############
# borrow style of https://raw.githubusercontent.com/noelmcloughlin/iot-edge-stepping-stones/master/mqtt/mqtt.py

def main(argv):
    try:
        opts, args = getopt.getopt(argv,"a:t:",["action=", "target="])
    except getopt.GetoptError as e:
        usage()

    if not opts:
        usage()

    ### command line arguments ###
    target='ec2'
    for opt, arg in opts:
        if opt in ("-a", "--action"):
            action = arg
        elif opt in ("-a", "--target"):
            target = arg
        else:
            usage()

    ### actions ###
    if action == "start" and "ec2" in target:
        start_ec2()
    elif action in ("stop", "clean_all", "terminate") and "ec2" in target:
        clean_ec2()

if __name__ == "__main__":
   main(sys.argv[1:])
exit(0)
