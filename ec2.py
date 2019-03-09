#!/usr/bin/env python3

import sys, os, getopt, boto3, botocore

### VARS ###
ec2_keypair_name='ec2_user'
ec2_ami='ami-0fad7378adf284ce0'
ec2_ami_type='t2.micro'
ec2_cidr_block='10.0.0.0/16'
ec2_group_name='mygroupname'
ec2_instance_id=None
ec2_project_name='assignment project'
ec2_region_name='eu-west-1'
ec2_userdata="""
#!/bin/bash
yum update -y
amazon-linux-extras install -y lamp-mariadb10.2-php7.2 php7.2
yum install -y httpd mariadb-server
systemctl start httpd
systemctl enable httpd
usermod -a -G apache ec2-user
chown -R ec2-user:apache /var/www
chmod 2775 /var/www
find /var/www -type d -exec chmod 2775 {} \;
find /var/www -type f -exec chmod 0664 {} \;
echo "<?php phpinfo(); ?>" > /var/www/html/phpinfo.php
"""

########### FUNCTIONS ############

def usage():
    print("\n%s Usage:" % os.path.basename(__file__))
    print("\n\t  -a --action\tstart|clean|info\tInteract with EC2 environment.")
    print("\n\t[ -t --target\tec2 ]\t\t\tEC2 target")
    print("\n\t[ -k --keypair\t<name> ]\t\tAWS keypair name")
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

#################
### KEYPAIRS ###
#################

def get_keypairs(client, name='key-name', values=[ec2_keypair_name,], mode=True):
    """
    Get keypairs
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.describe_key_pairs
    """
    try:
        return client.describe_key_pairs(Filters=[{'Name': name, 'Values': values}], DryRun=mode)
    except Exception as err:
        handle(err)


############
### VPCS ###
############

def create_vpc(client, name=ec2_project_name, cidr_ipv4=ec2_cidr_block, autoipv6=False, tenancy='default', mode=True):
    """
    Create a virtual private cloud.
    See https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.create_vpc
    """
    try:
        response = client.create_vpc(CidrBlock=ec2_cidr_block, AmazonProvidedIpv6CidrBlock=True, InstanceTenancy=tenancy, DryRun=mode)
        print('Created vpc %s' % ('(dryrun)' if mode else ''))
        return response
    except Exception as err:
        handle(err)
    return None

def delete_vpc(client, vpc_id, mode=True):
    """
    Delete a virtual private cloud.
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.delete_vpc
    """
    try:
        response = client.delete_vpc(VpcId=vpc_id, DryRun=mode)
        print('Deleted %s %s' % (vpc_id, ('(dryrun)' if mode else '')))
        return response
    except Exception as err:
        handle(err, 'vpc')

def get_vpcs(client, name='tag:project', values=[ec2_project_name,], mode=True):
    """
    Get VPC(s) by filter
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.describe_vpcs
    """
    try:
        return client.describe_vpcs(Filters=[{'Name': name, 'Values': values},], DryRun=mode)
    except Exception as err:
        handle(err)

##############
### SUBNET ###
##############

def create_subnet(client, vpc_id, name=ec2_project_name, cidr_ipv4=ec2_cidr_block, mode=True):
    """
    Create a subnet.
    See https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.create_subnet
    """
    try:
        response = client.create_subnet(CidrBlock=cidr_ipv4, VpcId=vpc_id, DryRun=mode)
        print('Created subnet for %s %s' % (cidr_ipv4, ('(dryrun)' if mode else '')))
        return response
    except Exception as err:
        handle(err)
    return None

def delete_subnet(client, subnet, mode=True):
    """
    Delete a subnet.
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.delete_subnet
    """
    try:
        response = client.delete_subnet(SubnetId=subnet, DryRun=mode)
        print('Deleted %s %s' % (subnet, ('(dryrun)' if mode else '')))
        return response
    except Exception as err:
        handle(err)

def get_subnets(client, name='tag:project', values=[ec2_project_name,], mode=True):
    """
    Get VPC(s) by tag (note: create_tags not working via client api, use cidr or object_id instead )
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.describe_subnets
    """
    try:
        return client.describe_subnets(Filters=[{'Name': name, 'Values': values},], DryRun=mode)
    except Exception as err:
        handle(err)

#######################
### SECURITY GROUPS ###
#######################

def create_sg(client, vpc_id, desc=ec2_project_name, groupname=ec2_group_name, mode=True):
    """
    Create security group.
    See https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.create_security_group
    """
    try:
        response = client.create_security_group( Description=desc, GroupName=groupname, VpcId=vpc_id, DryRun=mode)
        print('Created security group %s' % ('(dryrun)' if mode else ''))
        return response
    except Exception as err:
        handle(err)

def delete_sg(client, sg_id, mode=True):
    """
    Delete a security group.
    See https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.delete_security_group
    """
    try:
        response = client.delete_security_group( GroupId=sg_id, DryRun=mode)
        print('Deleted %s %s' % (sg_id, ('(dryrun)' if mode else '')))
        return response
    except Exception as err:
        handle(err)

def get_sgs(client, name='tag:project', values=[ec2_project_name,], groups=[ec2_group_name,], mode=True):
    """
    Get Security Groups by searching for VPC Id.
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.describe_security_groups
    """
    try:
        if groups:
            return client.describe_security_groups(Filters=[{'Name': 'group-name', 'Values': groups},], DryRun=mode)
        return client.describe_security_groups(Filters=[{'Name': name, 'Values': values},], DryRun=mode)
    except Exception as err:
        handle(err)


def authorize_sg_egress(client, from_port, to_port, proto, sg_id, ipv4, ipv6=[{'CidrIpv6', '::/0'},], mode=True):
    """
    Adds egress rules to a security group.
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.authorize_security_group_egress
    """
    try:
        response = client.authorize_security_group_egress(IpPermissions=[{'FromPort': from_port, 'ToPort': to_port, 'IpProtocol': proto, 'IpRanges': ipv4, 'Ipv6Ranges': ipv6},], GroupId=sg_id, DryRun=mode)
        print('Authorized sg egress %s %s' % (sg_id, ('(dryrun)' if mode else '')))
        return response
    except Exception as err:
        handle(err)

def authorize_sg_ingress(client, from_port, to_port, proto, sg_id, ipv4, ipv6=[{'CidrIpv6', '::/0'},], mode=True):
    """
    Adds ingress rules to a security group.
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.authorize_security_group_ingress
    """
    try:
        response = client.authorize_security_group_ingress(IpPermissions=[{'FromPort': from_port, 'ToPort': to_port, 'IpProtocol': proto, 'IpRanges': ipv4, 'Ipv6Ranges': ipv6},], GroupId=sg_id, DryRun=mode)
        print('Authorized sg ingress %s %s' % (sg_id, ('(dryrun)' if mode else '')))
        return response
    except Exception as err:
        handle(err)

def revoke_sg_egress(client, from_port, to_port, proto, sg_id, ipv4, ipv6=[{'CidrIpv6', '::/0'},], mode=True):
    """
    Revoke egress rules from a security group.
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.revoke_security_group_egress
    """
    try:
        response = client.revoke_security_group_egress(IpPermissions=[{'FromPort': from_port, 'ToPort': to_port, 'IpProtocol': proto, 'IpRanges': ipv4, 'Ipv6Ranges': ipv6},], GroupId=sg_id, DryRun=mode)
        print('Revoked sg egress %s %s' % (sg_id, ('(dryrun)' if mode else '')))
        return response
    except Exception as err:
        handle(err)

def revoke_sg_ingress(client, from_port, to_port, proto, sg_id, ipv4, ipv6=[{'CidrIpv6', '::/0'},], mode=True):
    """
    Remove ingress rules to a security group.
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.revoke_security_group_ingress
    """
    try:
        response = client.revoke_security_group_ingress(IpPermissions=[{'FromPort': from_port, 'ToPort': to_port, 'IpProtocol': proto, 'IpRanges': ipv4, 'Ipv6Ranges': ipv6},], GroupId=sg_id, DryRun=mode)
        print('Revoked sg ingress from %s %s' % (sg_id, ('(dryrun)' if mode else '')))
        return response
    except Exception as err:
        handle(err)

###################
### NAT GATEWAY ###
###################

def create_nat_gateway(client, allocation_id, subnet_id, mode=True):
    """
    Create nat gateway.
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.create_nat_gateway
    """
    try:
        if not mode:
            response = client.create_nat_gateway( AllocationId=allocation_id, SubnetId=subnet_id)
        print('Created nat gateway for %s %s' % (subnet_id, ('(dryrun)' if mode else '')))
        return response
    except Exception as err:
        handle(err)

def delete_nat_gateway(client, nat_gw_id, mode=True, response=None):
    """
    Delete a nat gateway.
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.delete_nat_gateway
    """
    try:
        if not mode:
            response = client.delete_nat_gateway( NatGatewayId=nat_gw_id)
            print('Deleted nat gateway for %s %s' % (nat_gw_id, ('(dryrun)' if mode else '')))
        return response
    except Exception as err:
        handle(err)

def get_nat_gateways(client, name='vpc-id', values=[], mode=True):
    """
    Get nat gateways by searching for vpc
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.describe_nat_gateways
    """
    try:
        if not mode:
            return client.describe_nat_gateways(Filters=[{'Name': name, 'Values': values},])
    except Exception as err:
        handle(err)

###################
### ROUTE TABLE ###
###################

def create_route_table(client, vpc_id, mode=True):
    """
    Create route table.
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.create_route_table
    """
    try:
        response = client.create_route_table( VpcId=vpc_id, DryRun=mode)
        print('Created route table for %s %s' % (vpc_id, ('(dryrun)' if mode else '')))
        return response
    except Exception as err:
        handle(err)

def associate_route_table(client, route_table_id, subnet_id, mode=True):
    """
    Associate route table with subnet
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.associate_route_table
    """
    try:
        response = client.associate_route_table( RouteTableId=route_table_id, SubnetId=subnet_id, DryRun=mode)
        print('Associated route table %s to %s %s' % (route_table_id, subnet_id, ('(dryrun)' if mode else '')))
        return response
    except Exception as err:
        handle(err)

def disassociate_route_table(client, association_id, mode=True):
    """
    Disassociate a route table.
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.disassociate_route_table
    """
    try:
        response = client.disassociate_route_table( AssociationId=association_id, DryRun=mode)
        print('Disassociated %s %s' % (association_id, ('(dryrun)' if mode else '')))
        return response
    except Exception as err:
        handle(err)

def delete_route_table(client, route_table_id, mode=True):
    """
    Delete a route table.
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.delete_route_table
    """
    try:
        response = client.delete_route_table( RouteTableId=route_table_id, DryRun=mode)
        print('Deleted %s %s' % (route_table_id, ('(dryrun)' if mode else '')))
        return response
    except Exception as err:
        handle(err)

def get_route_tables(client, name='vpc-id', values=[], mode=True):
    """
    Get route tables by searching for vpc
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.describe_route_tables
    """
    try:
        return client.describe_route_tables(Filters=[{'Name': name, 'Values': values},], DryRun=mode)
    except Exception as err:
        handle(err)

###################
### NETWORK ACL ###
###################

def create_network_acl(client, vpc_id, mode=True):
    """
    Create network acl.
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.create_network_acl
    """
    try:
        response = client.create_network_acl( VpcId=vpc_id, DryRun=mode)
        print('Created network acl for %s %s' % (vpc_id, ('(dryrun)' if mode else '')))
        return response
    except Exception as err:
        handle(err)

def create_network_acl_entry(client, id, num, action, cidr=ec2_cidr_block, proto='6', from_port=22, to_port=22, egress=False, mode=False):
    """
    Create network acl entry
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.create_network_acl_entry
    """
    try:
        if from_port and to_port:
            response = client.create_network_acl_entry(CidrBlock=cidr, Egress=egress, NetworkAclId=id, Protocol=proto, RuleAction=action, RuleNumber=num, DryRun=mode)
        else:
            response = client.create_network_acl_entry(CidrBlock=cidr, Egress=egress, NetworkAclId=id, PortRange={'From': from_port, 'To': to_port}, Protocol=proto, RuleAction=action, RuleNumber=num, DryRun=mode)
        print('Created network acl entry for %s %s' % (id, '(dryrun)' if mode else ''))
        return response

    except Exception as err:
        handle(err)

def delete_network_acl_entry(client, network_acl_id, num=100, egress=False, mode=True):
    """
    Delete a network acl entry
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.delete_network_acl_entry
    """
    try:
        response = client.delete_network_acl_entry( Egress=egress, NetworkAclId=network_acl_id, RuleNumber=num, DryRun=mode)
        print('Deleted %s %s' % (network_acl_id, ('(dryrun)' if mode else '')))
        return response
    except Exception as err:
        handle(err)

def delete_network_acl(client, network_acl_id, mode=True):
    """
    Delete a network acl.
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.delete_network_acl
    """
    try:
        response = client.delete_network_acl( NetworkAclId=network_acl_id, DryRun=mode)
        print('Deleted %s %s' % (network_acl_id, ('(dryrun)' if mode else '')))
        return response
    except Exception as err:
        handle(err)

def get_network_acls(client, name='vpc-id', values=[], mode=True):
    """
    Get network acls by searching for stuff
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.describe_network_acls
    """
    try:
        return client.describe_network_acls(Filters=[{'Name': name, 'Values': values}, {'Name':'default', 'Values':['False']}], DryRun=mode)
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
        response = client.allocate_address( Domain=domain, DryRun=mode)
        print('Created elastic ip for %s %s' % (domain, ('(dryrun)' if mode else '')))
        return response
    except Exception as err:
        handle(err)

def associate_elastic_ip(client, allocation_id, instance_id, mode=True):
    """
    Associate elastic ip with ec2_instance
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.associate_address
    """
    try:
        response = client.associate_address( AllocationId=allocation_id, InstanceId=instance_id, DryRun=mode)
        print('Associated elastic ip with %s %s' % (instance_id, '(dryrun)' if mode else ''))
        return response
    except Exception as err:
        handle(err)

def disassociate_elastic_ip(client, association_id, mode=True):
    """
    Disassociate elastic ip with ec2_instance
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.disassociate_address
    """
    try:
        response = client.disassociate_address( AssociationId=association_id, DryRun=mode)
        print('Disassociated elastic ip %s %s' % (association_id, '(dryrun)' if mode else ''))
        return response
    except Exception as err:
        handle(err)

def release_elastic_ip(client, allocation_id, public_ip='', mode=True):
    """
    Delete a elastic ip.
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.release_address
    """
    try:
        response = client.release_address( AllocationId=allocation_id, DryRun=mode)
        print('Released %s %s %s' % (allocation_id, public_ip, ('(dryrun)' if mode else '')))
        return response
    except Exception as err:
        handle(err)

def get_elastic_ips(client, name='domain', values=['vpc',], instances=[], mode=True):
    """
    Get Elastic IPs by searching for stuff
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.describe_addresses
    """
    try:
        if instances:
            return client.describe_addresses(Filters=[{'Name': 'instance-id', 'Values': instances},], DryRun=mode)
        else:
            return client.describe_addresses(Filters=[{'Name': name, 'Values': values},], DryRun=mode)
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
        response = client.create_internet_gateway(DryRun=mode)
        print('Created internet gateway %s' % ('(dryrun)' if mode else ''))
        return response
    except Exception as err:
        handle(err)

def delete_internet_gateway(client, gateway_id, mode=True):
    """
    Delete a internet gateway.
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.delete_internet_gateway
    """
    try:
        response = client.delete_internet_gateway( InternetGatewayId=gateway_id, DryRun=mode)
        print('Deleted internet gateway %s %s' % (gateway_id, ('(dryrun)' if mode else '')))
        return response
    except Exception as err:
        handle(err)

def get_internet_gateways(client, name='attachment.vpc-id', values=[], mode=True):
    """
    Get internet gateways IPs by searching for stuff
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.describe_internet_gateways
    """
    try:
        return client.describe_internet_gateways(Filters=[{'Name': name, 'Values': values},], DryRun=mode)
    except Exception as err:
        handle(err)

def attach_internet_gateway(client, gateway_id, vpc_id, mode=True):
    """
    Attaches an internet gateway to a VPC
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.attach_internet_gateway
    """
    try:
        response = client.attach_internet_gateway( InternetGatewayId=gateway_id, VpcId=vpc_id, DryRun=mode)
        print('Attached %s to %s %s' % ( gateway_id, vpc_id, ('(dryrun)' if mode else '' )))
        return response
    except Exception as err:
        handle(err)

def detach_internet_gateway(client, gateway_id, vpc_id, mode=True):
    """
    Attaches an internet gateway to a VPC
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.detach_internet_gateway
    """
    try:
        response = client.detach_internet_gateway( InternetGatewayId=gateway_id, VpcId=vpc_id, DryRun=mode)
        print('Detached %s from %s %s' % ( gateway_id, vpc_id, ('(dryrun)' if mode else '' )))
        return response
    except Exception as err:
        handle(err)


####################
### EC2 RESOURCE ###
####################

def create_instance(ec2, sg_id, sn_id, image_id=ec2_ami, image_type=ec2_ami_type, userdata='', key=ec2_keypair_name, mode=True):
    """
    Create and launch a new Amazon EC2 micro instance with boto3.
    Launch a free tier Amazon Linux AMI using your Amazon credentials.
    """
    try:
        response = ec2.create_instances(ImageId=image_id, MaxCount=1, MinCount=1, InstanceType=image_type, SecurityGroupIds=[sg_id,], SubnetId=sn_id, UserData=userdata, KeyName=key, DryRun=mode)
        print('Created instance %s' % ('(dryrun)' if mode else '') )
        return response
    except Exception as err:
        handle(err)

def delete_instance(instance, instances=[], mode=True):
    """
    Delete a ec2 instance
    See https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.delete_security_group
    """
    try:
        print('Terminating instance %s' % ('(dryrun)' if mode else '') )
        instance.terminate(DryRun=mode)
        instance.wait_until_terminated(Filters=[{'Name': 'instance-id', 'Values': instances},], DryRun=mode)
        print('Terminated instance %s' % ('(dryrun)' if mode else '') )
    except Exception as err:
        handle(err)

def get_instances(client, name='tag:project', values=[ec2_project_name,], mode=True):
    """
    Get EC2 instances by searching for stuff
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.describe_instances
    """
    try:
        return client.describe_instances(Filters=[{'Name': name, 'Values': values},], DryRun=mode)
    except Exception as err:
        handle(err)


################################
#### cleanup all resources #####
################################
def clean(ec2, client):
    for mode in (True, False):
        try:
            #### VPC ####
            print("\nCLEAN DOWN EC2 ENVIRON %s" % ('dryrun' if mode else 'for real, please be patient'))
            vpcs = get_vpcs(client, 'cidr', [ec2_cidr_block,], mode)
            if vpcs and "Vpcs" in vpcs and vpcs['Vpcs']:
                for vpc in vpcs['Vpcs']:
                    ec2_vpc_id = vpc['VpcId']

                    ### EC2 INSTANCES ###
                    instances = get_instances(client, 'vpc-id', [ec2_vpc_id,], mode)
                    if instances and "Reservations" in instances and instances['Reservations']:
                        for instance in instances['Reservations'][0]['Instances']:
                            ec2_instance_id = instance['InstanceId']

                            ### ELASTIC IPS ###
                            eips = get_elastic_ips(client, 'domain', ['vpc',], [ec2_instance_id,], mode)
                            if eips and "Addresses" in eips and eips['Addresses']:
                                for ip in eips['Addresses']:
                                    disassociate_elastic_ip(client, ip['AssociationId'], mode)
                                    release_elastic_ip(client, ip['AllocationId'], ip['PublicIp'], mode)
                            else:
                                print('No elastic ips detected')

                            delete_instance( ec2.Instance(ec2_instance_id), ec2_instance_id, mode)
                    else:
                        print('No ec2 instances detected')

                    ### SECURITY GROUPS ###
                    sgs = get_sgs(client, 'vpc-id', ec2_vpc_id, [ec2_group_name,], mode)
                    if sgs and "SecurityGroups" in sgs and sgs['SecurityGroups']:
                        for sg in sgs['SecurityGroups']:
                            revoke_sg_ingress(client, 22, 22, 'TCP',   sg['GroupId'], [{'CidrIp': '0.0.0.0/0'},], [], mode)
                            revoke_sg_ingress(client, 80, 80, 'TCP',   sg['GroupId'], [{'CidrIp': '0.0.0.0/0'},], [], mode)
                            revoke_sg_ingress(client, 443, 443, 'TCP', sg['GroupId'], [{'CidrIp': '0.0.0.0/0'},], [], mode)
                            revoke_sg_egress(client, 22, 22, 'TCP',    sg['GroupId'], [{'CidrIp': '0.0.0.0/0'},], [], mode)
                            revoke_sg_egress(client, 80, 80, 'TCP',    sg['GroupId'], [{'CidrIp': '0.0.0.0/0'},], [], mode)
                            revoke_sg_egress(client, 443, 443, 'TCP',  sg['GroupId'], [{'CidrIp': '0.0.0.0/0'},], [], mode)
                            delete_sg(client, sg['GroupId'], mode)
                    else:
                        print('No security groups detected')

                    ### INTERNET GATEWAY ###
                    gateways = get_internet_gateways(client, 'attachment.vpc-id', [ec2_vpc_id,], mode)
                    if gateways and "InternetGateways" in gateways and gateways['InternetGateways']:
                        for igw in gateways['InternetGateways']:
                            detach_internet_gateway(client, igw['InternetGatewayId'], ec2_vpc_id, mode)
                            delete_internet_gateway(client, igw['InternetGatewayId'], mode)
                    else:
                        print('No internet gateways detected')

                    ### NAT GATEWAY ###
                    gateways = get_nat_gateways(client, 'vpc-id', [ec2_vpc_id,], mode)
                    if gateways and "NatGateways" in gateways and gateways['NatGateways']:
                        for ngw in gateways['NatGateways']:
                            delete_nat_gateway(client, ngw['NatGatewayId'], mode)
                    else:
                        print('No nat gateways detected')

                    ### SUBNETS ###
                    subnets = get_subnets(client, 'vpc-id', [ec2_vpc_id,], mode)
                    if subnets and "Subnets" in subnets and subnets['Subnets']:
                        for sn in subnets['Subnets']:
                            delete_subnet(client, sn['SubnetId'], mode)
                    else:
                        print('No subnets detected')

                    ### NETWORK ACLS ###
                    acls = get_network_acls(client, 'vpc-id', [ec2_vpc_id,], mode)
                    if acls and "NetworkAcls" in acls and acls['NetworkAcls']:
                        for acl in acls['NetworkAcls']:
                            delete_network_acl_entry(client, acl['NetworkAclId'], 100, False, mode)
                            delete_network_acl_entry(client, acl['NetworkAclId'], 100, True, mode)
                            delete_network_acl(client, acl['NetworkAclId'], mode)
                    else:
                        print('No network acls detected')

                    ### ROUTE TABLE ###
                    route_tables = get_route_tables(client, 'vpc-id', [ec2_vpc_id,], mode)
                    if route_tables and "RouteTables" in route_tables and route_tables['RouteTables']:
                        for rt in route_tables['RouteTables']:
                            disassociate_route_table(client, rt['Associations'][0]['RouteTableAssociationId'], mode)
                            delete_route_table(client, rt['RouteTableId'], mode)
                    else:
                        print('No route tables detected')

                    ### VPC ###
                    delete_vpc(client, ec2_vpc_id, mode)
            else:
                print('No VPCs found')
        except Exception as err:
            handle(err)
    return(0)

##########################
#### Create resources ####
##########################
def start(ec2, client):
    for mode in (True, False):
        try:
            print("\nCREATE EC2 ENVIRON %s" % ('dryrun' if mode else 'for real, please be patient'))
            ec2_vpc_id = create_vpc(client, ec2_project_name, ec2_cidr_block, True, 'default', mode)
            if ec2_vpc_id:
                ec2_vpc_id = ec2_vpc_id['Vpc']['VpcId']

                ### INTERNET GATEWAY
                ec2_igw_id = create_internet_gateway(client, mode)
                if ec2_igw_id:
                    ec2_igw_id = ec2_igw_id['InternetGateway']['InternetGatewayId']
                    attach_internet_gateway(client, ec2_igw_id, ec2_vpc_id, mode)

                ### NETWORK ACL ###
                ec2_network_acl_id = create_network_acl(client, ec2_vpc_id, mode)
                if ec2_network_acl_id:
                    ec2_network_acl_id = ec2_network_acl_id['NetworkAcl']['NetworkAclId']
                    create_network_acl_entry(client, ec2_network_acl_id, 100, 'allow', ec2_cidr_block, '6', 0, 0, False, mode)
                    create_network_acl_entry(client, ec2_network_acl_id, 100, 'allow', ec2_cidr_block, '6', 0, 0, True, mode)

                ### ROUTE TABLE ###
                ec2_route_table_id = create_route_table(client, ec2_vpc_id, mode)
                if ec2_route_table_id:
                    ec2_route_table_id = ec2_route_table_id['RouteTable']['RouteTableId']

                ### SUBNET ###
                ec2_subnet_id = create_subnet(client, ec2_vpc_id, ec2_project_name, ec2_cidr_block, mode)
                if ec2_subnet_id:
                    ec2_subnet_id = ec2_subnet_id['Subnet']['SubnetId']

                    ### ELASTIC IP ###
                    ec2_elastic_ip_allocation_id = create_elastic_ip(client, 'vpc', mode)
                    if ec2_elastic_ip_allocation_id:
                        ec2_elastic_ip_allocation_id = ec2_elastic_ip_allocation_id['AllocationId']

                        ### NAT GATEWAY
                        ec2_nat_gw_id = create_nat_gateway(client, ec2_elastic_ip_allocation_id, ec2_subnet_id, mode)
                        if ec2_nat_gw_id:
                            ec2_nat_gw_id = ec2_nat_gw_id['NatGateway']['NatGatewayId']

                ### SECURITY GROUP ###
                ec2_sg_id = create_sg(client, ec2_vpc_id, ec2_project_name, ec2_group_name, mode)
                print(ec2_sg_id)
                if ec2_sg_id:
                    ec2_sg_id = ec2_sg_id['GroupId']
                    authorize_sg_ingress(client, 22, 22, 'TCP',   ec2_sg_id, [{'CidrIp': '0.0.0.0/0'},], [{'CidrIpv6': '::/0'},], mode)
                    authorize_sg_ingress(client, 80, 80, 'TCP',   ec2_sg_id, [{'CidrIp': '0.0.0.0/0'},], [{'CidrIpv6': '::/0'},], mode)
                    authorize_sg_ingress(client, 443, 443, 'TCP', ec2_sg_id, [{'CidrIp': '0.0.0.0/0'},], [{'CidrIpv6': '::/0'},], mode)
                    authorize_sg_egress(client, 22, 22, 'TCP',    ec2_sg_id, [{'CidrIp': '0.0.0.0/0'},], [{'CidrIpv6': '::/0'},], mode)
                    authorize_sg_egress(client, 80, 80, 'TCP',    ec2_sg_id, [{'CidrIp': '0.0.0.0/0'},], [{'CidrIpv6': '::/0'},], mode)
                    authorize_sg_egress(client, 443, 443, 'TCP',  ec2_sg_id, [{'CidrIp': '0.0.0.0/0'},], [{'CidrIpv6': '::/0'},], mode)

                    ### EC2 INSTANCE ###
                    instance = create_instance(ec2, ec2_sg_id, ec2_subnet_id, ec2_ami, ec2_ami_type, ec2_userdata, ec2_keypair_name, mode)
                    if instance and instance[0]:
                        ec2_instance_id = instance[0].id
                        if ec2_instance_id:
                            instance = ec2.Instance(ec2_instance_id)
                            instance.wait_until_running(Filters=[{'Name': 'instance-id', 'Values': [ec2_instance_id,]}], DryRun=mode)

                            #### ELASTIC IP ASSOCIATION  ####
                            ec2_elastic_ip_association_id = associate_elastic_ip(client, ec2_elastic_ip_allocation_id, ec2_instance_id, mode)
                            if ec2_elastic_ip_association_id:
                                ec2_elastic_ip_association_id = ec2_elastic_ip_association_id['AssociationId']

                            #### ROUTE TABLE ASSOCIATION  ####
                            ec2_route_table_association_id = associate_route_table(client, ec2_route_table_id, ec2_subnet_id, mode)
                            if ec2_route_table_association_id:
                                ec2_route_table_association_id = ec2_route_table_association_id['AssociationId']

                        print('created Instance %s %s' % (ec2_instance_id, ('(dryrun)' if mode else ec2_instance_id)))
            else:
                print('No VPCs found')
        except Exception as err:
            handle(err)
    return(0)

def info(ec2, client):
    ### KEY PAIR ###
    try:
        response = get_keypairs(client, 'key-name', [ec2_keypair_name,], False)
        if response and "KeyPairs" in response:
            for key in response['KeyPairs']:
                print("KeyName: %s, KeyFingerprint: %s" % (key['KeyName'], key['KeyFingerprint']))
    except Exception as err:
        handle(err)


#############
### MAIN ####
#############

def main(argv):
    try:
        opts, args = getopt.getopt(argv, "a:t:k:", ["action=", "target=", "keypair="])
    except getopt.GetoptError as e:
        handle(e)

    ### command line arguments ###
    target="ec2"

    if not opts:
        usage()
    for opt, arg in opts:
        if opt in ("-a", "--action",):
            action = arg.lower()
        elif opt in ("-t", "--target"):
            target = arg.lower() or 'ec2'
        elif opt in ("-k", "--keypair"):
            keypair_name = arg.lower()
        else:
            usage()

    client = boto3.client('ec2', region_name=ec2_region_name)
    ec2 = boto3.resource('ec2')
    tag = ec2.Tag('resource_id', 'key', 'value')

    ### workflow ###
    if action == "start" and "ec2" in target:
        start(ec2, client)
    elif action in ("stop", "clean", "terminate") and "ec2" in target:
        clean(ec2, client)
    elif action == "info" and "ec2" in target:
        info(ec2, client)
    else:
        usage()

if __name__ == "__main__":
   try:
       main(sys.argv[1:])
   except Exception as err:
       handle(err)
print('\n')
exit(0)
