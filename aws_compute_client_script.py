#!/usr/bin/env python3
#############################################
# Copyright 2019 NoelMcloughlin
#############################################

import sys, os, getopt, boto3, botocore, time

ec2_keypair_name='ec2_user'
ec2_ami='ami-0fad7378adf284ce0'
ec2_ami_type='t2.micro'
ec2_cidr_block='172.35.0.0/24'
ec2_group_name='mygroupname'
ec2_instance_id=None
ec2_project_name='boto3utils project'
ec2_region_name='eu-west-1'
ec2_peering_region_name='eu-west-1'

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
    print("\n\t  -a --action\tstart|clean|info\tStartup or Teardown EC2 instance environment.")
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

############
### VPCS ###
############

def create_vpc(client, name=ec2_project_name, cidr_ipv4=ec2_cidr_block, autoipv6=False, tenancy='default', dry=True):
    """
    Create a virtual private cloud.
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.create_vpc
    """
    try:
        response = client.create_vpc(CidrBlock=ec2_cidr_block, AmazonProvidedIpv6CidrBlock=True, InstanceTenancy=tenancy, DryRun=dry)
        print('Created vpc %s' % ('(dry)' if dry else ''))
        return response
    except Exception as err:
        handle(err)
    return None

def delete_vpc(client, vpc_id, dry=True):
    """
    Delete a virtual private cloud.
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.delete_vpc
    """
    try:
        response = client.delete_vpc(VpcId=vpc_id, DryRun=dry)
        print('Deleted %s %s' % (vpc_id, ('(dry)' if dry else '')))
        return response
    except Exception as err:
        handle(err, 'vpc')

def get_vpcs(client, name='tag:project', values=[ec2_project_name,], dry=True):
    """
    Get VPC(s) by filter
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.describe_vpcs
    """
    try:
        return client.describe_vpcs(Filters=[{'Name': name, 'Values': values},], DryRun=dry)
    except Exception as err:
        handle(err)


####################
### VPC ENDPOINTS ##
####################

def create_vpc_endpoint(client, vpc_id, rttable_ids, subnet_ids, sg_ids, type='Gateway', svc='com.amazonaws.eu-west-1.ec2', dry=True):
    """
    Create a virtual private cloud.
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.create_vpc_endpoint
    """
    try:
        response = client.create_vpc_endpoint(VpcEndpointType=type, VpcId=vpc_id, ServiceName=svc, RouteTableIds=rttable_ids, SubnetIds=subnet_ids, SecurityGroupIds=sg_ids, Dryrun=dry)
        print('Created vpc_endpoint  %s' % ('(dry)' if dry else ''))
        return response
    except Exception as err:
        handle(err)
    return None

def delete_vpc_endpoints(client, vpc_endpoint_id, dry=True):
    """
    Delete a virtual private cloud endpoint
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.delete_vpc_endpoints
    """
    try:
        response = client.delete_vpc_endpoints(VpcEndpointIds=[vpc_endpoint_id,], DryRun=dry)
        print('Deleted %s %s' % (vpc_endpoint_id, ('(dry)' if dry else '')))
        return response
    except Exception as err:
        handle(err)

def get_vpcs_endpoints(client, name='tag:project', values=[ec2_project_name,], dry=True):
    """
    Get VPC(s) by endpoints filter
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.describe_vpc_endpoints
    """
    try:
        return client.describe_vpc_endpoints(Filters=[{'Name': name, 'Values': values},], DryRun=dry)
    except Exception as err:
        handle(err)


##############################
### VPC PEERING CONNECTIONS ##
##############################

def create_vpc_peering_connection(client, peer_vpc_id, vpc_id, region=ec2_peering_region_name, dry=True):
    """
    Create a virtual private cloud peering connection
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.create_vpc_peering_connection
    """
    try:
        response = client.create_vpc_peering_connection(PeerVpcId=peer_vpc_id, VpcId=vpc_id, PeerRegion=region, Dryrun=dry)
        print('Created vpc_peering_connection  %s' % ('(dry)' if dry else ''))
        return response
    except Exception as err:
        handle(err)
    return None

def delete_vpc_peering_connection(client, vpc_peering_connection_id, dry=True):
    """
    Delete a virtual private cloud peering_connection
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.delete_vpc_peering_connections
    """
    try:
        response = client.delete_vpc_peering_connections(VpcPeeringConnectionId=vpc_peering_connection_id, DryRun=dry)
        print('Deleted %s %s' % (vpc_peering_connection_id, ('(dry)' if dry else '')))
        return response
    except Exception as err:
        handle(err)

def get_vpcs_peering_connections(client, name='tag:project', values=[ec2_project_name,], vpc_peering_connection_ids=None, dry=True):
    """-
    Get VPC(s) by peering_connections filter
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.describe_vpc_peering_connections
    """
    try:
        if vpc_peering_connection_ids:
            return client.describe_vpc_peering_connections(VpcPeeringConnectionIds=vpc_peering_connection_ids, DryRun=dry)
        else:
            return client.describe_vpc_peering_connections(Filters=[{'Name': name, 'Values': values},], DryRun=dry)
    except Exception as err:
        handle(err)


##########################
### NETWORK INTERFACES ###
##########################

def create_network_interface(client, desc=ec2_project_name, groups=None, private_ip=None, private_ips=None, subnet_id=None, dry=True):
    """
    Create a network_interface.
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.create_network_interface
    """
    try:
        response = client.create_network_interface(Description=desc, Groups=groups, PrivateIpAddress=private_ip, PrivateIpAddresses=private_ips, SubnetId=subnet_id, DryRun=dry)
        print('Created network_interface for %s %s' % (private_ip, ('(dry)' if dry else '')))
        return response
    except Exception as err:
        handle(err)
    return None

def delete_network_interface(client, id, dry=True):
    """
    Delete a network_interface.
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.delete_network_interface
    """
    try:
        response = client.delete_network_interface(NetworkInterfaceId=id, DryRun=dry)
        print('Deleted %s %s' % (id, ('(dry)' if dry else '')))
        return response
    except Exception as err:
        handle(err)

def get_network_interfaces(client, name='vpc-id', values=None, network_interface_ids=None, dry=True):
    """
    Get Network interfaces by tag name/value or maybe by array of ids.
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.describe_network_interfaces
    """
    try:
        if network_interface_ids:
            return client.describe_network_interfaces(NetworkInterfaceIds=network_interface_ids, DryRun=dry)
        else:
            return client.describe_network_interfaces(Filters=[{'Name': name, 'Values': values},], DryRun=dry)
    except Exception as err:
        handle(err)

##############
### SUBNET ###
##############

def create_subnet(client, vpc_id, name=ec2_project_name, cidr_ipv4=ec2_cidr_block, dry=True):
    """
    Create a subnet.
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.create_subnet
    """
    try:
        response = client.create_subnet(CidrBlock=cidr_ipv4, VpcId=vpc_id, DryRun=dry)
        print('Created subnet for %s %s' % (cidr_ipv4, ('(dry)' if dry else '')))
        return response
    except Exception as err:
        handle(err)
    return None

def modify_subnet_attribute(client, subnet, value, dry=True):
    """
    Modify a subnet.
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.modify_subnet_attribute
    """
    try:
        response = client.modify_subnet_attribute(SubnetId=subnet, MapPublicIpOnLaunch={'Value': value})
        print('Map %s public-ip-on-launch %s %s' % (subnet, value, ('(dry)' if dry else '')))
        return response
    except Exception as err:
        handle(err)
    return None

def delete_subnet(client, subnet, dry=True):
    """
    Delete a subnet.
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.delete_subnet
    """
    try:
        response = client.delete_subnet(SubnetId=subnet, DryRun=dry)
        print('Deleted %s %s' % (subnet, ('(dry)' if dry else '')))
        return response
    except Exception as err:
        handle(err)

def get_subnets(client, name='tag:project', values=[ec2_project_name,], dry=True):
    """
    Get VPC(s) by tag (note: create_tags not working via client api, use cidr or object_id instead )
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.describe_subnets
    """
    try:
        return client.describe_subnets(Filters=[{'Name': name, 'Values': values},], DryRun=dry)
    except Exception as err:
        handle(err)

#######################
### SECURITY GROUPS ###
#######################

def create_sg(client, vpc_id, desc=ec2_project_name, groupname=ec2_group_name, dry=True):
    """
    Create security group.
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.create_security_group
    """
    try:
        response = client.create_security_group( Description=desc, GroupName=groupname, VpcId=vpc_id, DryRun=dry)
        print('Created security group %s' % ('(dry)' if dry else ''))
        return response
    except Exception as err:
        handle(err)

def delete_sg(client, sg_id, dry=True):
    """
    Delete a security group.
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.delete_security_group
    """
    try:
        response = client.delete_security_group( GroupId=sg_id, DryRun=dry)
        print('Deleted %s %s' % (sg_id, ('(dry)' if dry else '')))
        return response
    except Exception as err:
        handle(err)

def get_sgs(client, name='tag:project', values=[ec2_project_name,], groups=[ec2_group_name,], dry=True):
    """
    Get Security Groups by searching for VPC Id.
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.describe_security_groups
    """
    try:
        if groups:
            return client.describe_security_groups(Filters=[{'Name': 'group-name', 'Values': groups},], DryRun=dry)
        else:
            return client.describe_security_groups(Filters=[{'Name': name, 'Values': values},], DryRun=dry)
    except Exception as err:
        handle(err)

def get_sgs_references(client, groups, dry=True):
    """
    Get Security Groups references
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.describe_security_group_references
    """
    try:
        return client.describe_security_group_references(GroupId=groups, DryRun=dry)
    except Exception as err:
        handle(err)

def authorize_sg_egress(client, from_port, to_port, proto, sg_id, ipv4, ipv6=[{'CidrIpv6', '::/0'},], dry=True):
    """
    Adds egress rules to a security group.
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.authorize_security_group_egress
    """
    try:
        response = client.authorize_security_group_egress(IpPermissions=[{'FromPort': from_port, 'ToPort': to_port, 'IpProtocol': proto, 'IpRanges': ipv4, 'Ipv6Ranges': ipv6},], GroupId=sg_id, DryRun=dry)
        print('Authorized sg egress %s %s' % (sg_id, ('(dry)' if dry else '')))
        return response
    except Exception as err:
        handle(err)

def authorize_sg_ingress(client, from_port, to_port, proto, sg_id, ipv4, ipv6=[{'CidrIpv6', '::/0'},], dry=True):
    """
    Adds ingress rules to a security group.
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.authorize_security_group_ingress
    """
    try:
        response = client.authorize_security_group_ingress(IpPermissions=[{'FromPort': from_port, 'ToPort': to_port, 'IpProtocol': proto, 'IpRanges': ipv4, 'Ipv6Ranges': ipv6},], GroupId=sg_id, DryRun=dry)
        print('Authorized sg ingress %s %s' % (sg_id, ('(dry)' if dry else '')))
        return response
    except Exception as err:
        handle(err)

def revoke_sg_egress(client, from_port, to_port, proto, sg_id, ipv4, ipv6=[{'CidrIpv6', '::/0'},], dry=True):
    """
    Revoke egress rules from a security group.
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.revoke_security_group_egress
    """
    try:
        response = client.revoke_security_group_egress(IpPermissions=[{'FromPort': from_port, 'ToPort': to_port, 'IpProtocol': proto, 'IpRanges': ipv4, 'Ipv6Ranges': ipv6},], GroupId=sg_id, DryRun=dry)
        print('Revoked sg egress %s %s' % (sg_id, ('(dry)' if dry else '')))
        return response
    except Exception as err:
        handle(err)

def revoke_sg_ingress(client, from_port, to_port, proto, sg_id, ipv4, ipv6=[{'CidrIpv6', '::/0'},], dry=True):
    """
    Remove ingress rules to a security group.
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.revoke_security_group_ingress
    """
    try:
        response = client.revoke_security_group_ingress(IpPermissions=[{'FromPort': from_port, 'ToPort': to_port, 'IpProtocol': proto, 'IpRanges': ipv4, 'Ipv6Ranges': ipv6},], GroupId=sg_id, DryRun=dry)
        print('Revoked sg ingress from %s %s' % (sg_id, ('(dry)' if dry else '')))
        return response
    except Exception as err:
        handle(err)

###################
### NAT GATEWAY ###
###################

def create_nat_gateway(client, alloc_id, subnet_id, dry=True):
    """
    Create nat gateway.
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.create_nat_gateway
    """
    try:
        response = client.create_nat_gateway( AllocationId=alloc_id, SubnetId=subnet_id)
        print('Created nat gateway for subnet %s %s' % (subnet_id, ('(dry)' if dry else '')))
        return response
    except Exception as err:
        handle(err)

def delete_nat_gateway(client, nat_gw_id, dry=True, response=None):
    """
    Delete a nat gateway.
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.delete_nat_gateway
    """
    try:
        response = client.delete_nat_gateway( NatGatewayId=nat_gw_id)
        print('Deleted nat gateway for subnet %s %s' % (nat_gw_id, ('(dry)' if dry else '')))
        return response
    except Exception as err:
        handle(err)

def get_nat_gateways(client, name, values, dry=True):
    """
    Get nat gateways by searching for vpc
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.describe_nat_gateways
    """
    try:
        return client.describe_nat_gateways(Filters=[{'Name': name, 'Values': values},])
    except Exception as err:
        handle(err)

###################
### ROUTE TABLE ###
###################

def create_route_table(client, vpc_id, dry=True):
    """
    Create route table.
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.create_route_table
    """
    try:
        response = client.create_route_table( VpcId=vpc_id, DryRun=dry)
        print('Created route table for %s %s' % (vpc_id, ('(dry)' if dry else '')))
        return response
    except Exception as err:
        handle(err)

def create_route(client, ver, cidr, gateway_id, route_table_id, dry=True):
    """
    Create a route in route table
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.create_route
    """
    try:
        if ver == 'ipv6':
            response = client.create_route( DestinationIpv6CidrBlock=cidr, GatewayId=gateway_id, RouteTableId=route_table_id, DryRun=dry)
        else:
            response = client.create_route( DestinationCidrBlock=cidr, GatewayId=gateway_id, RouteTableId=route_table_id, DryRun=dry)
        print('Created %s route for %s %s' % (ver, cidr, ('(dry)' if dry else '')))
        return response
    except Exception as err:
        handle(err)

def delete_route(client, cidr, route_table_id, dry=True):
    """
    Create a route in route table
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.delete_route
    """
    try:
        response = client.delete_route( DestinationCidrBlock=cidr, RouteTableId=route_table_id, DryRun=dry)
        print('Deleted route for %s %s' % (cidr, ('(dry)' if dry else '')))
        return response
    except Exception as err:
        handle(err)

def associate_route_table(client, route_table_id, subnet_id, dry=True):
    """
    Associate route table with subnet
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.associate_route_table
    """
    try:
        response = client.associate_route_table( RouteTableId=route_table_id, SubnetId=subnet_id, DryRun=dry)
        print('Associated route table %s to %s %s' % (route_table_id, subnet_id, ('(dry)' if dry else '')))
        return response
    except Exception as err:
        handle(err)

def disassociate_route_table(client, association_id, dry=True):
    """
    Disassociate a route table.
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.disassociate_route_table
    """
    try:
        response = client.disassociate_route_table( AssociationId=association_id, DryRun=dry)
        print('Disassociated %s %s' % (association_id, ('(dry)' if dry else '')))
        return response
    except Exception as err:
        handle(err)

def delete_route_table(client, route_table_id, dry=True):
    """
    Delete a route table.
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.delete_route_table
    """
    try:
        response = client.delete_route_table( RouteTableId=route_table_id, DryRun=dry)
        print('Deleted %s %s' % (route_table_id, ('(dry)' if dry else '')))
        return response
    except Exception as err:
        handle(err)

def get_route_tables(client, name, values, name1=None, values1=None, dry=True):
    """
    Get route tables by searching for vpc
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.describe_route_tables
    """
    try:
        if name1 and values1:
            return client.describe_route_tables(Filters=[{'Name': name, 'Values': values}, {'Name': name1, 'Values': values1}], DryRun=dry)
        else:
            return client.describe_route_tables(Filters=[{'Name': name, 'Values': values}], DryRun=dry)
    except Exception as err:
        handle(err)

###################
### NETWORK ACL ###
###################

def create_network_acl(client, vpc_id, dry=True):
    """
    Create network acl.
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.create_network_acl
    """
    try:
        response = client.create_network_acl( VpcId=vpc_id, DryRun=dry)
        print('Created network acl for %s %s' % (vpc_id, ('(dry)' if dry else '')))
        return response
    except Exception as err:
        handle(err)

def replace_network_acl_association(client, network_acl_id, association_id, dry=True):
    """
    Replace network acl.
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.replace_network_acl_association
    """
    try:
        response = client.replace_network_acl_association( AssociationId=association_id, NetworkAclId=network_acl_id, DryRun=dry)
        print('Replaced network association %s %s' % (network_acl_id, ('(dry)' if dry else '')))
        return response
    except Exception as err:
        handle(err)

def create_network_acl_entry(client, id, num, action, cidr=ec2_cidr_block, proto='6', from_port=22, to_port=22, egress=False, dry=False):
    """
    Create network acl entry
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.create_network_acl_entry
    """
    try:
        if from_port and to_port:
            response = client.create_network_acl_entry(CidrBlock=cidr, Egress=egress, NetworkAclId=id, Protocol=proto, RuleAction=action, RuleNumber=num, DryRun=dry)
        else:
            response = client.create_network_acl_entry(CidrBlock=cidr, Egress=egress, NetworkAclId=id, PortRange={'From': from_port, 'To': to_port}, Protocol=proto, RuleAction=action, RuleNumber=num, DryRun=dry)
        print('Created network acl entry for %s %s' % (id, '(dry)' if dry else ''))
        return response

    except Exception as err:
        handle(err)

def delete_network_acl_entry(client, network_acl_id, num=100, egress=False, dry=True):
    """
    Delete a network acl entry
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.delete_network_acl_entry
    """
    try:
        response = client.delete_network_acl_entry( Egress=egress, NetworkAclId=network_acl_id, RuleNumber=num, DryRun=dry)
        print('Deleted %s %s' % (network_acl_id, ('(dry)' if dry else '')))
        return response
    except Exception as err:
        handle(err)

def delete_network_acl(client, network_acl_id, dry=True):
    """
    Delete a network acl.
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.delete_network_acl
    """
    try:
        response = client.delete_network_acl( NetworkAclId=network_acl_id, DryRun=dry)
        print('Deleted %s %s' % (network_acl_id, ('(dry)' if dry else '')))
        return response
    except Exception as err:
        handle(err)

def get_network_acls(client, name, values, dry=True):
    """
    Get network acls by searching for stuff
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.describe_network_acls
    """
    try:
        return client.describe_network_acls(Filters=[{'Name': name, 'Values':values}], DryRun=dry)
    except Exception as err:
        handle(err)

###################
### ELASTIC IPS ###
###################

def create_elastic_ip(client, domain='vpc', dry=True):
    """
    Create elastic ip.
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.allocate_address
    """
    try:
        response = client.allocate_address( Domain=domain, DryRun=dry)
        print('Created elastic ip for %s %s' % (domain, ('(dry)' if dry else '')))
        return response
    except Exception as err:
        handle(err)

def associate_elastic_ip(client, alloc_id, instance_id, dry=True):
    """
    Associate elastic ip with ec2_instance
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.associate_address
    """
    try:
        response = client.associate_address( AllocationId=alloc_id, InstanceId=instance_id, DryRun=dry)
        print('Associated elastic ip with %s %s' % (instance_id, '(dry)' if dry else ''))
        return response
    except Exception as err:
        handle(err)

def disassociate_elastic_ip(client, association_id, dry=True):
    """
    Disassociate elastic ip with ec2_instance
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.disassociate_address
    """
    try:
        response = client.disassociate_address( AssociationId=association_id, DryRun=dry)
        print('Disassociated elastic ip %s %s' % (association_id, '(dry)' if dry else ''))
        return response
    except Exception as err:
        handle(err)

def release_elastic_ip(client, alloc_id, public_ip='', dry=True):
    """
    Delete a elastic ip.
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.release_address
    """
    try:
        response = client.release_address( AllocationId=alloc_id, DryRun=dry)
        print('Released %s %s %s' % (alloc_id, public_ip, ('(dry)' if dry else '')))
        return response
    except Exception as err:
        handle(err)

def get_elastic_ips(client, name='domain', values=['vpc',], instances=[], dry=True):
    """
    Get Elastic IPs by searching for stuff
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.describe_addresses
    """
    try:
        if instances:
            return client.describe_addresses(Filters=[{'Name': 'instance-id', 'Values': instances},], DryRun=dry)
        else:
            return client.describe_addresses(Filters=[{'Name': name, 'Values': values},], DryRun=dry)
    except Exception as err:
        handle(err)


########################
### INTERNET GATEWAY ###
########################

def create_internet_gateway(client, dry=True):
    """
    Create internet gateway.
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.create_internet_gateway
    """
    try:
        response = client.create_internet_gateway(DryRun=dry)
        print('Created internet gateway %s' % ('(dry)' if dry else ''))
        return response
    except Exception as err:
        handle(err)

def delete_internet_gateway(client, gateway_id, dry=True):
    """
    Delete a internet gateway.
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.delete_internet_gateway
    """
    try:
        response = client.delete_internet_gateway( InternetGatewayId=gateway_id, DryRun=dry)
        print('Deleted internet gateway %s %s' % (gateway_id, ('(dry)' if dry else '')))
        return response
    except Exception as err:
        handle(err)

def get_internet_gateways(client, name, values, dry=True):
    """
    Get internet gateways IPs by searching for stuff
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.describe_internet_gateways
    """
    try:
        return client.describe_internet_gateways(Filters=[{'Name': name, 'Values': values},], DryRun=dry)
    except Exception as err:
        handle(err)

def attach_internet_gateway(client, gateway_id, vpc_id, dry=True):
    """
    Attaches an internet gateway to a VPC
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.attach_internet_gateway
    """
    try:
        response = client.attach_internet_gateway( InternetGatewayId=gateway_id, VpcId=vpc_id, DryRun=dry)
        print('Attached %s to %s %s' % ( gateway_id, vpc_id, ('(dry)' if dry else '' )))
        return response
    except Exception as err:
        handle(err)

def detach_internet_gateway(client, gateway_id, vpc_id, dry=True):
    """
    Attaches an internet gateway to a VPC
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.detach_internet_gateway
    """
    try:
        response = client.detach_internet_gateway( InternetGatewayId=gateway_id, VpcId=vpc_id, DryRun=dry)
        print('Detached %s from %s %s' % ( gateway_id, vpc_id, ('(dry)' if dry else '' )))
        return response
    except Exception as err:
        handle(err)


####################
### EC2 RESOURCE ###
####################

def create_instance(ec2, sg_id, sn_id, image_id=ec2_ami, image_type=ec2_ami_type, userdata='', key=ec2_keypair_name, dry=True):
    """
    Create and launch a new Amazon EC2 micro instance with boto3.
    Launch a free tier Amazon Linux AMI using your Amazon credentials.
    """
    try:
        response = ec2.create_instances(ImageId=image_id, MaxCount=1, MinCount=1, InstanceType=image_type, SecurityGroupIds=[sg_id,], SubnetId=sn_id, UserData=userdata, KeyName=key, DryRun=dry)
        print('Creating instance %s' % ('(dry)' if dry else '') )
        return response
    except Exception as err:
        handle(err)

def delete_instance(instance, instances, dry=True):
    """
    Delete a ec2 instance
    """
    try:
        print('Terminating instance %s' % ('(dry)' if dry else '') )
        instance.terminate(DryRun=dry)
        instance.wait_until_terminated(Filters=[{'Name': 'instance-id', 'Values': instances},], DryRun=dry)
        print('Terminated instance %s' % ('(dry)' if dry else '') )
    except Exception as err:
        handle(err)

def get_instances(client, name, values, dry=True):
    """
    Get EC2 instances by searching for stuff
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.describe_instances
    """
    try:
        return client.describe_instances(Filters=[{'Name': name, 'Values': values},], DryRun=dry)
    except Exception as err:
        handle(err)


################################
#### cleanup all resources #####
################################
def clean_sgs(client, sg_id, sg_name, dry):
    revoke_sg_ingress(client, 22, 22, 'TCP',   sg_id, [{'CidrIp': '0.0.0.0/0'},], [], dry)
    revoke_sg_ingress(client, 80, 80, 'TCP',   sg_id, [{'CidrIp': '0.0.0.0/0'},], [], dry)
    revoke_sg_ingress(client, 443, 443, 'TCP', sg_id, [{'CidrIp': '0.0.0.0/0'},], [], dry)
    revoke_sg_egress(client, 22, 22, 'TCP',    sg_id, [{'CidrIp': '0.0.0.0/0'},], [], dry)
    revoke_sg_egress(client, 80, 80, 'TCP',    sg_id, [{'CidrIp': '0.0.0.0/0'},], [], dry)
    revoke_sg_egress(client, 443, 443, 'TCP',  sg_id, [{'CidrIp': '0.0.0.0/0'},], [], dry)
    if sg_name != 'default':
        time.sleep(5)
        print('Deleting sg %s' % sg_id)
        delete_sg(client, sg_id, dry)


def clean(ec2, client):
    for dry in (True, False):
        try:
            #### VPC ####
            print("\nCLEAN DOWN EC2 ENVIRON %s" % ('dry' if dry else 'for real, please be patient'))
            vpcs = get_vpcs(client, 'cidr', [ec2_cidr_block,], dry)
            if vpcs and "Vpcs" in vpcs and vpcs['Vpcs']:
                for vpc in vpcs['Vpcs']:
                    ec2_vpc_id = vpc['VpcId']
                    print('Found: %s' % ec2_vpc_id)

                    ### VPC ENDPOINTS ###
                    endpoints = get_vpcs_endpoints(client, 'vpc-id', [ec2_vpc_id,], dry)
                    if endpoints and 'VpcEndpoints' in endpoints and endpoints['VpcEndpoints']:
                        for endpoint in endpoints['VpcEndpoints']:
                            delete_vpc_endpoints(client, endpoint['VpcEndpointId'], dry)
                    else:
                        print('No vpc endpoints detected')

                    ### VPC CONNECTION ENDPOINTS ###
                    conn_endpoints = get_vpcs_peering_connections(client, 'tag:project', [ec2_project_name], dry)
                    if conn_endpoints and 'VpcPeeringConnections' in conn_endpoints and conn_endpoints['VpcPeeringConnections']:
                        for conn_endpoint in conn_endpoints['VpcPeeringConnections']:
                            delete_vpcs_peering_endpoints(client, conn_endpoint['VpcPeeringConnectionId'], dry)
                    else:
                        print('No vpc connection endpoints detected')

                    ### EC2 INSTANCES ###
                    instances = get_instances(client, 'vpc-id', [ec2_vpc_id,], dry)
                    if instances and "Reservations" in instances and instances['Reservations']:
                        for instance in instances['Reservations'][0]['Instances']:
                            ec2_instance_id = instance['InstanceId']

                            ### ELASTIC IPS ###
                            eips = get_elastic_ips(client, 'domain', ['vpc',], [ec2_instance_id,], dry)
                            if eips and "Addresses" in eips and eips['Addresses']:
                                for ip in eips['Addresses']:
                                    disassociate_elastic_ip(client, ip['AssociationId'], dry)
                                    release_elastic_ip(client, ip['AllocationId'], ip['PublicIp'], dry)
                            else:
                                print('No elastic ips detected')

                            delete_instance( ec2.Instance(ec2_instance_id), [ec2_instance_id,], dry)
                    else:
                        print('No ec2 instances detected')

                    ### INTERNET GATEWAY ###
                    gateways = get_internet_gateways(client, 'attachment.vpc-id', [ec2_vpc_id,], dry)
                    if gateways and "InternetGateways" in gateways and gateways['InternetGateways']:
                        for igw in gateways['InternetGateways']:
                            detach_internet_gateway(client, igw['InternetGatewayId'], ec2_vpc_id, dry)
                            delete_internet_gateway(client, igw['InternetGatewayId'], dry)
                    else:
                        print('No internet gateways detected')

                    ### NETWORK INTERFACES ###
                    network_interfaces = get_network_interfaces(client, 'group-name', [ec2_group_name], None, dry)
                    if network_interfaces and "NetworkInterfaces" in network_interfaces and network_interfaces['NetworkInterfaces']:
                        for iface in network_interfaces['NetworkInterfaces']:
                            delete_network_interface(client, iface ['NetworkInterfaceId'], dry)
                    else:
                        print('No network interfaces detected')

                    ### SUBNETS ###
                    subnets = get_subnets(client, 'vpc-id', [ec2_vpc_id,], dry)
                    if subnets and "Subnets" in subnets and subnets['Subnets']:
                        for sn in subnets['Subnets']:
                            delete_subnet(client, sn['SubnetId'], dry)
                    else:
                        print('No subnets detected')

                    ### ROUTE TABLES ###
                    route_tables = get_route_tables(client, 'vpc-id', [ec2_vpc_id,], 'association.main', False, dry)
                    if route_tables and "RouteTables" in route_tables and route_tables['RouteTables']:
                        for rt in route_tables['RouteTables']:
                            if rt['Associations']:
                                if rt['Associations'][0]['Main']:
                                    print('Skipping main route table')
                                else:
                                    disassociate_route_table(client, rt['Associations'][0]['RouteTableAssociationId'], dry)
                                    delete_route(client, '0.0.0.0/0',    rt['RouteTableId'], dry)
                                    delete_route(client, '::/0',         rt['RouteTableId'], dry)
                                    delete_route(client, ec2_cidr_block, rt['RouteTableId'], dry)
                                    delete_route_table(client, rt['RouteTableId'], dry)
                            else:
                                delete_route_table(client, rt['RouteTableId'], dry)
                    else:
                        print('No route tables detected')

                    ### NAT GATEWAY ###
                    gateways = get_nat_gateways(client, 'vpc-id', [ec2_vpc_id,], dry)
                    if gateways and "NatGateways" in gateways and gateways['NatGateways']:
                        for ngw in gateways['NatGateways']:
                            delete_nat_gateway(client, ngw['NatGatewayId'], dry)
                    else:
                        print('No nat gateways detected')

                    ### NETWORK ACLS ###
                    acls = get_network_acls(client, 'vpc-id', [ec2_vpc_id,], dry)
                    if acls and "NetworkAcls" in acls and acls['NetworkAcls']:
                        for acl in acls['NetworkAcls']:
                            delete_network_acl_entry(client, acl['NetworkAclId'], 100, False, dry)
                            delete_network_acl_entry(client, acl['NetworkAclId'], 100, True, dry)
                            delete_network_acl_entry(client, acl['NetworkAclId'], 101, False, dry)
                            delete_network_acl_entry(client, acl['NetworkAclId'], 101, True, dry)
                            delete_network_acl(client, acl['NetworkAclId'], dry)
                    else:
                        print('No network acls detected')

                    ### SECURITY GROUPS ###
                    sgs = get_sgs(client, 'vpc-id', [ec2_vpc_id,], [ec2_group_name,], dry)
                    if sgs and "SecurityGroups" in sgs and sgs['SecurityGroups']:
                        for sg in sgs['SecurityGroups']:

                            ### REFERENCING SECURITY GROUPS ###
                            refs = get_sgs_references(client, [sg['GroupId'],], dry)
                            if refs and "SecurityGroupReferenceSet" in refs and refs['SecurityGroupReferenceSet']:
                                for ref in refs['SecurityGroupReferenceSet']:
                                    for rg in get_sgs(client, 'vpc-id', [ref[0]['ReferencingVpcId'],], dry):
                                        clean_sgs(client, rg['GroupId'], rg['GroupName'], dry)
                            else:
                                print('No referencing security groups detected')
                            clean_sgs(client, sg['GroupId'], sg['GroupName'], dry)
                    else:
                        print('No security groups detected')

                    ### VPC ###
                    check = get_vpcs(client, 'vpc-id', [ec2_vpc_id,], dry)
                    if check and 'Vpcs' in check and check['Vpcs']:
                        print('Deleting VPC %s' % ec2_vpc_id)
                        delete_vpc(client, ec2_vpc_id, dry)
                    else:
                        print('Security group %s already deleted' % ec2_vpc_id)

            else:
                print('No VPCs found')
        except Exception as err:
            handle(err)
    return(0)

##########################
#### Create resources ####
##########################
def start(ec2, client):
    for dry in (True, False):
        try:
            print("\nCREATE EC2 ENVIRON %s" % ('dry' if dry else 'for real, please be patient'))
            ### VPC ###
            ec2_vpc_id = create_vpc(client, ec2_project_name, ec2_cidr_block, True, 'default', dry)
            if ec2_vpc_id:
                ec2_vpc_id = ec2_vpc_id['Vpc']['VpcId']
                ec2_elastic_ip_alloc_id=None
                ec2_route_table_id=None
                ec2_network_acl_associations_dict=None

                ### INTERNET GATEWAY
                ec2_igw_id = create_internet_gateway(client, dry)
                if ec2_igw_id:
                    ec2_igw_id = ec2_igw_id['InternetGateway']['InternetGatewayId']
                    attach_internet_gateway(client, ec2_igw_id, ec2_vpc_id, dry)

                ### ROUTE TABLE ###
                ec2_route_table_id = create_route_table(client, ec2_vpc_id, dry)
                if ec2_route_table_id:
                    ec2_route_table_id = ec2_route_table_id['RouteTable']['RouteTableId']
                    create_route(client, 'ipv4', '0.0.0.0/0', ec2_igw_id, ec2_route_table_id, dry)
                    create_route(client, 'ipv6', '::/0',      ec2_igw_id, ec2_route_table_id, dry)

                ### SUBNET ###
                ec2_subnet_id = create_subnet(client, ec2_vpc_id, ec2_project_name, ec2_cidr_block, dry)
                if ec2_subnet_id:
                    ec2_subnet_id = ec2_subnet_id['Subnet']['SubnetId']
                    modify_subnet_attribute(client, ec2_subnet_id, True, dry)

                    ### NETWORK ACL ###
                    ec2_network_acl_id = create_network_acl(client, ec2_vpc_id, dry)
                    if ec2_network_acl_id:
                        ec2_network_acl_associations_dict=ec2_network_acl_id['NetworkAcl']['Associations']
                        ec2_network_acl_id = ec2_network_acl_id['NetworkAcl']['NetworkAclId']
                        create_network_acl_entry(client, ec2_network_acl_id, 100, 'allow', ec2_cidr_block, '6', 0, 0, False, dry)
                        create_network_acl_entry(client, ec2_network_acl_id, 100, 'allow', ec2_cidr_block, '6', 0, 0, True, dry)

                    ### ELASTIC IP ###
                    ec2_elastic_ip_alloc_id = create_elastic_ip(client, 'vpc', dry)
                    if ec2_elastic_ip_alloc_id:
                        ec2_elastic_ip_alloc_id = ec2_elastic_ip_alloc_id['AllocationId']

                    ### NAT GATEWAY
                    #ec2_nat_gw_id = create_nat_gateway(client, ec2_elastic_ip_alloc_id, ec2_subnet_id, dry)
                    #if ec2_nat_gw_id:
                    #    ec2_nat_gw_id = ec2_nat_gw_id['NatGateway']['NatGatewayId']

                ### SECURITY GROUP ###
                ec2_sg_id = create_sg(client, ec2_vpc_id, ec2_project_name, ec2_group_name, dry)
                if ec2_sg_id:
                    ec2_sg_id = ec2_sg_id['GroupId']
                    authorize_sg_ingress(client, 22, 22, 'TCP',   ec2_sg_id, [{'CidrIp': '0.0.0.0/0'},], [{'CidrIpv6': '::/0'},], dry)
                    authorize_sg_ingress(client, 80, 80, 'TCP',   ec2_sg_id, [{'CidrIp': '0.0.0.0/0'},], [{'CidrIpv6': '::/0'},], dry)
                    authorize_sg_ingress(client, 443, 443, 'TCP', ec2_sg_id, [{'CidrIp': '0.0.0.0/0'},], [{'CidrIpv6': '::/0'},], dry)
                    authorize_sg_egress(client, 22, 22, 'TCP',    ec2_sg_id, [{'CidrIp': '0.0.0.0/0'},], [{'CidrIpv6': '::/0'},], dry)
                    authorize_sg_egress(client, 80, 80, 'TCP',    ec2_sg_id, [{'CidrIp': '0.0.0.0/0'},], [{'CidrIpv6': '::/0'},], dry)
                    authorize_sg_egress(client, 443, 443, 'TCP',  ec2_sg_id, [{'CidrIp': '0.0.0.0/0'},], [{'CidrIpv6': '::/0'},], dry)

                    ### EC2 INSTANCE ###
                    instance = create_instance(ec2, ec2_sg_id, ec2_subnet_id, ec2_ami, ec2_ami_type, ec2_userdata, ec2_keypair_name, dry)
                    if instance and instance[0]:
                        ec2_instance_id = instance[0].id
                        if ec2_instance_id:
                            instance = ec2.Instance(ec2_instance_id)
                            instance.wait_until_running(Filters=[{'Name': 'instance-id', 'Values': [ec2_instance_id,]}], DryRun=dry)

                            #### ELASTIC IP ASSOCIATION  ####
                            if ec2_elastic_ip_alloc_id:
                                ec2_elastic_ip_association_id=associate_elastic_ip(client, ec2_elastic_ip_alloc_id, ec2_instance_id, dry)
                                if ec2_elastic_ip_association_id:
                                    ec2_elastic_ip_association_id = ec2_elastic_ip_association_id['AssociationId']

                            #### ROUTE TABLE ASSOCIATION  ####
                            if ec2_route_table_id:
                                ec2_route_table_association_id = associate_route_table(client, ec2_route_table_id, ec2_subnet_id, dry)
                                if ec2_route_table_association_id:
                                    ec2_route_table_association_id = ec2_route_table_association_id['AssociationId']

                            #### NETWORK ACL ASSOCIATION ####
                            if ec2_subnet_id and ec2_network_acl_associations_dict:
                                acl_association_id = ec2_network_acl_associations_dict[0]['NetworkAclAssociationId']
                                replace_network_acl_association(client, ec2_network_acl_id, association_id, dry)

                        print('created Instance %s %s' % (ec2_instance_id, ('(dry)' if dry else ec2_instance_id)))
            else:
                print('No VPCs found')
        except Exception as err:
            handle(err)
    return(0)


#############
### MAIN ####
#############

def main(argv):
    try:
        opts, args = getopt.getopt(argv, "a:", ["action=",])
    except getopt.GetoptError as e:
        handle(e)

    ### command line arguments ###
    if not opts:
        usage()
    for opt, arg in opts:
        if opt in ("-a", "--action",):
            action = arg.lower()
        else:
            usage()

    ec2 = boto3.resource('ec2', region_name=ec2_region_name)
    client = ec2.meta.client
    tag = ec2.Tag('resource_id', 'key', 'value')

    ### workflow ###
    if action == "start":
        start(ec2, client)
    elif action in ("stop", "clean", "terminate"):
        clean(ec2, client)
    elif action == "info":
        info(ec2, client)
    else:
        usage()

if __name__ == "__main__":
   try:
       main(sys.argv[1:])
   except Exception as err:
       handle(err)
exit(0)
