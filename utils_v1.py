#!/usr/bin/env python3

import boto3
import botocore

g_ami='ami-0fad7378adf284ce0'
g_ami_type='t2.micro'
g_cidr_block='10.0.0.0/16'
g_elastic_ip_allocation_id=None
g_elastic_ip_association_id=None
g_group_name='mygroupname'
g_instance_id=None
g_internet_gateway_id=None
g_project_name='assignment project'
g_region_name='eu-west-1'
g_sg_id=None
g_subnet_id=None
g_tenancy='default'
g_vpc_id=None
instance=None
g_startup_script="""
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

def handle(error):
    if error.response['Error']['Code'] in ('DependencyViolation',):
        print('Failed (%s)' % error.response['Error']['Code'])
    elif error.response['Error']['Code'] in ('InvalidGroup.NotFound',):
        print('Failed (%s)' % error.response['Error']['Code'])
    elif error.response['Error']['Code'] in ('CannotDelete',):
        return
        print('Failed (%s)' % error.response['Error']['Code'])
    elif error.response['Error']['Code'] in ('VpcLimitExceeded',):
        print('Failed (%s)' % error.response['Error']['Code'])
    elif error.response['Error']['Code'] in ('UnauthorizedOperation',):
        print('Failed (%s)' % error.response['Error']['Code'])
    elif error.response['Error']['Code'] in ('DryRunOperation',):
        return
    else:
        print("Failed with %s" % error)
    print(error)
    exit (1)

############
### VPCS ###
############

def create_vpc(client, name=g_project_name, cidr_ipv4=g_cidr_block, autoipv6=False, tenancy=g_tenancy, mode=True):
    """
    Create a virtual private cloud.
    See https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.create_vpc
    """
    try:
        vpc = client.create_vpc(CidrBlock=g_cidr_block, AmazonProvidedIpv6CidrBlock=True, InstanceTenancy=tenancy, DryRun=mode)
        ##vpc.create_tags(Tags=[{"Key": "project", "Value": g_project_name}])
        return vpc
    except Exception as err:
        handle(err)
    return None

def delete_vpc(client, vpc_id=g_vpc_id, mode=True):
    """
    Delete a virtual private cloud.
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.delete_vpc
    """
    try:
        print('Deleting %s' % vpc_id)
        return client.delete_vpc(VpcId=vpc_id, DryRun=mode)
    except Exception as err:
        handle(err)

def get_vpcs(client, tagname='tag:project', tagvalue=g_project_name, mode=True):
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

def create_subnet(client, name=g_project_name, cidr_ipv4=g_cidr_block, vpc=g_vpc_id, mode=True):
    """
    Create a subnet.
    See https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.create_subnet
    """
    try:
        subnet = client.create_subnet(CidrBlock=g_cidr_block, VpcId=g_vpc_id, DryRun=mode)
        #not working#subnet.create_tags(Tags=[{"Key": "project", "Value": g_project_name}])
        return subnet
    except Exception as err:
        handle(err)
    return None

def delete_subnet(client, subnet=g_subnet_id, mode=True):
    """
    Delete a subnet.
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.delete_subnet
    """
    try:
        print('Deleting %s' % subnet)
        return client.delete_subnet(SubnetId=subnet, DryRun=mode)
    except Exception as err:
        handle(err)

def get_subnets(client, tagname='tag:project', tagvalue=g_project_name, mode=True):
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

def create_sg(client, desc=g_project_name, groupname=g_group_name, vpc=g_vpc_id, mode=True):
    """
    Create security group.
    See https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.create_security_group
    """
    try:
        return client.create_security_group( Description=desc, GroupName=groupname, VpcId=vpc, DryRun=mode)
    except Exception as err:
        handle(err)

def delete_sg(client, groupid=g_sg_id, mode=True):
    """
    Delete a security group.
    See https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.delete_security_group
    """
    try:
        print('Deleting %s' % groupid)
        return client.delete_security_group( GroupId=groupid, DryRun=mode)
    except Exception as err:
        handle(err)

def get_sgs(client, name='tag:project', value=g_project_name, groupname=g_group_name, mode=True):
    """
    Get Security Groups by searching for VPC Id.
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.describe_security_groups
    """
    try:
        return client.describe_security_groups(Filters=[{'Name': name, 'Values': [value,]}, {'Name': 'group-name', 'Values': [groupname,]},], DryRun=mode)
    except Exception as err:
        handle(err)

def add_sg_ingress(client, fromport=80, toport=80, ipprotocol='TCP', ipranges=[{'CidrIp': '0.0.0.0/0'},], ipv6ranges=[{'CidrIpv6', '::/0'},], groupid=g_sg_id, mode=True):
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

def associate_elastic_ip(client, allocation_id=g_elastic_ip_allocation_id, instance_id=g_instance_id, mode=True):
    """
    Associate elastic ip.
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.associate_address
    """
    try:
        return client.associate_address( AllocationId=allocation_id, InstanceId=instance_id, DryRun=mode)
    except Exception as err:
        handle(err)

def delete_elastic_ip(client, allocation_id=g_elastic_ip_allocation_id, public_ip='', mode=True):
    """
    Delete a elastic ip.
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.release_address
    """
    try:
        print('Deleting %s %s' % (allocation_id, public_ip))
        return client.release_address( AllocationId=allocation_id, DryRun=mode)
    except Exception as err:
        handle(err)

def get_elastic_ips(client, name='domain', value='vpc', allocation_id=g_elastic_ip_allocation_id, instance_id=g_instance_id, mode=True):
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
        client.create_internet_gateway(DryRun=mode)
    except Exception as err:
        handle(err)

def delete_internet_gateway(client, gateway_id=g_internet_gateway_id, mode=True):
    """
    Delete a internet gateway.
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.delete_internet_gateway
    """
    try:
        print('Deleting %s' % gateway_id)
        return client.delete_internet_gateway( gateway_id=g_internet_gateway_id, DryRun=mode)
    except Exception as err:
        handle(err)

def get_internet_gateways(client, name='attachment.vpc-id', value=g_vpc_id, gateway_id=g_internet_gateway_id, mode=True):
    """
    Get internet gateways IPs by searching for stuff
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.describe_internet_gateways
    """
    try:
        if gateway_id:
            return client.describe_internet_gateways(Filters=[{'Name': name, 'Values': [value,]},], InternetGatewayIds=[gateway_id,], DryRun=mode)
        else:
            return client.describe_internet_gateways(Filters=[{'Name': name, 'Values': [value,]},], DryRun=mode)
    except Exception as err:
        handle(err)

def attach_internet_gateway(client, gateway_id=g_internet_gateway_id, vpc_id=g_vpc_id, mode=True):
    """
    Attaches an internet gateway to a VPC
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.attach_internet_gateway
    """
    try:
        client.attach_internet_gateway( InternetGatewayId=gateway_id, VpcId=vpc_id, DryRun=mode)
    except Exception as err:
        handle(err)


####################
### EC2 RESOURCE ###
####################

def create_instance(image_id=g_ami, image_type=g_ami_type, sg_id=g_sg_id, sn_id=g_subnet_id, userdata='', mode=True):
    """
    Create and launch a new Amazon EC2 micro instance with boto3.
    Launch a free tier Amazon Linux AMI using your Amazon credentials.
    """
    try:
        print('Creating instance')
        return ec2.create_instances(ImageId=image_id, MaxCount=1, MinCount=1, InstanceType=image_type, SecurityGroupIds=[sg_id,], SubnetId=sn_id, UserData=userdata, DryRun=mode)
    except Exception as err:
        handle(err)

def delete_instance(instance, instance_id=g_instance_id, mode=True):
    """
    Delete a ec2 instance
    See https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.delete_security_group
    """
    try:
        instance.terminate(DryRun=mode)
        instance.wait_until_terminated(Filters=[{'Name': 'instance-id', 'Values': [instance_id,]},], DryRun=mode)
    except Exception as err:
        handle(err)

def get_instances(client, name='tag:project', value=g_project_name, running=False, mode=True):
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

def run_instance(client, image_id=g_ami, image_type=g_ami_type, sg_id=g_sg_id, sn_id=g_subnet_id, userdata='', mode=True):
    """
    Run an Amazon EC2 micro instance with boto3.
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.run_instances
    """
    try:
        return client.run_instances(ImageId=image_id, MaxCount=1, MinCount=1, InstanceType=image_type, SecurityGroupIds=[sg_id,], SubnetId=sn_id, UserData=userdata, DryRun=mode)
    except Exception as err:
        handle(err)



client = boto3.client('ec2', region_name=g_region_name)
ec2 = boto3.resource('ec2')

############################
#### cleanup resources #####
############################
for mode in (True, False):
    try:
        #### VPC ####
        vpcs = get_vpcs(client, 'cidr', g_cidr_block, mode)
        if vpcs:
            for vpc in vpcs['Vpcs']:
                g_vpc_id = vpc['VpcId'] 

                ### EC2 INSTANCES ###
                instances = get_instances(client, 'vpc-id', g_vpc_id, False, mode)
                if instances and "Reservations" in instances and instances['Reservations']:
                    for v in instances['Reservations'][0]['Instances']:
                        g_instance_id = v['InstanceId']
                        delete_instance(ec2.Instance(g_instance_id), g_instance_id, mode)

                ### INTERNET GATEWAYS ### 
                gateways = get_internet_gateways(

                ### ELASTIC IPS ###
                eips = get_elastic_ips(client, 'domain', 'vpc', None, g_instance_id, mode)
                if eips:
                    for ip in eips['Addresses']:
                        delete_elastic_ip(client, ip['AllocationId'], ip['PublicIp'], mode)

                ### SUBNETS ###
                subnets = get_subnets(client, 'vpc-id', g_vpc_id, mode)
                if subnets:
                    for sn in subnets['Subnets']:
                        delete_subnet(client, sn['SubnetId'], mode)

                ### SECURITY GROUPS ###
                sgs = get_sgs(client, 'vpc-id', g_vpc_id, g_group_name, mode)
                if sgs and "SecurityGroups" in sgs and sgs["SecurityGroups"]:
                    for sg in sgs['SecurityGroups']:
                        delete_sg(client, sg['GroupId'], mode)

                ### VPC ###
                delete_vpc(client, g_vpc_id, mode)
        else:
            print('No existing VPC found %s' % '(dryrun)' if mode else '')
    except Exception as err:
        handle(err)

##########################
#### Create resources ####
##########################
for mode in (True, False):
    try:
        g_vpc_id = create_vpc(client, g_project_name, g_cidr_block, True, g_tenancy, mode)
        if g_vpc_id:
            g_vpc_id = g_vpc_id['Vpc']['VpcId']

            ### INTERNET GATEWAY
            g_gateway_id = create_internet_gateway(client, mode)
            if g_gateway_id:
                g_gateway_id = g_gateway_id['InternetGateway']['InternetGatewayId']
                attach_internet_gateway(client, g_gateway_id, g_vpc_id, mode) 

            ### SUBNET ###
            g_subnet_id = create_subnet(client, g_project_name, g_cidr_block, g_vpc_id, mode)
            if g_subnet_id:
                g_subnet_id = g_subnet_id['Subnet']['SubnetId']

            ### SECURITY GROUP ###
            g_sg_id = create_sg(client, g_project_name, g_group_name, g_vpc_id, mode)
            if g_sg_id:
                g_sg_id = g_sg_id['GroupId']
                add_sg_ingress(client, 22, 22, 'TCP', [{'CidrIp': '0.0.0.0/0'},], [{'CidrIpv6': '::/0'},], g_sg_id, mode)
                add_sg_ingress(client, 80, 80, 'TCP', [{'CidrIp': '0.0.0.0/0'},], [{'CidrIpv6': '::/0'},], g_sg_id, mode)
                add_sg_ingress(client, 443, 443, 'TCP', [{'CidrIp': '0.0.0.0/0'},], [{'CidrIpv6': '::/0'},], g_sg_id, mode)

            ### ELASTIC IP ###
            g_elastic_ip_allocation_id = create_elastic_ip(client, 'vpc', mode)
            if g_elastic_ip_allocation_id:
                g_elastic_ip_allocation_id = g_elastic_ip_allocation_id['AllocationId']

            ### EC2 INSTANCE ###
            instance = create_instance(g_ami, g_ami_type, g_sg_id, g_subnet_id, g_startup_script, mode)
            if instance and instance[0]:
                g_instance_id = instance[0].id
            if g_instance_id:
                instance = ec2.Instance(g_instance_id)
                instance.wait_until_running(Filters=[{'Name': 'instance-id', 'Values': [g_instance_id,]},], DryRun=mode)
                g_elastic_ip_association_id = associate_elastic_ip(client, g_elastic_ip_allocation_id, g_instance_id, mode)
            if g_elastic_ip_allocation_id:
                g_elastic_ip_allocation_id = g_elastic_ip_allocation_id['AllocationId']

        print('created VPC %s' % ('(dryrun)' if mode else g_vpc_id))
        print('created Subnet %s' % ('(dryrun)' if mode else g_subnet_id))
        print('created Security Group %s' % ('(dryrun)' if mode else g_sg_id))
        print('created Instance %s' % ('(dryrun)' if mode else g_instance_id))
    except Exception as err:
        handle(err)

