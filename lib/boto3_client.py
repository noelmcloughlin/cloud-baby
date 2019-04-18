#############################################
# Copyright 2019 NoelMcloughlin
#############################################

import boto3
import time
import base64
import random
import string
from botocore.exceptions import ClientError


class Compute:
    """
    COMPUTE
    """
    def __init__(self, name='name', tag='tag', region='eu-west-1', zone='eu-west-1a', key_pair='ec2_user',
                 cidr4=None, ami_id='ami-0fad7378adf284ce0', ami_type='t2.micro', hibernate=True, user_data=None,
                 dry=False):
        """
        Initialise data for Cloud Compute
        """
        self.client = boto3.client('ec2')
        self.compute = boto3.resource('ec2', region)
        self.token = ''.join([random.choice(string.ascii_letters + string.digits) for n in range(63)])
        self.tag_specifications = [{'ResourceType': 'instance', 'Tags': [{'Key': name, 'Value': tag}]}]

        self.name = name
        self.tag = tag
        self.region = region
        self.zone = zone
        self.key_pair = key_pair
        self.cidr4 = cidr4
        self.ami_id = ami_id
        self.ami_type = ami_type
        self.hibernate = hibernate
        self.user_data = user_data or b'''
#!/bin/bash
yum update -y
yum install -y httpd
systemctl enable httpd && systemctl start httpd
usermod -a -G apache ec2_user
chown -R ec2_user:apache /var/www
chmod 2775 /var/www
find /var/www -type d -exec chmod 2775 {} \;
find /var/www -type f -exec chmod 0664 {} \;
echo "Create by AWS Boto3 SDK" >> /var/www/html/index.html
'''
        self.dry = dry
        self.response = None
        self.instance_id = None

    def create_tag(self, cloud, resource):
        """
        Adds or overwrite tag
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.create_tags
        """
        try:
            print('Create tag %s = %s for %s %s' % (cloud.name, cloud.tag, resource,  ('(dry)' if cloud.dry else '')))
            self.client.create_tags(Resources=(resource,), Tags=[{'Key': cloud.name, 'Value': cloud.tag}],
                                    DryRun=cloud.dry)
        except ClientError as err:
            Compute.handle(err)
        except Exception as err:
            Compute.fatal(err)

    @staticmethod
    def handle(error=None, resource=None):
        """
        Exception Handler
        """
        bad = ('DependencyViolation', 'VpcLimitExceeded', 'UnauthorizedOperation', 'ParamValidationError',
               'AddressLimitExceeded',)
        try:
            if "NotFound" in str(error) or "DryRunOperation" in str(error):
                return
            elif "InvalidParameterValue" in str(error):
                return
            elif error.response['Error']['Code'] in bad:
                print('Failed (%s)' % error.response['Error']['Code'])
                if resource == 'vpc':
                    return
            else:
                print("Failed with %s" % error)
        except AttributeError as err:
            print('Something went wrong %s %s' % (error, err))
        exit(1)

    @staticmethod
    def fatal(error=None):
        """
        Fatal Exception Handler
        :return:
        """
        print('Something bad happened %s' % (error or '!!'))
        exit(1)


# ************************************************ #
# ***************** EC2 CLIENT ******************* #
# ************************************************ #

class LaunchTemplate(Compute):
    """
    LAUNCH TEMPLATES
    """
    def __init__(self, cloud):
        """
        Initialize and create Launch template
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.create_launch_template
        """
        super().__init__(cloud.name)
        cloud.template_data = {
            'EbsOptimized': False,
            'BlockDeviceMappings': [],
            'ImageId': cloud.ami_id,
            'InstanceType': cloud.ami_type,
            'KeyName': cloud.key_pair,
            'Monitoring': {'Enabled': False},
            'Placement': {'AvailabilityZone': cloud.zone},
            'InstanceInitiatedShutdownBehavior': 'stop',
            'UserData': base64.b64encode(cloud.user_data).decode("ascii"),
            'TagSpecifications': cloud.tag_specifications,
            'SecurityGroupIds': (cloud.sg_id,),
            # 'HibernationOptions': {'Configured': cloud.hibernate}  ## not supported by t2.micro
            }

        try:
            print('Create launch_template %s' % ('(dry)' if cloud.dry else ''))
            self.response = self.client.create_launch_template(LaunchTemplateName=cloud.name,
                                                               VersionDescription=cloud.tag,
                                                               LaunchTemplateData=cloud.template_data,
                                                               ClientToken=cloud.token, DryRun=cloud.dry)
            self.create_tag(cloud, self.response['LaunchTemplate']['LaunchTemplateId'])
        except ClientError as err:
            Compute.handle(err)
        except Exception as err:
            Compute.fatal(err)

    @staticmethod
    def delete(self, template_id, name=None):
        """
        Delete launch_template
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.delete_launch_template
        """
        try:
            print('Delete launch_template %s %s' % ((template_id if template_id else ''), (name if name else ''))),
            if template_id:
                return self.client.delete_launch_template(LaunchTemplateId=template_id, DryRun=self.dry)
            else:
                return self.client.delete_launch_template(LaunchTemplateName=name, DryRun=self.dry)
        except ClientError as err:
            Compute.handle(err)
        except Exception as err:
            Compute.fatal(err)

    @staticmethod
    def list(self):
        """
        Get EC2 launch_templates by searching filters
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.describe_launch_templates
        """
        try:
            return self.client.describe_launch_templates(Filters=[{'Name': 'tag:' + self.name, 'Values': (self.tag,)}],
                                                         DryRun=self.dry)
        except ClientError as err:
            Compute.handle(err)
        except Exception as err:
            Compute.fatal(err)


class Instance(Compute):
    """
    INSTANCE
    """

    def __init__(self, cloud, max_count=1, min_count=1):
        """
        Initialize and Create Instance from Launch Template
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.ServiceResource.create_instances
        """
        super().__init__(cloud.name)
        cloud.max_count = max_count
        cloud.min_count = min_count
        try:
            print('Create Instance from %s' % cloud.template_id)
            self.response = cloud.compute.create_instances(LaunchTemplate={'LaunchTemplateId': cloud.template_id},
                                                           SubnetId=cloud.subnet_id, SecurityGroupIds=(cloud.sg_id,),
                                                           MaxCount=cloud.max_count, MinCount=cloud.min_count,
                                                           Placement={'AvailabilityZone': cloud.zone},
                                                           ClientToken=cloud.token)
            self.create_tag(cloud, self.response[0].id)
        except ClientError as err:
            Compute.handle(err)
        except Exception as err:
            Compute.fatal(err)

    @staticmethod
    def delete(self):
        """
        Delete a ec2 instance
        """
        try:
            print('Delete instance %s %s' % (self.instance_id, ('(dry)' if self.dry else '')))
            instance = self.compute.Instance(self.instance_id)
            instance.terminate(DryRun=self.dry)
            instance.wait_until_terminated(Filters=[{'Name': 'instance-id', 'Values': [self.instance_id]}],
                                           DryRun=self.dry)
            print('Terminated %s' % ('(dry)' if self.dry else ''))
        except ClientError as err:
            Compute.handle(err)
        except Exception as err:
            Compute.fatal(err)

    @staticmethod
    def reboot(self):
        """
        Delete a ec2 instance
        """
        try:
            print('Rebooting instance %s %s' % (self.instance_id, ('(dry)' if self.dry else '')))
            self.reboot_instances(InstanceIds=self.instance_id, DryRun=self.dry)
            while True:
                running = self.list(self, 'instance-id', (self.instance_id,), 'instance-state-code', 16)
                time.sleep(2)
                if running:
                    break
            print('Rebooted %s' % ('(dry)' if self.dry else ''))
        except ClientError as err:
            Compute.handle(err)
        except Exception as err:
            Compute.fatal(err)

    @staticmethod
    def list(self, name=None, value=None):
        """
        Get EC2 instances by searching for stuff
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.describe_instances
        """
        try:
            if name and value:
                return self.client.describe_instances(Filters=[{'Name': name, 'Values': (value,)}], DryRun=self.dry)
            else:
                return self.client.describe_instances(Filters=[{'Name': 'tag:' + self.name, 'Values': (self.tag,)}],
                                                      DryRun=self.dry)
        except ClientError as err:
            Compute.handle(err)
        except Exception as err:
            Compute.fatal(err)


class Volume(Compute):
    """
    VOLUME
    """

    def __init__(self, cloud, size=1, volume_type='standard', encrypted=False):
        """
        Create Volume instance
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.create_volume
        """
        super().__init__(cloud.name)
        try:
            print('Creating Volume %s' % ('(dry)' if cloud.dry else ''))
            self.response = self.client.create_volume(AvailabilityZone=cloud.zone,
                                                      TagSpecifications=cloud.tag_specifications,
                                                      Size=size, Encrypted=encrypted, VolumeType=volume_type,
                                                      DryRun=cloud.dry)
            self.create_tag(cloud, self.response['VolumeId'])
        except ClientError as err:
            Compute.handle(err)
        except Exception as err:
            Compute.fatal(err)

    @staticmethod
    def delete(self, volume_id):
        """
        Delete volume instance
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.delete_volume
        """
        try:
            print('Deleting Volume %s %s' % (volume_id, ('(dry)' if self.dry else '')))
            return self.client.delete_volume(VolumeId=volume_id, DryRun=self.dry)
        except ClientError as err:
            Compute.handle(err)
        except Exception as err:
            Compute.fatal(err)

    @staticmethod
    def list(self):
        """
        Get Volumes
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.describe_volumes
        """
        try:
            return self.client.describe_volumes(Filters=[{'Name': 'tag:' + self.name, 'Values': (self.tag,)}],
                                                DryRun=self.dry)
        except ClientError as err:
            Compute.handle(err)
        except Exception as err:
            Compute.fatal(err)


class Vpc(Compute):
    """
    VIRTUAL PRIVATE CLOUD (VPC)
    """

    def __init__(self, cloud, auto_ipv6=True, tenancy='default'):
        """
        Initialize and create Vpc
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.create_vpc
        """
        super().__init__(cloud.name)
        try:
            print('%s %s' % ('Create VPC', cloud.name) if cloud.dry else '')
            self.response = self.client.create_vpc(CidrBlock=cloud.cidr4, DryRun=cloud.dry,
                                                   InstanceTenancy=tenancy, AmazonProvidedIpv6CidrBlock=auto_ipv6)
            self.create_tag(cloud, self.response['Vpc']['VpcId'])
        except ClientError as err:
            Compute.handle(err, 'vpc')
        except Exception as err:
            Compute.fatal(err)

    @staticmethod
    def delete(self, vpc_id):
        """
        Delete virtual priv cloud.
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.delete_vpc
        """
        try:
            print('Delete %s %s' % (vpc_id, ('(dry)' if self.dry else '')))
            return self.client.delete_vpc(VpcId=vpc_id, DryRun=self.dry)
        except ClientError as err:
            Compute.handle(err, 'vpc')
        except Exception as err:
            Compute.fatal(err)

    @staticmethod
    def list(self):
        """
        Get VPC(s) by filter
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.describe_vpcs
        """
        try:
            return self.client.describe_vpcs(Filters=[{'Name': 'tag:' + self.name, 'Values': (self.tag,)}],
                                             DryRun=self.dry)
        except ClientError as err:
            Compute.handle(err)
        except Exception as err:
            Compute.fatal(err)
    

class VpcEndpoint(Compute):
    """
    VPC ENDPOINTS
    """

    def __init__(self, cloud, endpoint_type=None, service=None):
        """
        Initialize and create VpcEndPoint
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.create_vpc_endpoint
        """
        super().__init__(cloud.name)
        cloud.service = service or 'com.amazonaws.eu-west-1.ec2'
        try:
            print('Create vpc-endpoint  %s' % ('(dry)' if cloud.dry else ''))
            self.response = self.client.create_vpc_endpoint(VpcEndpointType=endpoint_type, VpcId=cloud.vpc_id,
                                                            ServiceName=cloud.service, RouteTableIds=(cloud.rtt_id,),
                                                            SubnetIds=(cloud.subnet_id,), DryRun=cloud.dry,
                                                            SecurityGroupIds=(cloud.sg_id,), ClientToken=cloud.token)
            self.create_tag(cloud, self.response['VpcEndpoint']['VpcEndpointId'])
        except ClientError as err:
            Compute.handle(err)
        except Exception as err:
            Compute.fatal(err)

    @staticmethod
    def delete(self, vpc_endpoint_id):
        """
        Delete a virtual private cloud endpoint
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.delete_vpc_endpoints
        """
        try:
            print('Delete %s %s' % (vpc_endpoint_id, ('(dry)' if self.dry else '')))
            return self.client.delete_vpc_endpoints(VpcEndpointIds=(vpc_endpoint_id,), DryRun=self.dry)
        except ClientError as err:
            Compute.handle(err)
        except Exception as err:
            Compute.fatal(err)

    @staticmethod
    def list(self, name=None, value=None):
        """
        Get VPC(s) by endpoints filter
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.describe_vpc_endpoints
        """
        try:
            if name and value:
                return self.client.describe_vpc_endpoints(Filters=[{'Name': name, 'Values': (value,)}], DryRun=self.dry)
            else:
                return self.client.describe_vpc_endpoints(Filters=[{'Name': 'tag:' + self.name, 'Values': (self.tag,)}],
                                                          DryRun=self.dry)
        except ClientError as err:
            Compute.handle(err)
        except Exception as err:
            Compute.fatal(err)
    
    
class VpcPeeringConnection(Compute):
    """
    VPC PEERING CONNECTION
    """

    def __init__(self, cloud, peer_vpc_id=None, peer_region=None):
        """
        Initialize and create VpcPeeringConnection
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.create_vpc_peering_connection
        """
        super().__init__(cloud.name)
        try:
            print('Create vpc_peering_connection  %s' % ('(dry)' if cloud.dry else ''))
            self.response = self.client.create_vpc_peering_connection(VpcId=cloud.vpc_id, PeerVpcId=peer_vpc_id,
                                                                      PeerRegion=peer_region, DryRun=cloud.dry)
            self.create_tag(cloud, self.response['VpcPeeringConnection']['VpcPeeringConnectionId'])
        except ClientError as err:
            Compute.handle(err)
        except Exception as err:
            Compute.fatal(err)

    @staticmethod
    def delete(self, vpc_peering_connection_id):
        """
        Delete a virtual priv cloud peering_connection
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.delete_vpc_peering_connections
        """
        try:
            print('Delete %s %s' % (vpc_peering_connection_id, ('(dry)' if self.dry else '')))
            return self.client.delete_vpc_peering_connections(VpcPeeringConnectionId=vpc_peering_connection_id,
                                                              DryRun=self.dry)
        except ClientError as err:
            Compute.handle(err)
        except Exception as err:
            Compute.fatal(err)

    @staticmethod
    def list(self):
        """-
        Get VPC(s) by peering_connections filter
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.describe_vpc_peering_connections
        """
        try:
            return self.client.describe_vpc_peering_connections(Filters=[{'Name': 'tag:' + self.name,
                                                                          'Values': (self.tag,)}], DryRun=self.dry)
        except ClientError as err:
            Compute.handle(err)
        except Exception as err:
            Compute.fatal(err)
    
    
class NetworkInterface(Compute):
    """
    NETWORK INTERFACE
    """

    def __init__(self, cloud, private_ip=None, private_ips=None):
        """
        Initialize and create NetworkInterface
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.create_network_interface
        """
        super().__init__(cloud.name)
        try:
            print('Create network_interface for %s %s' % (private_ip, ('(dry)' if cloud.dry else '')))
            self.response = self.client.create_network_interface(Description=cloud.tag, Groups=(cloud.sg_id,),
                                                                 SubnetId=cloud.subnet_id, PrivateIpAddress=private_ip,
                                                                 PrivateIpAddresses=private_ips, DryRun=cloud.dry)
            self.create_tag(cloud, self.response['NetworkInterface']['NetworkInterfaceId'])
        except ClientError as err:
            Compute.handle(err)
        except Exception as err:
            Compute.fatal(err)

    @staticmethod
    def delete(self, interface_id):
        """
        Delete a network_interface.
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.delete_network_interface
        """
        try:
            print('Delete %s %s' % (id, ('(dry)' if self.dry else '')))
            return self.client.delete_network_interface(NetworkInterfaceId=interface_id, DryRun=self.dry)
        except ClientError as err:
            Compute.handle(err)
        except Exception as err:
            Compute.fatal(err)

    @staticmethod
    def list(self):
        """
        Get Network interfaces by tag name/value or maybe by array of ids.
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.describe_network_interfaces
        """
        try:
            return self.client.describe_network_interfaces(Filters=[{'Name': 'tag:' + self.name,
                                                                     'Values': (self.tag,)}], DryRun=self.dry)
        except ClientError as err:
            Compute.handle(err)
        except Exception as err:
            Compute.fatal(err)


class Subnet(Compute):
    """
    SUBNET
    """

    def __init__(self, cloud):
        """
        Initialize and create Subnet
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.create_subnet
        """
        super().__init__(cloud.name)
        try:
            print('Create subnet for %s %s' % (cloud.cidr4, ('(dry)' if cloud.dry else '')))
            self.response = self.client.create_subnet(AvailabilityZone=cloud.zone, CidrBlock=cloud.cidr4,
                                                      VpcId=cloud.vpc_id, DryRun=cloud.dry)
            self.create_tag(cloud, self.response['Subnet']['SubnetId'])
        except ClientError as err:
            Compute.handle(err)
        except Exception as err:
            Compute.fatal(err)

    @staticmethod
    def modify_attr(self, subnet_id, value):
        """
        Modify a subnet.
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.modify_subnet_attribute
        """
        try:
            print('Map %s public-ip-on-launch' % subnet_id)
            return self.client.modify_subnet_attribute(SubnetId=subnet_id, MapPublicIpOnLaunch={'Value': value})
        except ClientError as err:
            Compute.handle(err)
        except Exception as err:
            Compute.fatal(err)
        return None

    @staticmethod
    def delete(self):
        """
        Delete a subnet.
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.delete_subnet
        """
        try:
            print('Delete %s %s' % (self.subnet_id, ('(dry)' if self.dry else '')))
            return self.client.delete_subnet(SubnetId=self.subnet_id, DryRun=self.dry)
        except ClientError as err:
            Compute.handle(err)
        except Exception as err:
            Compute.fatal(err)

    @staticmethod
    def list(self, name=None, value=None):
        """
        Get VPC(s) by tag
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.describe_subnets
        """
        try:
            if name and value:
                return self.client.describe_subnets(Filters=[{'Name': name, 'Values': (value,)}],
                                                    DryRun=self.dry)
            else:
                return self.client.describe_subnets(Filters=[{'Name': 'tag:' + self.name, 'Values': (self.tag,)}],
                                                    DryRun=self.dry)
        except ClientError as err:
            Compute.handle(err)
        except Exception as err:
            Compute.fatal(err)
    

class SecurityGroup(Compute):
    """
    SECURITY GROUPS
    """

    def __init__(self, cloud, description=None):
        """
        Initialize and Create Security Group
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.create_security_group
        """
        super().__init__(cloud.name)
        try:
            if not description:
                description = self.tag
            print('Create security group %s' % ('(dry)' if cloud.dry else ''))
            self.response = self.client.create_security_group(Description=description, GroupName=cloud.name,
                                                              VpcId=cloud.vpc_id, DryRun=cloud.dry)
            self.create_tag(cloud, self.response['GroupId'])
        except ClientError as err:
            Compute.handle(err)
        except Exception as err:
            Compute.fatal(err)

    @staticmethod
    def delete(self, sg_id):
        """
        Delete a security group.
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.delete_security_group
        """
        try:
            print('Delete %s %s' % (sg_id, ('(dry)' if self.dry else '')))
            return self.client.delete_security_group(GroupId=sg_id, DryRun=self.dry)
        except ClientError as err:
            Compute.handle(err)
        except Exception as err:
            Compute.fatal(err)

    @staticmethod
    def list(self, name=None, value=None):
        """
        Get Security Groups by searching for VPC Id.
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.describe_security_groups
        """
        try:
            if name and value:
                return self.client.describe_security_groups(Filters=[{'Name': name, 'Values': (value,)}],
                                                            DryRun=self.dry)
            else:
                return self.client.describe_security_groups(Filters=[{'Name': 'tag:' + self.name,
                                                                      'Values': (self.tag,)}], DryRun=self.dry)
        except ClientError as err:
            Compute.handle(err)
        except Exception as err:
            Compute.fatal(err)

    @staticmethod
    def list_refs(self, group_ids):
        """
        Get Security Groups references
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.describe_security_group_references
        """
        try:
            return self.client.describe_security_group_references(GroupId=group_ids, DryRun=self.dry)
        except ClientError as err:
            Compute.handle(err)
        except Exception as err:
            Compute.fatal(err)

    @staticmethod
    def auth_egress(self, from_port, to_port, proto, ipv4, ipv6=({'CidrIpv6', '::/0'},)):
        """
        Adds egress rules to a security group.
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.authorize_security_group_egress
        """
        try:
            print('Authorize sg egress %s %s' % (self.sg_id, ('(dry)' if self.dry else '')))
            return self.client.authorize_security_group_egress(IpPermissions=[{'FromPort': from_port, 'ToPort': to_port,
                                                                               'IpProtocol': proto, 'IpRanges': ipv4,
                                                                               'Ipv6Ranges': ipv6}],
                                                               GroupId=self.sg_id, DryRun=self.dry)
        except ClientError as err:
            Compute.handle(err)
        except Exception as err:
            Compute.fatal(err)

    @staticmethod
    def auth_ingress(self, from_port, to_port, proto, ipv4, ipv6=({'CidrIpv6', '::/0'},)):
        """
        Adds ingress rules to a security group.
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.authorize_security_group_ingress
        """
        try:
            print('Authorize sg ingress %s %s' % (self.sg_id, ('(dry)' if self.dry else '')))
            return self.client.authorize_security_group_ingress(IpPermissions=[{'FromPort': from_port,
                                                                                'ToPort': to_port,
                                                                                'IpProtocol': proto,
                                                                                'IpRanges': ipv4,
                                                                                'Ipv6Ranges': ipv6}],
                                                                GroupId=self.sg_id, DryRun=self.dry)
        except ClientError as err:
            Compute.handle(err)
        except Exception as err:
            Compute.fatal(err)

    @staticmethod
    def revoke_egress(self, from_port, to_port, proto, ipv4, ipv6=({'CidrIpv6', '::/0'},)):
        """
        Revoke egress rules from a security group.
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.revoke_security_group_egress
        """
        try:
            print('Revoke sg egress %s %s' % (self.sg_id, ('(dry)' if self.dry else '')))
            return self.client.revoke_security_group_egress(IpPermissions=[{'FromPort': from_port, 'ToPort': to_port,
                                                                            'IpProtocol': proto, 'IpRanges': ipv4,
                                                                            'Ipv6Ranges': ipv6}],
                                                            GroupId=self.sg_id, DryRun=self.dry)
        except ClientError as err:
            Compute.handle(err)
        except Exception as err:
            Compute.fatal(err)

    @staticmethod
    def revoke_ingress(self, from_port, to_port, proto, ipv4, ipv6=({'CidrIpv6', '::/0'},)):
        """
        Remove ingress rules to a security group.
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.revoke_security_group_ingress
        """
        try:
            print('Revoke sg ingress from %s %s' % (self.sg_id, ('(dry)' if self.dry else '')))
            return self.client.revoke_security_group_ingress(IpPermissions=[{'FromPort': from_port, 'ToPort': to_port,
                                                                             'IpProtocol': proto,
                                                                             'IpRanges': ipv4,
                                                                             'Ipv6Ranges': ipv6}],
                                                             GroupId=self.sg_id, DryRun=self.dry)
        except ClientError as err:
            Compute.handle(err)
        except Exception as err:
            Compute.fatal(err)
    

class NatGateway(Compute):
    """
    NAT GATEWAY
    """

    def __init__(self, cloud):
        """
        Initialize and Create NAT Gateway
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.create_nat_gateway
        """
        super().__init__(cloud.name)
        try:
            print('Create nat gateway for subnet %s %s' % (cloud.subnet_id, ('(dry)' if cloud.dry else '')))
            self.response = self.client.create_nat_gateway(ClientToken=cloud.token, AllocationId=cloud.eip_alloc_id,
                                                           SubnetId=cloud.subnet_id, DryRun=cloud.dry)
            self.create_tag(cloud, self.response['NatGateway']['NatGatewayId'])
        except ClientError as err:
            Compute.handle(err)
        except Exception as err:
            Compute.fatal(err)

    @staticmethod
    def delete(self, nat_gw_id):
        """
        Delete a nat gateway.
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.delete_nat_gateway
        """
        try:
            print('Delete nat gateway for subnet %s %s' % (nat_gw_id, ('(dry)' if self.dry else '')))
            return self.client.delete_nat_gateway(NatGatewayId=nat_gw_id, DryRun=self.dry)
        except ClientError as err:
            Compute.handle(err)
        except Exception as err:
            Compute.fatal(err)

    @staticmethod
    def list(self):
        """
        Get nat gateways by searching for vpc
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.describe_nat_gateways
        """
        try:
            if not self.dry:
                return self.client.describe_nat_gateways(Filters=[{'Name': 'tag:' + self.name, 'Values': (self.tag,)}])
        except ClientError as err:
            Compute.handle(err)
        except Exception as err:
            Compute.fatal(err)


class RouteTable(Compute):
    """
    ROUTE TABLE
    """

    def __init__(self, cloud):
        """
        Initialize and Create Route Table
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.create_route_table
        """
        super().__init__(cloud.name)
        try:
            print('Create route table for %s %s' % (cloud.vpc_id, ('(dry)' if cloud.dry else '')))
            self.response = self.client.create_route_table(VpcId=cloud.vpc_id, DryRun=cloud.dry)
            self.create_tag(cloud, self.response['RouteTable']['RouteTableId'])
        except ClientError as err:
            Compute.handle(err)
        except Exception as err:
            Compute.fatal(err)

    @staticmethod
    def delete(self, route_table_id):
        """
        Delete a route table.
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.delete_route_table
        """
        try:
            print('Delete %s %s' % (route_table_id, ('(dry)' if self.dry else '')))
            return self.client.delete_route_table(RouteTableId=route_table_id, DryRun=self.dry)
        except ClientError as err:
            Compute.handle(err)
        except Exception as err:
            Compute.fatal(err)

    @staticmethod
    def create_route(self, ip_version, cidr):
        """
        Initialize and Create Route Table
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.create_route
        """
        try:
            print('Create %s route for %s %s' % (ip_version, cidr, ('(dry)' if self.dry else '')))
            if ip_version == 'ipv6':
                return self.client.create_route(DestinationIpv6CidrBlock=cidr, GatewayId=self.igw_id,
                                                RouteTableId=self.rtt_id, DryRun=self.dry)
            else:
                return self.client.create_route(DestinationCidrBlock=cidr, GatewayId=self.igw_id, DryRun=self.dry,
                                                RouteTableId=self.rtt_id)
        except ClientError as err:
            Compute.handle(err)
        except Exception as err:
            Compute.fatal(err)

    @staticmethod
    def delete_route(self, cidr, route_table_id):
        """
        Create a route in route table
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.delete_route
        """
        try:
            print('Delete route for %s %s' % (cidr, ('(dry)' if self.dry else '')))
            return self.client.delete_route(DestinationCidrBlock=cidr, RouteTableId=route_table_id, DryRun=self.dry)
        except ClientError as err:
            Compute.handle(err)
        except Exception as err:
            Compute.fatal(err)

    @staticmethod
    def associate(self):
        """
        Associate route table with subnet
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.associate_route_table
        """
        try:
            print('Associate route table %s to %s %s' % (self.rtt_id, self.subnet_id, ('(dry)' if self.dry else '')))
            return self.client.associate_route_table(RouteTableId=self.rtt_id, SubnetId=self.subnet_id, DryRun=self.dry)
        except ClientError as err:
            Compute.handle(err)
        except Exception as err:
            Compute.fatal(err)

    @staticmethod
    def disassociate(self, association_id):
        """
        Disassociate a route table.
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.disassociate_route_table
        """
        try:
            print('Disassociate %s %s' % (association_id, ('(dry)' if self.dry else '')))
            return self.client.disassociate_route_table(AssociationId=association_id, DryRun=self.dry)
        except ClientError as err:
            Compute.handle(err)
        except Exception as err:
            Compute.fatal(err)

    @staticmethod
    def list(self, name=None, value=None):
        """
        Get route tables by searching for vpc
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.describe_route_tables
        """
        try:
            if name and value:
                return self.client.describe_route_tables(Filters=[{'Name': name, 'Values': (value,)}], DryRun=self.dry)
            else:
                return self.client.describe_route_tables(Filters=[{'Name': 'tag:' + self.name, 'Values': (self.tag,)}],
                                                         DryRun=self.dry)
        except ClientError as err:
            Compute.handle(err)
        except Exception as err:
            Compute.fatal(err)


class NetworkAcl(Compute):
    """
    NETWORK ACL
    """

    def __init__(self, cloud):
        """
        Initialize and Create Network ACL
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.create_network_acl
        """
        super().__init__(cloud.name)
        try:
            print('Create network acl for %s %s' % (cloud.vpc_id, ('(dry)' if cloud.dry else '')))
            self.response = self.client.create_network_acl(VpcId=cloud.vpc_id, DryRun=cloud.dry)
            self.create_tag(cloud, self.response['NetworkAcl']['NetworkAclId'])
        except ClientError as err:
            Compute.handle(err)
        except Exception as err:
            Compute.fatal(err)

    @staticmethod
    def delete(self, network_acl_id):
        """
        Delete a network acl.
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.delete_network_acl
        """
        try:
            print('Delete %s %s' % (network_acl_id, ('(dry)' if self.dry else '')))
            return self.client.delete_network_acl(NetworkAclId=network_acl_id, DryRun=self.dry)
        except ClientError as err:
            Compute.handle(err)
        except Exception as err:
            Compute.fatal(err)

    @staticmethod
    def replace_association(self, network_acl_id, association_id):
        """
        Replace network acl association
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.replace_network_acl_association
        """
        try:
            print('Replace network association %s %s' % (network_acl_id, ('(dry)' if self.dry else '')))
            return self.client.replace_network_acl_association(AssociationId=association_id,
                                                               NetworkAclId=network_acl_id, DryRun=self.dry)
        except ClientError as err:
            Compute.handle(err)
        except Exception as err:
            Compute.fatal(err)

    @staticmethod
    def create_entry(self, rule_num, action, from_port, to_port, proto='6', egress=False):
        """
        Create network acl entry
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.create_network_acl_entry
        """
        try:
            print('Create network acl entry for %s %s' % (self.acl_id, '(dry)' if self.dry else ''))
            if from_port and to_port:
                return self.client.create_network_acl_entry(CidrBlock=self.cidr4, Egress=egress, Protocol=proto,
                                                            RuleAction=action, NetworkAclId=self.acl_id,
                                                            PortRange={'From': from_port, 'To': to_port},
                                                            RuleNumber=rule_num, DryRun=self.dry)
            else:
                return self.client.create_network_acl_entry(CidrBlock=self.cidr4, Egress=egress, Protocol=proto,
                                                            RuleAction=action, NetworkAclId=self.acl_id,
                                                            PortRange={'From': from_port, 'To': to_port},
                                                            RuleNumber=rule_num, DryRun=self.dry)
        except ClientError as err:
            Compute.handle(err)
        except Exception as err:
            Compute.fatal(err)

    @staticmethod
    def delete_entry(self, network_acl_id, num=100, egress=False):
        """
        Delete a network acl entry
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.delete_network_acl_entry
        """
        try:
            print('Delete %s %s' % (network_acl_id, ('(dry)' if self.dry else '')))
            return self.client.delete_network_acl_entry(Egress=egress, NetworkAclId=network_acl_id, RuleNumber=num,
                                                        DryRun=self.dry)
        except ClientError as err:
            Compute.handle(err)
        except Exception as err:
            Compute.fatal(err)

    @staticmethod
    def list(self):
        """
        Get network acls by searching for stuff
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.describe_network_acls
        """
        try:
            return self.client.describe_network_acls(Filters=[{'Name': 'tag:' + self.name, 'Values': (self.tag,)}],
                                                     DryRun=self.dry)
        except ClientError as err:
            Compute.handle(err)
        except Exception as err:
            Compute.fatal(err)


class ElasticIp(Compute):
    """
    ELASTIC IP
    """

    def __init__(self, cloud, domain):
        """
        Initialize and Create Elastic IP
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.allocate_address
        """
        super().__init__(cloud.name)
        try:
            self.response = self.client.allocate_address(Domain=domain, DryRun=cloud.dry)
            self.create_tag(cloud, self.response['AllocationId'])
            print('Created elastic ip %s for %s %s' % (self.response['AllocationId'], domain,
                                                       ('(dry)' if cloud.dry else '')))
        except ClientError as err:
            Compute.handle(err)
        except Exception as err:
            Compute.fatal(err)

    @staticmethod
    def associate(self):
        """
        Associate elastic ip with ec2_instance
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.associate_address
        """
        try:
            print('Associate elastic ip %s with %s %s' % (self.eip_alloc_id, self.instance_id,
                                                          '(dry)' if self.dry else ''))
            return self.client.associate_address(AllocationId=self.eip_alloc_id, InstanceId=self.instance_id,
                                                 DryRun=self.dry)
        except ClientError as err:
            Compute.handle(err)
        except Exception as err:
            Compute.fatal(err)

    @staticmethod
    def disassociate(self, association_id):
        """
        Disassociate elastic ip with ec2_instance
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.disassociate_address
        """
        try:
            print('Disassociate elastic ip %s %s' % (association_id, '(dry)' if self.dry else ''))
            self.client.disassociate_address(AssociationId=association_id, DryRun=self.dry)
        except ClientError as err:
            Compute.handle(err)
        except Exception as err:
            Compute.fatal(err)

    @staticmethod
    def release(self, eip_alloc_id):
        """
        Delete a elastic ip.
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.release_address
        """
        try:
            print('Release %s %s' % (eip_alloc_id, ('(dry)' if self.dry else '')))
            return self.client.release_address(AllocationId=eip_alloc_id, DryRun=self.dry)
        except ClientError as err:
            Compute.handle(err)
        except Exception as err:
            Compute.fatal(err)

    @staticmethod
    def list(self):
        """
        Get Elastic IPs
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.describe_addresses
        """
        try:
            return self.client.describe_addresses(Filters=[{'Name': 'tag:' + self.name, 'Values': (self.tag,)}],
                                                  DryRun=self.dry)
        except ClientError as err:
            Compute.handle(err)
        except Exception as err:
            Compute.fatal(err)
    
    
class InternetGateway(Compute):
    """
    INTERNET GATEWAY
    """

    def __init__(self, cloud):
        """
        Initialize and Create Internet Gateway
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.create_internet_gateway
        """
        super().__init__(cloud.name)
        try:
            print('Create internet gateway %s' % ('(dry)' if cloud.dry else ''))
            self.response = self.client.create_internet_gateway(DryRun=cloud.dry)
            self.create_tag(cloud, self.response['InternetGateway']['InternetGatewayId'])
        except ClientError as err:
            Compute.handle(err)
        except Exception as err:
            Compute.fatal(err)

    @staticmethod
    def delete(self, igw_id):
        """
        Delete a internet gateway.
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.delete_internet_gateway
        """
        try:
            print('Delete internet gateway %s %s' % (igw_id, ('(dry)' if self.dry else '')))
            return self.client.delete_internet_gateway(InternetGatewayId=igw_id, DryRun=self.dry)
        except ClientError as err:
            Compute.handle(err)
        except Exception as err:
            Compute.fatal(err)

    @staticmethod
    def list(self, name=None, value=None):
        """
        Get internet gateways IPs
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.describe_internet_gateways
        """
        try:
            if name and value:
                return self.client.describe_internet_gateways(Filters=[{'Name': name, 'Values': (value,)}],
                                                              DryRun=self.dry)
            else:
                return self.client.describe_internet_gateways(Filters=[{'Name': 'tag:' + self.name,
                                                                        'Values': (self.tag,)}], DryRun=self.dry)
        except ClientError as err:
            Compute.handle(err)
        except Exception as err:
            Compute.fatal(err)

    @staticmethod
    def attach(self):
        """
        Attaches an internet gateway to a VPC
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.attach_internet_gateway
        """
        try:
            print('Attach %s to %s %s' % (self.igw_id, self.vpc_id, ('(dry)' if self.dry else '')))
            return self.client.attach_internet_gateway(InternetGatewayId=self.igw_id, VpcId=self.vpc_id,
                                                       DryRun=self.dry)
        except ClientError as err:
            Compute.handle(err)
        except Exception as err:
            Compute.fatal(err)

    @staticmethod
    def detach(self, igw_id, vpc_id):
        """
        Attaches an internet gateway to a VPC
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.detach_internet_gateway
        """
        try:
            print('Detach %s from %s %s' % (igw_id, vpc_id, ('(dry)' if self.dry else '')))
            return self.client.detach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id, DryRun=self.dry)
        except ClientError as err:
            Compute.handle(err)
        except Exception as err:
            Compute.fatal(err)


# ********************************************************* #
# ***************** AUTO-SCALING CLIENT ******************* #
# ********************************************************* #


class AutoScaling(Compute):
    """
    AUTO-SCALING
    """
    def __init__(self, name, tag='boto3-client-sdk', region='eu-west-1', zone='eu-west-1a', key_pair='ec2_user',
                 cidr4=None, ami_id='ami-0fad7378adf284ce0', ami_type='t2.micro', hibernate=True, user_data=None,
                 dry=False):
        """
        Initialise data for AutoScaling
        """
        super().__init__(name, tag, region, zone, key_pair, cidr4, ami_id, ami_type, hibernate, user_data, dry)
        self.autoscale = boto3.client('autoscaling')


class LaunchConfiguration(AutoScaling):
    """
    LAUNCH CONFIGURATION
    """
    def __init__(self, cloud, public_ip=True, iam_profile='', monitor=False, ebs_optimized=False, tenancy='default'):
        """
        Initialize and create Launch configuration
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/autoscaling.html#AutoScaling.Client.create_launch_configuration
        """
        super().__init__(cloud.name)
        try:
            if not cloud.dry:
                print('Create launch_configuration %s' % cloud.name)
                self.autoscale.create_launch_configuration(LaunchConfigurationName=cloud.name, ImageId=cloud.ami_id,
                                                           EbsOptimized=ebs_optimized, UserData=cloud.user_data,
                                                           InstanceType=cloud.ami_type, KeyName=cloud.key_pair,
                                                           InstanceMonitoring={'Enabled': monitor},
                                                           AssociatePublicIpAddress=public_ip,
                                                           SecurityGroups=(cloud.sg_id,),
                                                           PlacementTenancy=tenancy)
        except ClientError as err:
            AutoScaling.handle(err)
        except Exception as err:
            AutoScaling.fatal(err)

    @staticmethod
    def delete(self, launch_conf_name):
        """
        Delete launch_configuration
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/autoscaling.html#AutoScaling.Client.delete_launch_configuration
        """
        try:
            print('Delete launch_configuration %s' % launch_conf_name)
            self.autoscale.delete_launch_configuration(LaunchConfigurationName=launch_conf_name)
        except ClientError as err:
            AutoScaling.handle(err)
        except Exception as err:
            AutoScaling.fatal(err)

    @staticmethod
    def list(self):
        """
        Get AutoScaling launch configurations by name (or filter if supported)
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/autoscaling.html#AutoScaling.Client.describe_launch_configurations
        """
        try:
            if self.name:
                return self.autoscale.describe_launch_configurations(LaunchConfigurationNames=(self.name,))
            else:
                return self.autoscale.describe_launch_configurations()
        except ClientError as err:
            AutoScaling.handle(err)
        except Exception as err:
            AutoScaling.fatal(err)


class AutoScalingGroup(AutoScaling):
    """
    AUTO SCALING GROUP
    """

    def __init__(self, cloud, min_size=1, max_size=1, desired_capacity=1, health_check_type='EC2', lb_names=None):
        """
        Initialize and Create AutoScaling from Launch Configuration
        https://docs.aws.amazon.com/autoscaling/ec2/userguide/create-launch-template.html
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/autoscaling.html#AutoScaling.Client.create_auto_scaling_group
        """
        super().__init__(cloud.name)
        try:
            if cloud.name:   # always true I guess
                print('Create AutoScaling group: %s' % cloud.name)
                self.response = self.autoscale.create_auto_scaling_group(AutoScalingGroupName=cloud.name,
                                                                         LaunchConfigurationName=cloud.name,
                                                                         Tags=[{'Key': cloud.tag, 'Value': cloud.tag}],
                                                                         VPCZoneIdentifier=cloud.subnet_id,
                                                                         MinSize=min_size, MaxSize=max_size,
                                                                         HealthCheckType=health_check_type,
                                                                         DesiredCapacity=desired_capacity,
                                                                         AvailabilityZones=(cloud.zone,))
            elif cloud.launch_template_id:
                print('Create AutoScaling group: %s' % cloud.launch_template_id)
                self.response = self.autoscale.create_auto_scaling_group(AutoScalingGroupName=cloud.name,
                                                                         Tags=[{'Key': cloud.name, 'Value': cloud.tag}],
                                                                         LaunchTemplate={'LaunchTemplateId':
                                                                                         cloud.launch_template_id},
                                                                         VPCZoneIdentifier=cloud.subnet_id,
                                                                         MinSize=min_size, MaxSize=max_size,
                                                                         HealthCheckType=health_check_type,
                                                                         DesiredCapacity=desired_capacity,
                                                                         AvailabilityZones=(cloud.zone,))
            else:
                raise ClientError("Unable to invoke 'create_auto_scaling_group' due to bad arguments", 'Create')
        except ClientError as err:
            AutoScaling.handle(err)
        except Exception as err:
            AutoScaling.fatal(err)

    @staticmethod
    def delete(self, force=True):
        """
        Delete AutoScaling group
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/autoscaling.html#AutoScaling.Client.delete_auto_scaling_group
        """
        try:
            print('Delete AutoScaling group %s' % self.asg_name)
            self.autoscale.delete_auto_scaling_group(AutoScalingGroupName=self.asg_name, ForceDelete=force)
            print('Wait 60s for pending delete ...')
            time.sleep(60)
        except ClientError as err:
            AutoScaling.handle(err)
        except Exception as err:
            AutoScaling.fatal(err)

    @staticmethod
    def list(self):
        """
        Get AutoScaling groups by filtering
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/autoscaling.html#AutoScaling.Client.describe_auto_scaling_groups
        """
        try:
            if self.name:
                self.response = self.autoscale.describe_auto_scaling_groups(AutoScalingGroupNames=(self.name,))
            else:
                self.response = self.autoscale.describe_auto_scaling_groups()
            return self.response
        except ClientError as err:
            AutoScaling.handle(err)
        except Exception as err:
            AutoScaling.fatal(err)

    @staticmethod
    def list_instances(self, auto_scaling_instance_ids=None):
        """
        Get AutoScaling instances
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/autoscaling.html#AutoScaling.Client.describe_auto_scaling_instances
        """
        try:
            if auto_scaling_instance_ids:
                return self.autoscale.describe_auto_scaling_instances(InstanceIds=auto_scaling_instance_ids)
            else:
                return self.autoscale.describe_auto_scaling_instances()
        except ClientError as err:
            AutoScaling.handle(err)
        except Exception as err:
            AutoScaling.fatal(err)

    @staticmethod
    def attach_instances(self, asg_name, instance_ids):
        """
        Attaches one or more EC2 instances to the specified Auto Scaling group.
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/autoscaling.html#AutoScaling.Client.attach_instances
        """
        try:
            print('Attach instances to AutoScaling group %s' % asg_name)
            self.autoscale.delete_auto_scaling_group(InstanceIds=instance_ids, AutoScalingGroupName=asg_name)
        except ClientError as err:
            AutoScaling.handle(err)
        except Exception as err:
            AutoScaling.fatal(err)


class AutoScalingGroupTags(AutoScaling):
    """
    AUTO SCALING GROUP TAGS
    """

    def __init__(self, cloud, resource=None):
        """
        Creates or updates tags for the specified Auto Scaling group
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/autoscaling.html#AutoScaling.Client.create_or_update_tags
        """
        super().__init__(cloud.name)
        try:
            print('Create tag %s = %s for %s %s' % (cloud.name, cloud.tag, resource, ('(dry)' if cloud.dry else '')))
            self.autoscale.create_or_update_tags(Tags=[{'ResourceId': cloud.name, 'ResourceType': 'auto-scaling-group',
                                                        'Key': cloud.name, 'Value': cloud.tag,
                                                        'PropagateAtLaunch': True}])
        except ClientError as err:
            Compute.handle(err)
        except Exception as err:
            Compute.fatal(err)

    @staticmethod
    def delete(self):
        """
        Delete AutoScaling group tags
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/autoscaling.html#AutoScaling.Client.delete_tags
        """
        try:
            print('Delete AutoScaling group tags %s' % self.name)
            self.autoscale.delete_tags(Tags=[{'ResourceId': self.name, 'ResourceType': 'auto-scaling-group',
                                              'Key': self.name, 'Value': self.tag, 'PropagateAtLaunch': True}])
        except ClientError as err:
            AutoScaling.handle(err)
        except Exception as err:
            AutoScaling.fatal(err)

    @staticmethod
    def list(self):
        """
        Get AutoScaling group tags
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/autoscaling.html#AutoScaling.Client.describe_tags
        """
        try:
            return self.autoscale.describe_tags(Filters=[{'Name': 'key', 'Values': (self.tag,)}])
        except ClientError as err:
            AutoScaling.handle(err)
        except Exception as err:
            AutoScaling.fatal(err)


class AutoScalingPolicy(AutoScaling):
    """
    AUTO SCALING POLICY
    """

    def __init__(self, cloud, policy_type='TargetTrackingScaling',  estimated_instance_warmup=90,
                 metric='ASGAverageCPUUtilization', metric_value=50):
        """
        Creates or updates a policy for an Auto Scaling group
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/autoscaling.html#AutoScaling.Client.put_scaling_policy
        """
        super().__init__(cloud.name)
        config = {'PredefinedMetricSpecification': {'PredefinedMetricType': metric}, 'TargetValue': metric_value}
        try:
            print('Create AutoScaling policy %s' % cloud.name)
            self.autoscale.put_scaling_policy(AutoScalingGroupName=cloud.name, PolicyName=cloud.name,
                                              PolicyType=policy_type, EstimatedInstanceWarmup=estimated_instance_warmup,
                                              TargetTrackingConfiguration=config)
        except ClientError as err:
            AutoScaling.handle(err)
        except Exception as err:
            AutoScaling.fatal(err)

    @staticmethod
    def delete(self, pol_name=None):
        """
        Deletes the specified scaling policy.
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/autoscaling.html#AutoScaling.Client.delete_policy
        """
        try:
            print('Delete Auto Scaling Group %s policy %s' % (self.asg_name, pol_name))
            self.autoscale.delete_policy(AutoScalingGroupName=self.asg_name, PolicyName=pol_name)
        except ClientError as err:
            ElasticLoadBalancing.handle(err)
        except Exception as err:
            ElasticLoadBalancing.fatal(err)

    @staticmethod
    def list(self, asg_name=None, pol_names=None, pol_types=None, ):
        """
        Get AutoScaling groups by filtering
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/autoscaling.html#AutoScaling.Client.describe_policies
        """
        try:
            if asg_name and pol_names and pol_types:
                return self.autoscale.describe_auto_scaling_groups(AutoScalingGroupName=asg_name,
                                                                   PolicyNames=pol_names,
                                                                   PolicyTypes='TargetTrackingScaling')
            else:
                return self.autoscale.describe_auto_scaling_groups()
        except ClientError as err:
            AutoScaling.handle(err)
        except Exception as err:
            AutoScaling.fatal(err)


class AutoScalingNotification(AutoScaling):
    """
    AUTO SCALING NOTIFICATION
    """

    def __init__(self, cloud, notice_types=('autoscaling:TEST_NOTIFICATION',)):
        """
        Configures an Auto Scaling group to send notifications
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/autoscaling.html#AutoScaling.Client.put_notification_configuration
        """
        super().__init__(cloud.name)
        try:
            print('Create AutoScaling Notification %s' % cloud.name)
            self.autoscale.put_notification_configuration(AutoScalingGroupName=cloud.name,
                                                          NotificationTypes=notice_types,
                                                          TopicARN=cloud.topic_arn)
        except ClientError as err:
            AutoScaling.handle(err)
        except Exception as err:
            AutoScaling.fatal(err)

    @staticmethod
    def delete(self):
        """
        Deletes the specified scaling notification.
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/autoscaling.html#AutoScaling.Client.delete_notification_configuration
        """
        try:
            print('Delete Auto Scaling Group %s Notification %s' % (self.asg_name, self.topic_arn))
            self.autoscale.delete_policy(AutoScalingGroupName=self.asg_name, TopicARN=self.topic_arn)
        except ClientError as err:
            ElasticLoadBalancing.handle(err)
        except Exception as err:
            ElasticLoadBalancing.fatal(err)

    @staticmethod
    def list(self, pol_names=None, pol_types=('TargetTrackingScaling',)):
        """
        Get AutoScaling Notifications by filtering
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/autoscaling.html#AutoScaling.Client.describe_notification_configurations
        """
        try:
            if pol_names and pol_types:
                return self.autoscale.describe_policies(AutoScalingGroupName=self.name, PolicyNames=pol_names,
                                                        PolicyTypes=pol_types)
            else:
                return self.autoscale.describe_policies(PolicyTypes=pol_types)
        except ClientError as err:
            AutoScaling.handle(err)
        except Exception as err:
            AutoScaling.fatal(err)


# ********************************************************* #
# *********** ELASTIC LOAD BALANCING (ELB) **************** #
# ********************************************************* #

class ElasticLoadBalancing(Compute):
    """
    ELASTIC LOAD BALANCING v2
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/elbv2.html
    """

    def __init__(self, name, tag='boto3-client-sdk', region='eu-west-1', zone='eu-west-1a', key_pair='ec2_user',
                 cidr4=None, ami_id='ami-0fad7378adf284ce0', ami_type='t2.micro', hibernate=True, user_data=None,
                 dry=False):
        """
        Initialise data for ElasticLoadBalancing
        """
        super().__init__(name, tag, region, zone, key_pair, cidr4, ami_id, ami_type, hibernate, user_data, dry)
        self.elb = boto3.client('elbv2')
        self.response = None


class LoadBalancer(ElasticLoadBalancing):
    """
    LOAD BALANCER
    """

    def __init__(self, cloud, ip_version='ipv4', lb_type='application', scheme='internet-facing'):
        """
        Initialize and Create Elastic Load Balancerv2
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/elbv2.html#ElasticLoadBalancingv2.Client.create_load_balancer
        """
        super().__init__(cloud.name)
        try:
            print('Create Elastic Load Balancer: %s' % cloud.name)
            self.response = self.elb.create_load_balancer(Name=cloud.name, Subnets=(cloud.subnet_id,),
                                                          SecurityGroups=(cloud.sg_id,), IpAddressType=ip_version,
                                                          Tags=[{'Key': cloud.tag, 'Value': cloud.tag}],
                                                          Type=lb_type, Scheme=scheme)
            self.create_tag(cloud, self.response['LoadBalancers']['LoadBalancerArn'])
        except ClientError as err:
            ElasticLoadBalancing.handle(err)
        except Exception as err:
            ElasticLoadBalancing.fatal(err)

    @staticmethod
    def delete(self, load_balancer_arn=None):
        """
        Delete Elastic Load Balancer
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/elbv2.html#ElasticLoadBalancingv2.Client.delete_load_balancer
        """
        try:
            print('Delete Elastic Load Balancer %s' % load_balancer_arn)
            self.elb.delete_load_balancer(LoadBalancerArn=load_balancer_arn)
        except ClientError as err:
            ElasticLoadBalancing.handle(err)
        except Exception as err:
            ElasticLoadBalancing.fatal(err)

    @staticmethod
    def list(self):
        """
        Get Elastic Load Balancer groups by filtering
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/elbv2.html#ElasticLoadBalancingv2.Client.describe_load_balancers
        """
        try:
            if self.load_balancer_arn:
                return self.elb.describe_load_balancers(LoadBalancerArns=(self.load_balancer_arn,))
            elif self.name:
                return self.elb.describe_load_balancers(Names=(self.name,))
        except ClientError as err:
            ElasticLoadBalancing.handle(err)
        except Exception as err:
            ElasticLoadBalancing.fatal(err)


# ********************************************************* #
# ********* SIMPLE NOTIFICATION SERVICE CLIENT ************ #
# ********************************************************* #


class SimpleNotificationService(Compute):
    """
    SIMPLE NOTIFICATION SERVICE (SNS)
    """

    def __init__(self, name, tag='boto3-client-sdk', region='eu-west-1', zone='eu-west-1a', key_pair='ec2_user'):
        """
        Initialise data for Simple Notifications
        """
        super().__init__(name, tag, region, zone, key_pair)
        self.sns = boto3.client('sns')


class SimpleNotificationServiceTopic(SimpleNotificationService):
    """
    SNS TOPIC
    """

    def __init__(self, cloud):
        """
        Creates a topic to which notifications can be published
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/sns.html#SNS.Client.create_topic
        """
        super().__init__(cloud.name)
        try:
            print('Create SNS topic  %s' % cloud.name)
            self.response = self.sns.create_topic(Name=cloud.name)
            self.topic_arn = self.response['TopicArn']
        except ClientError as err:
            Compute.handle(err)
        except Exception as err:
            Compute.fatal(err)

    @staticmethod
    def delete(self):
        """
        Delete SNS topic
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/sns.html#SNS.Client.delete_topic
        """
        try:
            print('Delete SNS topic %s %s' % (self.topic_arn, ('(dry)' if self.dry else '')))
            return self.sns.delete_topic(TopicArn=self.topic_arn)
        except ClientError as err:
            Compute.handle(err)
        except Exception as err:
            Compute.fatal(err)

    @staticmethod
    def list(self):
        """
        Get (requester) SNS topics
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/sns.html#SNS.Client.list_topics
        """
        try:
            return self.sns.list_topics()
        except ClientError as err:
            Compute.handle(err)
        except Exception as err:
            Compute.fatal(err)
