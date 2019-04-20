#############################################
# Copyright 2019 noelmcloughlin
#############################################

import boto3
import time
import base64
from botocore.exceptions import ClientError
import string
import random


class Cloud:
    """
    A CLOUD
    """
    def __init__(self, data=None):
        """
        Initialise data for Cloud
        """
        if not isinstance(data, dict):
            data = {'cloud': {}}

        self.catalog = data['cloud']['catalog'] if 'catalog' in data['cloud'] else []
        self.cidr4 = data['cloud']['cidr4'] if 'cidr4' in data['cloud'] else []
        self.cidr6 = data['cloud']['cidr6'] if 'cidr6' in data['cloud'] else []
        self.dry = data['cloud']['dry'] if 'dry' in data['cloud'] else False
        self.key_pair = data['cloud']['key_pair'] if 'key_pair' in data['cloud'] else None
        self.name = data['cloud']['name'] if 'name' in data['cloud'] else None
        self.network_acls = data['cloud']['network_acls'] if 'network_acls' in data['cloud'] else []
        self.private_ip = data['cloud']['private_ip'] if 'private_ip' in data['cloud'] else '10.0.0.1'
        self.private_ips = data['cloud']['private_ips'] if 'private_ips' in data['cloud'] else ['10.0.0.2']
        self.peer_region = data['cloud']['peer_region'] if 'peer_region' in data['cloud'] else 'eu-west-2'
        self.region = data['cloud']['region'] if 'region' in data['cloud'] else 'eu-west-1'
        self.scope = data['cloud']['scope'] if 'scope' in data['cloud'] else 'vpc-instance'
        self.tag = data['cloud']['tag'] if 'tag' in data['cloud'] else None
        self.zones = data['cloud']['zones'] if 'zones' in data['cloud'] else []
        self.response = None

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


class Service(Cloud):
    """
    A SERVICE
    """
    def __init__(self, data=None):
        """
        Initialise data for MachineImage
        """
        if isinstance(data, dict):
            super().__init__(data)
        else:
            data = {'cloud': {}}

        self.auto_ipv6 = data['service']['auto_ipv6'] if 'auto_ipv6' in data['service'] else False
        self.ebs_optimized = data['service']['ebs_optimized'] if 'ebs_optimized' in data['service'] else False
        self.max_count = data['service']['max_count'] if 'max_count' in data['service'] else 1
        self.monitor = data['service']['monitor'] if 'monitor' in data['service'] else False
        self.public_ip = data['service']['public_ip'] if 'public_ip' in data['service'] else False
        self.tenancy = data['service']['tenancy'] if 'tenancy' in data['service'] else 'default'
        self.token = ''.join(random.SystemRandom().choice(string.ascii_uppercase + string.digits) for _ in range(63))

        self.sg_id = data['service']['sg_id'] if 'sg_id' in data['service'] else None
        self.sg_ids = data['service']['sg_ids'] if 'sg_ids' in data['service'] else []
        self.subnet_id = data['service']['subnet_id'] if 'subnet_id' in data['service'] else None
        self.subnet_ids = data['service']['subnet_ids'] if 'subnet_ids' in data['service'] else []
        self.template_ids = data['service']['template_ids'] if 'template_ids' in data['service'] else []
        self.topic_arn = data['service']['topic_arn'] if 'topic_arn' in data['service'] else None


class Compute(Service):
    """
    COMPUTE
    """
    def __init__(self, data=None):
        """
        Create Compute with DATA and METHODS
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#instance
        """
        if isinstance(data, dict):
            super().__init__(data)
        else:
            data = {'compute': {}}
        self.acl_id = data['compute']['acl_id'] if 'acl_id' in data['compute'] else None
        self.eip_id = data['compute']['eip_id'] if 'eip_id' in data['compute'] else None
        self.igw_id = data['compute']['igw_id'] if 'igw_id' in data['compute'] else None
        self.nat_gw_id = data['compute']['nat_gw_id'] if 'nat_gw_id' in data['compute'] else None
        self.peer_vpc_id = data['compute']['vpc_id'] if 'peer_vpc_id' in data['compute'] else None
        self.rtt_id = data['compute']['rtt_id'] if 'rtt_id' in data['compute'] else None
        self.vpc_id = data['compute']['vpc_id'] if 'vpc_id' in data['compute'] else None

        self.acl_ids = data['compute']['acl_ids'] if 'acl_ids' in data['compute'] else []
        self.eip_ids = data['compute']['eip_ids'] if 'eip_ids' in data['compute'] else []
        self.instance_ids = data['compute']['instance_ids'] if 'instance_ids' in data['compute'] else []
        self.nat_gw_ids = data['compute']['nat_gw_ids'] if 'nat_gw_ids' in data['compute'] else []
        self.rtt_ids = data['compute']['rtt_ids'] if 'rtt_ids' in data['compute'] else []

        self.client = boto3.client('ec2')
        self.compute = boto3.resource('ec2')

    @staticmethod
    def create_tag(self, resource):
        """
        Adds or overwrite tag
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.create_tags
        """
        try:
            print('Create tag %s = %s for %s %s' % (self.name, self.tag, resource,  ('(dry)' if self.dry else '')))
            self.client.create_tags(Resources=(resource,), Tags=[{'Key': self.name, 'Value': self.tag}],
                                    DryRun=self.dry)
        except ClientError as err:
            Compute.handle(err)
        except Exception as err:
            Compute.fatal(err)

# ***************************************** #
# ***************** EC2 ******************* #
# ***************************************** #


class Image(Compute):
    """
    A IMAGE
    """
    def __init__(self, data=None, img_data=None):
        """
        Initialise data for MachineImage
        """
        if isinstance(data, dict):
            super().__init__(data)
        if not isinstance(img_data, dict):
            img_data = {'image': {}}
        self.ami_id = img_data['image']['ami_id'] if 'ami_id' in img_data['image'] else None
        self.ami_type = img_data['image']['ami_type'] if 'ami_type' in img_data['image'] else None
        self.hibernate = img_data['image']['hibernate'] if 'hibernate' in img_data['image'] else False
        self.user_data = img_data['image']['user_data'] if 'user_data' in img_data['image'] else False


class LaunchTemplate(Compute, Image):
    """
    LAUNCH TEMPLATES
    """
    def __init__(self, data=None):
        """
        Initialize and create Launch template
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.create_launch_template
        # 'HibernationOptions': {'Configured': self.hibernate}  ## not supported by t2.micro
        """
        if isinstance(data, dict):
            super().__init__(data)
            Image().__init__(data)
        self.template_data = {
            'EbsOptimized': self.ebs_optimized,
            'BlockDeviceMappings': [],
            'ImageId': self.ami_id,
            'InstanceType': self.ami_type,
            'KeyName': self.key_pair,
            'Monitoring': {'Enabled': self.monitor},
            'Placement': {'AvailabilityZone': self.zone},
            'InstanceInitiatedShutdownBehavior': 'stop',
            'UserData': base64.b64encode(self.user_data).decode("ascii"),
            'TagSpecifications': [{'ResourceType': 'instance', 'Tags': [{'Key': self.name, 'Value': self.tag}]}],
            'SecurityGroupIds': (self.sg_id,)
            }

        try:
            print('Create launch_template %s' % ('(dry)' if self.dry else ''))
            self.response = self.client.create_launch_template(LaunchTemplateName=self.name,
                                                               VersionDescription=self.tag,
                                                               LaunchTemplateData=self.template_data,
                                                               ClientToken=self.token, DryRun=self.dry)
            self.create_tag(self, self.response['LaunchTemplate']['LaunchTemplateId'])
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


class Instance(Compute, Image):
    """
    INSTANCE
    """

    def __init__(self, data=None, min_count=1):
        """
        Initialize and Create Instance from Launch Template
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.ServiceResource.create_instances
        """
        if isinstance(data, dict):
            super().__init__(data)
            Image().__init__(data)
        self.min_count = min_count
        try:
            print('Create Instance from %s' % self.template_id)
            self.response = self.compute.create_instances(LaunchTemplate={'LaunchTemplateId': self.template_id},
                                                          SubnetId=self.subnet_id, SecurityGroupIds=(self.sg_id,),
                                                          MaxCount=self.max_count, MinCount=self.min_count,
                                                          Placement={'AvailabilityZone': self.zone},
                                                          ClientToken=self.token)
            self.create_tag(self, self.response[0].id)
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

    def __init__(self, data=None, zone=None, size=1, volume_type='standard', encrypted=False):
        """
        Create Volume instance
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.create_volume
        """
        super().__init__(data)
        try:
            tag_specifications = [{'ResourceType': 'volume', 'Tags': [{'Key': self.name, 'Value': self.tag}]}]
            print('Creating Volume %s' % ('(dry)' if self.dry else ''))
            self.response = self.client.create_volume(AvailabilityZone=zone, TagSpecifications=tag_specifications,
                                                      Size=size, Encrypted=encrypted, VolumeType=volume_type,
                                                      DryRun=self.dry)
            self.create_tag(self, self.response['VolumeId'])
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
    def __init__(self, data=None):
        """
        Initialize and create Vpc
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.create_vpc
        """
        super().__init__(data)
        try:
            print('%s %s' % ('Create VPC', self.name) if not self.dry else '(dry)')
            self.response = self.client.create_vpc(CidrBlock=self.cidr4, DryRun=self.dry, InstanceTenancy=self.tenancy,
                                                   AmazonProvidedIpv6CidrBlock=self.auto_ipv6)
            self.create_tag(self, self.response['Vpc']['VpcId'])
        except ClientError as err:
            Compute.handle(err, 'vpc')
        except Exception as err:
            Compute.fatal(err)

    @staticmethod
    def delete(self):
        """
        Delete virtual priv self.
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.delete_vpc
        """
        try:
            print('Delete %s %s' % (self.vpc_id, ('(dry)' if self.dry else '')))
            return self.client.delete_vpc(VpcId=self.vpc_id, DryRun=self.dry)
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

    def __init__(self, data=None, endpoint_type=None, service=None):
        """
        Initialize and create VpcEndPoint
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.create_vpc_endpoint
        """
        super().__init__(data)
        self.service = service or 'com.amazonaws.' + self.region + '.ec2'
        try:
            print('Create vpc-endpoint  %s' % ('(dry)' if self.dry else ''))
            self.response = self.client.create_vpc_endpoint(VpcEndpointType=endpoint_type, VpcId=self.vpc_id,
                                                            ServiceName=self.name, RouteTableIds=self.rtt_ids,
                                                            SubnetIds=self.subnet_ids, SecurityGroupIds=self.sg_ids,
                                                            ClientToken=self.token, DryRun=self.dry)
            self.create_tag(self, self.response['VpcEndpoint']['VpcEndpointId'])
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

    def __init__(self, data):
        """
        Initialize and create VpcPeeringConnection
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.create_vpc_peering_connection
        """
        super().__init__(data)
        try:
            print('Create vpc_peering_connection  %s' % ('(dry)' if self.dry else ''))
            self.response = self.client.create_vpc_peering_connection(VpcId=self.vpc_id, PeerVpcId=self.peer_vpc_id,
                                                                      PeerRegion=self.peer_region, DryRun=self.dry)
            self.create_tag(self, self.response['VpcPeeringConnection']['VpcPeeringConnectionId'])
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
    
    
class NetworkInterface(Compute,):
    """
    NETWORK INTERFACE
    """

    def __init__(self, data=None, private_ip=None):
        """
        Initialize and create NetworkInterface
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.create_network_interface
        """
        super().__init__(data)
        try:
            print('Create network_interface for %s %s' % (private_ip, ('(dry)' if self.dry else '')))
            self.response = self.client.create_network_interface(Description=self.tag, Groups=self.sg_ids,
                                                                 SubnetId=self.subnet_id, PrivateIpAddress=private_ip,
                                                                 PrivateIpAddresses=self.private_ips, DryRun=self.dry)
            self.create_tag(self, self.response['NetworkInterface']['NetworkInterfaceId'])
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

    def __init__(self, data, cidr_block, zone):
        """
        Initialize and create Subnet
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.create_subnet
        """
        super().__init__(data)
        try:
            print('Create subnet for %s %s' % (cidr_block, ('(dry)' if self.dry else '')))
            self.response = self.client.create_subnet(AvailabilityZone=zone, CidrBlock=cidr_block,
                                                      VpcId=self.vpc_id, DryRun=self.dry)
            self.create_tag(self, self.response['Subnet']['SubnetId'])
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

    def __init__(self, data=None, description='Boto3'):
        """
        Initialize and Create Security Group
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.create_security_group
        """
        super().__init__(data)
        try:
            if not description:
                description = self.tag
            print('Create security group %s' % ('(dry)' if self.dry else ''))
            self.response = self.client.create_security_group(Description=description, GroupName=self.name,
                                                              VpcId=self.vpc_id, DryRun=self.dry)
            self.create_tag(self, self.response['GroupId'])
        except ClientError as err:
            Compute.handle(err)
        except Exception as err:
            Compute.fatal(err)

    @staticmethod
    def delete(self):
        """
        Delete a security group.
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.delete_security_group
        """
        try:
            print('Delete %s %s' % (self.sg_id, ('(dry)' if self.dry else '')))
            return self.client.delete_security_group(GroupId=self.sg_id, DryRun=self.dry)
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
    def list_refs(self, sg_id):
        """
        Get Security Groups references
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.describe_security_group_references
        """
        try:
            return self.client.describe_security_group_references(GroupId=sg_id, DryRun=self.dry)
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

    def __init__(self, data):
        """
        Initialize and Create NAT Gateway
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.create_nat_gateway
        """
        super().__init__(data)
        try:
            print('Create nat gateway for subnet %s %s' % (self.subnet_id, ('(dry)' if self.dry else '')))
            self.response = self.client.create_nat_gateway(ClientToken=self.token, AllocationId=self.eip_id,
                                                           SubnetId=self.subnet_id, DryRun=self.dry)
            self.create_tag(self, self.response['NatGateway']['NatGatewayId'])
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

    def __init__(self, data):
        """
        Initialize and Create Route Table
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.create_route_table
        """
        super().__init__(data)
        try:
            print('Create route table for %s %s' % (self.vpc_id, ('(dry)' if self.dry else '')))
            self.response = self.client.create_route_table(VpcId=self.vpc_id, DryRun=self.dry)
            self.create_tag(self, self.response['RouteTable']['RouteTableId'])
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
    def associate(self, subnet_id):
        """
        Associate route table with subnet
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.associate_route_table
        """
        try:
            print('Associate route table %s to %s %s' % (self.rtt_id, subnet_id, ('(dry)' if self.dry else '')))
            return self.client.associate_route_table(RouteTableId=self.rtt_id, SubnetId=subnet_id, DryRun=self.dry)
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

    def __init__(self, data):
        """
        Initialize and Create Network ACL
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.create_network_acl
        """
        super().__init__(data)
        try:
            print('Create network acl for %s %s' % (self.vpc_id, ('(dry)' if self.dry else '')))
            self.response = self.client.create_network_acl(VpcId=self.vpc_id, DryRun=self.dry)
            self.create_tag(self, self.response['NetworkAcl']['NetworkAclId'])
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
    def replace_association(self, association_id):
        """
        Replace network acl association
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.replace_network_acl_association
        """
        try:
            print('Replace network association %s %s' % (self.acl_id, ('(dry)' if self.dry else '')))
            return self.client.replace_network_acl_association(AssociationId=association_id,
                                                               NetworkAclId=self.acl_id, DryRun=self.dry)
        except ClientError as err:
            Compute.handle(err)
        except Exception as err:
            Compute.fatal(err)

    @staticmethod
    def create_entry(self, cidr4, rule_num, action, from_port, to_port, proto='6', egress=False):
        """
        Create network acl entry
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.create_network_acl_entry
        """
        try:
            print('Create network acl entry for %s %s %s' % (self.acl_id, cidr4, '(dry)' if self.dry else ''))
            if from_port and to_port:
                return self.client.create_network_acl_entry(CidrBlock=cidr4, Egress=egress, Protocol=proto,
                                                            RuleAction=action, NetworkAclId=self.acl_id,
                                                            PortRange={'From': from_port, 'To': to_port},
                                                            RuleNumber=rule_num, DryRun=self.dry)
            else:
                return self.client.create_network_acl_entry(CidrBlock=cidr4, Egress=egress, Protocol=proto,
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

    def __init__(self, data, domain):
        """
        Initialize and Create Elastic IP
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.allocate_address
        """
        super().__init__(data)
        try:
            self.response = self.client.allocate_address(Domain=domain, DryRun=self.dry)
            self.create_tag(self, self.response['AllocationId'])
            print('Created elastic ip %s for %s %s' % (self.response['AllocationId'], domain,
                                                       ('(dry)' if self.dry else '')))
        except ClientError as err:
            Compute.handle(err)
        except Exception as err:
            Compute.fatal(err)

    @staticmethod
    def associate(self, eip_id):
        """
        Associate elastic ip with ec2_instance
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.associate_address
        """
        try:
            print('Associate elastic ip %s with %s %s' % (eip_id, self.instance_id, '(dry)' if self.dry else ''))
            return self.client.associate_address(AllocationId=eip_id, InstanceId=self.instance_id,
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
    def release(self, eip_id):
        """
        Delete a elastic ip.
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.release_address
        """
        try:
            print('Release %s %s' % (eip_id, ('(dry)' if self.dry else '')))
            return self.client.release_address(AllocationId=eip_id, DryRun=self.dry)
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

    def __init__(self, data):
        """
        Initialize and Create Internet Gateway
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.create_internet_gateway
        """
        super().__init__(data)
        try:
            print('Create internet gateway %s' % ('(dry)' if self.dry else ''))
            self.response = self.client.create_internet_gateway(DryRun=self.dry)
            self.create_tag(self, self.response['InternetGateway']['InternetGatewayId'])
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


class AutoScaling(Service):
    """
    AUTO-SCALING
    """
    def __init__(self, data=None):
        """
        Initialise data for AutoScaling
        """
        super().__init__(data)
        self.autoscale = boto3.client('autoscaling')


class LaunchConfiguration(AutoScaling, Image):
    """
    LAUNCH CONFIGURATION
    """
    def __init__(self, data):
        """
        Initialize and create Launch configuration
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/autoscaling.html#AutoScaling.Client.create_launch_configuration
        """
        super().__init__(data)
        Image().__init__(data)
        try:
            if not self.dry:
                print('Create launch_configuration %s' % self.name)
                self.autoscale.create_launch_configuration(LaunchConfigurationName=self.name, ImageId=self.ami_id,
                                                           EbsOptimized=self.ebs_optimized, UserData=self.user_data,
                                                           PlacementTenancy=self.tenancy, SecurityGroups=self.sg_ids,
                                                           InstanceType=self.ami_type, KeyName=self.key_pair,
                                                           InstanceMonitoring={'Enabled': self.monitor},
                                                           AssociatePublicIpAddress=self.public_ip)
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


class AutoScalingGroup(AutoScaling, Service):
    """
    AUTO SCALING GROUP
    """

    def __init__(self, data, min_size=2, desired_size=2, lb_arns=None):
        """
        Initialize and Create AutoScaling from Launch Configuration
        https://docs.aws.amazon.com/autoscaling/ec2/userguide/create-launch-template.html
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/autoscaling.html#AutoScaling.Client.create_auto_scaling_group
        """
        super().__init__(data)
        Service().__init__(data)
        try:
            print('Create AutoScaling group: %s' % self.name)
            self.response = self.autoscale.create_auto_scaling_group(AutoScalingGroupName=self.name,
                                                                     Tags=[{'Key': self.tag, 'Value': self.tag}],
                                                                     MinSize=min_size, MaxSize=self.max_count,
                                                                     LaunchConfigurationName=self.name,
                                                                     VPCZoneIdentifier=self.subnet_ids,
                                                                     DesiredCapacity=desired_size or self.max_count,
                                                                     TargetGroupARNs=lb_arns, HealthCheckType='EC2')
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
            print('Delete AutoScaling group %s' % self.name)
            self.autoscale.delete_auto_scaling_group(AutoScalingGroupName=self.name, ForceDelete=force)
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

    def __init__(self, data=None, resource='auto-scaling-group'):
        """
        Creates or updates tags for the specified Auto Scaling group
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/autoscaling.html#AutoScaling.Client.create_or_update_tags
        """
        super().__init__(data)
        try:
            print('Create tag %s = %s for %s %s' % (self.name, self.tag, resource, ('(dry)' if self.dry else '')))
            self.autoscale.create_or_update_tags(Tags=[{'ResourceId': self.name, 'ResourceType': 'auto-scaling-group',
                                                        'Key': self.name, 'Value': self.tag,
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

    def __init__(self, data, policy_type='TargetTrackingScaling',  estimated_instance_warmup=90,
                 metric='ASGAverageCPUUtilization', metric_value=50):
        """
        Creates or updates a policy for an Auto Scaling group
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/autoscaling.html#AutoScaling.Client.put_scaling_policy
        """
        super().__init__(data)
        config = {'PredefinedMetricSpecification': {'PredefinedMetricType': metric}, 'TargetValue': metric_value}
        try:
            print('Create AutoScaling policy %s' % self.name)
            self.autoscale.put_scaling_policy(AutoScalingGroupName=self.name, PolicyName=self.name,
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


class AutoScalingNotification(AutoScaling, Service):
    """
    AUTO SCALING NOTIFICATION
    """

    def __init__(self, data, notice_types=('autoscaling:TEST_NOTIFICATION',)):
        """
        Configures an Auto Scaling group to send notifications
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/autoscaling.html#AutoScaling.Client.put_notification_configuration
        """
        super().__init__(data)
        try:
            print('Create AutoScaling Notification %s' % self.name)
            self.autoscale.put_notification_configuration(AutoScalingGroupName=self.name,
                                                          NotificationTypes=notice_types,
                                                          TopicARN=self.topic_arn)
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

class ElasticLoadBalancing(Service):
    """
    ELASTIC LOAD BALANCING v2
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/elbv2.html
    """

    def __init__(self, data):
        """
        Initialise data for ElasticLoadBalancing
        """
        super().__init__(data)
        self.elb = boto3.client('elbv2')
        self.response = None
        self.elb_arn = None


class LoadBalancer(ElasticLoadBalancing):
    """
    LOAD BALANCER
    """

    def __init__(self, data, ip_version='dualstack', lb_type='application', scheme='internet-facing'):
        """
        Initialize and Create Elastic Load Balancerv2
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/elbv2.html#ElasticLoadBalancingv2.Client.create_load_balancer
        """
        super().__init__(data)
        try:
            print('Create Elastic Load Balancer: %s' % self.name)
            self.response = self.elb.create_load_balancer(Name=self.name, Tags=[{'Key': self.tag, 'Value': self.tag}],
                                                          IpAddressType=ip_version, Type=lb_type, Scheme=scheme,
                                                          Subnets=self.subnet_ids, SecurityGroups=self.sg_ids)
            self.elb.create_tag(self, self.response['LoadBalancers']['LoadBalancerArn'])
        except ClientError as err:
            ElasticLoadBalancing.handle(err)
        except Exception as err:
            ElasticLoadBalancing.fatal(err)

    @staticmethod
    def delete(self):
        """
        Delete Elastic Load Balancer
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/elbv2.html#ElasticLoadBalancingv2.Client.delete_load_balancer
        """
        try:
            print('Delete Elastic Load Balancer %s' % self.elb_arn)
            self.elb.delete_load_balancer(LoadBalancerArn=self.elb_arn)
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
            if self.elb_arn:
                return self.elb.describe_load_balancers(LoadBalancerArns=(self.elb_arn,))
            else:
                return self.elb.describe_load_balancers(Names=(self.name,))
        except ClientError as err:
            ElasticLoadBalancing.handle(err)
        except Exception as err:
            ElasticLoadBalancing.fatal(err)


# ********************************************************* #
# ********* SIMPLE NOTIFICATION SERVICE CLIENT ************ #
# ********************************************************* #


class SimpleNotificationService(Service):
    """
    SIMPLE NOTIFICATION SERVICE (SNS)
    """

    def __init__(self, data):
        """
        Initialise data for Simple Notifications
        """
        super().__init__(data)
        self.sns = boto3.client('sns')


class SimpleNotificationServiceTopic(SimpleNotificationService):
    """
    SNS TOPIC
    """
    def __init__(self, data):
        """
        Creates a topic to which notifications can be published
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/sns.html#SNS.Client.create_topic
        """
        super().__init__(data)
        try:
            print('Create SNS topic  %s' % self.name)
            self.response = self.sns.create_topic(Name=self.name)
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
