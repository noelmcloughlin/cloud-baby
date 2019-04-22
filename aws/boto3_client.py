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
        self.catalog = data['cloud']['catalog']
        self.cidr4_vpc = data['cloud']['cidr4_vpc']
        self.cidr4 = data['cloud']['cidr4']
        self.cidr6_vpc = data['cloud']['cidr6_vpc']
        self.cidr6 = data['cloud']['cidr6']
        self.dry = data['cloud']['dry']
        self.ipv4 = data['cloud']['ipv4']
        self.ipv6 = data['cloud']['ipv6']
        self.key_pair = data['cloud']['key_pair']
        self.name = data['cloud']['name']
        self.network_acls = data['cloud']['network_acls']
        self.private_ip = data['cloud']['private_ip']
        self.private_ips = data['cloud']['private_ips']
        self.peer_region = data['cloud']['peer_region']
        self.region = data['cloud']['region']
        self.scope = data['cloud']['scope']
        self.tag = data['cloud']['tag']
        self.zone = data['cloud']['zone']
        self.zones = data['cloud']['zones']
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
        super().__init__(data)
        self.auto_ipv6 = data['service']['auto_ipv6']
        self.ebs_optimized = data['service']['ebs_optimized']
        self.min_count = data['service']['min_count']
        self.max_count = data['service']['max_count']
        self.monitor = data['service']['monitor']
        self.public_ip = data['service']['public_ip']
        self.template_id = data['service']['template_id']
        self.tenancy = data['service']['tenancy']
        self.token = ''.join(random.SystemRandom().choice(string.ascii_uppercase + string.digits) for _ in range(63))

        self.acl_id = data['service']['acl_id']
        self.acl_ids = data['service']['acl_ids']
        self.sg_id = data['service']['sg_id']
        self.sg_ids = data['service']['sg_ids']
        self.subnet_id = data['service']['subnet_id']
        self.subnet_ids = data['service']['subnet_ids']
        self.template_ids = data['service']['template_ids']
        self.topic_arn = data['service']['topic_arn']


class Compute(Service):
    """
    COMPUTE
    """
    def __init__(self, data=None):
        """
        Create Compute with DATA and METHODS
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#instance
        """
        super().__init__(data)
        self.eip_id = data['compute']['eip_id']
        self.instance_id = data['compute']['instance_id']
        self.igw_id = data['compute']['igw_id']
        self.nat_gw_id = data['compute']['nat_gw_id']
        self.peer_vpc_id = data['compute']['vpc_id']
        self.rtt_id = data['compute']['rtt_id']
        self.vpc_id = data['compute']['vpc_id']
        self.eip_ids = data['compute']['eip_ids']
        self.igw_ids = data['compute']['igw_ids']
        self.instance_ids = data['compute']['instance_ids']
        self.nat_gw_ids = data['compute']['nat_gw_ids']
        self.rtt_ids = data['compute']['rtt_ids']

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
    def __init__(self, data=None):
        """
        Initialise data for MachineImage
        """
        super().__init__(data)
        self.ami_id = data['image']['ami_id']
        self.ami_type = data['image']['ami_type']
        self.hibernate = data['image']['hibernate']
        self.user_data = data['image']['user_data']


class LaunchTemplate(Image):
    """
    LAUNCH TEMPLATES
    """
    def __init__(self, data=None,):
        """
        Initialize and create Launch template
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.create_launch_template
        # 'HibernationOptions': {'Configured': self.hibernate}  ## not supported by t2.micro
        """
        super().__init__(data)
        self.template_data = {
            'EbsOptimized': self.ebs_optimized,
            'BlockDeviceMappings': [],
            'ImageId': self.ami_id,
            'InstanceType': self.ami_type,
            'KeyName': self.key_pair,
            'Monitoring': {'Enabled': self.monitor},
            'InstanceInitiatedShutdownBehavior': 'stop',
            'UserData': base64.b64encode(self.user_data).decode("ascii"),
            'TagSpecifications': [{'ResourceType': 'instance', 'Tags': [{'Key': self.name, 'Value': self.tag}]}],
            'SecurityGroupIds': self.sg_ids
            }

        try:
            print('Create launch_template %s' % ('(dry)' if self.dry else ''))
            self.response = self.client.create_launch_template(LaunchTemplateName=self.name, ClientToken=self.token,
                                                               VersionDescription=self.tag, DryRun=self.dry,
                                                               LaunchTemplateData=self.template_data)
            self.create_tag(self, self.response['LaunchTemplate']['LaunchTemplateId'])
        except ClientError as err:
            Compute.handle(err)
        except Exception as err:
            Compute.fatal(err)

    @staticmethod
    def delete(self):
        """
        Delete launch_template
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.delete_launch_template
        """
        try:
            print('Delete launch_template %s %s' % (self.template_id, self.name))
            return self.client.delete_launch_template(LaunchTemplateId=self.template_id, DryRun=self.dry)
        except ClientError as err:
            Compute.handle(err)

    @staticmethod
    def create_version(self, version=1, zone=None):
        """
        create_launch_template_version
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.create_launch_template_version
        """
        try:
            self.version = str(version)
            print('Create launch_template %s version %s' % (self.template_id, self.version))
            if zone:
                self.response = self.client.create_launch_template_version(LaunchTemplateId=self.template_id,
                                                                           LaunchTemplateData={'Placement': {
                                                                               'AvailabilityZone': zone}},
                                                                           DryRun=self.dry)
            else:
                self.response = self.client.create_launch_template_version(LaunchTemplateId=self.template_id,
                                                                           DryRun=self.dry)
            return self.response
        except ClientError as err:
            Compute.handle(err)
        except Exception as err:
            Compute.fatal(err)

    @staticmethod
    def delete_version(self, version=1):
        """
        Delete launch_template version
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.delete_launch_template_versions
        """
        try:
            self.version = str(version)
            print('Delete launch template %s version %s' % (self.template_id, self.version)),
            return self.client.delete_launch_template_versions(LaunchTemplateId=self.template_id, DryRun=self.dry,
                                                               Versions=[self.version])
        except ClientError as err:
            Compute.handle(err)
        except Exception as err:
            Compute.fatal(err)

    @staticmethod
    def list_versions(self):
        """
        List versions of a specified launch template
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.describe_launch_template_versions
        """
        try:
            return self.client.describe_launch_template_versions(LaunchTemplateId=self.template_id, DryRun=self.dry)
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


class Instance(Image):
    """
    INSTANCE
    """

    def __init__(self, data=None, template_id=None, subnet_id=None, zone=None):
        """
        Initialize and Create Instance from Launch Template
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.ServiceResource.create_instances
        """
        super().__init__(data)
        self.template_id = template_id
        self.subnet_id = subnet_id
        self.zone = zone
        try:
            self.response = self.compute.create_instances(LaunchTemplate={'LaunchTemplateId': self.template_id},
                                                          SubnetId=self.subnet_id, SecurityGroupIds=self.sg_ids,
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
    def list(self):
        """
        Get EC2 instances by searching for stuff
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.describe_instances
        """
        states = ('pending', 'running', 'shutting-down', 'stopping', 'stopped')
        try:
            self.response = self.client.describe_instances(Filters=[{'Name': 'tag:' + self.name, 'Values': (self.tag,)},
                                                                    {'Name': 'instance-state-name', 'Values': states}],
                                                           DryRun=self.dry)
            return self.response
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
            self.response = self.client.create_vpc(CidrBlock=self.cidr4_vpc[0], DryRun=self.dry,
                                                   InstanceTenancy=self.tenancy,
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
    def associate_cidr(self, cidr4):
        """
        Associates a CIDR block with your VPC.
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.associate_vpc_cidr_block
        """
        try:
            print('Associate %s with %s %s' % (cidr4, self.vpc_id, ('(dry)' if self.dry else '')))
            return self.client.associate_vpc_cidr_block(CidrBlock=cidr4, VpcId=self.vpc_id)
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

    def __init__(self, data=None):
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
            return self.client.describe_network_interfaces(Filters=[{'Name': self.name, 'Values': (self.tag,)}],
                                                           DryRun=self.dry)
        except ClientError as err:
            Compute.handle(err)
        except Exception as err:
            Compute.fatal(err)


class Subnet(Compute):
    """
    SUBNET
    """

    def __init__(self, data=None, cidr_block=None, zone=None):
        """
        Initialize and create Subnet
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.create_subnet
        """
        super().__init__(data)
        try:
            print('Create subnet for %s %s' % (cidr_block, ('(dry)' if self.dry else '')))
            self.response = self.client.create_subnet(AvailabilityZone=zone, CidrBlock=cidr_block, VpcId=self.vpc_id,
                                                      DryRun=self.dry)
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
            return self.client.describe_security_group_references(GroupId=(sg_id,), DryRun=self.dry)
        except ClientError as err:
            Compute.handle(err)
        except Exception as err:
            Compute.fatal(err)

    @staticmethod
    def auth_egress(self, f_port, t_port, proto, ip4=None, ip6=None):
        """
        Adds egress rules to a security group.
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.authorize_security_group_egress
        """
        try:
            print('Authorize sg egress %s %s' % (self.sg_id, ('(dry)' if self.dry else '')))
            if ip4 and ip6:
                return self.client.authorize_security_group_egress(IpPermissions=[{'FromPort': f_port,
                                                                                   'ToPort': t_port,
                                                                                   'IpProtocol': proto,
                                                                                   'IpRanges': ip4,
                                                                                   'Ipv6Ranges': ip6}],
                                                                   GroupId=self.sg_id, DryRun=self.dry)
            elif ip4:
                return self.client.authorize_security_group_egress(IpPermissions=[{'FromPort': f_port,
                                                                                   'ToPort': t_port,
                                                                                   'IpProtocol': proto,
                                                                                   'IpRanges': ip4}],
                                                                   GroupId=self.sg_id, DryRun=self.dry)
            elif ip6:
                return self.client.authorize_security_group_egress(IpPermissions=[{'FromPort': f_port,
                                                                                   'ToPort': t_port,
                                                                                   'Ipv6Ranges': ip6}],
                                                                   GroupId=self.sg_id, DryRun=self.dry)
        except ClientError as err:
            Compute.handle(err)
        except Exception as err:
            Compute.fatal(err)

    @staticmethod
    def auth_ingress(self, f_port, t_port, proto, ip4=None, ip6=None):
        """
        Adds ingress rules to a security group.
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.authorize_security_group_ingress
        """
        try:
            print('Authorize sg ingress %s %s' % (self.sg_id, ('(dry)' if self.dry else '')))
            if ip4 and ip6:
                return self.client.authorize_security_group_ingress(IpPermissions=[{'FromPort': f_port,
                                                                                    'ToPort': t_port,
                                                                                    'IpProtocol': proto,
                                                                                    'IpRanges': ip4,
                                                                                    'Ipv6Ranges': ip6}],
                                                                    GroupId=self.sg_id, DryRun=self.dry)
            elif ip4:
                return self.client.authorize_security_group_ingress(IpPermissions=[{'FromPort': f_port,
                                                                                    'ToPort': t_port,
                                                                                    'IpProtocol': proto,
                                                                                    'IpRanges': ip4}],
                                                                    GroupId=self.sg_id, DryRun=self.dry)
            elif ip6:
                return self.client.authorize_security_group_ingress(IpPermissions=[{'FromPort': f_port,
                                                                                    'ToPort': t_port,
                                                                                    'Ipv6Ranges': ip6}],
                                                                    GroupId=self.sg_id, DryRun=self.dry)
        except ClientError as err:
            Compute.handle(err)
        except Exception as err:
            Compute.fatal(err)

    @staticmethod
    def revoke_egress(self, f_port, t_port, proto, ip4=None, ip6=None):
        """
        Revoke egress rules from a security group.
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.revoke_security_group_egress
        """
        try:
            print('Revoke sg egress %s %s' % (self.sg_id, ('(dry)' if self.dry else '')))
            if ip4 and ip6:
                return self.client.revoke_security_group_egress(IpPermissions=[{'FromPort': f_port, 'ToPort': t_port,
                                                                                'IpProtocol': proto, 'IpRanges': ip4,
                                                                                'Ipv6Ranges': ip6}],
                                                                GroupId=self.sg_id, DryRun=self.dry)
            elif ip4:
                return self.client.revoke_security_group_egress(IpPermissions=[{'FromPort': f_port, 'ToPort': t_port,
                                                                                'IpProtocol': proto, 'IpRanges': ip4}],
                                                                GroupId=self.sg_id, DryRun=self.dry)
            elif ip6:
                return self.client.revoke_security_group_egress(IpPermissions=[{'FromPort': f_port, 'ToPort': t_port,
                                                                                'Ipv6Ranges': ip6}],
                                                                GroupId=self.sg_id, DryRun=self.dry)

        except ClientError as err:
            Compute.handle(err)
        except Exception as err:
            Compute.fatal(err)

    @staticmethod
    def revoke_ingress(self, f_port, t_port, proto, ip4=None, ip6=None):
        """
        Remove ingress rules to a security group.
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.revoke_security_group_ingress
        """
        try:
            print('Revoke sg ingress from %s %s' % (self.sg_id, ('(dry)' if self.dry else '')))
            if ip4 and ip6:
                return self.client.revoke_security_group_ingress(IpPermissions=[{'FromPort': f_port, 'ToPort': t_port,
                                                                                 'IpProtocol': proto, 'IpRanges': ip4,
                                                                                 'Ipv6Ranges': ip6}],
                                                                 GroupId=self.sg_id, DryRun=self.dry)
            elif ip4:
                return self.client.revoke_security_group_ingress(IpPermissions=[{'FromPort': f_port, 'ToPort': t_port,
                                                                                 'IpProtocol': proto, 'IpRanges': ip4}],
                                                                 GroupId=self.sg_id, DryRun=self.dry)
            elif ip6:
                return self.client.revoke_security_group_ingress(IpPermissions=[{'FromPort': f_port, 'ToPort': t_port,
                                                                                 'Ipv6Ranges': ip6}],
                                                                 GroupId=self.sg_id, DryRun=self.dry)
        except ClientError as err:
            Compute.handle(err)
        except Exception as err:
            Compute.fatal(err)
    

class NatGateway(Compute):
    """
    NAT GATEWAY
    """

    def __init__(self, data=None):
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

    def __init__(self, data=None):
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

    def __init__(self, data=None):
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
    def create_entry(self, cidr4, rule_num, action, f_port, t_port, proto='6', egress=False):
        """
        Create network acl entry
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.create_network_acl_entry
        """
        try:
            print('Create network acl entry for %s %s %s' % (self.acl_id, cidr4, '(dry)' if self.dry else ''))
            if f_port and t_port:
                return self.client.create_network_acl_entry(CidrBlock=cidr4, Egress=egress, Protocol=proto,
                                                            RuleAction=action, NetworkAclId=self.acl_id,
                                                            PortRange={'From': f_port, 'To': t_port},
                                                            RuleNumber=rule_num, DryRun=self.dry)
            else:
                return self.client.create_network_acl_entry(CidrBlock=cidr4, Egress=egress, Protocol=proto,
                                                            RuleAction=action, NetworkAclId=self.acl_id,
                                                            PortRange={'From': f_port, 'To': t_port},
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
            print('Delete entry for %s %s' % (network_acl_id, ('(dry)' if self.dry else '')))
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

    def __init__(self, data=None, domain='vpc'):
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

    def __init__(self, data=None):
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
# *********** ELASTIC LOAD BALANCING (ELB) **************** #
# ********************************************************* #

class ElasticLoadBalancing(Service):
    """
    ELASTIC LOAD BALANCING v2
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/elbv2.html
    """

    def __init__(self, data=None):
        """
        Initialise data for ElasticLoadBalancing
        """
        super().__init__(data)
        self.lb_arn = data['elb']['lb_arn']
        self.lb_arns = data['elb']['lb_arns']
        self.ip_version = data['elb']['ip_version']
        self.lb_type = data['elb']['lb_type']
        self.scheme = data['elb']['scheme']
        self.elb = boto3.client('elbv2')


class LoadBalancer(ElasticLoadBalancing):
    """
    LOAD BALANCER
    """

    def __init__(self, data=None):
        """
        Initialize and Create Elastic Load Balancerv2
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/elbv2.html#ElasticLoadBalancingv2.Client.create_load_balancer
        """
        super().__init__(data)
        try:
            print('Create Elastic Load Balancer: %s' % self.name)
            self.response = self.elb.create_load_balancer(Name=self.name, Tags=[{'Key': self.tag, 'Value': self.tag}],
                                                          IpAddressType=self.ip_version, Type=self.lb_type,
                                                          Scheme=self.scheme, Subnets=self.subnet_ids,
                                                          SecurityGroups=self.sg_ids)
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
            print('Delete Elastic Load Balancer %s' % self.lb_arn)
            self.elb.delete_load_balancer(LoadBalancerArn=self.lb_arn)
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
            if self.lb_arn:
                return self.elb.describe_load_balancers(LoadBalancerArns=(self.lb_arn,))
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

    def __init__(self, data=None):
        """
        Initialise data for Simple Notifications
        """
        super().__init__(data)
        self.sns = boto3.client('sns')


class SimpleNotificationServiceTopic(SimpleNotificationService):
    """
    SNS TOPIC
    """
    def __init__(self, data=None):
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

# ********************************************************* #
# ***************** AUTO-SCALING CLIENT ******************* #
# ********************************************************* #


class AutoScaling(Service):
    """
    AUTO-SCALING
    """
    def __init__(self, data):
        """
        Initialise data for AutoScaling
        """
        super().__init__(data)
        self.asg_name = data['autoscaling']['asg_name']
        self.desired_capacity = data['autoscaling']['desired_capacity']
        self.hc_type = data['autoscaling']['hc_type']
        self.resource = data['autoscaling']['resource']
        self.notice_types = data['autoscaling']['notice_types']
        self.policy_type = data['autoscaling']['policy_type']
        self.est_warmup = data['autoscaling']['est_warmup']
        self.metric = data['autoscaling']['metric']
        self.metric_value = data['autoscaling']['metric_value']
        self.force_delete = data['autoscaling']['force_delete']
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
        try:
            if not self.dry:
                print('Create launch_configuration %s' % self.name)
                self.autoscale.create_launch_configuration(LaunchConfigurationName=self.name, ImageId=self.ami_id,
                                                           PlacementTenancy=self.tenancy, SecurityGroups=self.sg_ids,
                                                           EbsOptimized=self.ebs_optimized, UserData=self.user_data,
                                                           InstanceType=self.ami_type, KeyName=self.key_pair,
                                                           InstanceMonitoring={'Enabled': self.monitor},
                                                           AssociatePublicIpAddress=self.public_ip)
        except ClientError as err:
            AutoScaling.handle(err)
        except Exception as err:
            AutoScaling.fatal(err)

    @staticmethod
    def delete(self, launch_configuration_name=None):
        """
        Delete launch_configuration
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/autoscaling.html#AutoScaling.Client.delete_launch_configuration
        """
        try:
            print('Delete launch_configuration %s' % self.name)
            self.autoscale.delete_launch_configuration(LaunchConfigurationName=launch_configuration_name)
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


class AutoScalingGroup(LaunchConfiguration, ElasticLoadBalancing):
    """
    AUTO SCALING GROUP
    """

    def __init__(self, data=None):
        """
        Initialize and Create AutoScaling from Launch Configuration
        https://docs.aws.amazon.com/autoscaling/ec2/userguide/create-launch-template.html
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/autoscaling.html#AutoScaling.Client.create_auto_scaling_group
        """
        super().__init__(data)
        try:
            print('Create AutoScaling group: %s' % self.name)
            self.response = self.autoscale.create_auto_scaling_group(AutoScalingGroupName=self.name,
                                                                     Tags=[{'Key': self.tag, 'Value': self.tag}],
                                                                     MinSize=self.min_count, MaxSize=self.max_count,
                                                                     LaunchConfigurationName=self.name,
                                                                     VPCZoneIdentifier=",".join(self.subnet_ids),
                                                                     DesiredCapacity=self.desired_capacity,
                                                                     HealthCheckType=self.hc_type)
            # Doing the separately due to annoying ValidationError from previous command
            self.attach_target_groups(self)
        except ClientError as err:
            AutoScaling.handle(err)
        except Exception as err:
            AutoScaling.fatal(err)

    @staticmethod
    def delete(self):
        """
        Delete AutoScaling group
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/autoscaling.html#AutoScaling.Client.delete_auto_scaling_group
        """
        try:
            print('Delete AutoScaling group %s' % self.name)
            self.autoscale.delete_auto_scaling_group(AutoScalingGroupName=self.name, ForceDelete=self.force_delete)
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
    def attach_instances(self, instance_ids):
        """
        Attaches one or more EC2 instances to the specified Auto Scaling group.
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/autoscaling.html#AutoScaling.Client.attach_instances
        """
        try:
            print('Attach instances to AutoScaling group %s' % self.asg_name)
            self.autoscale.delete_auto_scaling_group(InstanceIds=instance_ids, AutoScalingGroupName=self.asg_name)
        except ClientError as err:
            AutoScaling.handle(err)
        except Exception as err:
            AutoScaling.fatal(err)

    @staticmethod
    def attach_target_groups(self):
        """
        Attaches one or more target groups to the specified Auto Scaling group
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/autoscaling.html#AutoScaling.Client.attach_load_balancer_target_groups
        """
        try:
            print('Attach target groups to AutoScaling group %s' % self.asg_name)
            self.autoscale.attach_load_balancer_target_groups(AutoScalingGroupName=self.name,
                                                              TargetGroupARNs=self.lb_arns)
        except ClientError as err:
            AutoScaling.handle(err)
        except Exception as err:
            AutoScaling.fatal(err)

    @staticmethod
    def detach_target_groups(self):
        """
        Detaches one or more target groups from the specified Auto Scaling group.
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/autoscaling.html#AutoScaling.Client.detach_load_balancer_target_groups
        """
        try:
            print('Detach target groups to AutoScaling group %s' % self.asg_name)
            self.autoscale.detach_load_balancer_target_groups(AutoScalingGroupName=self.name,
                                                              TargetGroupARNs=self.lb_arns)
        except ClientError as err:
            AutoScaling.handle(err)
        except Exception as err:
            AutoScaling.fatal(err)


class AutoScalingGroupTags(AutoScaling):
    """
    AUTO SCALING GROUP TAGS
    """

    def __init__(self, data=None):
        """
        Creates or updates tags for the specified Auto Scaling group
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/autoscaling.html#AutoScaling.Client.create_or_update_tags
        """
        super().__init__(data)
        try:
            print('Create tag %s = %s for %s %s' % (self.name, self.tag, self.resource, ('(dry)' if self.dry else '')))
            self.autoscale.create_or_update_tags(Tags=[{'ResourceId': self.name, 'ResourceType': self.resource,
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

    def __init__(self, data=None):
        """
        Creates or updates a policy for an Auto Scaling group
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/autoscaling.html#AutoScaling.Client.put_scaling_policy
        """
        super().__init__(data)
        config = {'PredefinedMetricSpecification': {'PredefinedMetricType': self.metric},
                  'TargetValue': self.metric_value}
        try:
            print('Create AutoScaling policy %s' % self.name)
            self.autoscale.put_scaling_policy(AutoScalingGroupName=self.name, PolicyName=self.name,
                                              EstimatedInstanceWarmup=self.est_warmup,
                                              TargetTrackingConfiguration=config,
                                              PolicyType=self.policy_type)
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
                return self.autoscale.describe_auto_scaling_groups(AutoScalingGroupName=asg_name, PolicyNames=pol_names,
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

    def __init__(self, data=None):
        """
        Configures an Auto Scaling group to send notifications
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/autoscaling.html#AutoScaling.Client.put_notification_configuration
        """
        super().__init__(data)
        try:
            print('Create AutoScaling Notification %s' % self.name)
            self.autoscale.put_notification_configuration(AutoScalingGroupName=self.name, TopicARN=self.topic_arn,
                                                          NotificationTypes=self.notice_types)
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
    def list(self):
        """
        Get AutoScaling Notifications by filtering
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/autoscaling.html#AutoScaling.Client.describe_notification_configurations
        """
        try:
            return self.autoscale.describe_policies(AutoScalingGroupName=self.name, PolicyTypes=(self.policy_type,))
        except ClientError as err:
            AutoScaling.handle(err)
        except Exception as err:
            AutoScaling.fatal(err)
