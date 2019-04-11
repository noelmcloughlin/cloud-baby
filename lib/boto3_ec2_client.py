
import boto3
import base64
from botocore.exceptions import ClientError
default_desc = 'boto3-client-sdk'


class Compute:
    """
    COMPUTE
    """

    def __init__(self, service='ec2', region='eu-west-1', zone='eu-west-1a', tag=default_desc, cidr='172.35.0.0/24'):
        """
        Initialise data for Cloud Compute
        :type tag: String
        """

        self.client = boto3.client('ec2')
        self.compute = boto3.resource('ec2', region)
        self.tag = service + '-tag'
        self.desc = tag
        self.name = service
        self.zone = zone
        self.region = region
        self.key_name = 'ec2_user'
        self.response = None
        self.instance_id = None
        self.instance_type = 't2.micro'
        self.ami_id = 'ami-0fad7378adf284ce0'
        self.cidr_block = cidr
        self.max_count = 1
        self.min_count = 1
        self.user_data = b'''
#!/bin/bash
yum update -y
yum install -y httpd
systemctl enable httpd && systemctl start httpd
usermod -a -G apache ec2-user
chown -R ec2-user:apache /var/www
chmod 2775 /var/www
find /var/www -type d -exec chmod 2775 {} \;
find /var/www -type f -exec chmod 0664 {} \;
echo "Create by AWS Boto3 SDK" >> /var/www/html/index.html
'''

        self.data = {'EbsOptimized': False,
                     'ImageId': self.ami_id,
                     'InstanceType': self.instance_type,
                     'KeyName': self.key_name,
                     'Monitoring': {'Enabled': False},
                     'InstanceInitiatedShutdownBehavior': 'terminate',
                     'UserData': base64.b64encode(self.user_data).decode("ascii")
                     }

    def update_network_interfaces(self, subnet_id=None, group_ids=None):
        self.data['NetworkInterfaces'][0].update({'SubnetId': subnet_id, 'Groups': group_ids})

    def update_desc(self, desc):
        self.desc = desc

    def update_ami_id(self, ami_id):
        self.ami_id = ami_id
        self.data.update({'ImageId': ami_id})

    def update_instance_type(self, instance_type):
        self.instance_type = instance_type
        self.data.update({'InstanceType': instance_type})

    def update_key_name(self, key_name):
        self.key_name = key_name
        self.data.update({'KeyName': key_name})

    def update_availability_zone(self, zone):
        self.zone = zone
        self.data.update({'Placement': {'AvailabilityZone': zone}})

    def set_max_count(self, max_count):
        self.max_count = max_count

    def set_min_count(self, min_count):
        self.min_count = min_count

    def set_region(self, region):
        self.region = region

    def create_tag(self, resource, tag_key, tag_value, dry=False):
        """
        Adds or overwrite tag
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.create_tags
        """
        try:
            print('Create tag %s = %s for %s %s' % (tag_key, tag_value, resource, ('(dry)' if dry else '')))
            return self.client.create_tags(Resources=(resource,), Tags=[{'Key': tag_key, 'Value': tag_value}])
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
            if "NotFound" in error.response['Error']['Code'] or "DryRunOperation" in error.response['Error']['Code']:
                return
            elif "InvalidParameterValue" in error.response['Error']['Code']:
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
        print('Something bad happened %s' % error)
        exit(1)


class LaunchTemplate(Compute):
    """
    LAUNCH TEMPLATES
    """

    def __init__(self, dry=False, name='launch-template-tag', desc=default_desc, zone='eu-west-1a', ami_id=None,
                 instance_type=None, key_name=None):
        """
        Initialize and create Launch template
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.create_launch_template
        """
        try:
            super().__init__('launch-template')
            self.update_desc(desc)
            if ami_id:
                self.update_ami_id(ami_id)
            if instance_type:
                self.update_instance_type(instance_type)
            if key_name:
                self.update_key_name(key_name)
            if zone:
                self.update_availability_zone(zone)
            self.response = self.client.create_launch_template(LaunchTemplateName=name, VersionDescription=desc,
                                                               LaunchTemplateData=self.data, DryRun=dry)
            self.create_tag(self.response['LaunchTemplate']['LaunchTemplateId'], self.tag, self.desc, dry)
            print('Create launch_template %s' % ('(dry)' if dry else ''))
        except ClientError as err:
            Compute.handle(err)
        except Exception as err:
            Compute.fatal(err)

    def delete(self, tid, tname, dry=False):
        """
        Delete launch_template
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.delete_launch_template
        """
        try:
            print('Delete launch_template %s %s' % ((tid if tid else ''), (tname if tname else ''))),
            if tid:
                return self.client.delete_launch_template(LaunchTemplateId=tid, DryRun=dry)
            else:
                return self.client.delete_launch_template(LaunchTemplateName=tname, DryRun=dry)
        except ClientError as err:
            Compute.handle(err)
        except Exception as err:
            Compute.fatal(err)

    def list(self, name='tag:launch-template-tag', values=(default_desc,), dry=False):
        """
        Get EC2 launch_templates by searching filters
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.describe_launch_templates
        """
        try:
            return self.client.describe_launch_templates(Filters=[{'Name': name, 'Values': values}], DryRun=dry)
        except ClientError as err:
            Compute.handle(err)
        except Exception as err:
            Compute.fatal(err)


class Instance(Compute):
    """
    INSTANCES
    """

    def __init__(self, template_id, subnet_id, sg_ids, zone, max_count=1, min_count=1):
        """
        Initialize and Create Instance from Launch Template
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.ServiceResource.create_instances
        """
        try:
            super().__init__('instance')
            print('Create Instance from %s' % template_id )
            instance = self.compute.create_instances(LaunchTemplate={'LaunchTemplateId': template_id},
                                                     MaxCount=max_count, MinCount=min_count, SubnetId=subnet_id,
                                                     SecurityGroupIds=sg_ids,
                                                     Placement={'AvailabilityZone': zone})
            if instance and instance[0]:
                self.instance_id = instance[0].id
        except ClientError as err:
            Compute.handle(err)
        except Exception as err:
            Compute.fatal(err)

    def delete(self, instance, dry=False):
        """
        Delete a ec2 instance
        """
        try:
            print('Terminating instance %s %s' % (self.instance_id, ('(dry)' if dry else '')))
            self.terminate(DryRun=dry)
            self.wait_until_terminated(Filters=[{'Name': 'instance-id', 'Values': [self.instance_id]}], DryRun=dry)
            print('Terminated %s' % ('(dry)' if dry else ''))
        except ClientError as err:
            Compute.handle(err)
        except Exception as err:
            Compute.fatal(err)

    def list(self, name='tag:instance-tag', values=(default_desc,), dry=False):
        """
        Get EC2 instances by searching for stuff
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.describe_instances
        """
        try:
            return self.client.describe_instances(Filters=[{'Name': name, 'Values': values}], DryRun=dry)
        except ClientError as err:
            Compute.handle(err)
        except Exception as err:
            Compute.fatal(err)


class Volumes(Compute):
    """
    VOLUMES
    """

    def __init__(self, zone, size, snapshot_id=None, volume_type='default', dry=False):
        """
        Create Volume instance
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.create_volume
        """
        try:
            super().__init__('volume')
            print('Creating Volume %s' % ('(dry)' if dry else ''))
            if id:
                self.response = self.client.create_instances(AvailabilityZone=zone, SnapshotId=snapshot_id, Size=size,
                                                             VolumeType=volume_type, DryRun=dry)
            else:
                self.response = self.client.create_instances(AvailabilityZone=zone, Size=size, VolumeType=volume_type,
                                                             DryRun=dry)
            self.create_tag(self.response['VolumeId'], self.tag, self.desc, dry)
        except ClientError as err:
            Compute.handle(err)
        except Exception as err:
            Compute.fatal(err)

    def delete(self, volume_id, dry=False):
        """
        Delete volume instance
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.delete_volume
        """
        try:
            print('Deleting Volume %s %s' % (volume_id, ('(dry)' if dry else '')))
            return self.client.delete_volume(VolumeId=volume_id, DryRun=dry)
        except ClientError as err:
            Compute.handle(err)
        except Exception as err:
            Compute.fatal(err)

    def list(self, name='tag:volume-tag', values=(default_desc,), dry=False):
        """
        Get Volumes
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.describe_volumes
        """
        try:
            return self.client.describe_volumes(Filters=[{'Name': name, 'Values': values}], DryRun=dry)
        except ClientError as err:
            Compute.handle(err)
        except Exception as err:
            Compute.fatal(err)


class Vpc(Compute):
    """
    VIRTUAL PRIVATE CLOUD (VPC)
    """

    def __init__(self, cidr_ipv4, auto_ipv6=True, tenancy='default', dry=False):
        """
        Initialize and create Vpc
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.create_vpc
        """
        try:
            super().__init__('vpc')
            print('Create vpc %s' % ('(dry)' if dry else ''))
            self.response = self.client.create_vpc(CidrBlock=cidr_ipv4, AmazonProvidedIpv6CidrBlock=auto_ipv6,
                                                   InstanceTenancy=tenancy, DryRun=dry)
            self.create_tag(self.response['Vpc']['VpcId'], self.tag, self.desc, dry)
        except ClientError as err:
            Compute.handle(err, 'vpc')
        except Exception as err:
            Compute.fatal(err)

    def delete(self, vpc_id, dry=False):
        """
        Delete virtual priv cloud.
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.delete_vpc
        """
        try:
            print('Delete %s %s' % (vpc_id, ('(dry)' if dry else '')))
            return self.client.delete_vpc(VpcId=vpc_id, DryRun=dry)
        except ClientError as err:
            Compute.handle(err, 'vpc')
        except Exception as err:
            Compute.fatal(err)
    
    def list(self, name='tag:vpc-tag', values=(default_desc,), dry=False):
        """
        Get VPC(s) by filter
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.describe_vpcs
        """
        try:
            return self.client.describe_vpcs(Filters=[{'Name': name, 'Values': values}], DryRun=dry)
        except ClientError as err:
            Compute.handle(err)
        except Exception as err:
            Compute.fatal(err)
    

class VpcEndpoint(Compute):
    """
    VPC ENDPOINTS
    """

    def __init__(self, vpc_id, rtt_ids, sn_ids, sg_ids, ideal, svc='com.amazonaws.eu-west-1.ec2', dry=False):
        """
        Initialize and create VpcEndPoint
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.create_vpc_endpoint
        """
        try:
            super().__init__('vpc-endpoint')
            self.response = self.client.create_vpc_endpoint(VpcEndpointType=ideal, VpcId=vpc_id, ServiceName=svc,
                                                            RouteTableIds=rtt_ids, SubnetIds=sn_ids,
                                                            SecurityGroupIds=sg_ids, Dryrun=dry)
            self.create_tag(self.response['VpcEndpoint']['VpcEndpointId'], self.tag, self.desc, dry)
            print('Create vpc-endpoint  %s' % ('(dry)' if dry else ''))
        except ClientError as err:
            Compute.handle(err)
        except Exception as err:
            Compute.fatal(err)

    def delete(self, vpc_endpoint_id, dry=False):
        """
        Delete a virtual priv cloud endpoint
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.delete_vpc_endpoints
        """
        try:
            print('Delete %s %s' % (vpc_endpoint_id, ('(dry)' if dry else '')))
            return self.client.delete_vpc_endpoints(VpcEndpointIds=[vpc_endpoint_id], DryRun=dry)
        except ClientError as err:
            Compute.handle(err)
        except Exception as err:
            Compute.fatal(err)
    
    def list(self, name='tag:vpc-endpoint-tag', values=(default_desc,), dry=False):
        """
        Get VPC(s) by endpoints filter
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.describe_vpc_endpoints
        """
        try:
            return self.client.describe_vpc_endpoints(Filters=[{'Name': name, 'Values': values}], DryRun=dry)
        except ClientError as err:
            Compute.handle(err)
        except Exception as err:
            Compute.fatal(err)
    
    
class VpcPeeringConnection(Compute):
    """
    VPC PEERING CONNECTION
    """

    def __init__(self, peer_vpc_id, vpc_id, region, dry=False):
        """
        Initialize and create VpcPeeringConnection
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.create_vpc_peering_connection
        """
        try:
            super().__init__('vpc-peering-connection')
            self.response = self.client.create_vpc_peering_connection(PeerVpcId=peer_vpc_id, VpcId=vpc_id,
                                                                      PeerRegion=region, DryRun=dry)
            self.create_tag(self.response['VpcPeeringConnection']['VpcPeeringConnectionId'], self.tag, self.desc, dry)
            print('Create vpc_peering_connection  %s' % ('(dry)' if dry else ''))
        except ClientError as err:
            Compute.handle(err)
        except Exception as err:
            Compute.fatal(err)

    def delete(self, vpc_peering_connection_id, dry=False):
        """
        Delete a virtual priv cloud peering_connection
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.delete_vpc_peering_connections
        """
        try:
            print('Delete %s %s' % (vpc_peering_connection_id, ('(dry)' if dry else '')))
            return self.client.delete_vpc_peering_connections(VpcPeeringConnectionId=vpc_peering_connection_id,
                                                              DryRun=dry)
        except ClientError as err:
            Compute.handle(err)
        except Exception as err:
            Compute.fatal(err)
    
    def list(self, name='tag:vpc-peering-connection-tag', values=(default_desc,), dry=False):
        """-
        Get VPC(s) by peering_connections filter
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.describe_vpc_peering_connections
        """
        try:
            return self.client.describe_vpc_peering_connections(Filters=[{'Name': name, 'Values': values}], DryRun=dry)
        except ClientError as err:
            Compute.handle(err)
        except Exception as err:
            Compute.fatal(err)
    
    
class NetworkInterface(Compute):
    """
    NETWORK INTERFACE
    """

    def __init__(self, desc, groups=None, pri_ip=None, pri_ips=None, subnet_id=None, dry=False):
        """
        Initialize and create NetworkInterface
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.create_network_interface
        """
        try:
            super().__init__('network-interface')
            self.response = self.client.create_network_interface(Description=desc, Groups=groups, SubnetId=subnet_id,
                                                                 PrivateIpAddress=pri_ip, PrivateIpAddresses=pri_ips,
                                                                 DryRun=dry)
            self.create_tag(self.response['NetworkInterface']['NetworkInterfaceId'], self.tag, self.desc, dry)
            print('Create network_interface for %s %s' % (pri_ip, ('(dry)' if dry else '')))
        except ClientError as err:
            Compute.handle(err)
        except Exception as err:
            Compute.fatal(err)

    def delete(self, if_id, dry=False):
        """
        Delete a network_interface.
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.delete_network_interface
        """
        try:
            print('Delete %s %s' % (id, ('(dry)' if dry else '')))
            return self.client.delete_network_interface(NetworkInterfaceId=if_id, DryRun=dry)
        except ClientError as err:
            Compute.handle(err)
        except Exception as err:
            Compute.fatal(err)
    
    def list(self, name='tag:network-interface-tag', values=(default_desc,), dry=False):
        """
        Get Network interfaces by tag name/value or maybe by array of ids.
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.describe_network_interfaces
        """
        try:
            return self.client.describe_network_interfaces(Filters=[{'Name': name, 'Values': values}], DryRun=dry)
        except ClientError as err:
            Compute.handle(err)
        except Exception as err:
            Compute.fatal(err)


class Subnet(Compute):
    """
    SUBNET
    """

    def __init__(self, vpc_id, dry=False):
        """
        Initialize and create Subnet
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.create_subnet
        """
        try:
            super().__init__('subnet')
            self.response = self.client.create_subnet(CidrBlock=self.cidr_block, VpcId=vpc_id, DryRun=dry)
            self.create_tag(self.response['Subnet']['SubnetId'], self.tag, self.desc, dry)
            print('Create subnet for %s %s' % (self.cidr_block, ('(dry)' if dry else '')))
        except ClientError as err:
            Compute.handle(err)
        except Exception as err:
            Compute.fatal(err)

    def modify_attr(self, sn_id, value):
        """
        Modify a subnet.
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.modify_subnet_attribute
        """
        try:
            print('Map %s public-ip-on-launch' % sn_id)
            return self.client.modify_subnet_attribute(SubnetId=sn_id, MapPublicIpOnLaunch={'Value': value})
        except ClientError as err:
            Compute.handle(err)
        except Exception as err:
            Compute.fatal(err)
        return None
    
    def delete(self, sn_id, dry=False):
        """
        Delete a subnet.
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.delete_subnet
        """
        try:
            print('Delete %s %s' % (sn_id, ('(dry)' if dry else '')))
            return self.client.delete_subnet(SubnetId=sn_id, DryRun=dry)
        except ClientError as err:
            Compute.handle(err)
        except Exception as err:
            Compute.fatal(err)
    
    def list(self, name='tag:subnet-tag', values=(default_desc,), dry=False):
        """
        Get VPC(s) by tag (note: create_tags not working via client api, use cidr or object_id instead )
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.describe_subnets
        """
        try:
            return self.client.describe_subnets(Filters=[{'Name': name, 'Values': values}], DryRun=dry)
        except ClientError as err:
            Compute.handle(err)
        except Exception as err:
            Compute.fatal(err)
    

class SecurityGroup(Compute):
    """
    SECURITY GROUPS
    """

    def __init__(self, name, desc, vpc_id, dry=False):
        """
        Initialize and Create Security Group
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.create_security_group
        """
        try:
            super().__init__('security-group')
            self.response = self.client.create_security_group(Description=desc, GroupName=name, VpcId=vpc_id,
                                                              DryRun=dry)
            self.create_tag(self.response['GroupId'], self.tag, self.desc, dry)
            print('Create security group %s' % ('(dry)' if dry else ''))
        except ClientError as err:
            Compute.handle(err)
        except Exception as err:
            Compute.fatal(err)
    
    def delete(self, sg_id, dry=False):
        """
        Delete a security group.
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.delete_security_group
        """
        try:
            print('Delete %s %s' % (sg_id, ('(dry)' if dry else '')))
            return self.client.delete_security_group(GroupId=sg_id, DryRun=dry)
        except ClientError as err:
            Compute.handle(err)
        except Exception as err:
            Compute.fatal(err)
    
    def list(self, name='tag:security-group-tag', values=(default_desc,), dry=False):
        """
        Get Security Groups by searching for VPC Id.
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.describe_security_groups
        """
        try:
            return self.client.describe_security_groups(Filters=[{'Name': name, 'Values': values}], DryRun=dry)
        except ClientError as err:
            Compute.handle(err)
        except Exception as err:
            Compute.fatal(err)
    
    def list_refs(self, group_ids, dry=False):
        """
        Get Security Groups references
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.describe_security_group_references
        """
        try:
            return self.client.describe_security_group_references(GroupId=group_ids, DryRun=dry)
        except ClientError as err:
            Compute.handle(err)
        except Exception as err:
            Compute.fatal(err)
    
    def auth_egress(self, from_port, to_port, proto, sg_id, ipv4, ipv6=({'CidrIpv6', '::/0'},), dry=False):
        """
        Adds egress rules to a security group.
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.authorize_security_group_egress
        """
        try:
            print('Authorize sg egress %s %s' % (sg_id, ('(dry)' if dry else '')))
            return self.client.authorize_security_group_egress(IpPermissions=[{'FromPort': from_port, 'ToPort': to_port,
                                                                               'IpProtocol': proto, 'IpRanges': ipv4,
                                                                               'Ipv6Ranges': ipv6}],
                                                               GroupId=sg_id, DryRun=dry)
        except ClientError as err:
            Compute.handle(err)
        except Exception as err:
            Compute.fatal(err)
    
    def auth_ingress(self, from_port, to_port, proto, sg_id, ipv4, ipv6=({'CidrIpv6', '::/0'},), dry=False):
        """
        Adds ingress rules to a security group.
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.authorize_security_group_ingress
        """
        try:
            print('Authorize sg ingress %s %s' % (sg_id, ('(dry)' if dry else '')))
            return self.client.authorize_security_group_ingress(IpPermissions=[{'FromPort': from_port,
                                                                                'ToPort': to_port,
                                                                                'IpProtocol': proto,
                                                                                'IpRanges': ipv4,
                                                                                'Ipv6Ranges': ipv6}],
                                                                GroupId=sg_id, DryRun=dry)
        except ClientError as err:
            Compute.handle(err)
        except Exception as err:
            Compute.fatal(err)
    
    def revoke_egress(self, from_port, to_port, proto, sg_id, ipv4, ipv6=({'CidrIpv6', '::/0'},), dry=False):
        """
        Revoke egress rules from a security group.
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.revoke_security_group_egress
        """
        try:
            print('Revoke sg egress %s %s' % (sg_id, ('(dry)' if dry else '')))
            return self.client.revoke_security_group_egress(IpPermissions=[{'FromPort': from_port, 'ToPort': to_port,
                                                                            'IpProtocol': proto, 'IpRanges': ipv4,
                                                                            'Ipv6Ranges': ipv6}],
                                                            GroupId=sg_id, DryRun=dry)
        except ClientError as err:
            Compute.handle(err)
        except Exception as err:
            Compute.fatal(err)
    
    def revoke_ingress(self, from_port, to_port, proto, sg_id, ipv4, ipv6=({'CidrIpv6', '::/0'},), dry=False):
        """
        Remove ingress rules to a security group.
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.revoke_security_group_ingress
        """
        try:
            print('Revoke sg ingress from %s %s' % (sg_id, ('(dry)' if dry else '')))
            return self.client.revoke_security_group_ingress(IpPermissions=[{'FromPort': from_port, 'ToPort': to_port,
                                                                             'IpProtocol': proto,
                                                                             'IpRanges': ipv4,
                                                                             'Ipv6Ranges': ipv6}],
                                                             GroupId=sg_id, DryRun=dry)
        except ClientError as err:
            Compute.handle(err)
        except Exception as err:
            Compute.fatal(err)
    

class NatGateway(Compute):
    """
    NAT GATEWAY
    """

    def __init__(self, alloc_id, subnet_id, dry=False):
        """
        Initialize and Create NAT Gateway
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.create_nat_gateway
        """
        try:
            super().__init__('nat-gateway')
            self.response = self.client.create_nat_gateway(AllocationId=alloc_id, SubnetId=subnet_id, DryRun=dry)
            self.create_tag(self.response['NatGateway']['NatGatewayId'], self.tag, self.desc, dry)
            print('Create nat gateway for subnet %s %s' % (subnet_id, ('(dry)' if dry else '')))
        except ClientError as err:
            Compute.handle(err)
        except Exception as err:
            Compute.fatal(err)
    
    def delete(self, nat_gw_id, dry=False):
        """
        Delete a nat gateway.
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.delete_nat_gateway
        """
        try:
            print('Delete nat gateway for subnet %s %s' % (nat_gw_id, ('(dry)' if dry else '')))
            return self.client.delete_nat_gateway(NatGatewayId=nat_gw_id, DryRun=dry)
        except ClientError as err:
            Compute.handle(err)
        except Exception as err:
            Compute.fatal(err)
    
    def list(self, name='tag:nat-gateway-tag', values=(default_desc,)):
        """
        Get nat gateways by searching for vpc
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.describe_nat_gateways
        """
        try:
            return self.client.describe_nat_gateways(Filters=[{'Name': name, 'Values': values}])
        except ClientError as err:
            Compute.handle(err)
        except Exception as err:
            Compute.fatal(err)


class RouteTable(Compute):
    """
    ROUTE TABLE
    """

    def __init__(self, vpc_id, dry=False):
        """
        Initialize and Create Route Table
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.create_route_table
        """
        try:
            super().__init__('route-table')
            self.response = self.client.create_route_table(VpcId=vpc_id, DryRun=dry)
            self.create_tag(self.response['RouteTable']['RouteTableId'], self.tag, self.desc, dry)
            print('Create route table for %s %s' % (vpc_id, ('(dry)' if dry else '')))
        except ClientError as err:
            Compute.handle(err)
        except Exception as err:
            Compute.fatal(err)

    def delete(self, route_table_id, dry=False):
        """
        Delete a route table.
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.delete_route_table
        """
        try:
            print('Delete %s %s' % (route_table_id, ('(dry)' if dry else '')))
            return self.client.delete_route_table(RouteTableId=route_table_id, DryRun=dry)
        except ClientError as err:
            Compute.handle(err)
        except Exception as err:
            Compute.fatal(err)

    def create_route(self, version, cidr, gateway_id, route_table_id, dry=False):
        """
        Initialize and Create Route Table
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.create_route
        """
        try:
            print('Create %s route for %s %s' % (version, cidr, ('(dry)' if dry else '')))
            if version == 'ipv6':
                return self.client.create_route(DestinationIpv6CidrBlock=cidr, GatewayId=gateway_id,
                                                RouteTableId=route_table_id, DryRun=dry)
            else:
                return self.client.create_route(DestinationCidrBlock=cidr, GatewayId=gateway_id,
                                                RouteTableId=route_table_id, DryRun=dry)
        except ClientError as err:
            Compute.handle(err)
        except Exception as err:
            Compute.fatal(err)

    def delete_route(self, cidr, route_table_id, dry=False):
        """
        Create a route in route table
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.delete_route
        """
        try:
            print('Delete route for %s %s' % (cidr, ('(dry)' if dry else '')))
            return self.client.delete_route(DestinationCidrBlock=cidr, RouteTableId=route_table_id, DryRun=dry)
        except ClientError as err:
            Compute.handle(err)
        except Exception as err:
            Compute.fatal(err)

    def associate(self, route_table_id, subnet_id, dry=False):
        """
        Associate route table with subnet
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.associate_route_table
        """
        try:
            print('Associate route table %s to %s %s' % (route_table_id, subnet_id, ('(dry)' if dry else '')))
            return self.client.associate_route_table(RouteTableId=route_table_id, SubnetId=subnet_id, DryRun=dry)

        except ClientError as err:
            Compute.handle(err)
        except Exception as err:
            Compute.fatal(err)

    def disassociate(self, association_id, dry=False):
        """
        Disassociate a route table.
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.disassociate_route_table
        """
        try:
            print('Disassociate %s %s' % (association_id, ('(dry)' if dry else '')))
            return self.client.disassociate_route_table(AssociationId=association_id, DryRun=dry)
        except ClientError as err:
            Compute.handle(err)
        except Exception as err:
            Compute.fatal(err)
    
    def list(self, name='tag:route-table-tag', values=(default_desc,), dry=False):
        """
        Get route tables by searching for vpc
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.describe_route_tables
        """
        try:
            return self.client.describe_route_tables(Filters=[{'Name': name, 'Values': values}], DryRun=dry)
        except ClientError as err:
            Compute.handle(err)
        except Exception as err:
            Compute.fatal(err)


class NetworkAcl(Compute):
    """
    NETWORK ACL
    """

    def __init__(self, vpc_id, dry=False):
        """
        Initialize and Create Network ACL
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.create_network_acl
        """
        try:
            super().__init__('network-acl')
            self.response = self.client.create_network_acl(VpcId=vpc_id, DryRun=dry)
            self.create_tag(self.response['NetworkAcl']['NetworkAclId'], self.tag, self.desc, dry)
            print('Create network acl for %s %s' % (vpc_id, ('(dry)' if dry else '')))
        except ClientError as err:
            Compute.handle(err)
        except Exception as err:
            Compute.fatal(err)

    def delete(self, network_acl_id, dry=False):
        """
        Delete a network acl.
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.delete_network_acl
        """
        try:
            print('Delete %s %s' % (network_acl_id, ('(dry)' if dry else '')))
            return self.client.delete_network_acl(NetworkAclId=network_acl_id, DryRun=dry)
        except ClientError as err:
            Compute.handle(err)
        except Exception as err:
            Compute.fatal(err)

    def replace_association(self, network_acl_id, association_id, dry=False):
        """
        Replace network acl association
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.replace_network_acl_association
        """
        try:
            print('Replace network association %s %s' % (network_acl_id, ('(dry)' if dry else '')))
            return self.client.replace_network_acl_association(AssociationId=association_id,
                                                               NetworkAclId=network_acl_id, DryRun=dry)
        except ClientError as err:
            Compute.handle(err)
        except Exception as err:
            Compute.fatal(err)
    
    def create_entry(self, network_acl_id, num, action, cidr, from_port, to_port, proto='6', egress=False, dry=False):
        """
        Create network acl entry
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.create_network_acl_entry
        """
        try:
            print('Create network acl entry for %s %s' % (network_acl_id, '(dry)' if dry else ''))
            if from_port and to_port:
                return self.client.create_network_acl_entry(CidrBlock=cidr, Egress=egress, NetworkAclId=network_acl_id,
                                                            Protocol=proto, RuleAction=action, RuleNumber=num,
                                                            DryRun=dry)
            else:
                return self.client.create_network_acl_entry(CidrBlock=cidr, Egress=egress, NetworkAclId=network_acl_id,
                                                            PortRange={'From': from_port, 'To': to_port},
                                                            Protocol=proto, RuleAction=action, RuleNumber=num,
                                                            DryRun=dry)
        except ClientError as err:
            Compute.handle(err)
        except Exception as err:
            Compute.fatal(err)
    
    def delete_entry(self, network_acl_id, num=100, egress=False, dry=False):
        """
        Delete a network acl entry
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.delete_network_acl_entry
        """
        try:
            print('Delete %s %s' % (network_acl_id, ('(dry)' if dry else '')))
            return self.client.delete_network_acl_entry(Egress=egress, NetworkAclId=network_acl_id, RuleNumber=num,
                                                        DryRun=dry)
        except ClientError as err:
            Compute.handle(err)
        except Exception as err:
            Compute.fatal(err)
    
    def list(self, name='tag:network-acl-tag', values=(default_desc,), dry=False):
        """
        Get network acls by searching for stuff
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.describe_network_acls
        """
        try:
            return self.client.describe_network_acls(Filters=[{'Name': name, 'Values': values}], DryRun=dry)
        except ClientError as err:
            Compute.handle(err)
        except Exception as err:
            Compute.fatal(err)


class ElasticIp(Compute):
    """
    ELASTIC IP
    """

    def __init__(self, domain='vpc', dry=False):
        """
        Initialize and Create Elastic IP
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.allocate_address
        """
        try:
            super().__init__('elastic-ip')
            self.response = self.client.allocate_address(Domain=domain, DryRun=dry)
            self.create_tag(self.response['AllocationId'], self.tag, self.desc, dry)
            print('Create elastic ip %s for %s %s' % (self.response['AllocationId'], domain, ('(dry)' if dry else '')))
        except ClientError as err:
            Compute.handle(err)
        except Exception as err:
            Compute.fatal(err)

    def associate(self, alloc_id, instance_id, dry=False):
        """
        Associate elastic ip with ec2_instance
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.associate_address
        """
        try:
            print('Associate elastic ip %s with %s %s' % (alloc_id, instance_id, '(dry)' if dry else ''))
            return self.client.associate_address(AllocationId=alloc_id, InstanceId=instance_id, DryRun=dry)
        except ClientError as err:
            Compute.handle(err)
        except Exception as err:
            Compute.fatal(err)
    
    def disassociate(self, association_id, dry=False):
        """
        Disassociate elastic ip with ec2_instance
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.disassociate_address
        """
        try:
            print('Disassociate elastic ip %s %s' % (association_id, '(dry)' if dry else ''))
            self.client.disassociate_address(AssociationId=association_id, DryRun=dry)
        except ClientError as err:
            Compute.handle(err)
        except Exception as err:
            Compute.fatal(err)
    
    def release(self, alloc_id, dry=False):
        """
        Delete a elastic ip.
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.release_address
        """
        try:
            print('Release %s %s' % (alloc_id, ('(dry)' if dry else '')))
            return self.client.release_address(AllocationId=alloc_id, DryRun=dry)
        except ClientError as err:
            Compute.handle(err)
        except Exception as err:
            Compute.fatal(err)
    
    def list(self, name='tag:elastic-ip-tag', values=(default_desc,), dry=False):
        """
        Get Elastic IPs
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.describe_addresses
        """
        try:
            return self.client.describe_addresses(Filters=[{'Name': name, 'Values': values}], DryRun=dry)
        except ClientError as err:
            Compute.handle(err)
        except Exception as err:
            Compute.fatal(err)
    
    
class InternetGateway(Compute):
    """
    INTERNET GATEWAY
    """

    def __init__(self, dry=False):
        """
        Initialize and Create Internet Gateway
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.create_internet_gateway
        """
        try:
            super().__init__('internet-gateway')
            self.response = self.client.create_internet_gateway(DryRun=dry)
            self.create_tag(self.response['InternetGateway']['InternetGatewayId'], self.tag, self.desc, dry)
            print('Create internet gateway %s' % ('(dry)' if dry else ''))
        except ClientError as err:
            Compute.handle(err)
        except Exception as err:
            Compute.fatal(err)
    
    def delete(self, gateway_id, dry=False):
        """
        Delete a internet gateway.
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.delete_internet_gateway
        """
        try:
            print('Delete internet gateway %s %s' % (gateway_id, ('(dry)' if dry else '')))
            return self.client.delete_internet_gateway(InternetGatewayId=gateway_id, DryRun=dry)
        except ClientError as err:
            Compute.handle(err)
        except Exception as err:
            Compute.fatal(err)
    
    def list(self, name='tag:internet-gateway-tag', values=(default_desc,), dry=False):
        """
        Get internet gateways IPs
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.describe_internet_gateways
        """
        try:
            return self.client.describe_internet_gateways(Filters=[{'Name': name, 'Values': values}], DryRun=dry)
        except ClientError as err:
            Compute.handle(err)
        except Exception as err:
            Compute.fatal(err)
    
    def attach(self, gateway_id, vpc_id, dry=False):
        """
        Attaches an internet gateway to a VPC
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.attach_internet_gateway
        """
        try:
            print('Attach %s to %s %s' % (gateway_id, vpc_id, ('(dry)' if dry else '')))
            return self.client.attach_internet_gateway(InternetGatewayId=gateway_id, VpcId=vpc_id, DryRun=dry)
        except ClientError as err:
            Compute.handle(err)
        except Exception as err:
            Compute.fatal(err)
    
    def detach(self, gateway_id, vpc_id, dry=False):
        """
        Attaches an internet gateway to a VPC
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.detach_internet_gateway
        """
        try:
            print('Detach %s from %s %s' % (gateway_id, vpc_id, ('(dry)' if dry else '')))
            return self.client.detach_internet_gateway(InternetGatewayId=gateway_id, VpcId=vpc_id, DryRun=dry)
        except ClientError as err:
            Compute.handle(err)
        except Exception as err:
            Compute.fatal(err)
