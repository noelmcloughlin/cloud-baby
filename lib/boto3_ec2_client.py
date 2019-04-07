import boto3, botocore
global_tag = 'boto3-client-sdk'
workdir = str(os.getcwd()) + "/"


class Compute:
    """
    COMPUTE
    """

    def __init__(self, service='ec2', zone='eu-west-1', tag=global_tag, cidr='172.35.0.0/24'):
        """
        Initialise data for Cloud Compute
        :type tag: String
        """

        self.tag = service + '-tag'
        self.name = service
        self.zone = zone
        self.tagval = tag
        self.cidr_block = cidr
        self.data = {'EbsOptimized': False,
                     'NetworkInterfaces': [
                               {'AssociatePublicIpAddress': True,
                                'DeleteOnTermination': True,
                                },
                           ],
                     'ImageId': 'ami-0fad7378adf284ce0',
                     'InstanceType': 't2.micro',
                     'KeyName': 'ec2_user',
                     'MaxCount': 1,
                     'MinCount': 1,
                     'Monitoring': {'Enabled': False},
                     'Placement': { 'AvailabilityZone': self.zone },
                     'InstanceInitiatedShutdownBehavior': 'terminate',
                     'UserData': b'''
                                       #!/bin/bash
                                       yum update -y
                                       yum install -y httpd
                                       systemctl enable httpd && systemctl start httpd
                                       usermod -a -G apache ec2-user
                                       chown -R ec2-user:apache /var/www
                                       chmod 2775 /var/www
                                       find /var/www -type d -exec chmod 2775 {} \;
                                       find /var/www -type f -exec chmod 0664 {} \;
                                       echo "Created by AWS Boto3 SDK" >> /var/www/html/index.html
                                  ''',
                     'TagSpecifications': [{'ResourceType': self.name,
                                            'Tags': [{'Key': self.tag, 'Value': self.tagval}]
                                            }],
                     'LaunchTemplate': {}
                     }
        self.service = None
        self.client = boto3.client('ec2')
        self.compute = boto3.resource('ec2', self.zone)

    def update_group_ids(self, group_ids):
        self.data.update({'NetworkInterfaces': [{'Groups': group_ids}, ], 'SecurityGroupIds': group_ids, })

    def update_subnet_id(self, subnet_id):
        self.data.update({'NetworkInterfaces': [{'SubnetId': subnet_id}, ]})

    def update_ami_id(self, ami_id):
        self.data.update({'ImageId': ami_id})

    def update_instance_type(self, instance_type):
        self.data.update({'InstanceType': instance_type})

    def update_key_name(self, key_name):
        self.data.update({'KeyName': key_name})

    def update_max_count(self, max_count):
        self.data.update({'MaxCount': max_count})

    def update_min_count(self, min_count):
        self.data.update({'MinCount': min_count})

    def update_availability_zone(self, zone):
        self.data.update({'Placement': {'AvailabilityZone': zone}})

    def update_tag_specifications(self, service, tag_key, tag_value):
        self.data['TagSpecifications'].append({'ResourceType': service,
                                               'Tags': [{'Key': tag_key, 'Value': tag_value}, ]})

    @staticmethod
    def handle(error=None, reply=None, resource=None):
        """
        Exception Handler
        """
        bad = ('DependencyViolation', 'VpcLimitExceeded', 'UnauthorizedOperation', 'ParamValidationError',
               'AddressLimitExceeded',)
        try:
            if reply:
                if "NotFound" in reply['Error']['Code'] or "DryRunOperation" in reply['Error']['Code']:
                    return
                elif "InvalidParameterValue" in reply['Error']['Code']:
                    return
                elif reply['Error']['Code'] in bad:
                    print('Failed (%s)' % reply['Error']['Code'])
                    if resource == 'vpc':
                        return
                else:
                    print("Failed with %s" % error)
            elif type(error) == Exception:
                print("Failed with %s" % error.value)
            else:
                print("Failed with %s" % error)
        except AttributeError as err:
            print('Something went wrong %s %s' % (error, err))
        exit(1)


class LaunchTemplates(Compute):
    """
    LAUNCH TEMPLATES
    """

    def __init__(self, dry=False, name=super().tag, desc=super().tagval, subnet_id=None, group_ids=None,
                 zone=None, ami_id=None, instance_type=None, key_name=None):
        """
        Initialize and create Launch template
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.create_launch_template
        """
        try:
            super().__init__('launch-template')
            if group_ids:
                self.update_group_ids(group_ids)
            if subnet_id:
                self.update_subnet_id(subnet_id)
            if ami_id:
                self.update_ami_id(ami_id)
            if instance_type:
                self.update_instance_type(instance_type)
            if key_name:
                self.update_key_name(key_name)
            if zone:
                self.update_availability_zone(zone)
            self.reply = self.client.create_launch_template(LaunchTemplateName=name, VersionDescription=desc,
                                                            LaunchTemplateData=self.data, DryRun=dry)
            print('Creating launch_template %s' % ('(dry)' if dry else ''))
        except Exception as err:
            Compute.handle(err, self.reply)

    def delete(self, tid, tname, dry=False):
        """
        Delete launch_template
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.delete_launch_template
        """
        try:
            if tid:
                self.reply = self.client.delete_launch_template(LaunchTemplateId=tid, DryRun=dry)
            else:
                self.reply = self.client.delete_launch_template(LaunchTemplateName=tname, DryRun=dry)
            print('Delete launch_template %s %s' % ((tid if tid else ''), (tname if tname else ''))),
            return self.reply
        except Exception as err:
            Compute.handle(err, self.reply)

    def list(self, name=super().tag, values=[global_tag], dry=False):
        """
        Get EC2 launch_templates by searching filters
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.describe_launch_templates
        """
        try:
            self.reply = self.client.describe_launch_templates(Filters=[{'Name': name, 'Values': values}], DryRun=dry)
            return self.reply
        except Exception as err:
            Compute.handle(err, self.reply)


class Instances(Compute):
    """
    INSTANCES
    """

    def __init__(self, template_id, max_count=1, min_count=1, dry=False):
        """
        Initialize and create Instance from launch template
        """
        try:
            super().__init__('instance')
            self.reply = self.compute.create_instances(LaunchTemplate=template_id, MaxCount=max_count,
                                                       MinCount=min_count)
            print('Creating Instance %s' % ('(dry)' if dry else ''))
        except Exception as err:
            Compute.handle(err, self.reply)

    def delete(self, instances, dry=False):
        """
        Delete a ec2 instance
        """
        try:
            print('Terminating instance %s' % ('(dry)' if dry else ''))
            self.reply = self.compute.terminate(DryRun=dry)
            self.compute.wait_until_terminated(Filters=[{'Name': 'instance-id', 'Values': instances}], DryRun=dry)
            print('Terminated instance %s' % ('(dry)' if dry else ''))
            return self.reply
        except Exception as err:
            Compute.handle(err, self.reply)

    def list(self, name=super().tag, values=[global_tag], dry=False):
        """
        Get EC2 instances by searching for stuff
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.describe_instances
        """
        try:
            self.reply = self.client.describe_instances(Filters=[{'Name': name, 'Values': values}], DryRun=dry)
            return self.reply
        except Exception as err:
            Compute.handle(err, self.reply)


class Volumes(Compute):
    """
    VOLUMES
    """

    def __init__(self, zone, size, id=None, volume_type='default', dry=False):
        """
        Create Volume instance
        """
        try:
            super().__init__('volume')
            if id:
                self.reply = self.client.create_instances(AvailabilityZone=zone, SnapshotId=id,
                                                          Size=size, VolumeType=volume_type, DryRun=dry)
            else:
                self.reply = self.client.create_instances(AvailabilityZone=zone, Size=size,
                                                          VolumeType=volume_type, DryRun=dry)
            print('Creating Volume %s' % ('(dry)' if dry else ''))
        except Exception as err:
            Compute.handle(err, self.reply)

    def delete(self, volume_id, dry=False):
        """
        Delete volume instance
        """
        try:
            self.reply = self.client.delete_volume(VolumeId=volume_id, DryRun=dry)
            print('Deleting Volume %s %s' % (volume_id, ('(dry)' if dry else '')))
            return self.reply
        except Exception as err:
            Compute.handle(err, self.reply)

    def list(self, name=super().tag, values=[global_tag], dry=False):
        """
        Get Volumes
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.describe_volumes
        """
        try:
            self.reply = self.client.describe_volumes(Filters=[{'Name': name, 'Values': values}], DryRun=dry)
            return self.reply
        except Exception as err:
            Compute.handle(err, self.reply)


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
            self.reply = self.client.create_vpc(CidrBlock=cidr_ipv4, AmazonProvidedIpv6CidrBlock=auto_ipv6,
                                                InstanceTenancy=tenancy, DryRun=dry)
            print('Created vpc %s' % ('(dry)' if dry else ''))
        except Exception as err:
            Compute.handle(err, self.reply)

    def delete(self, vpc_id, dry=False):
        """
        Delete virtual priv cloud.
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.delete_vpc
        """
        try:
            self.reply = self.client.delete_vpc(VpcId=vpc_id, DryRun=dry)
            print('Deleted %s %s' % (vpc_id, ('(dry)' if dry else '')))
            return self.reply
        except Exception as err:
            Compute.handle(err, self.reply, 'vpc')
    
    def list(self, name=super().tag, values=[global_tag,], dry=False):
        """
        Get VPC(s) by filter
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.describe_vpcs
        """
        try:
            self.reply = self.client.describe_vpcs(Filters=[{'Name': name, 'Values': values}], DryRun=dry)
            return self.reply
        except Exception as err:
            Compute.handle(err, self.reply)
    

class VpcEndPoint(Compute):
    """
    VPC ENDPOINTS
    """

    def __init__(self, vpc_id, rtt_ids, sn_ids, sg_ids, ideal, svc='com.amazonaws.' + super().zone + '.ec2', dry=False):
        """
        Initialize and create VpcEndPoint
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.create_vpc_endpoint
        """
        try:
            super().__init__('vpc-endpoint')
            self.reply = self.client.create_vpc_endpoint(VpcEndpointType=ideal, VpcId=vpc_id, ServiceName=svc,
                                                         RouteTableIds=rtt_ids, SubnetIds=sn_ids,
                                                         SecurityGroupIds=sg_ids, Dryrun=dry)
            print('Created vpc-endpoint  %s' % ('(dry)' if dry else ''))
        except Exception as err:
            Compute.handle(err, self.reply)

    def delete(self, vpc_endpoint_id, dry=False):
        """
        Delete a virtual priv cloud endpoint
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.delete_vpc_endpoints
        """
        try:
            self.reply = self.client.delete_vpc_endpoints(VpcEndpointIds=[vpc_endpoint_id], DryRun=dry)
            print('Deleted %s %s' % (vpc_endpoint_id, ('(dry)' if dry else '')))
            return self.reply
        except Exception as err:
            Compute.handle(err, self.reply)
    
    def list(self, name=super().tag, values=[global_tag,], dry=False):
        """
        Get VPC(s) by endpoints filter
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.describe_vpc_endpoints
        """
        try:
            self.reply = self.client.describe_vpc_endpoints(Filters=[{'Name': name, 'Values': values}], DryRun=dry)
            return self.reply
        except Exception as err:
            Compute.handle(err, self.reply)
    
    
class VpcPeeringConnection(Compute):
    """
    VPC PEERING CONNECTION
    """

    def __init__(self, peer_vpc_id, vpc_id, zone, dry=False):
        """
        Initialize and create VpcPeeringConnection
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.create_vpc_peering_connection
        """
        try:
            super().__init__('vpc-peering-connection')
            self.reply = self.client.create_vpc_peering_connection(PeerVpcId=peer_vpc_id, VpcId=vpc_id,
                                                                   PeerRegion=zone, Dryrun=dry)
            print('Created vpc_peering_connection  %s' % ('(dry)' if dry else ''))
        except Exception as err:
            Compute.handle(err, self.reply)

    def delete(self, vpc_peering_connection_id, dry=False):
        """
        Delete a virtual priv cloud peering_connection
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.delete_vpc_peering_connections
        """
        try:
            self.reply = self.client.delete_vpc_peering_connections(VpcPeeringConnectionId=vpc_peering_connection_id,
                                                                    DryRun=dry)
            print('Deleted %s %s' % (vpc_peering_connection_id, ('(dry)' if dry else '')))
            return self.reply
        except Exception as err:
            Compute.handle(err, self.reply)
    
    def list(self, name=super().tag, values=[global_tag,], dry=False):
        """-
        Get VPC(s) by peering_connections filter
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.describe_vpc_peering_connections
        """
        try:
            self.reply = self.client.describe_vpc_peering_connections(Filters=[{'Name': name, 'Values': values}],
                                                                      DryRun=dry)
            return self.reply
        except Exception as err:
            Compute.handle(err, self.reply)
    
    
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
            self.reply = self.client.create_network_interface(Description=desc, Groups=groups, SubnetId=subnet_id,
                                                              PrivateIpAddress=pri_ip, PrivateIpAddresses=pri_ips,
                                                              DryRun=dry)
            print('Created network_interface for %s %s' % (pri_ip, ('(dry)' if dry else '')))
        except Exception as err:
            Compute.handle(err, self.reply)

    def delete(self, if_id, dry=False):
        """
        Delete a network_interface.
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.delete_network_interface
        """
        try:
            self.reply = self.client.delete_network_interface(NetworkInterfaceId=if_id, DryRun=dry)
            print('Deleted %s %s' % (id, ('(dry)' if dry else '')))
            return self.reply
        except Exception as err:
            Compute.handle(err, self.reply)
    
    def list(self, name=super().tag, values=[global_tag,], dry=False):
        """
        Get Network interfaces by tag name/value or maybe by array of ids.
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.describe_network_interfaces
        """
        try:
            self.reply = self.client.describe_network_interfaces(Filters=[{'Name': name, 'Values': values}], DryRun=dry)
            return self.reply
        except Exception as err:
            Compute.handle(err, self.reply)


class SubNet(Compute):
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
            self.reply = self.client.create_subnet(CidrBlock=self.cidr_block, VpcId=vpc_id, DryRun=dry)
            print('Created subnet for %s %s' % (self.cidr_block, ('(dry)' if dry else '')))
        except Exception as err:
            Compute.handle(err, self.reply)

    def modify_attr(self, sn_id, value, dry=False):
        """
        Modify a subnet.
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.modify_subnet_attribute
        """
        try:
            self.reply = self.client.modify_subnet_attribute(SubnetId=sn_id, MapPublicIpOnLaunch={'Value': value})
            print('Map %s public-ip-on-launch %s %s' % (sn_id, value, ('(dry)' if dry else '')))
            return self.reply
        except Exception as err:
            Compute.handle(err, self.reply)
        return None
    
    def delete(self, sn_id, dry=False):
        """
        Delete a subnet.
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.delete_subnet
        """
        try:
            self.reply = self.client.delete_subnet(SubnetId=sn_id, DryRun=dry)
            print('Deleted %s %s' % (sn_id, ('(dry)' if dry else '')))
            return self.reply
        except Exception as err:
            Compute.handle(err, self.reply)
    
    def list(self, name=super().tag, values=[global_tag,], dry=False):
        """
        Get VPC(s) by tag (note: create_tags not working via client api, use cidr or object_id instead )
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.describe_subnets
        """
        try:
            self.reply = self.client.describe_subnets(Filters=[{'Name': name, 'Values': values}], DryRun=dry)
            return self.reply
        except Exception as err:
            Compute.handle(err, self.reply)
    

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
            self.reply = self.client.create_security_group(Description=desc, GroupName=name, VpcId=vpc_id, DryRun=dry)
            print('Created security group %s' % ('(dry)' if dry else ''))
        except Exception as err:
            Compute.handle(err, self.reply)
    
    def delete(self, sg_id, dry=False):
        """
        Delete a security group.
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.delete_security_group
        """
        try:
            self.reply = self.client.delete_security_group(GroupId=sg_id, DryRun=dry)
            print('Deleted %s %s' % (sg_id, ('(dry)' if dry else '')))
            return self.reply
        except Exception as err:
            Compute.handle(err, self.reply)
    
    def list(self, name=super().tag, values=[global_tag,], dry=False):
        """
        Get Security Groups by searching for VPC Id.
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.describe_security_groups
        """
        try:
            self.reply = self.client.describe_security_groups(Filters=[{'Name': name, 'Values': values}], DryRun=dry)
            return self.reply
        except Exception as err:
            Compute.handle(err, self.reply)
    
    def list_refs(self, group_ids, dry=False):
        """
        Get Security Groups references
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.describe_security_group_references
        """
        try:
            self.reply = self.client.describe_security_group_references(GroupId=group_ids, DryRun=dry)
            return self.reply
        except Exception as err:
            Compute.handle(err, self.reply)
    
    def auth_egress(self, from_port, to_port, proto, sg_id, ipv4, ipv6=[{'CidrIpv6', '::/0'}], dry=False):
        """
        Adds egress rules to a security group.
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.authorize_security_group_egress
        """
        try:
            self.reply = self.client.authorize_security_group_egress(IpPermissions=[{'FromPort': from_port,
                                                                                     'ToPort': to_port,
                                                                                     'IpProtocol': proto,
                                                                                     'IpRanges': ipv4,
                                                                                     'Ipv6Ranges': ipv6}],
                                                                     GroupId=sg_id, DryRun=dry)
            print('Authorized sg egress %s %s' % (sg_id, ('(dry)' if dry else '')))
            return self.reply
        except Exception as err:
            Compute.handle(err, self.reply)
    
    def auth_ingress(self, from_port, to_port, proto, sg_id, ipv4, ipv6=[{'CidrIpv6', '::/0'}], dry=False):
        """
        Adds ingress rules to a security group.
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.authorize_security_group_ingress
        """
        try:
            self.reply = self.client.authorize_security_group_ingress(IpPermissions=[{'FromPort': from_port,
                                                                                      'ToPort': to_port,
                                                                                      'IpProtocol': proto,
                                                                                      'IpRanges': ipv4,
                                                                                      'Ipv6Ranges': ipv6}],
                                                                      GroupId=sg_id, DryRun=dry)
            print('Authorized sg ingress %s %s' % (sg_id, ('(dry)' if dry else '')))
            return self.reply
        except Exception as err:
            Compute.handle(err, self.reply)
    
    def revoke_egress(self, from_port, to_port, proto, sg_id, ipv4, ipv6=[{'CidrIpv6', '::/0'}], dry=False):
        """
        Revoke egress rules from a security group.
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.revoke_security_group_egress
        """
        try:
            self.reply = self.client.revoke_security_group_egress(IpPermissions=[{'FromPort': from_port,
                                                                                  'ToPort': to_port,
                                                                                  'IpProtocol': proto,
                                                                                  'IpRanges': ipv4,
                                                                                  'Ipv6Ranges': ipv6}],
                                                                  GroupId=sg_id, DryRun=dry)
            print('Revoked sg egress %s %s' % (sg_id, ('(dry)' if dry else '')))
            return self.reply
        except Exception as err:
            Compute.handle(err, self.reply)
    
    def revoke_ingress(self, from_port, to_port, proto, sg_id, ipv4, ipv6=[{'CidrIpv6', '::/0'}], dry=False):
        """
        Remove ingress rules to a security group.
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.revoke_security_group_ingress
        """
        try:
            self.reply = self.client.revoke_security_group_ingress(IpPermissions=[{'FromPort': from_port,
                                                                                   'ToPort': to_port,
                                                                                   'IpProtocol': proto,
                                                                                   'IpRanges': ipv4,
                                                                                   'Ipv6Ranges': ipv6}],
                                                                   GroupId=sg_id, DryRun=dry)
            print('Revoked sg ingress from %s %s' % (sg_id, ('(dry)' if dry else '')))
            return self.reply
        except Exception as err:
            Compute.handle(err, self.reply)
    

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
            self.reply = self.client.create_nat_gateway(AllocationId=alloc_id, SubnetId=subnet_id)
            print('Created nat gateway for subnet %s %s' % (subnet_id, ('(dry)' if dry else '')))
        except Exception as err:
            Compute.handle(err, self.reply)
    
    def delete(self, nat_gw_id, dry=False):
        """
        Delete a nat gateway.
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.delete_nat_gateway
        """
        try:
            self.reply = self.client.delete_nat_gateway(NatGatewayId=nat_gw_id)
            print('Deleted nat gateway for subnet %s %s' % (nat_gw_id, ('(dry)' if dry else '')))
            return self.reply
        except Exception as err:
            Compute.handle(err, self.reply)
    
    def list(self, name=super().tag, values=[global_tag,], dry=False):
        """
        Get nat gateways by searching for vpc
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.describe_nat_gateways
        """
        try:
            self.reply = self.client.describe_nat_gateways(Filters=[{'Name': name, 'Values': values}])
            return self.reply
        except Exception as err:
            Compute.handle(err, self.reply)


class RouteTable(Compute):
    """
    ROUTE TABLE
    """

    def __init__(self, version, cidr, gateway_id, route_table_id, dry=False):
        """
        Initialize and Create Route Table
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.create_route_table
        """
        try:
            super().__init__('route-table')
            if version == 'ipv6':
                self.reply = self.client.create_route(DestinationIpv6CidrBlock=cidr, GatewayId=gateway_id,
                                                      RouteTableId=route_table_id, DryRun=dry)
            else:
                self.reply = self.client.create_route(DestinationCidrBlock=cidr, GatewayId=gateway_id,
                                                      RouteTableId=route_table_id, DryRun=dry)
            print('Created %s route for %s %s' % (version, cidr, ('(dry)' if dry else '')))
        except Exception as err:
            Compute.handle(err, self.reply)

    def delete(self, route_table_id, dry=False):
        """
        Delete a route table.
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.delete_route_table
        """
        try:
            self.reply = self.client.delete_route_table(RouteTableId=route_table_id, DryRun=dry)
            print('Deleted %s %s' % (route_table_id, ('(dry)' if dry else '')))
            return self.reply
        except Exception as err:
            Compute.handle(err, self.reply)

    def delete_route(self, cidr, route_table_id, dry=False):
        """
        Create a route in route table
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.delete_route
        """
        try:
            self.reply = self.client.delete_route(DestinationCidrBlock=cidr, RouteTableId=route_table_id, DryRun=dry)
            print('Deleted route for %s %s' % (cidr, ('(dry)' if dry else '')))
            return self.reply
        except Exception as err:
            Compute.handle(err, self.reply)
    
    def associate(self, route_table_id, subnet_id, dry=False):
        """
        Associate route table with subnet
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.associate_route_table
        """
        try:
            self.reply = self.client.associate_route_table(RouteTableId=route_table_id, SubnetId=subnet_id, DryRun=dry)
            print('Associated route table %s to %s %s' % (route_table_id, subnet_id, ('(dry)' if dry else '')))
            return self.reply
        except Exception as err:
            Compute.handle(err, self.reply)
    
    def disassociate(self, association_id, dry=False):
        """
        Disassociate a route table.
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.disassociate_route_table
        """
        try:
            self.reply = self.client.disassociate_route_table(AssociationId=association_id, DryRun=dry)
            print('Disassociated %s %s' % (association_id, ('(dry)' if dry else '')))
            return self.reply
        except Exception as err:
            Compute.handle(err, self.reply)
    
    def list(self, name=super().tag, values=[global_tag], name2=None, values2=[], dry=False):
        """
        Get route tables by searching for vpc
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.describe_route_tables
        """
        try:
            if name2 and values2:
                self.reply = self.client.describe_route_tables(Filters=[{'Name': name, 'Values': values},
                                                                        {'Name': name2, 'Values': values2}], DryRun=dry)
            else:
                self.reply = self.client.describe_route_tables(Filters=[{'Name': name, 'Values': values}], DryRun=dry)
            return self.reply
        except Exception as err:
            Compute.handle(err, self.reply)


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
            self.reply = self.client.create_network_acl(VpcId=vpc_id, DryRun=dry)
            print('Created network acl for %s %s' % (vpc_id, ('(dry)' if dry else '')))
        except Exception as err:
            Compute.handle(err, self.reply)

    def delete(self, network_acl_id, dry=False):
        """
        Delete a network acl.
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.delete_network_acl
        """
        try:
            self.reply = self.client.delete_network_acl(NetworkAclId=network_acl_id, DryRun=dry)
            print('Deleted %s %s' % (network_acl_id, ('(dry)' if dry else '')))
            return self.reply
        except Exception as err:
            Compute.handle(err, self.reply)

    def replace_association(self, network_acl_id, association_id, dry=False):
        """
        Replace network acl association
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.replace_network_acl_association
        """
        try:
            self.reply = self.client.replace_network_acl_association(AssociationId=association_id,
                                                                     NetworkAclId=network_acl_id, DryRun=dry)
            print('Replaced network association %s %s' % (network_acl_id, ('(dry)' if dry else '')))
            return self.reply
        except Exception as err:
            Compute.handle(err, self.reply)
    
    def create_entry(self, network_acl_id, num, action, cidr, from_port, to_port, proto='6', egress=False, dry=False):
        """
        Create network acl entry
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.create_network_acl_entry
        """
        try:
            if from_port and to_port:
                self.reply = self.client.create_network_acl_entry(CidrBlock=cidr, Egress=egress, NetworkAclId=id,
                                                                  Protocol=proto, RuleAction=action, RuleNumber=num,
                                                                  DryRun=dry)
            else:
                self.reply = self.client.create_network_acl_entry(CidrBlock=cidr, Egress=egress, NetworkAclId=id,
                                                                  PortRange={'From': from_port, 'To': to_port},
                                                                  Protocol=proto, RuleAction=action, RuleNumber=num,
                                                                  DryRun=dry)
            print('Created network acl entry for %s %s' % (network_acl_id, '(dry)' if dry else ''))
            return self.reply
        except Exception as err:
            Compute.handle(err, self.reply)
    
    def delete_entry(self, network_acl_id, num=100, egress=False, dry=False):
        """
        Delete a network acl entry
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.delete_network_acl_entry
        """
        try:
            self.reply = self.client.delete_network_acl_entry(Egress=egress, NetworkAclId=network_acl_id,
                                                              RuleNumber=num, DryRun=dry)
            print('Deleted %s %s' % (network_acl_id, ('(dry)' if dry else '')))
            return self.reply
        except Exception as err:
            Compute.handle(err, self.reply)
    
    def list(self, name=super().tag, values=[global_tag,], dry=False):
        """
        Get network acls by searching for stuff
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.describe_network_acls
        """
        try:
            self.reply = self.client.describe_network_acls(Filters=[{'Name': name, 'Values':values}], DryRun=dry)
            return self.reply
        except Exception as err:
            Compute.handle(err, self.reply)


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
            self.reply = self.client.allocate_address(Domain=domain, DryRun=dry)
            print('Created elastic ip for %s %s' % (domain, ('(dry)' if dry else '')))
        except Exception as err:
            Compute.handle(err, self.reply)

    @staticmethod
    def associate(self, alloc_id, instance_id, dry=False):
        """
        Associate elastic ip with ec2_instance
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.associate_address
        """
        try:
            self.reply = self.client.associate_address(AllocationId=alloc_id, InstanceId=instance_id, DryRun=dry)
            print('Associated elastic ip with %s %s' % (instance_id, '(dry)' if dry else ''))
            return self.reply
        except Exception as err:
            Compute.handle(err, self.reply)
    
    @staticmethod
    def disassociate(self, association_id, dry=False):
        """
        Disassociate elastic ip with ec2_instance
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.disassociate_address
        """
        try:
            self.reply = self.client.disassociate_address(AssociationId=association_id, DryRun=dry)
            print('Disassociated elastic ip %s %s' % (association_id, '(dry)' if dry else ''))
            return self.reply
        except Exception as err:
            Compute.handle(err, self.reply)
    
    def release(self, alloc_id, public_ip='', dry=False):
        """
        Delete a elastic ip.
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.release_address
        """
        try:
            self.reply = self.client.release_address(AllocationId=alloc_id, DryRun=dry)
            print('Released %s %s %s' % (alloc_id, public_ip, ('(dry)' if dry else '')))
            return self.reply
        except Exception as err:
            Compute.handle(err, self.reply)
    
    def list(self, name=super().tag, values=[global_tag,], dry=False):
        """
        Get Elastic IPs
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.describe_addresses
        """
        try:
            self.reply = self.client.describe_addresses(Filters=[{'Name': name, 'Values': values}], DryRun=dry)
            return self.reply
        except Exception as err:
            Compute.handle(err, self.reply)
    
    
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
            self.reply = self.client.create_internet_gateway(DryRun=dry)
            print('Created internet gateway %s' % ('(dry)' if dry else ''))
        except Exception as err:
            Compute.handle(err, self.reply)
    
    def delete(self, gateway_id, dry=False):
        """
        Delete a internet gateway.
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.delete_internet_gateway
        """
        try:
            self.reply = self.client.delete_internet_gateway(InternetGatewayId=gateway_id, DryRun=dry)
            print('Deleted internet gateway %s %s' % (gateway_id, ('(dry)' if dry else '')))
            return self.reply
        except Exception as err:
            Compute.handle(err, self.reply)
    
    def list(self, name=super().tag, values=[global_tag,], dry=False):
        """
        Get internet gateways IPs
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.describe_internet_gateways
        """
        try:
            self.reply = self.client.describe_internet_gateways(Filters=[{'Name': name, 'Values': values}], DryRun=dry)
            return self.reply
        except Exception as err:
            Compute.handle(err, self.reply)
    
    def attach(self, gateway_id, vpc_id, dry=False):
        """
        Attaches an internet gateway to a VPC
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.attach_internet_gateway
        """
        try:
            self.reply = self.client.attach_internet_gateway(InternetGatewayId=gateway_id, VpcId=vpc_id, DryRun=dry)
            print('Attached %s to %s %s' % (gateway_id, vpc_id, ('(dry)' if dry else '' )))
            return self.reply
        except Exception as err:
            Compute.handle(err, self.reply)
    
    def detach(self, gateway_id, vpc_id, dry=False):
        """
        Attaches an internet gateway to a VPC
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.detach_internet_gateway
        """
        try:
            self.reply = self.client.detach_internet_gateway(InternetGatewayId=gateway_id, VpcId=vpc_id, DryRun=dry)
            print('Detached %s from %s %s' % (gateway_id, vpc_id, ('(dry)' if dry else '' )))
            return self.reply
        except Exception as err:
            Compute.handle(err, self.reply)

