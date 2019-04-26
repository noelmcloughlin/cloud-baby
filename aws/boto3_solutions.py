# Copyright 2019 noelmcloughlin
#############################################

import sys
import boto3
import time
import getopt
import string
import random

try:
    sys.path.append('./aws')
    import aws.boto3_client as client
except ImportError:
    sys.path.append('../aws')
    import aws.boto3_client as client

_DEFS = {'choices': ('start', 'clean', 'cleanstart'),
         'catalog': ('sns', 'vpc', 'elb', 'autoscaling', 'ec2', 'sec'),
         'cidr4_vpc': ['10.0.0.0/24'],
         'cidr4': ['10.0.0.0/25', '10.0.0.128/25'],
         'hibernate': True,
         'ami_id': 'ami-0fad7378adf284ce0',
         'ami_type': 't2.micro',
         'ip6': False,
         'key_pair': 'ec2_user',
         'max_count': 2,
         'name': 'boto3-client-sdk',
         'region': 'eu-west-1',
         'peer_region': 'eu-west-2',
         'tag': 'boto3-client-sdk',
         'tenancy': 'default',
         'zones': ('eu-west-1a', 'eu-west-1b')}


class Solution:
    """
    A SOLUTION
    """
    def __init__(self, solution=None):
        """
        Initialise site for Solution
        """
        try:
            self.choices = solution.choices
        except AttributeError:
            self.choices = _DEFS['choices']

        try:
            self.debug = solution.debug
        except AttributeError:
            self.debug = False

        try:
            self.dry = solution.dry
        except AttributeError:
            self.dry = False

        try:
            self.name = solution.name
        except AttributeError:
            self.name = _DEFS['name']

        try:
            self.scope = solution.scope
        except AttributeError:
            self.scope = None

        self.token = ''.join(random.SystemRandom().choice(string.ascii_uppercase + string.digits) for _ in range(63))

    @staticmethod
    def console(message=None):
        if message:
            print('\n' + message)

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
    def fatal(error=None, message='Something bad happened'):
        """
        Fatal Exception Handler
        :return:
        """
        print("%s %s" % (message, (error or '!!')))
        exit(1)


class CloudSolution(Solution):
    """
    VPC
    """
    def __init__(self, solution=None):
        """
        Initialise the VPC
        :return: object
        """
        super().__init__(solution)
        try:
            self.vpc_id = solution.vpc_id
        except AttributeError:
            self.vpc_id = None

        try:
            self.vpc_ids = solution.vpc_ids
        except AttributeError:
            self.vpc_ids = []

        try:
            self.cidr4_vpc = solution.cidr4_vpc
        except AttributeError:
            self.cidr4_vpc = _DEFS['cidr4_vpc']

        try:
            self.cidr4 = solution.cidr4
        except AttributeError:
            self.cidr4 = _DEFS['cidr4']

        try:
            self.cidr6_vpc = solution.cidr6_vpc
        except AttributeError:
            self.cidr6_vpc = []

        try:
            self.cidr6 = solution.cidr6
        except AttributeError:
            self.cidr6 = []

        try:
            self.eip_id = solution.eip_id
        except AttributeError:
            self.eip_id = None

        try:
            self.eip_ids = solution.eip_ids
        except AttributeError:
            self.eip_ids = []

        try:
            self.igw_id = solution.igw_id
        except AttributeError:
            self.igw_id = None

        try:
            self.igw_ids = solution.igw_ids
        except AttributeError:
            self.igw_ids = []

        try:
            self.ip4 = solution.ip4
        except AttributeError:
            self.ip4 = True

        try:
            self.ip6 = solution.ip6
        except AttributeError:
            self.ip6 = _DEFS['ip6']

        try:
            self.ami_id = solution.ami_id
        except AttributeError:
            self.ami_id = _DEFS['ami_id']

        try:
            self.ami_type = solution.ami_type
        except AttributeError:
            self.ami_type = _DEFS['ami_type']

        try:
            self.instance_id = solution.instance_id
        except AttributeError:
            self.instance_id = None

        try:
            self.instance_ids = solution.instance_ids
        except AttributeError:
            self.instance_ids = []

        try:
            self.name = solution.name
        except AttributeError:
            self.name = _DEFS['name']

        try:
            self.nat_gw_id = solution.nat_gw_id
        except AttributeError:
            self.nat_gw_id = None

        try:
            self.nat_gw_ids = solution.nat_gw_ids
        except AttributeError:
            self.nat_gw_ids = []

        try:
            self.network_acls = solution.network_acls
        except AttributeError:
            self.network_acls = (self.name,)

        try:
            self.peer_vpc_id = solution.vpc_id
        except AttributeError:
            self.peer_vpc_id = None

        try:
            self.peer_vpc_ids = solution.vpc_ids
        except AttributeError:
            self.peer_vpc_ids = []

        try:
            self.peer_region = solution.peer_region
        except AttributeError:
            self.peer_region = _DEFS['peer_region']

        try:
            self.private_ip = solution.private_ip
        except AttributeError:
            self.private_ip = None

        try:
            self.private_ips = solution.private_ips
        except AttributeError:
            self.private_ips = []

        try:
            self.region = solution.region
        except AttributeError:
            self.region = _DEFS['region']

        try:
            self.rtt_id = solution.rtt_id
        except AttributeError:
            self.rtt_id = None

        try:
            self.rtt_ids = solution.rtt_ids
        except AttributeError:
            self.rtt_ids = []

        try:
            self.tag = solution.name
        except AttributeError:
            self.tag = self.name

        try:
            self.tenancy = solution.tenancy
        except AttributeError:
            self.tenancy = _DEFS['tenancy']

        try:
            self.topic_arn = solution.topic_arn
        except AttributeError:
            self.topic_arn = self.name

        try:
            self.zone = solution.zone
        except AttributeError:
            self.zone = None

        try:
            self.zones = solution.zones
        except AttributeError:
            self.zones = _DEFS['zones']

        try:
            self.user_data = solution.user_data
        except AttributeError:
            self.user_data = b'''
#!/bin/bash
yum update -y
yum install -y httpd
systemctl enable httpd && systemctl start httpd
usermod -a -G apache ec2_user
chown -R ec2_user:apache /var/www
chmod 2775 /var/www
find /var/www -type d -exec chmod 2775 {} \;
find /var/www -type f -exec chmod 0664 {} \;
echo "Create by AWS Boto3 SDK (hostname: $(hostname))" >> /var/www/html/index.html
'''


class CloudService(CloudSolution):
    """
    A CLOUD SERVICE
    """
    def __init__(self, solution=None):
        """
        Initialise cloud service parameters
        """
        super().__init__(solution)
        try:
            self.acl_id = solution.acl_id
        except AttributeError:
            self.acl_id = None

        try:
            self.acl_ids = solution.acl_ids
        except AttributeError:
            self.acl_ids = []

        try:
            self.any_ip4 = solution.any_ip4
        except AttributeError:
            self.any_ip4 = '0.0.0.0/0'

        try:
            self.any_ip6 = solution.any_ip4
        except AttributeError:
            self.any_ip6 = '::/0'

        try:
            self.auto_ip6 = solution.auto_ip6
        except AttributeError:
            self.auto_ip6 = True

        try:
            self.ebs_optimized = solution.ebs_optimized
        except AttributeError:
            self.ebs_optimized = False

        try:
            self.hibernate = solution.hibernate
        except AttributeError:
            self.hibernate = _DEFS['hibernate']

        try:
            self.key_pair = solution.key_pair
        except AttributeError:
            self.key_pair = _DEFS['key_pair']

        try:
            self.min_count = solution.min_count
        except AttributeError:
            self.min_count = 1

        try:
            self.max_count = solution.max_count
        except AttributeError:
            self.max_count = _DEFS['max_count']

        try:
            self.monitor = solution.monitor
        except AttributeError:
            self.monitor = False

        try:
            self.ports = solution.ports
        except AttributeError:
            self.ports = [80]

        try:
            self.protocols = solution.protocols
        except AttributeError:
            self.protocols = ['HTTP']

        try:
            self.public_ip = solution.public_ip
        except AttributeError:
            self.public_ip = True

        try:
            self.subnet_id = solution.subnet_id
        except AttributeError:
            self.subnet_id = None

        try:
            self.subnet_ids = solution.subnet_ids
        except AttributeError:
            self.subnet_ids = []

        try:
            self.template_id = solution.template_id
        except AttributeError:
            self.template_id = None

        try:
            self.template_ids = solution.template_ids
        except AttributeError:
            self.template_ids = []


class SecureCloudService(CloudService):
    """
    SECURITY
    """
    def __init__(self, solution=None):
        """
        Create a Secure Cloud Service
        """
        super().__init__(solution)
        try:
            self.sg_id = solution.sg_id
        except AttributeError:
            self.sg_id = None

        try:
            self.sg_ids = solution.sg_ids
        except AttributeError:
            self.sg_ids = []

        self.client = boto3.client('ec2')
        self.compute = boto3.resource('ec2')


class ScalableCloudService(SecureCloudService):
    """
    SCALABILITY
    """
    def __init__(self, solution=None):
        """
        Create Service Availability Infrastructure
        :param solution:
        """
        super().__init__(solution)

        # ELBv2
        try:
            self.lb_arn = solution.lb_arn
        except AttributeError:
            self.lb_arn = None

        try:
            self.lb_arns = solution.lb_arns
        except AttributeError:
            self.lb_arns = []

        try:
            self.lb_choices = solution.lb_choices
        except AttributeError:
            self.lb_choices = ['forward', 'forward', 'forward', 'forward', 'forward', 'forward']

        try:
            self.lb_listener_arn = solution.lb_listener_arn
        except AttributeError:
            self.lb_listener_arn = None

        try:
            self.lb_listener_arns = solution.lb_listener_arns
        except AttributeError:
            self.lb_listener_arns = []

        try:
            self.ip_version = solution.ip_version
        except AttributeError:
            self.ip_version = 'ipv4'

        try:
            self.lb_target_group_arn = solution.lb_target_group_arn
        except AttributeError:
            self.lb_target_group_arn = self.name

        try:
            self.lb_target_group_arns = solution.lb_target_group_arns
        except AttributeError:
            self.lb_target_group_arns = []

        try:
            self.lb_target_group_type = solution.lb_target_group_type
        except AttributeError:
            self.lb_target_group_type = 'instance'

        try:
            self.lb_type = solution.lb_type
        except AttributeError:
            self.lb_type = 'application'

        try:
            self.scheme = solution.scheme
        except AttributeError:
            self.scheme = 'internet-facing'

        # ASG
        try:
            self.asg_name = solution.asg_name
        except AttributeError:
            self.asg_name = self.name

        try:
            self.desired_capacity = solution.desired_capacity
        except AttributeError:
            self.desired_capacity = self.max_count

        try:
            self.hc_type = solution.hc_type
        except AttributeError:
            self.hc_type = 'EC2'

        try:
            self.resource = solution.resource
        except AttributeError:
            self.resource = 'auto-scaling-group'

        try:
            self.notice_types = solution.notice_types
        except AttributeError:
            self.notice_types = ['autoscaling:EC2_INSTANCE_LAUNCH',
                                 'autoscaling:EC2_INSTANCE_LAUNCH_ERROR',
                                 'autoscaling:EC2_INSTANCE_TERMINATE',
                                 'autoscaling:EC2_INSTANCE_TERMINATE_ERROR']

        try:
            self.policy_type = solution.policy_type
        except AttributeError:
            self.policy_type = 'TargetTrackingScaling'

        try:
            self.est_warmup = solution.est_warmup
        except AttributeError:
            self.est_warmup = 90

        try:
            self.metric = solution.metric
        except AttributeError:
            self.metric = 'ASGAverageCPUUtilization'

        try:
            self.metric_value = solution.metric_value
        except AttributeError:
            self.metric_value = 50

        try:
            self.force_delete = solution.force_delete
        except AttributeError:
            self.force_delete = True

        self.autoscale = boto3.client('autoscaling')

######################
# AWS CLOUD SOLUTION
######################


class AwsSolution(SecureCloudService):
    """
    AWS SOLUTION
    """
    def __init__(self, argv):
        """
        Initialise
        :param argv: Command line arguments
        :return: object
        """
        super().__init__()
        self.catalog = _DEFS['catalog']
        self.choices = _DEFS['choices']
        self.scope = 'vpc-sec-sns-ec2-two'
        self.name = _DEFS['name']

        opts = None
        try:
            opts, args = getopt.getopt(argv, "a:c:dhi:k:m:n:r:s:t:v:w:6",
                                       ["choice=", "cidr4=", "debug", "help", "image=", "image-type=", "keypair=",
                                        "maxcount=", "name=", "region=", "sleep=", "tag=", "vpc4", "wanted=", "ip6"])
            if not opts:
                self.usage()
        except getopt.GetoptError as e:
            Solution.fatal(e)

        try:
            for opt, arg in opts:

                if opt in ("-a", "--choice",):
                    self.choice = arg.lower()
                    if self.choice not in self.choices:
                        self.usage()

                elif opt in ("-c", "--cidr4"):
                    self.cidr4 = arg

                elif opt in ("-d", "--debug"):
                    self.debug = True
                    import logging
                    log = logging.getLogger('test')
                    log.warning('warn')
                    log.debug('debug')
                    logging.basicConfig(level=logging.DEBUG)

                elif opt in ("-h", "--help"):
                    self.usage()

                elif opt in ("-i", "--image"):
                    self.ami_id = arg

                elif opt in ("-k", "--key-pair"):
                    self.key_pair = arg

                elif opt in ("-m", "--max-count"):
                    self.max_count = arg

                elif opt in ("-n", "--name"):
                    self.name = arg

                elif opt in ("-r", "--region"):
                    self.region = arg

                elif opt in ("-w", "--wanted",):
                    self.scope = arg.lower()
                    for service in self.scope.split('-'):
                        if service not in _DEFS['catalog']:
                            print('Unknown service %s' % service)
                            self.usage()

                elif opt in ("-s", "--sleep"):
                    self.hibernate = True

                elif opt in ("-t", "--instance-type"):
                    self.ami_type = arg

                elif opt in ("-v", "--vpc4"):
                    self.cidr4_vpc = arg

                elif opt in ("-6", "--ip6"):
                    self.ip6 = True

                else:
                    self.usage()
        except getopt.GetoptError as e:
            Solution.fatal(e)

    def usage(self):
        """
        Usage
        """
        print("""
    Create, configure, and manage Amazon Web Services (AWS) across multiple Availability zones.
    The currently available features are AutoScaling, ELB, VPC, and EC2 services.

    ACTIONS
      -a --choice      %s | %s | %s ]        (default: help)
    [ -w --wanted      %s %s %s %s %s %s ]   (default: vpc-sec-ec2)""" % (_DEFS['choices'][0],
                                                                          _DEFS['choices'][1],
                                                                          _DEFS['choices'][2],
                                                                          _DEFS['catalog'][0],
                                                                          _DEFS['catalog'][1],
                                                                          _DEFS['catalog'][2],
                                                                          _DEFS['catalog'][3],
                                                                          _DEFS['catalog'][4],
                                                                          _DEFS['catalog'][5]))
        print("""
    ARGUMENTS
        [ -c --cidr4       <value> ]    IPv4 Child Cidrs   (default: %s)""" % _DEFS['cidr4'])
        print("""        [ -i --image       <value> ]    Image ID           (default: %s)""" % _DEFS['ami_id'])
        print("""        [ -y --image-type  <value> ]    Instance Type      (default: %s)""" % _DEFS['ami_type'])
        print("""        [ -k --keypair     <value> ]    Key Pair name      (default: %s)""" % _DEFS['key_pair'])
        print("""        [ -m --maxcount    <value> ]    Max instances      (default: %s)""" % _DEFS['max_count'])
        print("""        [ -n --name        <value> ]    Name / Tag Key     (default: %s)""" % _DEFS['name'])
        print("""        [ -r --region      <value> ]    Cloud Region       (default: %s)""" % _DEFS['region'])
        print("""        [ -s --sleep       <Boolean> ]  Hibernate          (default: %s)""" % _DEFS['hibernate'])
        print("""        [ -t --tag         <value> ]    Tag value          (default: %s)""" % _DEFS['tag'])
        print("""        [ -i --vpc4        <value> ]    IPv4 Parent Cidr   (default: %s)""" % _DEFS['cidr4_vpc'])
        print("""
    FLAGS
        [ -6 --ip6 ]                    Use IpV6           (default: %s)
        [ -d --debug ]
        [ -h --help ]\n""" % self.ip6)

        sys.exit(2)


class Vpc(SecureCloudService):
    """
    VPC
    """

    def __init__(self, solution, message='Create a Virtual Private Cloud'):
        """
        Create AWS VPC
        :return: object
        """
        super().__init__(solution)
        if message:
            self.console(message)

        self.vpc = client.Vpc(self)
        if self.vpc.response and 'Vpc' in self.vpc.response and 'VpcId' in self.vpc.response['Vpc']:
            self.vpc_id = self.vpc.response['Vpc']['VpcId']
            self.vpc_ids.append(self.vpc_id)
        else:
            Solution.fatal()

    def clean(self, message=None):
        """
        Teardown VPC, Endpoints, and Peering Connection Endpoints
        """
        self.client = boto3.client('ec2')
        if message:
            self.console(message)

        inventory = self.vpc.list(self)
        if inventory and "Vpcs" in inventory and inventory['Vpcs']:
            for vpc in inventory['Vpcs']:
                self.vpc_id = vpc['VpcId']
                print('Found: %s' % self.vpc_id)

                # VPC ENDPOINTS
                inventory = client.VpcEndpoint.list(self.vpc, 'vpc-id', self.vpc.vpc_id)
                if inventory and 'VpcEndpoints' in inventory and inventory['VpcEndpoints']:
                    for endpoint in inventory['VpcEndpoints']:
                        client.VpcEndpoint.delete(self.vpc, endpoint['VpcEndpointId'])
                elif not self.vpc.dry:
                    print('No vpc endpoints detected')

                # VPC PEERING CONNECTION ENDPOINTS
                inventory = client.VpcPeeringConnection.list(self.vpc)
                if 'VpcPeeringConnections' in inventory and inventory['VpcPeeringConnections']:
                    for endpoint in inventory['VpcPeeringConnections']:
                        client.VpcPeeringConnection.delete(self.vpc, endpoint['VpcPeeringConnectionId'])
                elif not self.vpc.dry:
                    print('No vpc connection items detected')
                client.Vpc.delete(self)


class SecurityGroup(SecureCloudService):
    """
    SECURITY GROUP
    """

    def __init__(self, solution, message=None):
        """
        Initialise AWS SecurityGroup
        :return: object
        """
        super().__init__(solution)
        if message:
            self.console(message)

        resource = client.SecurityGroup(self)
        if resource.response and 'GroupId' in resource.response and resource.response['GroupId']:
            self.sg_id = resource.response['GroupId']
            resource.auth_ingress(self, 22, 22, 'TCP', [{'CidrIp': self.any_ip4}], [{'CidrIpv6': self.any_ip6}])
            resource.auth_egress(self, 22, 22, 'TCP', [{'CidrIp': self.any_ip4}], [{'CidrIpv6': self.any_ip6}])
            resource.auth_ingress(self, 80, 80, 'TCP', [{'CidrIp': self.any_ip4}], [{'CidrIpv6': self.any_ip6}])
            resource.auth_egress(self, 80, 80, 'TCP', [{'CidrIp': self.any_ip4}], [{'CidrIpv6': self.any_ip6}])
            resource.auth_ingress(self, 443, 443, 'TCP', [{'CidrIp': self.any_ip4}], [{'CidrIpv6': self.any_ip6}])
            resource.auth_egress(self, 443, 443, 'TCP', [{'CidrIp': self.any_ip4}], [{'CidrIpv6': self.any_ip6}])

            inventory = client.SecurityGroup.list(self, 'vpc-id', self.vpc_id)
            if inventory and "SecurityGroups" in inventory and inventory['SecurityGroups']:
                for item in inventory['SecurityGroups']:
                    self.sg_ids.append(item['GroupId'])
        else:
            Solution.fatal()

    def clean(self, message='Teardown Security Group'):
        """
        Teardown Security Groups
        """
        self.client = boto3.client('ec2')
        if message:
            self.console(message)

        inventory = client.SecurityGroup.list(self)
        if inventory and "SecurityGroups" in inventory and inventory['SecurityGroups']:
            for item in inventory['SecurityGroups']:
                self.sg_id = item['GroupId']

                # INGRESS
                for perm in item['IpPermissions']:
                    if perm['IpRanges'] and 'FromPort' in perm:
                        for c in perm['IpRanges']:
                            if 'CidrIp' in c:
                                client.SecurityGroup.revoke_ingress(self, perm['FromPort'], perm['ToPort'],
                                                                    perm['IpProtocol'], [{'CidrIp': c['CidrIp']}])
                    if perm['Ipv6Ranges'] and 'FromPort' in perm:
                        for c in perm['Ipv6Ranges']:
                            if 'CidrIpv6' in c:
                                client.SecurityGroup.revoke_ingress(self, perm['FromPort'], perm['ToPort'],
                                                                    perm['IpProtocol'], [{'CidrIp': ''}],
                                                                    [{'CidrIpv6': c['CidrIpv6']}])
                # EGRESS
                for perm in item['IpPermissionsEgress']:
                    if perm['IpRanges'] and 'FromPort' in perm:
                        for c in perm['IpRanges']:
                            if 'CidrIp' in c:
                                client.SecurityGroup.revoke_egress(self, perm['FromPort'], perm['ToPort'],
                                                                   perm['IpProtocol'], [{'CidrIp': c['CidrIp']}])
                    if perm['Ipv6Ranges'] and 'FromPort' in perm:
                        for c in perm['Ipv6Ranges']:
                            if 'CidrIpv6' in c:
                                client.SecurityGroup.revoke_egress(self, perm['FromPort'], perm['ToPort'],
                                                                   perm['IpProtocol'], [{'CidrIp': ''}],
                                                                   [{'CidrIpv6': c['CidrIpv6']}])

                # REFERENCING SECURITY GROUPS
                refs = client.SecurityGroup.list_refs(self, self.sg_id)
                if refs and "SecurityGroupReferenceSet" in refs and refs['SecurityGroupReferenceSet']:
                    for ref in refs['SecurityGroupReferenceSet']:

                        # VPC ON OTHER SIDE OF A VPC-PEERING-CONNECTION
                        for sgs in client.SecurityGroup.list(self, 'vpc-id', [ref[0]['ReferencingVpcId']]):
                            for sg in sgs['SecurityGroups']:
                                self.sg_id = sg['GroupId']

                                # INGRESS
                                for perm in sg['IpPermissions']:
                                    if perm['IpRanges'] and 'FromPort' in perm and perm['FromPort']:
                                        for c in perm['IpRanges']:
                                            if 'CidrIp' in c:
                                                client.SecurityGroup.revoke_ingress(self, perm['FromPort'],
                                                                                    perm['ToPort'], perm['IpProtocol'],
                                                                                    [{'CidrIp': c['CidrIp']}])
                                    if perm['Ipv6Ranges'] and 'FromPort' in perm and perm['FromPort']:
                                        for c in perm['Ipv6Ranges']:
                                            if 'CidrIpv6' in c:
                                                client.SecurityGroup.revoke_ingress(self, perm['FromPort'],
                                                                                    perm['ToPort'], perm['IpProtocol'],
                                                                                    [{'CidrIp': ''}],
                                                                                    [{'CidrIpv6': c['CidrIpv6']}])
                                # EGRESS
                                for perm in sg['IpPermissionsEgress']:
                                    if perm['IpRanges'] and 'FromPort' in perm and perm['FromPort']:
                                        for c in perm['IpRanges']:
                                            if 'CidrIp' in c:
                                                client.SecurityGroup.revoke_egress(self, perm['FromPort'],
                                                                                   perm['ToPort'], perm['IpProtocol'],
                                                                                   [{'CidrIp': c['CidrIp']}])
                                    if perm['Ipv6Ranges'] and 'FromPort' in perm and perm['FromPort']:
                                        for c in perm['Ipv6Ranges']:
                                            if 'CidrIpv6' in c:
                                                client.SecurityGroup.revoke_egress(self, perm['FromPort'],
                                                                                   perm['ToPort'], perm['IpProtocol'],
                                                                                   [{'CidrIp': ''}],
                                                                                   [{'CidrIpv6': c['CidrIp']}])

                                # DELETE NON-DEFAULT REFERENCING SG
                                if sg['GroupName'] != 'default':
                                    print('Deleting referencing security group %s' % sg)
                                    self.sg_id = sg
                                    client.SecurityGroup.delete(self)

                elif not self.dry:
                    print('No referencing security groups detected')

                # DELETE NON-DEFAULT SG
                if item['GroupName'] != 'default':
                    self.sg_id = item['GroupId']
                    print('Deleting security group %s' % self.sg_id)
                    client.SecurityGroup.delete(self)
        elif not self.dry:
            print('No security groups detected')


class Ec2(SecureCloudService):
    """
    EC2 COMPUTE
    """

    def __init__(self, solution, message='Create a EC2 compute environment'):
        """
        Initialise EC2 infrastructure
        :return: object
        """
        super().__init__(solution)
        if message:
            self.console(message)

        if not self.vpc_ids and self.sg_ids:
            self.console('Error: Compute needs VPC and SecurityGroup')
            Solution.fatal()

        # INTERNET GATEWAY
        resource = client.InternetGateway(self)
        if resource.response and 'InternetGateway' in resource.response:
            self.igw_id = resource.response['InternetGateway']['InternetGatewayId']
            self.igw_ids.append(self.igw_id)
            resource.attach(self)

            # ROUTE TABLE
            self.rtt_ids = []
            resource = client.RouteTable(self)
            if resource.response and 'RouteTable' in resource.response and resource.response['RouteTable']:
                self.rtt_id = resource.response['RouteTable']['RouteTableId']
                self.rtt_ids.append(self.rtt_id)
                if self.ip4:
                    resource.create_route(self, 'ip4', self.any_ip4)
                if self.ip6:
                    resource.create_route(self, 'ip6', self.any_ip6)

        # SUBNETS
        # Note: cidr's must be subset of VPC cidr_block
        self.subnet_ids = []
        self.acl_ids = []
        for i in range(len(self.cidr4)):
            subnet = client.Subnet(self, self.cidr4[i], self.zones[i])
            if subnet.response and 'Subnet' in subnet.response:
                self.subnet_id = subnet.response['Subnet']['SubnetId']
                self.subnet_ids.append(self.subnet_id)
                subnet.modify_attr(self, self.subnet_id, True)

                # ROUTE TABLE ASSOCIATIONS
                for j in range(len(self.rtt_ids)):
                    self.rtt_id = self.rtt_ids[j]
                    client.RouteTable.associate(self, self.subnet_id)

            # NETWORK ACL
            acl = client.NetworkAcl(self)
            if acl.response and 'NetworkAcl' in acl.response:
                self.acl_id = acl.response['NetworkAcl']['NetworkAclId']
                self.acl_ids.append(self.acl_id)
                acl.create_entry(self, self.cidr4[i], 100, 'allow', 0, 0, '6', False)
                acl.create_entry(self, self.cidr4[i], 101, 'allow', 0, 0, '6', True)

                # NETWORK ACL ASSOCIATION
                if acl.response['NetworkAcl']['Associations']:
                    assoc_id = acl.response['NetworkAcl']['Associations'][i]['NetworkAclAssociationId']
                    client.NetworkAcl.replace_association(self, assoc_id)

        # LAUNCH TEMPLATE
        self.template_ids = []
        self.instance_ids = []
        resource2 = client.LaunchTemplate(self)
        if resource2.response and 'LaunchTemplate' in resource2.response:
            self.template_id = resource2.response['LaunchTemplate']['LaunchTemplateId']
            self.template_ids.append(self.template_id)

            # LAUNCH TEMPLATE VERSION PER ZONE
            for j in range(len(self.zones)):
                resource3 = resource2.create_version(self, j, self.zones[j])
                if resource3 and 'LaunchTemplateVersion' in resource3:
                    self.template_id = resource3['LaunchTemplateVersion']['LaunchTemplateId']
                    self.template_ids.append(self.template_id)

                    ################
                    # EC2 INSTANCE
                    ###############
                    if 'ec2' in self.scope and 'autoscaling' not in self.scope:
                        print('Startup EC2 Instance group %d' % j)
                        resource4 = client.Instance(self, self.template_ids[j], self.subnet_ids[j], self.zones[j])
                        if resource4:
                            for k in range(self.max_count):
                                self.instance_id = resource4.response[k].id
                                self.instance_ids.append(self.instance_id)

                                if 'eip' in self.scope:
                                    print('Wait until running ...')
                                    instance = self.compute.Instance(self.instance_id)
                                    instance.wait_until_running(Filters=[{'Name': 'instance-id',
                                                                          'Values': [self.instance_id]}],
                                                                DryRun=self.dry)
                                    print('created Instance %s' % self.instance_id)
                                else:
                                    print('initialized Instance %s' % self.instance_id)

            # ELASTIC IP
            if 'eip' in self.scope and 'autoscaling' not in self.scope:
                self.eip_ids = []
                self.nat_gw_ids = []
                for k in range(self.max_count*len(self.zones)):
                    resource = client.ElasticIp(self, 'vpc')
                    if resource.response and 'AllocationId' in resource.response:
                        self.eip_id = resource.response['AllocationId']
                        self.eip_ids.append(self.eip_id)
                        client.ElasticIp.associate(self, self.instance_ids[k], self.eip_ids[k])
                    else:
                        print('failed to create elastic IP (try "-d" param to debug')

    def clean(self, message='Teardown EC2 infrastructure'):
        """
        Teardown EC2 Infrastructure
        """
        self.client = boto3.client('ec2')
        if message:
            self.console(message)

        inventory = client.Vpc.list(self)
        if inventory and "Vpcs" in inventory and inventory['Vpcs']:
            for vpc in inventory['Vpcs']:
                self.vpc_id = vpc['VpcId']

                # EC2 INSTANCES
                self.instance_ids = []
                inventory = client.Instance.list(self)
                if inventory and "Reservations" in inventory and inventory['Reservations']:
                    for i in range(len(inventory['Reservations'])):
                        for instance in inventory['Reservations'][i]['Instances']:
                            self.instance_id = instance['InstanceId']
                            client.Instance.delete(self)
                elif not self.dry:
                    print('No ec2 instances detected')

                # ELASTIC IPS
                elastic_ips = client.ElasticIp.list(self)
                if elastic_ips and "Addresses" in elastic_ips and elastic_ips['Addresses']:
                    for ip in elastic_ips['Addresses']:
                        if 'AssociationId' in ip and ip['AssociationId'] != '-':
                            client.ElasticIp.disassociate(self, ip['AllocationId'])
                        client.ElasticIp.release(self, ip['AllocationId'])
                elif not self.dry:
                    print('No elastic ips detected')

                # LAUNCH TEMPLATES
                inventory = client.LaunchTemplate.list(self)
                if inventory and 'LaunchTemplates' in inventory and inventory['LaunchTemplates']:
                    for i in range(len(inventory['LaunchTemplates'])):
                        self.template_id = inventory['LaunchTemplates'][i]['LaunchTemplateId']

                        # CHILD VERSIONS
                        versions = client.LaunchTemplate.list_versions(self)
                        if versions:
                            for version in versions['LaunchTemplateVersions']:
                                client.LaunchTemplate.delete_version(self, version['VersionNumber'])
                        else:
                            print('No launch template versions detected')

                        # DELETE TEMPLATE
                        client.LaunchTemplate.delete(self)

                elif not self.dry:
                    print('No launch templates detected')

                # NETWORK INTERFACES
                inventory = client.NetworkInterface.list(self)
                if inventory and "NetworkInterfaces" in inventory and inventory['NetworkInterfaces']:
                    for item in inventory['NetworkInterfaces']:
                        client.NetworkInterface.delete(self, item['NetworkInterfaceId'])
                    print('wait for deletion ...')
                    while True:
                        inventory = client.NetworkInterface.list(self)
                        if "NetworkInterfaces" in inventory and inventory['NetworkInterfaces']:
                            time.sleep(1)
                        else:
                            break
                elif not self.dry:
                    print('No network interfaces detected')

                # INTERNET GATEWAY
                time.sleep(10)
                inventory = client.InternetGateway.list(self, 'attachment.vpc-id', vpc['VpcId'])
                if inventory and "InternetGateways" in inventory and inventory['InternetGateways']:
                    for item in inventory['InternetGateways']:
                        time.sleep(20)
                        client.InternetGateway.detach(self, item['InternetGatewayId'], vpc['VpcId'])
                        time.sleep(20)
                        client.InternetGateway.delete(self, item['InternetGatewayId'])
                elif not self.dry:
                    print('No internet gateways detected')

                # SUBNET
                self.subnet_ids = []
                inventory = client.Subnet.list(self)
                if inventory and "Subnets" in inventory and inventory['Subnets']:
                    for item in inventory['Subnets']:
                        self.subnet_id = item['SubnetId']
                        self.subnet_ids.append(self.subnet_id)
                        client.Subnet.delete(self)
                elif not self.dry:
                    print('No subnets detected')

                # ROUTE TABLES
                inventory = client.RouteTable.list(self, 'vpc-id', vpc['VpcId'])
                if inventory and "RouteTables" in inventory and inventory['RouteTables']:
                    for item in inventory['RouteTables']:
                        if item['Associations']:
                            if item['Associations'][0]['Main']:
                                print('Skipping main route table')
                            else:
                                client.RouteTable.disassociate(self, item['Associations'][0]['RouteTableAssociationId'])
                                client.RouteTable.delete_route(self, self.any_ip4, item['RouteTableId'])
                                for cidr in self.cidr4:
                                    client.RouteTable.delete_route(self, cidr, item['RouteTableId'])
                                if self.ip6:
                                    client.RouteTable.delete_route(self, self.any_ip6, item['RouteTableId'])
                                    for cidr in self.cidr6:
                                        client.RouteTable.delete_route(self, cidr, item['RouteTableId'])
                                client.RouteTable.delete(self, item['RouteTableId'])
                        else:
                            client.RouteTable.delete(self, item['RouteTableId'])
                elif not self.dry:
                    print('No route tables detected')

                # NAT GATEWAY
                inventory = client.NatGateway.list(self)
                if inventory and "NatGateways" in inventory and inventory['NatGateways']:
                    for ngw in inventory['NatGateways']:
                        client.NatGateway.delete(self, ngw['NatGatewayId'])
                elif not self.dry:
                    print('No nat gateways detected')

                # NETWORK ACL
                inventory = client.NetworkAcl.list(self)
                if inventory and "NetworkAcls" in inventory and inventory['NetworkAcls']:
                    for item in inventory['NetworkAcls']:
                        client.NetworkAcl.delete_entry(self, item['NetworkAclId'], 101, False)
                        client.NetworkAcl.delete_entry(self, item['NetworkAclId'], 101, True)
                        client.NetworkAcl.delete_entry(self, item['NetworkAclId'], 102, False)
                        client.NetworkAcl.delete_entry(self, item['NetworkAclId'], 102, True)
                        client.NetworkAcl.delete(self, item['NetworkAclId'])
                elif not self.dry:
                    print('No network acls detected')

                # WE NEED TO DELETE SECURITY GROUP SO VPC CAN GO
                # MAYBE DISASSOCIATE_SG IS ALTERNATIVE WAY
                SecurityGroup.clean(self)   # intended

                print('\nTeardown VPC')
                client.Vpc.delete(self)
        elif not self.dry:
            print('No VPCs found')


class ElasticLoadBalancing(ScalableCloudService):
    """
    ELASTIC LOAD BALANCING
    """

    def __init__(self, solution, message='Create Elastic Load Balancing environment'):
        """
        Initialise ELBv2
        :return: object
        """
        super().__init__(solution)
        self.elb = boto3.client('elbv2')
        if message:
            self.console(message)

        resource = client.LoadBalancer(self)
        if resource.response and 'LoadBalancers' in resource.response and resource.response['LoadBalancers']:
            self.lb_arn = resource.response['LoadBalancers'][0]['LoadBalancerArn']
            self.lb_arns.append(self.lb_arn)

            # WAIT UNTIL ELB IS ACTIVE
            print('Wait until active ...')
            provisioning = True
            while provisioning:
                lbs = client.LoadBalancer.list(self)
                if lbs and 'LoadBalancers' in lbs and lbs['LoadBalancers']:
                    for lb in lbs['LoadBalancers']:
                        provisioning = True
                        if self.lb_arn == lb['LoadBalancerArn'] and lb['State']['Code'] == 'provisioning':
                            time.sleep(1)
                        else:
                            provisioning = False
            resource.create_tags(self, self.lb_arn)

            # TARGET GROUPS
            target = client.LoadBalancerTargetGroup(self, self.protocols[0], self.ports[0])
            if target.response and 'TargetGroups' in target.response and target.response['TargetGroups']:
                self.lb_target_group_arn = target.response['TargetGroups'][0]['TargetGroupArn']
                self.lb_target_group_arns.append(self.lb_target_group_arn)
                resource.create_tags(self, self.lb_target_group_arn)

                # LISTENERS
                for j in range(len(self.protocols)):
                    listy = client.LoadBalancerListener(self, self.protocols[j], self.ports[j], self.lb_choices[j])
                    if listy.response and 'Listeners' in listy.response and listy.response['Listeners']:
                        self.lb_listener_arn = listy.response['Listeners'][0]['ListenerArn']
                        self.lb_listener_arns.append(self.lb_listener_arn)
            print('elb created')
        else:
            print('failed to created ELB instance')

    def clean(self, message='Teardown Elastic Load Balancing'):
        """
        Teardown ELBv2
        """
        self.elb = boto3.client('elbv2')
        if message:
            self.console(message)

        inventory = client.LoadBalancer.list(self)
        if inventory and 'LoadBalancers' in inventory and inventory['LoadBalancers']:
            for elb in inventory['LoadBalancers']:
                self.lb_arn = elb['LoadBalancerArn']

                # LISTENERS
                inventory = client.LoadBalancerListener.list(self)
                if inventory and 'Listeners' in inventory and inventory['Listeners']:
                    for listener in inventory['Listeners']:
                        self.lb_listener_arn = listener['ListenerArn']
                        client.LoadBalancerListener.delete(self)

                # TARGET GROUPS
                inventory = client.LoadBalancerTargetGroup.list(self)
                previous_arn = None
                if inventory and 'TargetGroups' in inventory and inventory['TargetGroups']:
                    for target in inventory['TargetGroups']:
                        self.lb_target_group_arn = target['TargetGroupArn']
                        if self.topic_arn != previous_arn:
                            client.LoadBalancerTargetGroup.delete(self)
                            previous_arn = self.lb_target_group_arn

                # ELB
                client.LoadBalancer.delete(self)
        else:
            print('No Elastic Load Balancer found')


class AutoScaling(ScalableCloudService):
    """
    AUTO SCALING
    """

    def __init__(self, solution, message='Create AutoScaling'):
        """
        Initialise AUTOSCALING
        :return: object
        """
        super().__init__(solution)
        self.autoscale = boto3.client('autoscaling')
        if message:
            self.console(message)

        client.AutoScalingGroup(self)
        client.AutoScalingGroupTags(self)
        client.AutoScalingPolicy(self)
        client.AutoScalingNotification(self)

    def clean(self, message='Teardown AutoScaling'):
        """
        Teardown AutoScaling
        :return: None
        """
        self.autoscale = boto3.client('autoscaling')
        if message:
            self.console(message)

        inventory = client.AutoScalingGroup.list(self)
        if inventory and 'AutoScalingGroups' in inventory and inventory['AutoScalingGroups']:
            for group in inventory['AutoScalingGroups']:
                self.asg_name = group['AutoScalingGroupName']

                # AUTO SCALING NOTIFICATIONS
                inventory2 = client.AutoScalingNotification.list(self)
                if 'NotificationConfigurations' in inventory2 and inventory2['NotificationConfigurations']:
                    previous_arn = None
                    for notification in inventory2['NotificationConfigurations']:
                        self.topic_arn = notification['TopicARN']
                        if self.topic_arn != previous_arn:
                            client.AutoScalingNotification.delete(self)
                            previous_arn = self.topic_arn
                else:
                    print('No auto-scaling notifications found')

                # AUTO SCALING POLICIES
                inventory3 = client.AutoScalingPolicy.list(self)
                if inventory3 and 'ScalingPolicies' in inventory3 and inventory3['ScalingPolicies']:
                    for policy in inventory3['ScalingPolicies']:
                        client.AutoScalingPolicy.delete(self, policy['ResourceId'])
                else:
                    print('No auto-scaling policies found')

                # AUTO SCALE GROUPS (FORCE DELETE INSTANCES = TRUE)
                inventory4 = client.AutoScalingGroup.list(self)
                if inventory4 and 'AutoScalingGroups' in inventory4 and inventory4['AutoScalingGroups']:
                    for item in inventory4['AutoScalingGroups']:
                        self.name = item['AutoScalingGroupName']
                        client.AutoScalingGroup.delete(self)
                    print('wait for deletion ...')
                    while True:
                        inventory5 = client.AutoScalingGroup.list(self)
                        if 'AutoScalingGroups' in inventory5 and inventory5['AutoScalingGroups']:
                            time.sleep(1)
                        else:
                            break
        else:
            print('No Auto Scaling Groups found')

        # LAUNCH CONFIGURATIONS
        inventory = client.LaunchConfiguration.list(self)
        if inventory and 'LaunchConfigurations' in inventory and inventory['LaunchConfigurations']:
            for configuration in inventory['LaunchConfigurations']:
                client.LaunchConfiguration.delete(self, configuration['LaunchConfigurationName'])
        else:
            print('No Launch Configurations found')


class SimpleNotificationService(ScalableCloudService):
    """
    SIMPLE NOTIFICATION SERVICE
    :return: object
    """
    def __init__(self, solution, message='Create Simple Notification Service Topic'):
        """
        Initialise AWS SNS
        """
        super().__init__(solution)
        self.sns = boto3.client('sns')
        if message:
            self.console(message)

        self.sns_topic = client.SimpleNotificationServiceTopic(self)
        self.topic_arn = self.sns_topic.response['TopicArn']

    def clean(self, message='Teardown Simple Notification Service'):
        """
        Teardown SNS
        """
        if message:
            self.console(message)

        self.sns = boto3.client('sns')
        inventory = client.SimpleNotificationServiceTopic.list(self)
        if inventory and "Topics" in inventory and inventory['Topics']:
            found = False
            for topic in inventory['Topics']:
                self.topic_arn = topic['TopicArn']
                if self.name in str(topic['TopicArn']):
                    client.SimpleNotificationServiceTopic.delete(self)
                    found = True
            if not found:
                print('No Simple Notification Service found')
        else:
            print('No Simple Notification Service found')
