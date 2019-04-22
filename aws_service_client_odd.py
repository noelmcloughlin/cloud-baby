#!/usr/bin/env python3
#############################################
# Copyright 2019 noelmcloughlin
#############################################

import getopt
import time
import sys
try:
    sys.path.append('./aws')
    import boto3_client as aws
    import sitedata as data
except ImportError:
    sys.path.append(('../aws', '../data'))
    import boto3_client as aws
    import sitedata as data

# GLOBALS
data = data.init
all_ip4 = '0.0.0.0/0'
all_ip6 = '::/0'
_SUPPORTED = ('sns', 'vpc', 'elb', 'autoscaling', 'instance')


def launch(cloud):
    """
    Launch AWS clouds
    :param cloud: Object representing a Cloud cloud
    :return:
    """
    try:
        ###########################
        # SIMPLE MESSAGING SERVICE
        ###########################
        if 'sns' in cloud.scope and 'SimpleNotificationService' in str(type(cloud)):
            print('\nStartup Simple Notification Service')
            resource = aws.SimpleNotificationServiceTopic(data)
            data['service']['topic_arn'] = resource.response['TopicArn']

        ###################################
        # VIRTUAL PRIVATE CLOUD & SECURITY
        ###################################
        if 'vpc' in cloud.scope and 'Compute' in str(type(cloud)):
            print('\nStartup Virtual Private Cloud & Security')
            resource = aws.Vpc(data)
            if resource.response and 'Vpc' in resource.response and 'VpcId' in resource.response['Vpc']:
                cloud.vpc_id = resource.response['Vpc']['VpcId']
                data['compute']['vpc_id'] = cloud.vpc_id

                # INTERNET GATEWAY
                resource = aws.InternetGateway(data)
                if resource.response and 'InternetGateway' in resource.response:
                    cloud.igw_id = data['compute']['igw_id'] = resource.response['InternetGateway']['InternetGatewayId']
                    cloud.igw_ids.append(cloud.igw_id)
                    resource.attach(cloud)
                    data['compute']['igw_ids'] = cloud.igw_ids

                    # ROUTE TABLE
                    cloud.rtt_ids = []
                    resource = aws.RouteTable(data)
                    if resource.response and 'RouteTable' in resource.response:
                        cloud.rtt_id = resource.response['RouteTable']['RouteTableId']
                        cloud.rtt_ids.append(cloud.rtt_id)
                        data['compute']['rtt_ids'] = cloud.rtt_ids
                        resource.create_route(cloud, 'ipv4', all_ip4)
                        resource.create_route(cloud, 'ipv6', all_ip6)

                # SUBNETS
                # Note: cidr's must be subset of VPC cidr_block
                cloud.subnet_ids = []
                cloud.acl_ids = []
                for i in range(len(cloud.cidr4)):
                    resource = aws.Subnet(data, cloud.cidr4[i], cloud.zones[i])
                    if resource.response and 'Subnet' in resource.response:
                        subnet_id = resource.response['Subnet']['SubnetId']
                        cloud.subnet_ids.append(subnet_id)
                        data['service']['subnet_ids'] = cloud.subnet_ids
                        resource.modify_attr(cloud, subnet_id, True)

                        # ROUTE TABLE ASSOCIATIONS
                        for j in range(len(cloud.rtt_ids)):
                            cloud.rtt_id = cloud.rtt_ids[j]
                            aws.RouteTable.associate(cloud, subnet_id)

                    # NETWORK ACL
                    for j in range(len(cloud.network_acls)):
                        resource = aws.NetworkAcl(data)
                        if resource.response and 'NetworkAcl' in resource.response:
                            cloud.acl_id = resource.response['NetworkAcl']['NetworkAclId']
                            cloud.acl_ids.append(cloud.acl_id)
                            data['compute']['acl_ids'] = cloud.acl_ids
                            resource.create_entry(cloud, cloud.cidr4[j], 100, 'allow', 0, 0, '6', False)
                            resource.create_entry(cloud, cloud.cidr4[j], 101, 'allow', 0, 0, '6', True)

                            # NETWORK ACL ASSOCIATION
                            if resource.response['NetworkAcl']['Associations']:
                                assoc_id = resource.response['NetworkAcl']['Associations'][0]['NetworkAclAssociationId']
                                aws.NetworkAcl.replace_association(cloud, assoc_id)

                # ELASTIC IP
                cloud.eip_ids = []
                cloud.nat_gw_ids = []
                for i in range(cloud.max_count):
                    resource = aws.ElasticIp(data, 'vpc')
                    if resource.response and 'AllocationId' in resource.response:
                        cloud.eip_ids.append(resource.response['AllocationId'])
                        data['compute']['eip_ids'] = cloud.eip_ids

                    # NAT GATEWAY
                    # cloud.nat_gw_ids.append(aws.NatGateway(cloud).response['NatGateway']['NatGatewayId'])

                # SECURITY GROUP
                cloud.sg_ids = []
                resource = aws.SecurityGroup(data)
                if resource and resource.response and 'GroupId' in resource.response:
                    cloud.sg_id = resource.response['GroupId']
                    cloud.sg_ids.append(cloud.sg_id)
                    data['service']['sg_ids'] = cloud.sg_ids
                    resource.auth_ingress(cloud, 22, 22, 'TCP', [{'CidrIp': all_ip4}], [{'CidrIpv6': all_ip6}])
                    resource.auth_egress(cloud, 22, 22, 'TCP',  [{'CidrIp': all_ip4}], [{'CidrIpv6': all_ip6}])
                    resource.auth_ingress(cloud, 80, 80, 'TCP', [{'CidrIp': all_ip4}], [{'CidrIpv6': all_ip6}])
                    resource.auth_egress(cloud, 80, 80, 'TCP',  [{'CidrIp': all_ip4}], [{'CidrIpv6': all_ip6}])
                    resource.auth_ingress(cloud, 443, 443, 'TCP', [{'CidrIp': all_ip4}], [{'CidrIpv6': all_ip6}])
                    resource.auth_egress(cloud, 443, 443, 'TCP', [{'CidrIp': all_ip4}], [{'CidrIpv6': all_ip6}])

                    # LAUNCH TEMPLATE
                    cloud.template_ids = []
                    cloud.instance_ids = []
                    launch_resource = aws.LaunchTemplate(data)
                    if launch_resource.response and 'LaunchTemplate' in launch_resource.response:
                        cloud.template_id = launch_resource.response['LaunchTemplate']['LaunchTemplateId']
                        cloud.template_ids.append(cloud.template_id)
                        data['service']['template_ids'] = cloud.template_ids

                        # LAUNCH TEMPLATE VERSION PER ZONE
                        for i in range(len(cloud.zones)):
                            version_resource = launch_resource.create_version(cloud, i, cloud.zones[i])
                            if version_resource and 'LaunchTemplateVersion' in version_resource:
                                cloud.template_id = version_resource['LaunchTemplateVersion']['LaunchTemplateId']
                                cloud.template_ids.append(cloud.template_id)
                                data['service']['template_ids'] = cloud.template_ids

                                ################
                                # EC2 INSTANCE
                                ###############
                                if 'instance' in cloud.scope:
                                    print('Startup EC2 Instance group %d' % (i+1))
                                    resource = aws.Instance(data, cloud.template_ids[i+1], cloud.subnet_ids[i],
                                                            cloud.zones[i])
                                    if resource:
                                        for j in range(cloud.max_count):
                                            cloud.instance_id = resource.response[j].id
                                            cloud.instance_ids.append(cloud.instance_id)

                                            print('Wait until running ...')
                                            instance = cloud.compute.Instance(cloud.instance_id)
                                            instance.wait_until_running(Filters=[{'Name': 'instance-id',
                                                                                  'Values': [cloud.instance_id]}],
                                                                        DryRun=cloud.dry)
                                            print('created Instance %s' % cloud.instance_id)
                                            data['service']['instance_ids'] = cloud.instance_ids

                                            # ELASTIC IP ASSOCIATION
                                            if cloud.eip_ids:
                                                aws.ElasticIp.associate(cloud, cloud.eip_ids[j])
            else:
                print('failed to create instance (try "-d" param to debug')
            data['compute']['peer_vpc_id'] = None

        #########################
        # ELASTIC LOAD BALANCING
        #########################
        elif 'ElasticLoadBalancing' in str(type(cloud)) and 'elb' in cloud.scope:
            cloud.lb_arns = []
            print('\nStartup Elastic Load Balancer')
            resource = aws.LoadBalancer(data)
            if resource.response and 'LoadBalancers' in resource.response and resource.response['LoadBalancers']:
                for i in range(len(resource.response['LoadBalancers'])):
                    cloud.lb_arn = resource.response['LoadBalancers'][i]['LoadBalancerArn']
                    cloud.lb_arns.append(cloud.lb_arn)
                    data['elb']['lb_arns'] = cloud.lb_arns

                    # WAIT UNTIL ELB IS ACTIVE
                    print('Wait until active ...')
                    provisioning = True
                    while provisioning:
                        lb_list = aws.LoadBalancer.list(cloud)
                        if lb_list and 'LoadBalancers' in lb_list and lb_list['LoadBalancers']:
                            for lb in lb_list['LoadBalancers']:
                                provisioning = True
                                if cloud.lb_arn == lb['LoadBalancerArn'] and lb['State']['Code'] == 'provisioning':
                                    time.sleep(1)
                                else:
                                    provisioning = False
                print('elb created')
            else:
                print('failed to created ELB instance')

        #############################################################################
        # AUTO-SCALING, LAUNCH CONFIGURATION, GROUPS, TAGS, POLICIES, NOTIFICATIONS
        #############################################################################
        elif 'AutoScaling' in str(type(cloud)) and 'autoscaling' in cloud.scope:
            print('\nStartup AutoScaling Instances')
            aws.AutoScalingGroup(data)
            aws.AutoScalingGroupTags(data)
            aws.AutoScalingPolicy(data)
            aws.AutoScalingNotification(data)
    except Exception as err:
        aws.Compute.handle(err)


def teardown(cloud):
    """
    Get rid of AWS Services
    :param cloud: String - Representation of Cloud Service
    :return:
    """
    try:
        ##############################
        # SIMPLE NOTIFICATION SERVICE
        ##############################
        if 'SimpleNotificationService' in str(type(cloud)) and 'sns' in cloud.scope:
            print('\nTeardown Simple Notification Service')
            resources = aws.SimpleNotificationServiceTopic.list(cloud)
            if resources and 'Topics' in resources and resources['Topics']:
                for topic in resources['Topics']:
                    cloud.topic_arn = topic['TopicArn']
                    if cloud.name in str(topic['TopicArn']):
                        aws.SimpleNotificationServiceTopic.delete(cloud)
            else:
                print('No Simple Notification Service found')
            print('Done')

        ######################
        # AUTO SCALING GROUPS
        ######################
        if 'AutoScaling' in str(type(cloud)) and 'autoscaling' in cloud.scope:
            print('\nTeardown AutoScaling')
            resources = aws.AutoScalingGroup.list(cloud)
            if resources and 'AutoScalingGroups' in resources and resources['AutoScalingGroups']:
                for group in resources['AutoScalingGroups']:
                    cloud.asg_name = group['AutoScalingGroupName']

                    # AUTO SCALING NOTIFICATIONS
                    resource = aws.AutoScalingNotification.list(cloud)
                    if 'NotificationConfigurations' in resource and resources['NotificationConfigurations']:
                        for notification in resource['NotificationConfigurations']:
                            cloud.topic_arn = notification['TopicArn']
                            aws.AutoScalingNotification.delete(cloud)
                    else:
                        print('No auto-scaling notifications found')

                    # AUTO SCALING GROUP TAGS
                    resources = aws.AutoScalingGroupTags.list(cloud)
                    if resources and 'Tags' in resources and resources['Tags']:
                        for policy in resources['Tags']:
                            cloud.name = policy['Key']
                            cloud.tag = policy['Value']
                            aws.AutoScalingGroupTags.delete(cloud)
                    else:
                        print('No auto-scaling group tags found')

                    # AUTO SCALING POLICIES
                    resources = aws.AutoScalingPolicy.list(cloud)
                    if resources and 'ScalingPolicies' in resources and resources['ScalingPolicies']:
                        for policy in resources['ScalingPolicies']:
                            aws.AutoScalingPolicy.delete(cloud, policy['ResourceId'])
                    else:
                        print('No auto-scaling policies found')

                    # AUTO SCALE GROUPS (FORCE DELETE INSTANCES = TRUE)
                    resources = aws.AutoScalingGroup.list(cloud)
                    if resources and 'AutoScalingGroups' in resources and resources['AutoScalingGroups']:
                        for item in resources['AutoScalingGroups']:
                            cloud.name = item['AutoScalingGroupName']
                            aws.AutoScalingGroup.delete(cloud)
                        print('wait for deletion ...')
                        while True:
                            resources = aws.AutoScalingGroup.list(cloud)
                            if resources and 'AutoScalingGroups' in resources and resources['AutoScalingGroups']:
                                time.sleep(1)
                            else:
                                break
                    elif not cloud.dry:
                        print('No auto-scaling groups found')
            else:
                print('No Auto Scaling Groups found')

            # LAUNCH CONFIGURATIONS
            resources = aws.LaunchConfiguration.list(cloud)
            if resources and 'LaunchConfigurations' in resources and resources['LaunchConfigurations']:
                for configuration in resources['LaunchConfigurations']:
                    aws.LaunchConfiguration.delete(cloud, configuration['LaunchConfigurationName'])
            else:
                print('No Launch Configurations found')

        #########################
        # ELASTIC LOAD BALANCING
        #########################
        if 'ElasticLoadBalancing' in str(type(cloud)) and 'elb' in cloud.scope:
            print('\nTeardown Elastic Load Balancer')
            resources = aws.LoadBalancer.list(cloud)
            if resources and 'LoadBalancers' in resources and resources['LoadBalancers']:
                for elb in resources['LoadBalancers']:
                    cloud.lb_arn = elb['LoadBalancerArn']
                    aws.LoadBalancer.delete(cloud)
            else:
                print('No Elastic Load Balancer found')

        ###################################
        # VIRTUAL PRIVATE CLOUD & SECURITY
        ###################################
        if 'Compute' in str(type(cloud)) and ('vpc' in cloud.scope or 'instance' in cloud.scope):
            print('%s' % ('\nTeardown VPC & Security ' if not cloud.dry else ''))
            vpc_ids = []
            vpcs = aws.Vpc.list(cloud)
            if vpcs and "Vpcs" in vpcs and vpcs['Vpcs']:
                for vpc in vpcs['Vpcs']:
                    cloud.vpc_id = vpc['VpcId']
                    vpc_ids.append(cloud.vpc_id)
                    print('Found: %s' % cloud.vpc_id)

                    # VPC ENDPOINTS
                    resources = aws.VpcEndpoint.list(cloud, 'vpc-id', cloud.vpc_id)
                    if resources and 'VpcEndpoints' in resources and resources['VpcEndpoints']:
                        for endpoint in resources['VpcEndpoints']:
                            aws.VpcEndpoint.delete(cloud, endpoint['VpcEndpointId'])
                    elif not cloud.dry:
                        print('No vpc endpoints detected')

                    # VPC PEERING CONNECTION ENDPOINTS
                    resources = aws.VpcPeeringConnection.list(cloud)
                    if resources and 'VpcPeeringConnections' in resources and resources['VpcPeeringConnections']:
                        for endpoint in resources['VpcPeeringConnections']:
                            aws.VpcPeeringConnection.delete(cloud, endpoint['VpcPeeringConnectionId'])
                    elif not cloud.dry:
                        print('No vpc connection endpoints detected')

                    # EC2 INSTANCES
                    cloud.instance_ids = []
                    resources = aws.Instance.list(cloud)
                    if resources and "Reservations" in resources and resources['Reservations']:
                        for i in range(len(resources['Reservations'])):
                            for instance in resources['Reservations'][i]['Instances']:
                                cloud.instance_id = instance['InstanceId']
                                cloud.instance_ids.append(cloud.instance_id)
                                aws.Instance.delete(cloud)
                    elif not cloud.dry:
                        print('No ec2 instances detected')
                    data['service']['instance_ids'] = cloud.instance_ids

                    # ELASTIC IPS
                    elastic_ips = aws.ElasticIp.list(cloud)
                    if elastic_ips and "Addresses" in elastic_ips and elastic_ips['Addresses']:
                        for ip in elastic_ips['Addresses']:
                            if 'AssociationId' in ip and ip['AssociationId'] != '-':
                                aws.ElasticIp.disassociate(cloud, ip['AllocationId'])
                            aws.ElasticIp.release(cloud, ip['AllocationId'])
                    elif not cloud.dry:
                        print('No elastic ips detected')

                    # LAUNCH TEMPLATES
                    resources = aws.LaunchTemplate.list(cloud)
                    if resources and 'LaunchTemplates' in resources and resources['LaunchTemplates']:
                        for i in range(len(resources['LaunchTemplates'])):
                            cloud.template_id = resources['LaunchTemplates'][i]['LaunchTemplateId']

                            # CHILD VERSIONS
                            versions = aws.LaunchTemplate.list_versions(cloud)
                            if versions:
                                for version in versions['LaunchTemplateVersions']:
                                    aws.LaunchTemplate.delete_version(cloud, version['VersionNumber'])
                            else:
                                print('No launch template versions detected')

                            # DELETE TEMPLATE
                            aws.LaunchTemplate.delete(cloud)

                    elif not cloud.dry:
                        print('No launch templates detected')

                    # NETWORK INTERFACES
                    resources = aws.NetworkInterface.list(cloud)
                    if resources and "NetworkInterfaces" in resources and resources['NetworkInterfaces']:
                        for item in resources['NetworkInterfaces']:
                            aws.NetworkInterface.delete(cloud, item['NetworkInterfaceId'])
                        print('wait for deletion ...')
                        while True:
                            resources = aws.NetworkInterface.list(cloud, 'group-name', cloud.name)
                            if resources and "NetworkInterfaces" in resources and resources['NetworkInterfaces']:
                                time.sleep(1)
                            else:
                                break
                    elif not cloud.dry:
                        print('No network interfaces detected')

                    # INTERNET GATEWAY
                    resources = aws.InternetGateway.list(cloud, 'attachment.vpc-id', vpc['VpcId'])
                    if resources and "InternetGateways" in resources and resources['InternetGateways']:
                        for item in resources['InternetGateways']:
                            aws.InternetGateway.detach(cloud, item['InternetGatewayId'], vpc['VpcId'])
                            aws.InternetGateway.delete(cloud, item['InternetGatewayId'])
                    elif not cloud.dry:
                        print('No internet gateways detected')

                    # SUBNET
                    cloud.subnet_ids = []
                    resources = aws.Subnet.list(cloud)
                    if resources and "Subnets" in resources and resources['Subnets']:
                        for item in resources['Subnets']:
                            cloud.subnet_id = item['SubnetId']
                            cloud.subnet_ids.append(cloud.subnet_id)
                            aws.Subnet.delete(cloud)
                    elif not cloud.dry:
                        print('No subnets detected')

                    # ROUTE TABLES
                    resources = aws.RouteTable.list(cloud, 'vpc-id', vpc['VpcId'])
                    if resources and "RouteTables" in resources and resources['RouteTables']:
                        for item in resources['RouteTables']:
                            if item['Associations']:
                                if item['Associations'][0]['Main']:
                                    print('Skipping main route table')
                                else:
                                    aws.RouteTable.disassociate(cloud,
                                                                item['Associations'][0]['RouteTableAssociationId'])
                                    aws.RouteTable.delete_route(cloud, cloud.cidr4, item['RouteTableId'])
                                    aws.RouteTable.delete_route(cloud, all_ip6, item['RouteTableId'])
                                    aws.RouteTable.delete_route(cloud, cloud.cidr4, item['RouteTableId'])
                                    aws.RouteTable.delete(cloud, item['RouteTableId'])
                            else:
                                aws.RouteTable.delete(cloud, item['RouteTableId'])
                    elif not cloud.dry:
                        print('No route tables detected')

                    # NAT GATEWAY
                    resources = aws.NatGateway.list(cloud)
                    if resources and "NatGateways" in resources and resources['NatGateways']:
                        for ngw in resources['NatGateways']:
                            aws.NatGateway.delete(cloud, ngw['NatGatewayId'])
                    elif not cloud.dry:
                        print('No nat gateways detected')

                    # NETWORK ACL
                    resources = aws.NetworkAcl.list(cloud)
                    if resources and "NetworkAcls" in resources and resources['NetworkAcls']:
                        for item in resources['NetworkAcls']:
                            aws.NetworkAcl.delete_entry(cloud, item['NetworkAclId'], 101, False)
                            aws.NetworkAcl.delete_entry(cloud, item['NetworkAclId'], 101, True)
                            aws.NetworkAcl.delete_entry(cloud, item['NetworkAclId'], 102, False)
                            aws.NetworkAcl.delete_entry(cloud, item['NetworkAclId'], 102, True)
                            aws.NetworkAcl.delete(cloud, item['NetworkAclId'])
                    elif not cloud.dry:
                        print('No network acls detected')

                    # SECURITY GROUPS
                    resources = aws.SecurityGroup.list(cloud)
                    if resources and "SecurityGroups" in resources and resources['SecurityGroups']:
                        for item in resources['SecurityGroups']:
                            cloud.sg_id = item['GroupId']
                            # INGRESS
                            for perm in item['IpPermissions']:
                                if perm['IpRanges'] and 'FromPort' in perm:
                                    for c in perm['IpRanges']:
                                        if 'CidrIp' in c:
                                            aws.SecurityGroup.revoke_ingress(cloud, perm['FromPort'], perm['ToPort'],
                                                                             perm['IpProtocol'],
                                                                             [{'CidrIp': c['CidrIp']}])
                                if perm['Ipv6Ranges'] and 'FromPort' in perm:
                                    for c in perm['Ipv6Ranges']:
                                        if 'CidrIpv6' in c:
                                            aws.SecurityGroup.revoke_ingress(cloud, perm['FromPort'], perm['ToPort'],
                                                                             perm['IpProtocol'],
                                                                             [{'CidrIp': ''}],
                                                                             [{'CidrIpv6': c['CidrIpv6']}])
                            # EGRESS
                            for perm in item['IpPermissionsEgress']:
                                if perm['IpRanges'] and 'FromPort' in perm:
                                    for c in perm['IpRanges']:
                                        if 'CidrIp' in c:
                                            aws.SecurityGroup.revoke_egress(cloud, perm['FromPort'], perm['ToPort'],
                                                                            perm['IpProtocol'],
                                                                            [{'CidrIp': c['CidrIp']}])
                                if perm['Ipv6Ranges'] and 'FromPort' in perm:
                                    for c in perm['Ipv6Ranges']:
                                        if 'CidrIpv6' in c:
                                            aws.SecurityGroup.revoke_egress(cloud, perm['FromPort'], perm['ToPort'],
                                                                            perm['IpProtocol'],
                                                                            [{'CidrIp': ''}],
                                                                            [{'CidrIpv6': c['CidrIpv6']}])

                            # REFERENCING SECURITY GROUPS
                            refs = aws.SecurityGroup.list_refs(cloud, cloud.sg_id)
                            if refs and "SecurityGroupReferenceSet" in refs and refs['SecurityGroupReferenceSet']:
                                for ref in refs['SecurityGroupReferenceSet']:

                                    # VPC ON OTHER SIDE OF A VPC-PEERING-CONNECTION
                                    for sgs in aws.SecurityGroup.list(cloud, 'vpc-id', [ref[0]['ReferencingVpcId']]):
                                        for sg in sgs['SecurityGroups']:
                                            cloud.sg_id = sg['GroupId']
                                            # INGRESS
                                            for perm in sg['IpPermissions']:
                                                if perm['IpRanges'] and 'FromPort' in perm and perm['FromPort']:
                                                    for c in perm['IpRanges']:
                                                        if 'CidrIp' in c:
                                                            aws.SecurityGroup.revoke_ingress(cloud, perm['FromPort'],
                                                                                             perm['ToPort'],
                                                                                             perm['IpProtocol'],
                                                                                             [{'CidrIp': c['CidrIp']}])
                                                if perm['Ipv6Ranges'] and 'FromPort' in perm and perm['FromPort']:
                                                    for c in perm['Ipv6Ranges']:
                                                        if 'CidrIpv6' in c:
                                                            aws.SecurityGroup.revoke_ingress(cloud, perm['FromPort'],
                                                                                             perm['ToPort'],
                                                                                             perm['IpProtocol'],
                                                                                             [{'CidrIp': ''}],
                                                                                             [{'CidrIpv6':
                                                                                                 c['CidrIpv6']}])
                                            # EGRESS
                                            for perm in sg['IpPermissionsEgress']:
                                                if perm['IpRanges'] and 'FromPort' in perm and perm['FromPort']:
                                                    for c in perm['IpRanges']:
                                                        if 'CidrIp' in c:
                                                            aws.SecurityGroup.revoke_egress(cloud, perm['FromPort'],
                                                                                            perm['ToPort'],
                                                                                            perm['IpProtocol'],
                                                                                            [{'CidrIp': c['CidrIp']}])
                                                if perm['Ipv6Ranges'] and 'FromPort' in perm and perm['FromPort']:
                                                    for c in perm['Ipv6Ranges']:
                                                        if 'CidrIpv6' in c:
                                                            aws.SecurityGroup.revoke_egress(cloud, perm['FromPort'],
                                                                                            perm['ToPort'],
                                                                                            perm['IpProtocol'],
                                                                                            [{'CidrIp': ''}],
                                                                                            [{'CidrIpv6':
                                                                                                c['CidrIp']}])

                                            # DELETE NON-DEFAULT REFERENCING SG
                                            if sg['GroupName'] != 'default':
                                                print('Deleting referencing security group %s' % sg)
                                                cloud.sg_id = sg
                                                aws.SecurityGroup.delete(cloud)

                            elif not cloud.dry:
                                print('No referencing security groups detected')

                            # DELETE NON-DEFAULT SG
                            if item['GroupName'] != 'default':
                                cloud.sg_id = item['GroupId']
                                print('Deleting security group %s' % cloud.sg_id)
                                aws.SecurityGroup.delete(cloud)

                    elif not cloud.dry:
                        print('No security groups detected')
                    aws.Vpc.delete(cloud)

            elif not cloud.dry:
                print('No VPCs found')
    except Exception as err:
        aws.Compute.handle(err)

################
# AWS SERVICES
#################


def usage():
    """
    Usage
    :return: None
    """
    text = """
   Create, configure, and manage Amazon Web Services (AWS) services across multiple
   Availability Zones: SNS, AutoScaling, ELB, VPC, and EC2 instances.

   ACTIONS
          -a --action      start | clean | cleanstart ]        (default: 'help')
        [ -w --wanted      %s %s %s %s %s ]  (default: 'vpc-instance-sns')
   ARGUMENTS
        [ -c --cidr4       <value> ]    IPv4 Cidr Block  (default: '[172.35.0.0/24, 127.36.0.0/24])'
        [ -i --image       <value> ]    Image ID         (default: 'ami-0fad7378adf284ce0')
        [ -k --keypair     <value> ]    Key Pair name    (default: 'ec2_user'
        [ -m --maxcount    <value> ]    Max instances    (default: 2)
        [ -n --name        <value> ]    Name / Tag Key   (default: 'boto3-client-sdk')
        [ -r --region      <value> ]    Cloud Region     (default 'eu-west-1)
        [ -s --sleep       True|False ] Hibernate        (default: True)
        [ -t --tag         <value> ]    Tag value        (default: 'boto3-client-sdk')
        [ -y --image-type  <value> ]    Instance Type    (default: 't2.micro')
   FLAGS
        [ -6 --ipv6 ]                   Use IpV6         (default: False)
        [ -d --debug ]
        [ -h --help ]\n""" % _SUPPORTED

    print(text)
    sys.exit(2)


def main(argv):
    opts = None
    action = None
    scope = data['cloud']['scope']
    try:
        opts, args = getopt.getopt(argv, "a:c:dhi:k:m:n:r:s:t:w:6", ["action=", "cidr4=", "debug", "help", "image=",
                                                                     "image-type=", "keypair=", "maxcount=", "name=",
                                                                     "region=", "sleep=", "tag=", "wanted=", "ipv6"])
        if not opts:
            usage()
    except getopt.GetoptError as e:
        aws.Compute.fatal(e)

    try:
        for opt, arg in opts:

            # ACTION
            if opt in ("-a", "--action",):
                action = arg
                if action not in ('start', 'clean', 'cleanstart'):
                    usage()

            elif opt in ("c", "--cidr4"):
                data['cloud']['cidr4'] = arg

            elif opt in ("-d", "--debug"):
                import logging
                log = logging.getLogger('test')
                log.warning('warn')
                log.debug('debug')
                logging.basicConfig(level=logging.DEBUG)

            elif opt in ("-h", "--help"):
                usage()

            elif opt in ("-i", "--image"):
                data['image']['ami_id'] = arg

            elif opt in ("-k", "--key-pair"):
                data['cloud']['key_pair'] = arg

            elif opt in ("-m", "--max-count"):
                data['service']['max_count'] = arg

            elif opt in ("-n", "--name"):
                data['cloud']['name'] = data['image']['name'] = data['service']['name'] = arg

            elif opt in ("-r", "--region"):
                data['cloud']['region'] = data['image']['region'] = data['service']['region'] = arg

            elif opt in ("-w", "--wanted",):
                scope = data['cloud']['scope'] = arg.lower()
                for service in arg.lower().split('-'):
                    if service not in data['cloud']['catalog']:
                        print('Unknown service %s' % service)
                        usage()

            elif opt in ("-s", "--sleep"):
                data['image']['hibernate'] = arg

            elif opt in ("-t", "--instance-type"):
                data['image']['ami_type'] = arg

            elif opt in ("-6", "--ipv6"):
                data['cloud']['ipv6'] = arg

            else:
                usage()

        # ACTION
        if 'clean' in action:
            teardown(aws.SimpleNotificationService(data))
            teardown(aws.ElasticLoadBalancing(data))
            teardown(aws.AutoScaling(data))
            teardown(aws.Compute(data))

        if 'start' in action:
            if 'sns' in scope:
                launch(aws.SimpleNotificationService(data))
            if 'instance' in scope or 'vpc' in scope:
                launch(aws.Compute(data))
            if 'elb' in scope:
                launch(aws.ElasticLoadBalancing(data))
            if 'autoscaling' in scope:
                launch(aws.AutoScaling(data))

        if 'help' in action:
            usage()

    except getopt.GetoptError as e:
        aws.Compute.fatal(e)


if __name__ == "__main__":
    try:
        main(sys.argv[1:])
    except Exception as problem:
        aws.Compute.fatal(problem)
exit(0)
