#!/usr/bin/env python3
#############################################
# Copyright 2019 noelmcloughlin
#############################################

import getopt
import time
import sys
import os
try:
    sys.path.append(('./lib', './data'))
    import boto3_client as aws
    import sitedata as data
except ImportError:
    sys.path.append(('../lib', '../data'))
    import boto3_client as aws
    import sitedata as data

# GLOBALS
scope = data['service']['scope']
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
        if 'sns' in scope and 'SimpleNotificationService' in str(type(cloud)):
            print('\nStartup Simple Notification Service')
            resource = aws.SimpleNotificationServiceTopic(data)
            data['service']['topic_arn'] = resource.response['TopicArn']

        ###################################
        # VIRTUAL PRIVATE CLOUD & SECURITY
        ###################################
        if 'vpc' in scope and 'Compute' in str(type(cloud)):
            print('\nStartup Virtual Private Cloud & Security')
            resource = aws.Vpc(data)
            if resource.response and 'Vpc' in resource.response and 'VpcId' in resource.response['Vpc']:
                cloud.vpc_id = data['id']['vpc_id'] = resource.response['Vpc']['VpcId']

                # INTERNET GATEWAY
                resource = aws.InternetGateway(data)
                if resource.response and 'InternetGateway' in resource.response:
                    cloud.igw_id = data['id']['igw_id'] = resource.response['InternetGateway']['InternetGatewayId']
                    resource.attach(cloud)

                    # ROUTE TABLE
                    cloud.rtt_ids = []
                    resource = aws.RouteTable(data)
                    if resource.response and 'RouteTable' in resource.response:
                        cloud.rtt_id = data['id']['rtt_id'] = resource.response['RouteTable']['RouteTableId']
                        cloud.rtt_ids.append(cloud.rtt_id)
                        resource.create_route(cloud, 'ipv4', all_ip4)
                        resource.create_route(cloud, 'ipv6', all_ip6)

                # SUBNETS
                cloud.subnet_ids = data['service']['subnet_ids'] = []
                for i in range(len(cloud.cidr4)):
                    resource = aws.Subnet(data, cloud.cidr4[i], cloud.zones[i])
                    if resource.response and 'Subnet' in resource.response:
                        subnet_id = resource.response['Subnet']['SubnetId']
                        cloud.subnet_ids.append(subnet_id)
                        resource.modify_attr(cloud, subnet_id, True)

                        # ROUTE TABLE ASSOCIATIONS
                        for j in range(len(cloud.rtt_ids)):
                            cloud.rtt_id = cloud.rtt_ids[j]
                            aws.RouteTable.associate(cloud, subnet_id)

                # NETWORK ACL
                cloud.acl_ids = data['id']['acl_ids'] = []
                for i in range(len(cloud.network_acls)):
                    resource = aws.NetworkAcl(data)
                    if resource.response and 'NetworkAcl' in resource.response:
                        cloud.acl_id = data['id']['acl_id'] = resource.response['NetworkAcl']['NetworkAclId']
                        cloud.acl_ids.append(cloud.acl_id)
                        resource.create_entry(cloud, cloud.cidr4[i], 100+i, 'allow', 0, 0, '6', False)
                        resource.create_entry(cloud, cloud.cidr4[i], 101+i, 'allow', 0, 0, '6', True)

                        # NETWORK ACL ASSOCIATION
                        assoc_id = resource.response['NetworkAcl']['Associations'][0]['NetworkAclAssociationId']
                        aws.NetworkAcl.replace_association(cloud, assoc_id)

                # ELASTIC IP
                cloud.eip_ids = []
                for i in range(cloud.max_count):
                    resource = aws.ElasticIp(cloud, 'vpc')
                    if resource.response and 'AllocationId' in resource.response:
                        cloud.eip_ids.append(resource.response['AllocationId'])

                    # NAT GATEWAY
                    cloud.nat_gw_ids = []
                    # cloud.nat_gw_ids.append(aws.NatGateway(cloud).response['NatGateway']['NatGatewayId'])

                # SECURITY GROUP
                cloud.sg_ids = []
                resource = aws.SecurityGroup(cloud)
                if resource and resource.response and 'GroupId' in resource.response:
                    cloud.sg_id = resource.response['GroupId']
                    cloud.sg_ids.append(cloud.sg_id)
                    resource.auth_ingress(cloud, 22, 22, 'TCP', [{'CidrIp': all_ip4}], [{'CidrIpv6': all_ip6}])
                    resource.auth_egress(cloud, 22, 22, 'TCP',  [{'CidrIp': all_ip4}], [{'CidrIpv6': all_ip6}])
                    resource.auth_ingress(cloud, 80, 80, 'TCP', [{'CidrIp': all_ip4}], [{'CidrIpv6': all_ip6}])
                    resource.auth_egress(cloud, 80, 80, 'TCP',  [{'CidrIp': all_ip4}], [{'CidrIpv6': all_ip6}])
                    resource.auth_ingress(cloud, 443, 443, 'TCP', [{'CidrIp': all_ip4}], [{'CidrIpv6': all_ip6}])
                    resource.auth_egress(cloud, 443, 443, 'TCP', [{'CidrIp': all_ip4}], [{'CidrIpv6': all_ip6}])

                    # LAUNCH TEMPLATE
                    cloud.template_ids = []
                    resource = aws.LaunchTemplate(cloud)
                    if resource.response and 'LaunchTemplate' in resource.response:
                        cloud.template_id = resource.response['LaunchTemplate']['LaunchTemplateId']
                        cloud.template_ids.append(cloud.template_id)

                        ################
                        # EC2 INSTANCE
                        ###############
                        if 'instance' in scope:
                            print('Startup EC2 Instance')
                            resource = aws.Instance(cloud, 1, cloud.max_count)
                            if resource:
                                cloud.instance_ids = []
                                for i in range(cloud.max_count):
                                    cloud.instance_id = resource.response[i].id
                                    cloud.instance_ids.append(cloud.instance_id)

                                    # ELASTIC IP ASSOCIATION
                                    if cloud.eip_alloc_ids:
                                        aws.ElasticIp.associate(cloud, cloud.eip_alloc_ids[i])

                                print('Wait until running ...')
                                instance = cloud.compute.Instance(cloud.instance_id)
                                instance.wait_until_running(Filters=[{'Name': 'instance-id',
                                                                      'Values': [cloud.instance_id]}],
                                                            DryRun=cloud.dry)
                                print('created Instance %s' % cloud.instance_id)
            else:
                print('failed to create instance (try "-d" param to debug')

        #########################
        # ELASTIC LOAD BALANCING
        #########################
        elif 'ElasticLoadBalancing' in str(type(cloud)) and 'elb' in scope and cloud.sg_ids and cloud.subnet_ids:
            cloud.lb_arns = []
            print('\nStartup Elastic Load Balancer')
            resource = aws.LoadBalancer(cloud, 'dualstack', 'application', 'internet-facing')
            if resource and 'LoadBalancers' in resource and resource['LoadBalancers']:
                for i in range(len(resource['LoadBalancers'])):
                    cloud.lb_arns.append(resource['LoadBalancers'][i]['LoadBalancerArn'])
                print('elb created')
            else:
                print('failed to created ELB instance')

        #############################################################################
        # AUTO-SCALING, LAUNCH CONFIGURATION, GROUPS, TAGS, POLICIES, NOTIFICATIONS
        #############################################################################
        elif 'AutoScaling' in str(type(cloud)) and 'autoscaling' in scope:
            print('\nStartup AutoScaling Instances')
            aws.LaunchConfiguration(cloud, data)
            aws.AutoScalingGroup(cloud, cloud.max_count-2, cloud.max_count, None)
            aws.AutoScalingGroupTags(cloud, 'auto-scaling-group')
            aws.AutoScalingPolicy(cloud, 'TargetTrackingScaling', 90, 'ASGAverageCPUUtilization', 50)
            aws.AutoScalingNotification(cloud, ('autoscaling:EC2_INSTANCE_LAUNCH',
                                                'autoscaling:EC2_INSTANCE_LAUNCH_ERROR',
                                                'autoscaling:EC2_INSTANCE_TERMINATE',
                                                'autoscaling:EC2_INSTANCE_TERMINATE_ERROR'))

        ###################
        # GLOBAL DATA
        ###################
        data['compute']['acl_ids'] = cloud.acl_ids
        data['compute']['eip_ids'] = cloud.eips_ids
        data['compute']['igw_ids'] = cloud.igw_ids
        data['compute']['nat_gw_ids'] = cloud.nat_gw_ids
        # data['compute']['peer_vpc_id'] = cloud.peer_vpc_id
        data['compute']['lb_arns'] = cloud.lb_arns
        data['compute']['rtt_ids'] = cloud.rtt_ids

        data['service']['instance_ids'] = cloud.instance_ids
        data['service']['sg_ids'] = cloud.sg_ids
        data['service']['subnet_ids'] = cloud.subnet_ids
        data['service']['template_ids'] = cloud.template_ids

    except Exception as err:
        aws.Compute.handle(err)
    return cloud


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
        if 'SimpleNotificationService' in str(type(cloud)) and 'sns' in scope:
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
        if 'AutoScaling' in str(type(cloud)) and 'autoscaling' in scope:
            print('\nTeardown AutoScaling')
            resources = aws.AutoScalingGroup.list(cloud)
            if resources and 'AutoScalingGroups' in resources and resources['AutoScalingGroups']:
                for group in resources['AutoScalingGroups']:
                    cloud.asg_name = group['AutoScalingGroupName']

                    # AUTO SCALING NOTIFICATIONS
                    resource = aws.AutoScalingNotification.list(cloud, (cloud.name,))
                    if 'NotificationConfigurations' in resource and resources['NotificationConfigurations']:
                        for notification in resource['NotificationConfigurations']:
                            cloud.topic_arn = notification['TopicArn']
                            aws.AutoScalingNotification.delete(cloud)
                    else:
                        print('No auto-scaling notifications found')

                    # AUTO SCALE GROUP INSTANCES
                    resources = aws.AutoScalingGroup.list_instances(cloud)
                    if 'AutoScalingInstances' in resources and resources['AutoScalingInstances']:
                        for instance in resources['AutoScalingInstances']:
                            if instance['AutoScalingGroupName'] == cloud.asg_name:
                                cloud.instance_id = instance['InstanceId']
                                data.update({'instance_id': cloud.instanace_id})
                                aws.Instance.delete(cloud)
                    else:
                        print('No auto-scaling instances found')

                    # AUTO SCALING GROUP TAGS
                    resources = aws.AutoScalingGroupTags.list(cloud)
                    if resources and 'Tags' in resources and resources['Tags']:
                        for policy in resources['Tags']:
                            cloud.name = policy['Key']
                            cloud.tag = policy['Value']
                            data.update({'name': cloud.name, 'tag': cloud.tag})
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

                    # AUTO SCALE GROUPS
                    resources = aws.AutoScalingGroup.list(cloud)
                    if resources and 'AutoScalingGroups' in resources and resources['AutoScalingGroups']:
                        for instance in resources['AutoScalingGroups']:
                            cloud.asg_name = instance['AutoScalingGroupName']
                            data.update({'asg_name': cloud.asg_name})
                            aws.AutoScalingGroup.delete(cloud, True)
                    else:
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
        if 'ElasticLoadBalancing' in str(type(cloud)) and 'elb' in scope:
            print('\nTeardown Elastic Load Balancer')
            resources = aws.LoadBalancer.list(cloud)
            if resources and 'LoadBalancers' in resources and resources['LoadBalancers']:
                for elb in resources['LoadBalancers']:
                    cloud.elb_arn = elb['LoadBalancerArn']
                    data.update({'elb_arn': cloud.elb_arn})
                    aws.LoadBalancer.delete(cloud)
            else:
                print('No Elastic Load Balancer found')

        ###################################
        # VIRTUAL PRIVATE CLOUD & SECURITY
        ###################################
        if 'Compute' in str(type(cloud)) and ('vpc' in scope or 'instance' in scope):
            print('%s' % ('Teardown VPC & Security ' if not cloud.dry else ''))
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
                    instance_ids = []
                    resources = aws.Instance.list(cloud, 'vpc-id', vpc['VpcId'])
                    if resources and "Reservations" in resources and resources['Reservations']:
                        for instance in resources['Reservations'][0]['Instances']:
                            cloud.instance_id = instance['InstanceId']
                            instance_ids.append(cloud.instance_id)
                            aws.Instance.delete(cloud)
                        data.update({'instance_id': instance_ids})
                    elif not cloud.dry:
                        print('No ec2 instances detected')

                    # ELASTIC IPS
                    elastic_ips = aws.ElasticIp.list(cloud)
                    if elastic_ips and "Addresses" in elastic_ips and elastic_ips['Addresses']:
                        for ip in elastic_ips['Addresses']:
                            if 'AssociationId' in ip and ip['AssociationId'] != '-':
                                aws.ElasticIp.disassociate(cloud, ip['AllocationId'])
                            time.sleep(2)
                            aws.ElasticIp.release(cloud, ip['AllocationId'])
                    elif not cloud.dry:
                        print('No elastic ips detected')

                    # LAUNCH TEMPLATE
                    resources = aws.LaunchTemplate.list(cloud)
                    if resources and 'LaunchTemplates' in resources and resources['LaunchTemplates']:
                        for item in resources['LaunchTemplates']:
                            aws.LaunchTemplate.delete(cloud, item['LaunchTemplateId'], item['LaunchTemplateName'])
                    elif not cloud.dry:
                        print('No launch templates detected')

                    # INTERNET GATEWAY
                    resources = aws.InternetGateway.list(cloud, 'attachment.vpc-id', vpc['VpcId'])
                    if resources and "InternetGateways" in resources and resources['InternetGateways']:
                        for item in resources['InternetGateways']:
                            aws.InternetGateway.detach(cloud, item['InternetGatewayId'], vpc['VpcId'])
                            aws.InternetGateway.delete(cloud, item['InternetGatewayId'])
                    elif not cloud.dry:
                        print('No internet gateways detected')

                    # NETWORK INTERFACES
                    resources = aws.NetworkInterface.list(cloud)
                    if resources and "NetworkInterfaces" in resources and resources['NetworkInterfaces']:
                        for item in resources['NetworkInterfaces']:
                            aws.NetworkInterface.delete(cloud, item['NetworkInterfaceId'])
                    elif not cloud.dry:
                        print('No network interfaces detected')

                    # SUBNET
                    subnet_ids = []
                    resources = aws.Subnet.list(cloud)
                    if resources and "Subnets" in resources and resources['Subnets']:
                        for item in resources['Subnets']:
                            cloud.subnet_id = data['subnet_id'] = item['SubnetId']
                            subnet_ids.append(cloud.subnet_id)
                            aws.Subnet.delete(cloud)
                        data.update({'subnet_ids': subnet_ids})
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

                            # REFERENCING SECURITY GROUPS
                            refs = aws.SecurityGroup.list_refs(cloud, item['GroupId'])
                            if refs and "SecurityGroupReferenceSet" in refs and refs['SecurityGroupReferenceSet']:
                                for ref in refs['SecurityGroupReferenceSet']:
                                    for g in aws.SecurityGroup.list(cloud, 'vpc-id', [ref[0]['ReferencingVpcId']]):
                                        cloud.sg_id = g['GroupId']
                                        aws.SecurityGroup.revoke_ingress(cloud, 22, 22, 'TCP',
                                                                         [{'CidrIp': all_ip4}], [{'CidrIpv6', '::/0'}])
                                        aws.SecurityGroup.revoke_ingress(cloud, 80, 80, 'TCP',
                                                                         [{'CidrIp': all_ip4}], [{'CidrIpv6', '::/0'}])
                                        aws.SecurityGroup.revoke_ingress(cloud, 443, 443, 'TCP',
                                                                         [{'CidrIp': all_ip4}], [{'CidrIpv6', '::/0'}])
                                        aws.SecurityGroup.revoke_egress(cloud, 22, 22, 'TCP',
                                                                        [{'CidrIp': all_ip4}], [{'CidrIpv6', '::/0'}])
                                        aws.SecurityGroup.revoke_egress(cloud, 80, 80, 'TCP',
                                                                        [{'CidrIp': all_ip4}], [{'CidrIpv6', '::/0'}])
                                        aws.SecurityGroup.revoke_egress(cloud, 443, 443, 'TCP',
                                                                        [{'CidrIp': all_ip4}], [{'CidrIpv6', '::/0'}])

                                        # WE CAN DELETE NON-DEFAULT REFERENCING SG's ONLY!!!
                                        if g['GroupName'] != 'default':
                                            time.sleep(5)
                                            print('Deleting referencing security group %s' % cloud.sg_id)
                                            aws.SecurityGroup.delete(cloud)

                            elif not cloud.dry:
                                print('No referencing security groups detected')

                            # WE CAN DELETE NON-DEFAULT SG's ONLY!!!
                            if item['GroupName'] != 'default':
                                cloud.sg_id = data['sg_id'] = item['GroupId']
                                print('Deleting security group %s' % cloud.sg_id)
                                aws.SecurityGroup.delete(cloud)

                    elif not cloud.dry:
                        print('No security groups detected')
                    aws.Vpc.delete(cloud)

                data.update({'vpc_ids': vpc_ids})
            elif not cloud.dry:
                print('No VPCs found')
    except Exception as err:
        aws.Compute.handle(err)

    return data

################
# AWS SERVICES
#################


def usage():
    """
    Usage
    :return: None
    """
    print("\n%s Usage:" % os.path.basename(__file__))
    print("\n\t  -a --action\t\tstart | clean | cleanstart\n")
    print("\t[ -c --cidr4\t\t<value> ]\tIPv4 Cidr Block\t (default: '[172.35.0.0/24, 127.36.0.0/24]'")
    print("\t[ -d --debug ]\t\t\t\tDebug logging\t (default: off)")
    print("\t[ -h --help ]\t\t\t\tDisplay help")
    print("\t[ -i --image\t\t<value> ]\tImage ID\t (default: 'ami-0fad7378adf284ce0')")
    print("\t[ -k --keypair\t\t<value> ]\tKey Pair name\t (default: 'ec2_data'")
    print("\t[ -m --maxcount\t\t<value> ]\tMax number of instances to launch\t (default: 1)")
    print("\t[ -n --name\t\t<value> ]\tTag Key\t\t (default: 'ec2_data')")
    print("\t[ -r --region\t\t<value> ]\tCloud Region\t (default 'eu-west-1)")
    print("\t[ -s --services\t\t \" %s &| %s &| %s &| %s &| %s \" ]\t (default: 'sns-vpc-instance')" % _SUPPORTED)
    print("\t\t\t\tA valid string combination of AWS service keywords.\n")
    print("\t[ -s --sleep\tTrue|False ]\tHibernate\t (default: True)")
    print("\t[ -t --tag\t\t<value> ]\tTag value\t (default: 'boto3-client-aws')")
    print("\t[ -y --instance-type\t<value> ]\tInstance Type\t (default: 't2.micro')")
    print("\t[ -4 --ipv4 ]\t\t\t\tUse IpV4\t (default: True)")
    print("\t[ -6 --ipv6 ]\t\t\t\tUse IpV6\t (default: False)")
    print("\n")
    sys.exit(2)


def main(argv, data):
    opts = None
    action = 'help'
    try:
        opts, args = getopt.getopt(argv, "a:c:dhi:k:m:n:r:s:t:y:46", ["action=", "cidr4=", "debug", "help", "image=",
                                                                      "keypair=", "maxcount=", "name=", "region=",
                                                                      "services=", "sleep=", "tag=", "instance-type=",
                                                                      "ipv4", "ipv6"])
    except getopt.GetoptError as e:
        aws.Compute.fatal(e)

    try:
        data = data['init']
        for opt, arg in opts:

            # ACTION
            if opt in ("-a", "--action",):
                if action not in ('start', 'clean', 'cleanstart'):
                    usage()

            elif opt in ("c", "--cidr4"):
                data['cloud']['cidr4'] = arg()

            elif opt in ("-d", "--debug"):
                import logging
                log = logging.getLogger('test')
                log.warning('warn')
                log.debug('debug')
                logging.basicConfig(level=logging.DEBUG)

            elif opt in ("-h", "--help"):
                usage()

            elif opt in ("-i", "--image"):
                data['image']['ami_id'] = arg()

            elif opt in ("-k", "--key-pair"):
                data['cloud']['key_pair'] = arg()

            elif opt in ("-m", "--max-count"):
                data['service']['max_count'] = arg()

            elif opt in ("-n", "--name"):
                data['cloud']['name'] = data['image']['name'] = data['service']['name'] = arg()

            elif opt in ("-r", "--region"):
                data['cloud']['region'] = data['image']['region'] = data['service']['region'] = arg()

            elif opt in ("-s", "--services",):
                data['service']['scope'] = arg().lower()
                for service in data['service']['request']:
                    if service not in data['cloud']['catalog'].split():
                        print('Unknown service %s' % service)
                        usage()

            elif opt in ("-s", "--sleep"):
                data['image']['hibernate'] = arg()

            elif opt in ("-t", "--instance-type"):
                data['image']['ami_type'] = arg()

            elif opt in ("-4", "--cidr4"):
                data['cloud']['cidr4'] = arg()

            elif opt in ("-6", "--cidr4"):
                data['cloud']['cidr6'] = arg()

            else:
                usage()
            if not (opts and data['services']):
                usage()

        # ACTION
        if 'clean' in action:
            teardown(aws.SimpleNotificationService(data))
            teardown(aws.Compute(data))
            teardown(aws.AutoScaling(data))
            teardown(aws.ElasticLoadBalancing(data))

        if 'start' in action:
            if 'sns' in data['scope']:
                launch(aws.SimpleNotificationService(data))
            if 'instance' in data['scope'] or 'vpc' in data['scope']:
                launch(aws.Compute(data))
            if 'elb' in data['scope']:
                launch(aws.ElasticLoadBalancing(data))
            if 'autoscaling' in data['scope']:
                launch(aws.AutoScaling(data))

    except getopt.GetoptError as e:
        aws.Compute.fatal(e)


if __name__ == "__main__":
    try:
        main(sys.argv[1:], data)
    except Exception as problem:
        aws.Compute.fatal(problem)
exit(0)
