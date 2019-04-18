#!/usr/bin/env python3
#############################################
# Copyright 2019 NoelMcloughlin
#############################################

import getopt
import time
import sys
import os
try:
    sys.path.append('./lib')
    import boto3_client as sdk
except ImportError:
    sys.path.append('../lib')
    import boto3_client as sdk

all_ip4 = '0.0.0.0/0'
all_ip6 = '::/0'


def set_token(token):
    return {'mode': token['mode'], 'topic_arn': token['topic_arn'],
            'sg_id': token['sg_id'], 'subnet_id': token['subnet_id']}


def launch_aws(cloud, token):

    token = set_token(token)
    for cloud.dry in (True, False):
        try:

            #############
            # MESSAGING
            #############
            if 'SimpleNotificationService' in str(type(cloud)):
                print('%s' % ('Startup Simple Notification Service' if not cloud.dry else ''))

                if not cloud.dry:
                    print('Setup Simple Notification Service')
                    resource = sdk.SimpleNotificationServiceTopic(cloud)
                    cloud.topic_arn = token['topic_arn'] = resource.response['TopicArn']

            ###################################
            # VIRTUAL PRIVATE CLOUD & SECURITY
            ###################################
            if 'Compute' in str(type(cloud)):

                print('%s' % ('Startup Virtual Private Cloud & Security' if not cloud.dry else ''))
                resource = sdk.Vpc(cloud, True, 'default')
                if resource.response and 'Vpc' in resource.response and 'VpcId' in resource.response['Vpc']:
                    cloud.vpc_id = resource.response['Vpc']['VpcId']

                    # INTERNET GATEWAY
                    resource = sdk.InternetGateway(cloud)
                    if resource.response and 'InternetGateway' in resource.response:
                        cloud.igw_id = resource.response['InternetGateway']['InternetGatewayId']
                        resource.attach(cloud)

                        # ROUTE TABLE
                        resource = sdk.RouteTable(cloud)
                        if resource.response and 'RouteTable' in resource.response:
                            cloud.rtt_id = resource.response['RouteTable']['RouteTableId']
                            resource.create_route(cloud, 'ipv4', all_ip4)
                            resource.create_route(cloud, 'ipv6', all_ip6)

                    # SUBNET
                    resource = sdk.Subnet(cloud)
                    if resource.response and 'Subnet' in resource.response:
                        cloud.subnet_id = token['subnet_id'] = resource.response['Subnet']['SubnetId']
                        resource.modify_attr(cloud, cloud.subnet_id, True)

                        # NETWORK ACL
                        resource = sdk.NetworkAcl(cloud)
                        if resource.response and 'NetworkAcl' in resource.response:
                            cloud.acl_assoc_dict = resource.response['NetworkAcl']['Associations']
                            cloud.acl_id = resource.response['NetworkAcl']['NetworkAclId']
                            resource.create_entry(cloud, 100, 'allow', 0, 0, '6', False)
                            resource.create_entry(cloud, 101, 'allow', 0, 0, '6', True)

                            # NETWORK ACL ASSOCIATION
                            if cloud.subnet_id and cloud.acl_assoc_dict:
                                cloud.acl_association_id = cloud.acl_assoc_dict[0]['NetworkAclAssociationId']
                                sdk.NetworkAcl.replace_association(cloud, cloud.acl_id, cloud.acl_association_id)

                        # ROUTE TABLE ASSOCIATION
                        if cloud.rtt_id:
                            resource = sdk.RouteTable.associate(cloud)
                            cloud.rtt_association_id = resource['AssociationId']

                    # ELASTIC IP
                    resource = sdk.ElasticIp(cloud, 'vpc')
                    if resource.response and 'AllocationId' in resource.response:
                        cloud.eip_alloc_id = resource.response['AllocationId']

                        # NAT GATEWAY
                        # resource = sdk.NatGateway(cloud)
                        # if resource.response and 'NatGateway' in resource.response:
                        #    cloud.nat_gw_id = resource.response['NatGateway']['NatGatewayId']
    
                    # SECURITY GROUP
                    resource = sdk.SecurityGroup(cloud)
                    if resource and resource.response and 'GroupId' in resource.response:
                        cloud.sg_id = token['sg_id'] = resource.response['GroupId']
                        resource.auth_ingress(cloud, 22, 22, 'TCP', [{'CidrIp': all_ip4}], [{'CidrIpv6': all_ip6}])
                        resource.auth_egress(cloud, 22, 22, 'TCP',  [{'CidrIp': all_ip4}], [{'CidrIpv6': all_ip6}])
                        resource.auth_ingress(cloud, 80, 80, 'TCP', [{'CidrIp': all_ip4}], [{'CidrIpv6': all_ip6}])
                        resource.auth_egress(cloud, 80, 80, 'TCP',  [{'CidrIp': all_ip4}], [{'CidrIpv6': all_ip6}])
                        resource.auth_ingress(cloud, 443, 443, 'TCP', [{'CidrIp': all_ip4}], [{'CidrIpv6': all_ip6}])
                        resource.auth_egress(cloud, 443, 443, 'TCP', [{'CidrIp': all_ip4}], [{'CidrIpv6': all_ip6}])

                        # LAUNCH TEMPLATE
                        resource = sdk.LaunchTemplate(cloud)
                        if resource.response and 'LaunchTemplate' in resource.response:
                            cloud.template_id = resource.response['LaunchTemplate']['LaunchTemplateId']

                            #######################
                            # STANDARD EC2 INSTANCE
                            #######################
                            if 'Compute' in str(type(cloud)) and token['mode'] == 'instance':

                                print('%s' % ('Startup EC2 Instance' if not cloud.dry else ''))
                                resource = sdk.Instance(cloud, 1, 1)
                                if resource:
                                    cloud.instance_id = resource.response[0].id
                                    instance = cloud.compute.Instance(cloud.instance_id)
                                    print('Wait until running ...')
                                    instance.wait_until_running(Filters=[{'Name': 'instance-id',
                                                                'Values': [cloud.instance_id]}], DryRun=cloud.dry)

                                    # ELASTIC IP ASSOCIATION
                                    if cloud.eip_alloc_id:
                                        sdk.ElasticIp.associate(cloud)

                                    # NETWORK ACL ASSOCIATION
                                    if cloud.subnet_id and cloud.acl_assoc_dict:
                                        cloud.acl_association_id = cloud.acl_assoc_dict[0]['NetworkAclAssociationId']
                                        sdk.NetworkAcl.replace_association(cloud.acl_id, cloud.acl_association_id)

                                    print('created Instance %s' % ('(dry)' if cloud.dry else cloud.instance_id))
                                else:
                                    print('failed to create instance (try "-d" param to debug')

            #######################
            # AUTO SCALING GROUP
            #######################
            if 'AutoScaling' in str(type(cloud)) and token['mode'] == 'autoscaling':

                print('%s' % ('Startup AutoScaling Instances' if not cloud.dry else ''))
                if not cloud.dry:
                    cloud.topic_arn = token['topic_arn']
                    cloud.sg_id = token['sg_id']
                    cloud.subnet_id = token['subnet_id']
                    # LAUNCH CONFIGURATION
                    resource = sdk.LaunchConfiguration(cloud)
                    if resource:
                        # AUTO SCALING GROUP
                        resource = sdk.AutoScalingGroup(cloud)
                        if resource:
                            # AUTO SCALING POLICY
                            sdk.AutoScalingGroupTags(cloud)
                            resource = sdk.AutoScalingPolicy(cloud, 'TargetTrackingScaling', 90,
                                                             'ASGAverageCPUUtilization', 50)
                            if resource:
                                # AUTO SCALING NOTIFICATION
                                sdk.AutoScalingNotification(cloud, ('autoscaling:EC2_INSTANCE_LAUNCH',
                                                                    'autoscaling:EC2_INSTANCE_LAUNCH_ERROR',
                                                                    'autoscaling:EC2_INSTANCE_TERMINATE',
                                                                    'autoscaling:EC2_INSTANCE_TERMINATE_ERROR'))
        except Exception as err:
            sdk.Compute.handle(err)
    return token


def teardown_aws(cloud, token):

    token = set_token(token)

    for cloud.dry in (True, False):
        try:
            ##############################
            # SIMPLE NOTIFICATION SERVICE
            ##############################
            if 'SimpleNotificationService' in str(type(cloud)) and not cloud.dry:
                print('%s' % ('\nTeardown Simple Notification Service ' if not cloud.dry else ''))
                resources = sdk.SimpleNotificationServiceTopic.list(cloud)
                if resources and 'Topics' in resources and resources['Topics']:
                    for topic in resources['Topics']:
                        cloud.topic_arn = token['topic_arn'] = topic['TopicArn']
                        if cloud.name in str(topic['TopicArn']):
                            sdk.SimpleNotificationServiceTopic.delete(cloud)
                    print('Done')
                else:
                    print('No Simple Notification Service found')

            ######################
            # AUTO SCALING GROUPS
            ######################
            elif 'AutoScaling' in str(type(cloud)) and not cloud.dry:

                print('\nTeardown AutoScaling')
                resources = sdk.AutoScalingGroup.list(cloud)
                if resources and 'AutoScalingGroups' in resources and resources['AutoScalingGroups']:
                    for group in resources['AutoScalingGroups']:
                        cloud.asg_name = group['AutoScalingGroupName']

                        # AUTO SCALING NOTIFICATIONS
                        resource = sdk.AutoScalingNotification.list(cloud, (cloud.name,))
                        if 'NotificationConfigurations' in resource and resources['NotificationConfigurations']:
                            for notification in resource['NotificationConfigurations']:
                                cloud.topic_arn = token['topic_arn'] = notification['TopicArn']
                                sdk.AutoScalingNotification.delete(cloud)
                        elif not cloud.dry:
                            print('No auto-scaling notifications found')

                        # AUTO SCALE GROUP INSTANCES
                        resources = sdk.AutoScalingGroup.list_instances(cloud)
                        if 'AutoScalingInstances' in resources and resources['AutoScalingInstances']:
                            for instance in resources['AutoScalingInstances']:
                                if instance['AutoScalingGroupName'] == cloud.asg_name:
                                    cloud.instance_id = instance['InstanceId']
                                    sdk.Instance.delete(cloud)
                        elif not cloud.dry:
                            print('No auto-scaling instances found')

                        # AUTO SCALING GROUP TAGS
                        resources = sdk.AutoScalingGroupTags.list(cloud)
                        if resources and 'Tags' in resources and resources['Tags']:
                            for policy in resources['Tags']:
                                cloud.name = policy['Key']
                                cloud.tag = policy['Value']
                                sdk.AutoScalingGroupTags.delete(cloud)
                        elif not cloud.dry:
                            print('No auto-scaling group tags found')

                        # AUTO SCALING POLICIES
                        resources = sdk.AutoScalingPolicy.list(cloud)
                        if resources and 'ScalingPolicies' in resources and resources['ScalingPolicies']:
                            for policy in resources['ScalingPolicies']:
                                sdk.AutoScalingPolicy.delete(cloud, policy['ResourceId'])
                        elif not cloud.dry:
                            print('No auto-scaling policies found')

                        # AUTO SCALE GROUPS
                        resources = sdk.AutoScalingGroup.list(cloud)
                        if resources and 'AutoScalingGroups' in resources and resources['AutoScalingGroups']:
                            for instance in resources['AutoScalingGroups']:
                                cloud.asg_name = instance['AutoScalingGroupName']
                                sdk.AutoScalingGroup.delete(cloud, True)
                        elif not cloud.dry:
                            print('No auto-scaling groups found')

                elif not cloud.dry:
                    print('No Auto Scaling Groups found')

                # LAUNCH CONFIGURATIONS
                resources = sdk.LaunchConfiguration.list(cloud)
                if resources and 'LaunchConfigurations' in resources and resources['LaunchConfigurations']:
                    for configuration in resources['LaunchConfigurations']:
                        sdk.LaunchConfiguration.delete(cloud, configuration['LaunchConfigurationName'])
                elif not cloud.dry:
                    print('No Launch Configurations found')

            ###################################
            # VIRTUAL PRIVATE CLOUD & SECURITY
            ###################################
            elif 'Compute' in str(type(cloud)):

                print('%s' % ('Teardown VPC & Security ' if not cloud.dry else ''))
                vpcs = sdk.Vpc.list(cloud)
                if vpcs and "Vpcs" in vpcs and vpcs['Vpcs']:
                    for vpc in vpcs['Vpcs']:
                        cloud.vpc_id = vpc['VpcId']
                        print('Found: %s' % cloud.vpc_id)

                        # VPC ENDPOINTS
                        resources = sdk.VpcEndpoint.list(cloud, 'vpc-id', cloud.vpc_id)
                        if resources and 'VpcEndpoints' in resources and resources['VpcEndpoints']:
                            for endpoint in resources['VpcEndpoints']:
                                sdk.VpcEndpoint.delete(cloud, endpoint['VpcEndpointId'])
                        elif not cloud.dry:
                            print('No vpc endpoints detected')

                        # VPC PEERING CONNECTION ENDPOINTS
                        resources = sdk.VpcPeeringConnection.list(cloud)
                        if resources and 'VpcPeeringConnections' in resources and resources['VpcPeeringConnections']:
                            for endpoint in resources['VpcPeeringConnections']:
                                sdk.VpcPeeringConnection.delete(cloud, endpoint['VpcPeeringConnectionId'])
                        elif not cloud.dry:
                            print('No vpc connection endpoints detected')

                        # EC2 INSTANCES
                        resources = sdk.Instance.list(cloud, 'vpc-id', cloud.vpc_id)
                        if resources and "Reservations" in resources and resources['Reservations']:
                            for instance in resources['Reservations'][0]['Instances']:
                                cloud.instance_id = instance['InstanceId']
                                sdk.Instance.delete(cloud)
                        elif not cloud.dry:
                            print('No ec2 instances detected')

                        # ELASTIC IPS
                        elastic_ips = sdk.ElasticIp.list(cloud)
                        if elastic_ips and "Addresses" in elastic_ips and elastic_ips['Addresses']:
                            for ip in elastic_ips['Addresses']:
                                if 'AssociationId' in ip and ip['AssociationId'] != '-':
                                    sdk.ElasticIp.disassociate(cloud, ip['AllocationId'])
                                time.sleep(2)
                                sdk.ElasticIp.release(cloud, ip['AllocationId'])
                        elif not cloud.dry:
                            print('No elastic ips detected')

                        # LAUNCH TEMPLATE
                        resources = sdk.LaunchTemplate.list(cloud)
                        if resources and 'LaunchTemplates' in resources and resources['LaunchTemplates']:
                            for item in resources['LaunchTemplates']:
                                sdk.LaunchTemplate.delete(cloud, item['LaunchTemplateId'], item['LaunchTemplateName'])
                        elif not cloud.dry:
                            print('No launch templates detected')

                        # INTERNET GATEWAY
                        resources = sdk.InternetGateway.list(cloud, 'attachment.vpc-id', cloud.vpc_id)
                        if resources and "InternetGateways" in resources and resources['InternetGateways']:
                            for item in resources['InternetGateways']:
                                sdk.InternetGateway.detach(cloud, item['InternetGatewayId'], cloud.vpc_id)
                                sdk.InternetGateway.delete(cloud, item['InternetGatewayId'])
                        elif not cloud.dry:
                            print('No internet gateways detected')

                        # NETWORK INTERFACES
                        resources = sdk.NetworkInterface.list(cloud)
                        if resources and "NetworkInterfaces" in resources and resources['NetworkInterfaces']:
                            for item in resources['NetworkInterfaces']:
                                sdk.NetworkInterface.delete(cloud, item['NetworkInterfaceId'])
                        elif not cloud.dry:
                            print('No network interfaces detected')

                        # SUBNET
                        resources = sdk.Subnet.list(cloud)
                        if resources and "Subnets" in resources and resources['Subnets']:
                            for item in resources['Subnets']:
                                cloud.subnet_id = token['subnet_id'] = item['SubnetId']
                                sdk.Subnet.delete(cloud)
                        elif not cloud.dry:
                            print('No subnets detected')

                        # ROUTE TABLES
                        resources = sdk.RouteTable.list(cloud, 'vpc-id', cloud.vpc_id)
                        if resources and "RouteTables" in resources and resources['RouteTables']:
                            for item in resources['RouteTables']:
                                if item['Associations']:
                                    if item['Associations'][0]['Main']:
                                        print('Skipping main route table')
                                    else:
                                        sdk.RouteTable.disassociate(cloud,
                                                                    item['Associations'][0]['RouteTableAssociationId'])
                                        sdk.RouteTable.delete_route(cloud, cloud.cidr4, item['RouteTableId'])
                                        sdk.RouteTable.delete_route(cloud, all_ip6, item['RouteTableId'])
                                        sdk.RouteTable.delete_route(cloud, cloud.cidr4, item['RouteTableId'])
                                        sdk.RouteTable.delete(cloud, item['RouteTableId'])
                                else:
                                    sdk.RouteTable.delete(cloud, item['RouteTableId'])
                        elif not cloud.dry:
                            print('No route tables detected')

                        # NAT GATEWAY
                        resources = sdk.NatGateway.list(cloud)
                        if resources and "NatGateways" in resources and resources['NatGateways']:
                            for ngw in resources['NatGateways']:
                                sdk.NatGateway.delete(cloud, ngw['NatGatewayId'])
                        elif not cloud.dry:
                            print('No nat gateways detected')

                        # NETWORK ACL
                        resources = sdk.NetworkAcl.list(cloud)
                        if resources and "NetworkAcls" in resources and resources['NetworkAcls']:
                            for item in resources['NetworkAcls']:
                                sdk.NetworkAcl.delete_entry(cloud, item['NetworkAclId'], 100, False)
                                sdk.NetworkAcl.delete_entry(cloud, item['NetworkAclId'], 100, True)
                                sdk.NetworkAcl.delete_entry(cloud, item['NetworkAclId'], 101, False)
                                sdk.NetworkAcl.delete_entry(cloud, item['NetworkAclId'], 101, True)
                                sdk.NetworkAcl.delete(cloud, item['NetworkAclId'])
                        elif not cloud.dry:
                            print('No network acls detected')

                        # SECURITY GROUPS
                        resources = sdk.SecurityGroup.list(cloud)
                        if resources and "SecurityGroups" in resources and resources['SecurityGroups']:
                            for item in resources['SecurityGroups']:

                                # REFERENCING SECURITY GROUPS
                                refs = sdk.SecurityGroup.list_refs(cloud, (item['GroupId'],))
                                if refs and "SecurityGroupReferenceSet" in refs and refs['SecurityGroupReferenceSet']:
                                    for ref in refs['SecurityGroupReferenceSet']:
                                        for g in sdk.SecurityGroup.list(cloud, 'vpc-id', [ref[0]['ReferencingVpcId']]):
                                            sdk.SecurityGroup.revoke_ingress(cloud, 22, 22, 'TCP', g['GroupId'],
                                                                             [{'CidrIp': all_ip4}], [])
                                            sdk.SecurityGroup.revoke_ingress(cloud, 80, 80, 'TCP', g['GroupId'],
                                                                             [{'CidrIp': all_ip4}, ], [])
                                            sdk.SecurityGroup.revoke_ingress(cloud, 443, 443, 'TCP', g['GroupId'],
                                                                             [{'CidrIp': all_ip4}, ], [])
                                            sdk.SecurityGroup.revoke_egress(cloud, 22, 22, 'TCP', g['GroupId'],
                                                                            [{'CidrIp': all_ip4}, ], [])
                                            sdk.SecurityGroup.revoke_egress(cloud, 80, 80, 'TCP', g['GroupId'],
                                                                            [{'CidrIp': all_ip4}, ], [])
                                            sdk.SecurityGroup.revoke_egress(cloud, 443, 443, 'TCP', g['GroupId'],
                                                                            [{'CidrIp': all_ip4}, ], [])
                                            if g['GroupName'] != 'default':
                                                time.sleep(5)
                                                print('Deleting referencing security group %s' % g['GroupId'])
                                                sdk.SecurityGroup.delete(cloud, g['GroupId'])
                                elif not cloud.dry:
                                    print('No referencing security groups detected')

                                if item['GroupName'] != 'default':
                                    cloud.sg_id = token['sg_id'] = item['GroupId']
                                    print('Deleting security group %s' % cloud.sg_id)
                                    sdk.SecurityGroup.delete(cloud, cloud.sg_id)
                        elif not cloud.dry:
                            print('No security groups detected')
                        sdk.Vpc.delete(cloud, cloud.vpc_id)
                elif not cloud.dry:
                    print('No VPCs found')
        except Exception as err:
            sdk.Compute.handle(err)

    return token


def usage():
    print("\n%s Usage:" % os.path.basename(__file__))
    print("\n\t  -a --action\t\tstart | clean | cleanstart")
    print("\n\t[ -m --mode\t\tinstance | autoscaling ]\t (default: 'instance')")
    print("\n\t[ -n --name\t\t<value> ]\tTag Key\t\t (default: 'ec2_user')")
    print("\t[ -i --image\t\t<value> ]\tImage ID\t (default: 'ami-0fad7378adf284ce0')")
    print("\t[ -y --instance-type\t<value> ]\tInstance Type\t (default: 't2.micro')")
    print("\t[ -h --hibernate\tTrue|False ]\tHibernate\t (default: True)")
    print("\t[ -t --tag\t\t<value> ]\tTag value\t (default: 'boto3-client-sdk')")
    print("\t[ -z --region\t\t<value> ]\tCloud Region\t (default 'eu-west-1)")
    print("\t[ -c --cidr\t\t<value> ]\tIPv4 Cidr Block\t (default: '172.35.0.0/24'")
    print("\t[ -k --keypair\t\t<value> ]\tKey Pair name\t (default: 'ec2_user'")
    print("\t[ -d --debug ]\t\t\t\tDebug logging\t (default: off)")
    print("\n")
    sys.exit(2)


def main(argv):
    opts = None
    try:
        opts, args = getopt.getopt(argv, "a:i:y:h:n:t:r:c:dk:m:", ["action=", "image=", "instance-type=", "sleep=",
                                                                   "name=", "tag=", "region=", "cidr=", "debug",
                                                                   "keypair=", "mode="])
    except getopt.GetoptError as e:
        sdk.Compute.fatal(e)
    
    action = 'help'
    zone = 'eu-west-1a'
    region = 'eu-west-1'
    name = 'boto3-client-sdk'
    tag = 'boto3-client-sdk'
    cidr4 = '172.35.0.0/24'
    key = 'ec2_user'
    ami_id = 'ami-0fad7378adf284ce0'
    ami_type = 't2.micro'
    sleep = True
    token = {'mode': 'instance', 'topic_arn': None, 'sg_id': None, 'subnet_id': None}

    for opt, arg in opts:
        if opt in ("-a", "--action",):
            action = arg.lower()
            if action not in ('start', 'clean', 'cleanstart',):
                usage()
        elif opt in ("-m", "--mode",):
            token.update({'mode': arg.lower()})
        elif opt in ("-n", "--name"):
            name = arg()
        elif opt in ("-i", "--image"):
            ami_id = arg()
        elif opt in ("-y", "--instance-type"):
            ami_type = arg()
        elif opt in ("-t", "--tag"):
            tag = arg()
        elif opt in ("-c", "--cidr"):
            cidr4 = arg()
        elif opt in ("-r", "--region"):
            region = arg.lower()
        elif opt in ("-k", "--keypair"):
            key = arg()
        elif opt in ("-s", "--sleep"):
            sleep = arg()
        elif opt in ("-d", "--debug"):
            import logging
            log = logging.getLogger('test')
            log.warning('warn')
            log.debug('debug')
            logging.basicConfig(level=logging.DEBUG)
        else:
            usage()

    if not opts:
        usage()

    # interface
    if 'clean' in action:
        token = teardown_aws(sdk.SimpleNotificationService(name, tag, region, zone, key), token)
        token = teardown_aws(sdk.Compute(name, tag, region, zone, key, cidr4), token)
        teardown_aws(sdk.AutoScaling(name, tag, region, zone, key, cidr4), token)

    if 'start' in action:
        if 'instance' in token['mode']:
            launch_aws(sdk.Compute(name, tag, region, zone, key, cidr4, ami_id, ami_type, sleep), token)
        elif 'autoscaling' in token['mode']:
            token = launch_aws(sdk.SimpleNotificationService(name, tag, region, zone, key), token)
            token = launch_aws(sdk.Compute(name, tag, region, zone, key, cidr4, ami_id, ami_type, sleep), token)
            launch_aws(sdk.AutoScaling(name, tag, region, zone, key, cidr4, ami_id, ami_type), token)
        else:
            usage()


if __name__ == "__main__":
    try:
        main(sys.argv[1:])
    except Exception as problem:
        sdk.Compute.fatal(problem)
exit(0)
