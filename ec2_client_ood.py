#!/usr/bin/env python3

import getopt
import time
import sys
import os
try:
    sys.path.append('./lib')
    import boto3_ec2_client as sdk
except ImportError:
    sys.path.append('../lib')
    import boto3_ec2_client as sdk

all_ip4 = '0.0.0.0/0'
all_ip6 = '::/0'


def launch_compute_vpc_instance(cloud):
    try:
        for cloud.dry in (True, False):

            # VPC
            resource = sdk.Vpc(cloud, True, 'default')
            if resource and resource.response and 'Vpc' in resource.response and 'VpcId' in resource.response['Vpc']:
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
                    cloud.subnet_id = resource.response['Subnet']['SubnetId']
                    resource.modify_attr(cloud, cloud.subnet_id, True)

                    # NETWORK ACL
                    resource = sdk.NetworkAcl(cloud)
                    if resource.response and 'NetworkAcl' in resource.response:
                        cloud.acl_associations_dict = resource.response['NetworkAcl']['Associations']
                        cloud.acl_id = resource.response['NetworkAcl']['NetworkAclId']
                        resource.create_entry(cloud, 100, 'allow', 0, 0, '6', False)
                        resource.create_entry(cloud, 101, 'allow', 0, 0, '6', True)

                        # NETWORK ACL ASSOCIATION
                        if cloud.subnet_id and cloud.acl_associations_dict:
                            cloud.acl_association_id = cloud.acl_associations_dict[0]['NetworkAclAssociationId']
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
                if resource.response and 'GroupId' in resource.response:
                    cloud.sg_id = resource.response['GroupId']
                    resource.auth_ingress(cloud, 22, 22, 'TCP', [{'CidrIp': all_ip4}], [{'CidrIpv6': all_ip6}])
                    resource.auth_egress(cloud, 22, 22, 'TCP',  [{'CidrIp': all_ip4}], [{'CidrIpv6': all_ip6}])
                    resource.auth_ingress(cloud, 80, 80, 'TCP', [{'CidrIp': all_ip4}], [{'CidrIpv6': all_ip6}])
                    resource.auth_egress(cloud, 80, 80, 'TCP',  [{'CidrIp': all_ip4}], [{'CidrIpv6': all_ip6}])
                    resource.auth_ingress(cloud, 443, 443, 'TCP', [{'CidrIp': all_ip4}], [{'CidrIpv6': all_ip6}])
                    resource.auth_egress(cloud, 443, 443, 'TCP', [{'CidrIp': all_ip4}], [{'CidrIpv6': all_ip6}])

                    # GET AVAILABILITY ZONE
                    resources = sdk.Subnet.list(cloud, 'subnet-id', cloud.subnet_id)
                    if resources and 'Subnets' in resources and resources['Subnets']:
                        cloud.zone = resources['Subnets'][0]['AvailabilityZone']

                    # LAUNCH TEMPLATE
                    resource = sdk.LaunchTemplate(cloud)
                    if resource.response and 'LaunchTemplate' in resource.response:
                        cloud.template_id = resource.response['LaunchTemplate']['LaunchTemplateId']

                        # INSTANCE
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
                            if cloud.subnet_id and cloud.acl_associations_dict:
                                cloud.acl_association_id = cloud.acl_associations_dict[0]['NetworkAclAssociationId']
                                sdk.NetworkAcl.replace_association(cloud.acl_id, cloud.acl_association_id)

                            print('created Instance %s' % ('(dry)' if cloud.dry else cloud.instance_id))
                        else:
                            print('failed to create instance (try "-d" param to debug')
    except Exception as err:
        sdk.Compute.handle(err)


def teardown_compute_vpc_instances(cloud):
    try:
        for dry in (True, False):
            cloud.dry = dry

            # VPC
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
                    else:
                        print('No vpc endpoints detected')

                    # VPC PEERING CONNECTION ENDPOINTS
                    resources = sdk.VpcPeeringConnection.list(cloud)
                    if resources and 'VpcPeeringConnections' in resources and resources['VpcPeeringConnections']:
                        for endpoint in resources['VpcPeeringConnections']:
                            sdk.VpcPeeringConnection.delete(cloud, endpoint['VpcPeeringConnectionId'])
                    else:
                        print('No vpc connection endpoints detected')

                    # EC2 INSTANCES
                    resources = sdk.Instance.list(cloud, 'vpc-id', cloud.vpc_id)
                    if resources and "Reservations" in resources and resources['Reservations']:
                        for instance in resources['Reservations'][0]['Instances']:
                            cloud.instance_id = instance['InstanceId']
                            sdk.Instance.delete(cloud)
                    else:
                        print('No ec2 instances detected')

                    # ELASTIC IPS
                    elastic_ips = sdk.ElasticIp.list(cloud)
                    if elastic_ips and "Addresses" in elastic_ips and elastic_ips['Addresses']:
                        for ip in elastic_ips['Addresses']:
                            if 'AssociationId' in ip and ip['AssociationId'] != '-':
                                sdk.ElasticIp.disassociate(cloud, ip['AllocationId'])
                            time.sleep(2)
                            sdk.ElasticIp.release(cloud, ip['AllocationId'])
                    else:
                        print('No elastic ips detected')

                    # INSTANCE TEMPLATES
                    resources = sdk.LaunchTemplate.list(cloud)
                    if resources and 'LaunchTemplates' in resources and resources['LaunchTemplates']:
                        for item in resources['LaunchTemplates']:
                            sdk.LaunchTemplate.delete(cloud, item['LaunchTemplateId'], item['LaunchTemplateName'])
                    else:
                        print('No launch templates detected')

                    # INTERNET GATEWAY
                    resources = sdk.InternetGateway.list(cloud, 'attachment.vpc-id', cloud.vpc_id)
                    if resources and "InternetGateways" in resources and resources['InternetGateways']:
                        for item in resources['InternetGateways']:
                            sdk.InternetGateway.detach(cloud, item['InternetGatewayId'], cloud.vpc_id)
                            sdk.InternetGateway.delete(cloud, item['InternetGatewayId'])
                    else:
                        print('No internet gateways detected')

                    # NETWORK INTERFACES
                    resources = sdk.NetworkInterface.list(cloud)
                    if resources and "NetworkInterfaces" in resources and resources['NetworkInterfaces']:
                        for item in resources['NetworkInterfaces']:
                            sdk.NetworkInterface.delete(cloud, item['NetworkInterfaceId'])
                    else:
                        print('No network interfaces detected')

                    # SUBNET
                    resources = sdk.Subnet.list(cloud)
                    if resources and "Subnets" in resources and resources['Subnets']:
                        for item in resources['Subnets']:
                            sdk.Subnet.delete(cloud, item['SubnetId'])
                    else:
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
                                    sdk.RouteTable.delete_route(cloud, cloud.cidr_block, item['RouteTableId'])
                                    sdk.RouteTable.delete_route(cloud, all_ip6, item['RouteTableId'])
                                    sdk.RouteTable.delete_route(cloud, cloud.cidr_block, item['RouteTableId'])
                                    sdk.RouteTable.delete(cloud, item['RouteTableId'])
                            else:
                                sdk.RouteTable.delete(cloud, item['RouteTableId'])
                    else:
                        print('No route tables detected')

                    # NAT GATEWAY
                    resources = sdk.NatGateway.list(cloud)
                    if resources and "NatGateways" in resources and resources['NatGateways']:
                        for ngw in resources['NatGateways']:
                            sdk.NatGateway.delete(cloud, ngw['NatGatewayId'])
                    else:
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
                    else:
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
                            else:
                                print('No referencing security groups detected')
                            if item['GroupName'] != 'default':
                                print('Deleting security group %s' % item['GroupId'])
                                sdk.SecurityGroup.delete(cloud, item['GroupId'])
                    else:
                        print('No security groups detected')
                    sdk.Vpc.delete(cloud, cloud.vpc_id)
            else:
                print('No VPCs found %s' % "[dry] if cloud.dry else ''")
    except Exception as err:
        sdk.Compute.handle(err)


def usage():
    print("\n%s Usage:" % os.path.basename(__file__))
    print("\n\t  -a --action\t\tstart | clean | cleanstart")
    print("\n\t[ -n --name\t\t<value>\t\tTag Key (default: 'ec2')")
    print("\n\t[ -i --image\t\t<value>\t\tImage ID (default: 'ami-0fad7378adf284ce0')")
    print("\n\t[ -y --instance-type\t<value>\t\tInstance Type (default: 't2.micro')")
    print("\n\t[ -h --hibernate\tTrue|False\tEnable instance hibernation (default: True)")
    print("\n\t[ -t --tag\t\t<value>\t\tTag (default: 'boto3-client-sdk')")
    print("\n\t[ -z --region\t\t<value>\t\tCloud Region (default 'eu-west-1)")
    print("\n\t[ -c --cidr\t\t<value>\t\tIPv4 Cidr Block (default: '172.35.0.0/24'")
    print("\n\t[ -k --keypair\t\t<value>\t\tKey Pair name (default: 'ec2_user'")
    print("\n\t[ -d --debug\t\t\t\tDebug logging (default: off)")
    print("\n")
    sys.exit(2)


def main(argv):
    opts = None
    try:
        opts, args = getopt.getopt(argv, "a:i:y:h:n:t:r:c:dk:", ["action=", "image", "instance-type", "hibernate",
                                                                  "name", "tag", "region", "cidr", "debug", "keypair"])
    except getopt.GetoptError as e:
        sdk.Compute.fatal(e)
    
    if not opts:
        usage()

    zone = 'eu-west-1a'
    region = 'eu-west-1'
    name = 'boto3-client-sdk'
    tag = 'boto3-client-sdk'
    cidr_block_ipv4 = '172.35.0.0/24'
    key_pair = 'ec2_user'
    ami_id = 'ami-0fad7378adf284ce0'
    instance_type = 't2.micro'
    hibernate = True

    action = None
    for opt, arg in opts:
        if opt in ("-a", "--action",):
            action = arg.lower()
        elif opt in ("-n", "--name"):
            name = arg()
        elif opt in ("-i", "--image"):
            ami_id = arg()
        elif opt in ("-y", "--instance-type"):
            instance_type = arg()
        elif opt in ("-t", "--tag"):
            tag = arg()
        elif opt in ("-c", "--cidr"):
            cidr_block_ipv4 = arg()
        elif opt in ("-r", "--region"):
            region = arg.lower()
        elif opt in ("-k", "--keypair"):
            key_pair = arg()
        elif opt in ("-s", "--sleep"):
            hibernate = arg()
        elif opt in ("-d", "--debug"):
            import logging
            log = logging.getLogger('test')
            log.warning('warn')
            log.debug('debug')
            logging.basicConfig(level=logging.DEBUG)
        else:
            usage()
    if action not in ('start', 'clean', 'cleanstart',):
        usage()

    # workflow
    cloud = sdk.Compute(name, tag, region, zone, key_pair, cidr_block_ipv4, ami_id, instance_type, hibernate)
    if 'clean' in action:
        teardown_compute_vpc_instances(cloud)
    if 'start' in action:
        launch_compute_vpc_instance(cloud)


if __name__ == "__main__":
    try:
        main(sys.argv[1:])
    except Exception as problem:
        sdk.Compute.fatal(problem)
exit(0)
