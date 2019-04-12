#!/usr/bin/env python3

import getopt
import time
import sys
import os
try:
    sys.path.append('./lib')
    import boto3_ec2_client as sdk
except:
    sys.path.append('../lib')
    import boto3_ec2_client as sdk


def launch_compute_vpc_instance(service='ec2', name='boto3-client-sdk', region='eu-west-1', zone='eu-west-1a',
                                cidr_block='172.35.0.0/24'):
    compute = None
    try:
        cloud = sdk.Compute(service, region, zone, name, cidr_block)
        for dry in (True, False):
            print("\nCreate Compute instance in VPC%s" % ' [dry]' if dry else ', please be patient')

            # VPC
            compute = sdk.Vpc(cloud.cidr_block, True, 'default', dry)
            if compute.response and 'Vpc' in compute.response:
                vpc_id = compute.response['Vpc']['VpcId']
                if vpc_id:

                    acl_id = None
                    rtt_id = None
                    subnet_id = None
                    eip_alloc_id = None
                    acl_associations_dict = None

                    # INTERNET GATEWAY
                    compute = sdk.InternetGateway(dry)
                    if compute and compute.response and 'InternetGateway' in compute.response:
                        igw_id = compute.response['InternetGateway']['InternetGatewayId']
                        compute.attach(igw_id, vpc_id, dry)
    
                        # ROUTE TABLE
                        compute = sdk.RouteTable(vpc_id,  dry)
                        if compute and compute.response and 'RouteTable' in compute.response:
                            rtt_id = compute.response['RouteTable']['RouteTableId']
                            compute.create_route('ipv4', '0.0.0.0/0', igw_id, rtt_id, dry)
                            compute.create_route('ipv6', '::/0', igw_id, rtt_id, dry)

                    # SUBNET
                    compute = sdk.Subnet(vpc_id, dry)
                    if compute and compute.response and 'Subnet' in compute.response:
                        subnet_id = compute.response['Subnet']['SubnetId']
                        compute.modify_attr(subnet_id, True)

                        # NETWORK ACL
                        compute = sdk.NetworkAcl(vpc_id, dry)
                        if compute and compute.response and 'NetworkAcl' in compute.response:
                            acl_associations_dict = compute.response['NetworkAcl']['Associations']
                            acl_id = compute.response['NetworkAcl']['NetworkAclId']
                            compute.create_entry(acl_id, 1, 'allow', cloud.cidr_block, 0, 0, '6', False, dry)
                            compute.create_entry(acl_id, 1, 'allow', cloud.cidr_block, 0, 0, '6', True, dry)

                            # NETWORK ACL ASSOCIATION
                            if subnet_id and acl_associations_dict:
                                acl_association_id = acl_associations_dict[0]['NetworkAclAssociationId']
                                compute = sdk.NetworkAcl.replace_association(acl_id, acl_association_id, dry)

                        # ROUTE TABLE ASSOCIATION
                        if rtt_id:
                            compute = sdk.RouteTable.associate(cloud, rtt_id, subnet_id, dry)

                    # ELASTIC IP
                    compute = sdk.ElasticIp('vpc', dry)
                    if compute and compute.response and 'AllocationId' in compute.response:
                        eip_alloc_id = compute.response['AllocationId']

                        # NAT GATEWAY
                        # compute = sdk.NatGateway(eip_alloc_id, subnet_id, dry)
                        # if compute and compute.response and 'NatGateway' in compute.response:
                        #    nat_gw_id = compute.response['NatGateway']['NatGatewayId']
    
                    # SECURITY GROUP
                    compute = sdk.SecurityGroup(cloud.desc, cloud.desc, vpc_id, dry)
                    if compute and compute.response and 'GroupId' in compute.response:
                        sg_id = compute.response['GroupId']
                        compute.auth_ingress(22,  22, 'TCP', sg_id, [{'CidrIp': '0.0.0.0/0'}], [{'CidrIpv6': '::/0'}])
                        compute.auth_ingress(80,  80, 'TCP', sg_id, [{'CidrIp': '0.0.0.0/0'}], [{'CidrIpv6': '::/0'}])
                        compute.auth_ingress(443, 443, 'TCP', sg_id, [{'CidrIp': '0.0.0.0/0'}], [{'CidrIpv6': '::/0'}])
                        compute.auth_egress(22,  22, 'TCP', sg_id, [{'CidrIp': '0.0.0.0/0'}], [{'CidrIpv6': '::/0'}])
                        compute.auth_egress(80,  80, 'TCP', sg_id, [{'CidrIp': '0.0.0.0/0'}], [{'CidrIpv6': '::/0'}])
                        compute.auth_egress(443, 443, 'TCP', sg_id, [{'CidrIp': '0.0.0.0/0'}], [{'CidrIpv6': '::/0'}])

                        # GET AVAILABILITY ZONE
                        items = sdk.Subnet.list(cloud, 'subnet-id', [subnet_id], dry)
                        if items and "Subnets" in items and items['Subnets']:
                            zone = items['Subnets'][0]['AvailabilityZone']
                            compute.update_availability_zone(zone)

                        # LAUNCH TEMPLATE
                        compute = sdk.LaunchTemplate(dry, 'launch-template-tag', cloud.desc, zone)
                        if compute and compute.response and 'LaunchTemplate' in compute.response:
                            template_id = compute.response['LaunchTemplate']['LaunchTemplateId']

                            # INSTANCE
                            compute = sdk.Instance(template_id, subnet_id, [sg_id], zone, 1, 1)
                            if compute and compute.instance_id:
                                instance_id = compute.instance_id
                                instance = cloud.compute.Instance(instance_id)
                                instance.wait_until_running(Filters=[{'Name': 'instance-id', 'Values': [instance_id]}],
                                                            DryRun=dry)
                                compute.create_tag(instance_id, 'instance-tag', cloud.desc, dry)

                                # ELASTIC IP ASSOCIATION
                                if eip_alloc_id:
                                    sdk.ElasticIp.associate(cloud, eip_alloc_id, instance_id, dry)

                                # NETWORK ACL ASSOCIATION
                                if subnet_id and acl_associations_dict:
                                    acl_association_id = acl_associations_dict[0]['NetworkAclAssociationId']
                                    compute = sdk.NetworkAcl.replace_association(acl_id, acl_association_id, dry)
    
                                print('created Instance %s %s' % (instance_id, ('(dry)' if dry else instance_id)))
                            else:
                                print('failed to create instance (try "-d" param to debug')
    except Exception as err:
            sdk.Compute.handle(err, compute)


def teardown_compute_vpc_instances(service='ec2', name='boto3-client-sdk', region='eu-west-1', zone='eu-west-1a',
                                   cidr_block='172.35.0.0/24'):
    try:
        cloud = sdk.Compute(service, region, zone, name, cidr_block)
        for dry in (True, False):
            print("\nTear down EC2 instance and VPC%s" % (' [dry]' if dry else ', please be patient'))

            # VPC
            vpcs = sdk.Vpc.list(cloud, 'tag:vpc-tag', [cloud.desc], dry)
            if vpcs and "Vpcs" in vpcs and vpcs['Vpcs']:
                for vpc in vpcs['Vpcs']:
                    vpc_id = vpc['VpcId']
                    print('Found: %s' % vpc_id)

                    # VPC ENDPOINTS
                    items = sdk.VpcEndpoint.list(cloud, 'vpc-id', [vpc_id], dry)
                    if items and 'VpcEndpoints' in items and items['VpcEndpoints']:
                        for endpoint in items['VpcEndpoints']:
                            sdk.VpcEndpoint.delete(cloud, endpoint['VpcEndpointId'], dry)
                    else:
                        print('No vpc endpoints detected')

                    # VPC PEERING CONNECTION ENDPOINTS
                    items = sdk.VpcPeeringConnection.list(cloud, 'tag:vpc-peering-connection-tag', [cloud.desc], dry)
                    if items and 'VpcPeeringConnections' in items and items['VpcPeeringConnections']:
                        for endpoint in items['VpcPeeringConnections']:
                            sdk.VpcPeeringConnection.delete(cloud, endpoint['VpcPeeringConnectionId'], dry)
                    else:
                        print('No vpc connection endpoints detected')

                    # EC2 INSTANCES
                    items = sdk.Instance.list(cloud, 'vpc-id', [vpc_id], None, None, dry)
                    if items and "Reservations" in items and items['Reservations']:
                        for instance in items['Reservations'][0]['Instances']:
                            instance_id = instance['InstanceId']
                            sdk.Instance.delete(cloud.compute.Instance(instance_id), [instance_id], dry)

                            # ELASTIC IPS
                            eips = sdk.ElasticIp.list(cloud, 'tag:elastic-ip-tag', [cloud.desc], dry)
                            if eips and "Addresses" in eips and eips['Addresses']:
                                for ip in eips['Addresses']:
                                    if 'AssociationId' in ip and ip['AssociationId'] != '-':
                                        sdk.ElasticIp.disassociate(cloud, ip['AllocationId'], dry)
                                    time.sleep(2)
                                    sdk.ElasticIp.release(cloud, ip['AllocationId'], dry)
                            else:
                                print('No elastic ips detected')
                    else:
                        print('No ec2 instances detected')

                    # INSTANCE TEMPLATES
                    items = sdk.LaunchTemplate.list(cloud, 'tag:launch-template-tag', [cloud.desc], dry)
                    if items and 'LaunchTemplates' in items and items['LaunchTemplates']:
                        for item in items['LaunchTemplates']:
                            sdk.LaunchTemplate.delete(cloud, item['LaunchTemplateId'], item['LaunchTemplateName'], dry)
                    else:
                        print('No launch templates detected')

                    # INTERNET GATEWAY
                    items = sdk.InternetGateway.list(cloud, 'attachment.vpc-id', [vpc_id, ], dry)
                    if items and "InternetGateways" in items and items['InternetGateways']:
                        for item in items['InternetGateways']:
                            sdk.InternetGateway.detach(cloud, item['InternetGatewayId'], vpc_id, dry)
                            sdk.InternetGateway.delete(cloud, item['InternetGatewayId'], dry)
                    else:
                        print('No internet gateways detected')

                    # NETWORK INTERFACES
                    items = sdk.NetworkInterface.list(cloud, 'tag:network-interface-tag', [cloud.desc], dry)
                    if items and "NetworkInterfaces" in items and items['NetworkInterfaces']:
                        for item in items['NetworkInterfaces']:
                            sdk.NetworkInterface.delete(cloud, item['NetworkInterfaceId'], dry)
                    else:
                        print('No network interfaces detected')

                    # SUBNET
                    items = sdk.Subnet.list(cloud, 'tag:subnet-tag', [cloud.desc], dry)
                    if items and "Subnets" in items and items['Subnets']:
                        for item in items['Subnets']:
                            sdk.Subnet.delete(cloud, item['SubnetId'], dry)
                    else:
                        print('No subnets detected')

                    # ROUTE TABLES
                    items = sdk.RouteTable.list(cloud, 'vpc-id', [vpc_id], dry)
                    if items and "RouteTables" in items and items['RouteTables']:
                        for item in items['RouteTables']:
                            if item['Associations']:
                                if item['Associations'][0]['Main']:
                                    print('Skipping main route table')
                                else:
                                    sdk.RouteTable.disassociate(cloud,
                                                                item['Associations'][0]['RouteTableAssociationId'], dry)
                                    sdk.RouteTable.delete_route(cloud, cidr_block, item['RouteTableId'], dry)
                                    sdk.RouteTable.delete_route(cloud, '::/0', item['RouteTableId'], dry)
                                    sdk.RouteTable.delete_route(cloud, cidr_block, item['RouteTableId'], dry)
                                    sdk.RouteTable.delete(cloud, item['RouteTableId'], dry)
                            else:
                                sdk.RouteTable.delete(cloud, item['RouteTableId'], dry)
                    else:
                        print('No route tables detected')

                    # NAT GATEWAY
                    items = sdk.NatGateway.list(cloud, 'tag:nat-gateway-tag', [cloud.desc])
                    if items and "NatGateways" in items and items['NatGateways']:
                        for ngw in items['NatGateways']:
                            sdk.NatGateway.delete(cloud, ngw['NatGatewayId'], dry)
                    else:
                        print('No nat gateways detected')

                    # NETWORK ACL
                    items = sdk.NetworkAcl.list(cloud, 'tag:network-acl-tag', [cloud.desc], dry)
                    if items and "NetworkAcls" in items and items['NetworkAcls']:
                        for item in items['NetworkAcls']:
                            sdk.NetworkAcl.delete_entry(cloud, item['NetworkAclId'], 1, False, dry)
                            sdk.NetworkAcl.delete_entry(cloud, item['NetworkAclId'], 1, True, dry)
                            sdk.NetworkAcl.delete_entry(cloud, item['NetworkAclId'], 2, False, dry)
                            sdk.NetworkAcl.delete_entry(cloud, item['NetworkAclId'], 2, True, dry)
                            sdk.NetworkAcl.delete(cloud, item['NetworkAclId'], dry)
                    else:
                        print('No network acls detected')

                    # SECURITY GROUPS
                    items = sdk.SecurityGroup.list(cloud, 'tag:security-group-tag', [cloud.desc], dry)
                    if items and "SecurityGroups" in items and items['SecurityGroups']:
                        for item in items['SecurityGroups']:

                            # REFERENCING SECURITY GROUPS
                            refs = sdk.SecurityGroup.list_refs(cloud, [item['GroupId']], dry)
                            if refs and "SecurityGroupReferenceSet" in refs and refs['SecurityGroupReferenceSet']:
                                for ref in refs['SecurityGroupReferenceSet']:
                                    for g in sdk.SecurityGroup.list(cloud, 'vpc-id', [ref[0]['ReferencingVpcId']], dry):
                                        sdk.SecurityGroup.revoke_ingress(cloud, 22, 22, 'TCP', g['GroupId'],
                                                                         [{'CidrIp': '0.0.0.0/0'}], [], dry)
                                        sdk.SecurityGroup.revoke_ingress(cloud, 80, 80, 'TCP', g['GroupId'],
                                                                         [{'CidrIp': '0.0.0.0/0'}, ], [], dry)
                                        sdk.SecurityGroup.revoke_ingress(cloud, 443, 443, 'TCP', g['GroupId'],
                                                                         [{'CidrIp': '0.0.0.0/0'}, ], [], dry)
                                        sdk.SecurityGroup.revoke_egress(cloud, 22, 22, 'TCP', g['GroupId'],
                                                                        [{'CidrIp': '0.0.0.0/0'}, ], [], dry)
                                        sdk.SecurityGroup.revoke_egress(cloud, 80, 80, 'TCP', g['GroupId'],
                                                                        [{'CidrIp': '0.0.0.0/0'}, ], [], dry)
                                        sdk.SecurityGroup.revoke_egress(cloud, 443, 443, 'TCP', g['GroupId'],
                                                                        [{'CidrIp': '0.0.0.0/0'}, ], [], dry)
                                        if g['GroupName'] != 'default':
                                            time.sleep(5)
                                            print('Deleting referencing security group %s' % g['GroupId'])
                                            sdk.SecurityGroup.delete(cloud, g['GroupId'], dry)
                            else:
                                print('No referencing security groups detected')
                            if item['GroupName'] != 'default':
                                print('Deleting security group %s' % item['GroupId'])
                                sdk.SecurityGroup.delete(cloud, item['GroupId'], dry)
                    else:
                        print('No security groups detected')
                    sdk.Vpc.delete(cloud, vpc_id, dry)
            else:
                print('No VPCs found')
    except Exception as err:
        sdk.Compute.handle(err)


def usage():
    print("\n%s Usage:" % os.path.basename(__file__))
    print("\n\t-a --action\tstart | clean ")
    print("\n\t[ -n --name\tPrivate Cloud Name (default: 'boto3-client-sdk')")
    print("\n\t[ -z --region\tCloud Region (default 'eu-west-1)")
    print("\n\t[ -c --cidr\tIPv4 Cidr Block (default: '172.35.0.0/24'")
    print("\n\t[ -d --debug\tTurn on Debug logging (default: off)")
    print("\n")
    sys.exit(2)


def main(argv):
    opts = None
    try:
        opts, args = getopt.getopt(argv, "a:n:r:c:d", ["action=", "name", "region", "cidr", "debug"])
    except getopt.GetoptError as e:
        sdk.Compute.fatal(e)
    
    if not opts:
        usage()

    zone = 'eu-west-1a'
    region = 'eu-west-1'
    name = 'boto3-client-sdk'
    # region_fqdn = 'com.amazonaws.eu-west-1.ec2'
    cloud_service = 'ec2'
    cidr_block_ipv4 = '172.35.0.0/24'
    action = None

    for opt, arg in opts:
        if opt in ("-a", "--action",):
            action = arg.lower()
        elif opt in ("-n", "--name"):
            name = arg()
        elif opt in ("-c", "--cidr"):
            cidr_block_ipv4 = arg()
        elif opt in ("-r", "--region"):
            region = arg.lower()
            # region_fqdn = 'com.amazonaws.' + region + '.' + cloud_service
        elif opt in ("-d", "--debug"):
            import logging
            log = logging.getLogger('test')
            log.warning('warn')
            log.debug('debug')
            logging.basicConfig(level=logging.DEBUG)
        else:
            usage()
    
    # workflow
    if action == "start":
        launch_compute_vpc_instance(cloud_service, name, region, zone, cidr_block_ipv4)
    elif action == "clean":
        teardown_compute_vpc_instances(cloud_service, name, region, cidr_block_ipv4)
    else:
        usage()


if __name__ == "__main__":
    try:
        main(sys.argv[1:])
    except Exception as problem:
        sdk.Compute.fatal(problem)
exit(0)
