#!/usr/bin/env python3

import getopt
import time
import sys
import os
sys.path.append('./lib')

import boto3_ec2_client as sdk

def launch_compute_vpc_instance(compute='ec2', name='boto3-client-sdk', zone='eu-west-1', cidr_block='172.35.0.0/24'):
    try:
        cloud = sdk.Compute(compute, zone, name, cidr_block)
        for dry in (True, False):
            print("\nCreate Compute instance in VPC%s" % (' [dry]' if dry else ', please be patient'))

            # VPC
            compute = sdk.Vpc(cloud, cloud.cidr_block, True, 'default', dry)
            if compute and 'Vpc' in compute:
                vpc_id = compute['Vpc']['VpcId']
                if vpc_id:

                    acl_id = None
                    eip_id = None
                    rtt_id = None
                    subnet_id = None

                    # INTERNET GATEWAY
                    compute = sdk.InternetGateway(cloud, dry)
                    if compute and 'InternetGateway' in compute:
                        igw_id = compute['InternetGateway']['InternetGatewayId']
                        compute.attach(cloud, igw_id, vpc_id, dry)
    
                        # ROUTE TABLE
                        compute = sdk.RouteTable(cloud, vpc_id, dry)
                        if compute and 'RouteTable' in compute:
                            rtt_id = compute['RouteTable']['RouteTableId']
                            compute.create_route(cloud, 'ipv4', '0.0.0.0/0', igw_id, rtt_id, dry)
                            sdk.Compute.servce.create_route(cloud, 'ipv6', '::/0', igw_id, rtt_id, dry)

                    # SUBNET
                    compute = sdk.SubNet(cloud, vpc_id, dry)
                    if compute and 'Subnet' in compute:
                        subnet_id = compute['Subnet']['SubnetId']
                        compute.modify_attr(cloud, subnet_id, True, dry)
    
                        # NETWORK ACL
                        compute = sdk.NetworkAcl(cloud, vpc_id, dry)
                        if compute and 'NetworkAcl' in compute:
                            acl_associations_dict = compute['NetworkAcl']['Associations']
                            acl_id = compute['NetworkAcl']['NetworkAclId']
                            compute.create_entry(cloud, acl_id, 1, 'allow', cloud.cidr_block, '6', 0, 0, False, dry)
                            compute.create_entry(cloud, acl_id, 1, 'allow', cloud.cidr_block, '6', 0, 0, True, dry)

                            # NETWORK ACL ASSOCIATION
                            if subnet_id and acl_associations_dict:
                                acl_association_id = acl_associations_dict[0]['NetworkAclAssociationId']
                                compute = sdk.NetworkAcl.replace_association(cloud, acl_id, acl_association_id, dry)

                        # ROUTE TABLE ASSOCIATION
                        if rtt_id:
                            compute = sdk.RouteTable.associate(cloud, rtt_id, subnet_id, dry)

                    # ELASTIC IP
                    compute = sdk.ElasticIp(cloud, 'vpc', dry)
                    if compute and 'AllocationId' in compute:
                        eip_id = compute['AllocationId']

                        # NAT GATEWAY
                        #compute = sdk.NatGateway(cloud, eip_id, subnet_id, dry)
                        #if compute and 'NatGateway' in compute:
                        #    nat_gw_id = compute['NatGateway']['NatGatewayId']
    
                    # SECURITY GROUP
                    compute = sdk.SecurityGroup(cloud, cloud.tagval, cloud.tagval, dry)
                    if compute and 'GroupId' in compute:
                        sg_id = compute['GroupId']
                        compute.auth_ingress(cloud,  22,  22, 'TCP', sg_id, [{'CidrIp': '0.0.0.0/0'}],
                                             [{'CidrIpv6': '::/0'}], dry)
                        compute.auth_ingress(cloud,  80,  80, 'TCP', sg_id, [{'CidrIp': '0.0.0.0/0'}],
                                             [{'CidrIpv6': '::/0'}], dry)
                        compute.auth_ingress(cloud, 443, 443, 'TCP', sg_id, [{'CidrIp': '0.0.0.0/0'}],
                                             [{'CidrIpv6': '::/0'}], dry)
                        compute.auth_egress(cloud,   22,  22, 'TCP', sg_id, [{'CidrIp': '0.0.0.0/0'}],
                                            [{'CidrIpv6': '::/0'}], dry)
                        compute.auth_egress(cloud,   80,  80, 'TCP', sg_id, [{'CidrIp': '0.0.0.0/0'}],
                                            [{'CidrIpv6': '::/0'}], dry)
                        compute.auth_egress(cloud,  443, 443, 'TCP', sg_id, [{'CidrIp': '0.0.0.0/0'}],
                                            [{'CidrIpv6': '::/0'}], dry)
    
                        # LAUNCH TEMPLATE
                        compute = sdk.LaunchTemplate(cloud, dry, cloud.tag, cloud.tagval, subnet_id, [sg_id])
                        if compute and 'LaunchTemplate' in compute:
                            template_id = compute['LaunchTemplate']['LaunchTemplateId']

                            # INSTANCE
                            compute = sdk.Instance(cloud, template_id, 1, 1, dry)
                            if compute:
                                instance_id = compute[0].id
                                if instance_id:
                                    compute = cloud.compute.Instance(instance_id)
                                    compute.wait_until_running(Filters=[{'Name': 'instance-id',
                                                                         'Values': [instance_id]}], DryRun=dry)
    
                                    # ELASTIC IP ASSOCIATION
                                    if eip_id:
                                        compute = sdk.ElasticIp.associate(cloud, eip_id, instance_id, dry)

                                    # NETWORK ACL ASSOCIATION
                                    if subnet_id and acl_associations_dict:
                                        acl_association_id = acl_associations_dict[0]['NetworkAclAssociationId']
                                        compute = sdk.NetworkAcl.replace_association(cloud, acl_id, acl_association_id, dry)
    
                                    print('created Instance %s %s' % (instance_id, ('(dry)' if dry else instance_id)))
        else:
            print('No VPCs found')
    except Exception as err:
            sdk.Compute.handle(err, compute)


def teardown_compute_vpc_instances(compute='ec2', name='boto3-client-sdk', zone='eu-west-1', cidr_block='172.35.0.0/24'):
    items = None
    try:
        cloud = sdk.Compute(compute, zone, name, cidr_block)
        for dry in (True, False):
            print("\nTear down EC2 instance and VPC%s" % (' [dry]' if dry else ', please be patient'))

            # VPC
            vpcs = items = sdk.Vpc.list(cloud, cloud.tag, cloud.tagval, dry)
            if vpcs and "Vpcs" in vpcs and vpcs['Vpcs']:
                for vpc in vpcs['Vpcs']:
                    vpc_id = vpc['VpcId']
                    print('Found: %s' % vpc_id)

                    # VPC ENDPOINTS
                    items = sdk.VpcEndPoint.list(cloud, cloud.tag, [cloud.tagval], dry)
                    if items and 'VpcEndpoints' in items and items['VpcEndpoints']:
                        for endpoint in items['VpcEndpoints']:
                            sdk.VpcEndPoint.delete(endpoint['VpcEndpointId'], dry)
                    else:
                        print('No vpc endpoints detected')

                    # VPC PEERING CONNECTION ENDPOINTS
                    items = sdk.VpcPeeringConnection.list(cloud, cloud.tag, [cloud.tagval], dry)
                    if items and 'VpcPeeringConnections' in items and items['VpcPeeringConnections']:
                        for endpoint in items['VpcPeeringConnections']:
                            sdk.VpcPeeringConnection.delete(cloud, endpoint['VpcPeeringConnectionId'], dry)
                    else:
                        print('No vpc connection endpoints detected')

                    # EC2 INSTANCES
                    items = sdk.Instance.list(cloud, cloud.tag, [cloud.tagval], dry)
                    if items and "Reservations" in items and items['Reservations']:
                        for instance in items['Reservations'][0]['Instances']:
                            instance_id = instance['InstanceId']

                            # ELASTIC IPS
                            eips = sdk.ElasticIp.list(cloud, cloud.tag, [cloud.tagval], dry)
                            if eips and "Addresses" in eips and eips['Addresses']:
                                for ip in eips['Addresses']:
                                    if ip['AssociationId'] and ip['AssociationId'] != '-':
                                        sdk.ElasticIp.disassociate(cloud, ip['AssociationId'], dry)
                                    sdk.ElasticIp.release(cloud, ip['AllocationId'], ip['PublicIp'], dry)
                            else:
                                print('No elastic ips detected')
                            instance.delete(cloud.compute.Instance(instance_id), [instance_id], dry)
                    else:
                        print('No ec2 instances detected')

                    # Dangling elastic ips
                    items = sdk.ElasticIp.list(cloud, cloud.tag, [cloud.tagval], dry)
                    if items and "Addresses" in items and items['Addresses']:
                        for ip in items['Addresses']:
                            if 'AssociationId' in ip and ip['AssociationId']:
                                sdk.ElasticIp.disassociate(cloud, ip['AssociationId'], dry)
                            sdk.ElasticIp.release(cloud, ip['AllocationId'], ip['PublicIp'], dry)

                    # INSTANCE TEMPLATES
                    items = sdk.LaunchTemplate.list(cloud, cloud.tag, [cloud.tagval], dry)
                    if items and 'LaunchTemplates' in items and items['LaunchTemplates']:
                        for item in items['LaunchTemplates']:
                            sdk.LaunchTemplate.delete(cloud, item['LaunchTemplateId'], item['LaunchTemplateName'],
                                                      dry)
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
                    items = sdk.NetworkInterface.list(cloud, cloud.tag, [cloud.tagval], None, dry)
                    if items and "NetworkInterfaces" in items and items['NetworkInterfaces']:
                        for item in items['NetworkInterfaces']:
                            sdk.NetworkInterface.delete(cloud, item['NetworkInterfaceId'], dry)
                    else:
                        print('No network interfaces detected')

                    # SUBNETS
                    items = sdk.SubNet.list(cloud, cloud.tag, [cloud.tagval], dry)
                    if items and "Subnets" in items and items['Subnets']:
                        for item in items['Subnets']:
                            sdk.SubNet.delete(cloud, item['SubnetId'], dry)
                    else:
                        print('No subnets detected')

                    # ROUTE TABLES
                    items = sdk.RouteTable.list(cloud, cloud.tag, [cloud.tagval], 'association.main', False, dry)
                    if items and "RouteTables" in items and items['RouteTables']:
                        for item in items['RouteTables']:
                            if item['Associations']:
                                if item['Associations'][0]['Main']:
                                    print('Skipping main route table')
                                else:
                                    sdk.RouteTable.disassociate(cloud,
                                                                item['Associations'][0]['RouteTableAssociationId'], dry)
                                    sdk.RouteTable.delete_route(cloud, '0.0.0.0/0', item['RouteTableId'], dry)
                                    sdk.RouteTable.delete_route(cloud, '::/0', item['RouteTableId'], dry)
                                    sdk.RouteTable.delete_route(cloud, cidr_block, item['RouteTableId'], dry)
                                    sdk.RouteTable.delete(cloud, item['RouteTableId'], dry)
                            else:
                                sdk.RouteTable.delete(cloud, item['RouteTableId'], dry)
                    else:
                        print('No route tables detected')

                    # NAT GATEWAY
                    items = sdk.NatGateway.list(cloud, cloud.tag, [cloud.tagval], dry)
                    if items and "NatGateways" in items and items['NatGateways']:
                        for ngw in items['NatGateways']:
                            sdk.NatGateway.delete(cloud, ngw['NatGatewayId'], dry)
                    else:
                        print('No nat gateways detected')

                    # NETWORK ACL
                    items = sdk.NetworkAcl.list(cloud, cloud.tag, [cloud.tagval], dry)
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
                    items = sdk.SecurityGroup.list(cloud, cloud.tag, [cloud.tagval], dry)
                    if items and "SecurityGroups" in items and items['SecurityGroups']:
                        for item in items['SecurityGroups']:

                            # REFERENCING SECURITY GROUPS
                            refs = sdk.SecurityGroup.list_refs(cloud, [item['GroupId']], dry)
                            if refs and "SecurityGroupReferenceSet" in refs and refs['SecurityGroupReferenceSet']:
                                for ref in refs['SecurityGroupReferenceSet']:
                                    for g in sdk.SecurityGroup.list(cloud, 'vpc-id', [ref[0]['ReferencingVpcId']], dry):
                                        sdk.SecurityGroup.revoke_ingress(cloud, 22, 22, 'TCP', g['GroupId'],
                                                                         [{'CidrIp': '0.0.0.0/0'} ], [], dry)
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
            else:
                print('No VPCs found')
    except Exception as err:
        sdk.Compute.handle(err, items)


def usage():
    print("\n%s Usage:" % os.path.basename(__file__))
    print("\n\t-a --action\tstart | clean ")
    print("\n\t[ -n --name\tPrivate Cloud Name (default: 'boto3-client-sdk')")
    print("\n\t[ -z --zone\tAvailability Zone (default 'eu-west-1'")
    print("\n\t[ -c --cidr\tIPv4 Cidr Block (default: '10.10.0.0/24'")
    print("\n")
    sys.exit(2)


def main(argv):
    opts = None
    try:
        opts, args = getopt.getopt(argv, "a:n:z:c", ["action=", "name", "zone", "cidr"])
    except getopt.GetoptError as e:
        sdk.Compute.handle(e)
    
    if not opts:
        usage()

    cloud = 'ec2'
    name = 'boto3-client-sdk'
    zone = 'eu-west-1'
    cidr_block_ipv4 = '10.10.0.0/24'
    action = None

    for opt, arg in opts:
        if opt in ("-a", "--action",):
            action = arg.lower()
        elif opt in ("-n", "name"):
            name = arg()
        elif opt in ("-z", "-zone"):
            zone = arg.lower()
        elif opt in ("-c", "-cidr"):
            cidr_block_ipv4 = arg()
        else:
            usage()
    
    # workflow
    if action == "start":
        launch_compute_vpc_instance(cloud, name, zone, cidr_block_ipv4)
    elif action == "clean":
        teardown_compute_vpc_instances(cloud, name, zone, cidr_block_ipv4)
    else:
        usage()
    
    if __name__ == "__main__":
        try:
            main(sys.argv[1:])
        except Exception as err:
            sdk.Compute.handle(err)
    exit(0)
