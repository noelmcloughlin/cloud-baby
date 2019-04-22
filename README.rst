================
public-cloud-cli
================

AWS
===

Boto3 Client SDK
======

   $ ./aws_service_client_ood.py --help

   Create, configure, and manage Amazon Web Services (AWS) services across multiple
   Availability Zones: SNS, AutoScaling, ELB, VPC, and EC2 instances.
 
   ACTIONS
 	  -a --action	   start | clean | cleanstart ]		(default: 'help')
 	[ -w --wanted	  sns vpc elb autoscaling instance ]	(default: 'vpc-instance')
   ARGUMENTS
 	[ -c --cidr4	   <value> ]	IPv4 Cidr Block	 (default: '[172.35.0.0/24, 127.36.0.0/24])'
 	[ -i --image	   <value> ]	Image ID	 (default: 'ami-0fad7378adf284ce0')
 	[ -k --keypair	   <value> ]	Key Pair name	 (default: 'ec2_data'
 	[ -m --maxcount	   <value> ]	Max instances	 (default: 2)
 	[ -n --name	   <value> ]	Tag Key		 (default: 'ec2_data')
 	[ -r --region	   <value> ]	Cloud Region	 (default 'eu-west-1)
 	[ -s --sleep	   True|False ] Hibernate	 (default: True)
 	[ -t --tag	   <value> ]	Tag value	 (default: 'boto3-client-aws')
 	[ -y --image-type  <value> ]	Instance Type	 (default: 't2.micro')
   FLAGS
 	[ -6 --ipv6 ]			Use IpV6	 (default: False)
 	[ -d --debug ]
 	[ -h --help ]


Create tagged secure EC2/SNS/VPC service with four instances::

     $ ./aws_service_client_ood.py -a start

        Startup Simple Notification Service
        Create SNS topic  boto3-client-sdk
        
        Startup Virtual Private Cloud & Security
        Create VPC boto3-client-sdk
        Create tag boto3-client-sdk = boto3-client-sdk for vpc-098b2fa5ee724352c 
        Create internet gateway 
        Create tag boto3-client-sdk = boto3-client-sdk for igw-013cd2de19cd970ff 
        Attach igw-013cd2de19cd970ff to vpc-098b2fa5ee724352c 
        Create route table for vpc-098b2fa5ee724352c 
        Create tag boto3-client-sdk = boto3-client-sdk for rtb-071bb1bce1a2a8176 
        Create ipv4 route for 0.0.0.0/0 
        Create ipv6 route for ::/0 
        Create subnet for 10.0.0.0/25 
        Create tag boto3-client-sdk = boto3-client-sdk for subnet-08b06ebcbdf1cb1ec 
        Map subnet-08b06ebcbdf1cb1ec public-ip-on-launch
        Associate route table rtb-071bb1bce1a2a8176 to subnet-08b06ebcbdf1cb1ec 
        Create network acl for vpc-098b2fa5ee724352c 
        Create tag boto3-client-sdk = boto3-client-sdk for acl-0a0588f83ca9819a9 
        Create network acl entry for acl-0a0588f83ca9819a9 10.0.0.0/25 
        Create network acl entry for acl-0a0588f83ca9819a9 10.0.0.0/25 
        Create subnet for 10.0.0.128/25 
        Create tag boto3-client-sdk = boto3-client-sdk for subnet-0c5e48ae85c7464ad 
        Map subnet-0c5e48ae85c7464ad public-ip-on-launch
        Associate route table rtb-071bb1bce1a2a8176 to subnet-0c5e48ae85c7464ad 
        Create network acl for vpc-098b2fa5ee724352c 
        Create tag boto3-client-sdk = boto3-client-sdk for acl-028389faff507ba3b 
        Create network acl entry for acl-028389faff507ba3b 10.0.0.0/25 
        Create network acl entry for acl-028389faff507ba3b 10.0.0.0/25 
        Create tag boto3-client-sdk = boto3-client-sdk for eipalloc-0f6f2757684e693e2 
        Created elastic ip eipalloc-0f6f2757684e693e2 for vpc 
        Create tag boto3-client-sdk = boto3-client-sdk for eipalloc-01c8f7fff2b56b9cb 
        Created elastic ip eipalloc-01c8f7fff2b56b9cb for vpc 
        Create security group 
        Create tag boto3-client-sdk = boto3-client-sdk for sg-05b76b08982610fe0 
        Authorize sg ingress sg-05b76b08982610fe0 
        Authorize sg egress sg-05b76b08982610fe0 
        Authorize sg ingress sg-05b76b08982610fe0 
        Authorize sg egress sg-05b76b08982610fe0 
        Authorize sg ingress sg-05b76b08982610fe0 
        Authorize sg egress sg-05b76b08982610fe0 
        Create launch_template 
        Create tag boto3-client-sdk = boto3-client-sdk for lt-0d98d8afd54ba10f0 
        Create launch_template lt-0d98d8afd54ba10f0 version 0
        Startup EC2 Instance group 1
        Create tag boto3-client-sdk = boto3-client-sdk for i-01a06ad79883a2a39 
        Wait until running ...
        created Instance i-01a06ad79883a2a39
        Associate elastic ip eipalloc-0f6f2757684e693e2 with i-01a06ad79883a2a39 
        Wait until running ...
        created Instance i-071ccb10a4aa8e22a
        Associate elastic ip eipalloc-01c8f7fff2b56b9cb with i-071ccb10a4aa8e22a 
        Create launch_template lt-0d98d8afd54ba10f0 version 1
        Startup EC2 Instance group 2
        Create tag boto3-client-sdk = boto3-client-sdk for i-07a079fe927221872 
        Wait until running ...
        created Instance i-07a079fe927221872
        Associate elastic ip eipalloc-0f6f2757684e693e2 with i-07a079fe927221872 
        Wait until running ...
        created Instance i-034699240c0a04a74
        Associate elastic ip eipalloc-01c8f7fff2b56b9cb with i-034699240c0a04a74 


Teardown tagged secure EC2/SNS/VPC service with four instances::

     $ ./aws_service_client_ood.py -a start

        $ ./aws_compute_client_ood.py -a clean
        
        Teardown Simple Notification Service
        Delete SNS topic arn:aws:sns:eu-west-1:347924373385:boto3-client-sdk 
        Done
        
        Teardown VPC & Security 
        Found: vpc-098b2fa5ee724352c
        No vpc endpoints detected
        No vpc connection endpoints detected
        Delete instance i-071ccb10a4aa8e22a 
        Terminated 
        Delete instance i-01a06ad79883a2a39 
        Terminated 
        Delete instance i-034699240c0a04a74 
        Terminated 
        Delete instance i-07a079fe927221872 
        Terminated 
        Release eipalloc-01c8f7fff2b56b9cb 
        Release eipalloc-0f6f2757684e693e2 
        Delete launch template lt-0d98d8afd54ba10f0 version 3
        Delete launch template lt-0d98d8afd54ba10f0 version 2
        Delete launch template lt-0d98d8afd54ba10f0 version 1
        Delete launch_template lt-0d98d8afd54ba10f0 boto3-client-sdk
        No network interfaces detected
        Detach igw-013cd2de19cd970ff from vpc-098b2fa5ee724352c 
        Delete internet gateway igw-013cd2de19cd970ff 
        Delete subnet-08b06ebcbdf1cb1ec 
        Delete subnet-0c5e48ae85c7464ad 
        Delete rtb-071bb1bce1a2a8176 
        Skipping main route table
        No nat gateways detected
        Delete entry for acl-0a0588f83ca9819a9 
        Delete entry for acl-0a0588f83ca9819a9 
        Delete entry for acl-0a0588f83ca9819a9 
        Delete entry for acl-0a0588f83ca9819a9 
        Delete acl-0a0588f83ca9819a9 
        Delete entry for acl-028389faff507ba3b 
        Delete entry for acl-028389faff507ba3b 
        Delete entry for acl-028389faff507ba3b 
        Delete entry for acl-028389faff507ba3b 
        Delete acl-028389faff507ba3b 
        Revoke sg ingress from sg-05b76b08982610fe0 
        Revoke sg ingress from sg-05b76b08982610fe0 
        Revoke sg ingress from sg-05b76b08982610fe0 
        Revoke sg ingress from sg-05b76b08982610fe0 
        Revoke sg ingress from sg-05b76b08982610fe0 
        Revoke sg ingress from sg-05b76b08982610fe0 
        Revoke sg egress sg-05b76b08982610fe0 
        Revoke sg egress sg-05b76b08982610fe0 
        Revoke sg egress sg-05b76b08982610fe0 
        Revoke sg egress sg-05b76b08982610fe0 
        Revoke sg egress sg-05b76b08982610fe0 
        Revoke sg egress sg-05b76b08982610fe0 
        No referencing security groups detected
        Deleting security group sg-05b76b08982610fe0
        Delete sg-05b76b08982610fe0 
        Delete vpc-098b2fa5ee724352c 


Create tagged secure ASG/EC2/ELB/SNS/VPC service with two zones/instances::

     $ ./aws_service_client_ood.py -a start -w 'sns-vpc-autoscaling-elb'

        Startup Simple Notification Service
        Create SNS topic  boto3-client-sdk
        
        Startup Virtual Private Cloud & Security
        Create VPC boto3-client-sdk
        Create tag boto3-client-sdk = boto3-client-sdk for vpc-049ecaea22b0cf135 
        Create internet gateway 
        Create tag boto3-client-sdk = boto3-client-sdk for igw-06b7accd6eb6a6db7 
        Attach igw-06b7accd6eb6a6db7 to vpc-049ecaea22b0cf135 
        Create route table for vpc-049ecaea22b0cf135 
        Create tag boto3-client-sdk = boto3-client-sdk for rtb-00f4787156ee2e12c 
        Create ipv4 route for 0.0.0.0/0 
        Create ipv6 route for ::/0 
        Create subnet for 10.0.0.0/25 
        Create tag boto3-client-sdk = boto3-client-sdk for subnet-0a3cdf8ad2703976a 
        Map subnet-0a3cdf8ad2703976a public-ip-on-launch
        Associate route table rtb-00f4787156ee2e12c to subnet-0a3cdf8ad2703976a 
        Create network acl for vpc-049ecaea22b0cf135 
        Create tag boto3-client-sdk = boto3-client-sdk for acl-093a613a461b4f34f 
        Create network acl entry for acl-093a613a461b4f34f 10.0.0.0/25 
        Create network acl entry for acl-093a613a461b4f34f 10.0.0.0/25 
        Create subnet for 10.0.0.128/25 
        Create tag boto3-client-sdk = boto3-client-sdk for subnet-09cc65b33ee26cdc1 
        Map subnet-09cc65b33ee26cdc1 public-ip-on-launch
        Associate route table rtb-00f4787156ee2e12c to subnet-09cc65b33ee26cdc1 
        Create network acl for vpc-049ecaea22b0cf135 
        Create tag boto3-client-sdk = boto3-client-sdk for acl-078cbcfe52be729e4 
        Create network acl entry for acl-078cbcfe52be729e4 10.0.0.0/25 
        Create network acl entry for acl-078cbcfe52be729e4 10.0.0.0/25 
        Create tag boto3-client-sdk = boto3-client-sdk for eipalloc-0e749f729f25443cc 
        Created elastic ip eipalloc-0e749f729f25443cc for vpc 
        Create tag boto3-client-sdk = boto3-client-sdk for eipalloc-00eaaaf15060163db 
        Created elastic ip eipalloc-00eaaaf15060163db for vpc 
        Create security group 
        Create tag boto3-client-sdk = boto3-client-sdk for sg-037185ec7c86f4473 
        Authorize sg ingress sg-037185ec7c86f4473 
        Authorize sg egress sg-037185ec7c86f4473 
        Authorize sg ingress sg-037185ec7c86f4473 
        Authorize sg egress sg-037185ec7c86f4473 
        Authorize sg ingress sg-037185ec7c86f4473 
        Authorize sg egress sg-037185ec7c86f4473 
        Create launch_template 
        Create tag boto3-client-sdk = boto3-client-sdk for lt-071e6d6ef4dd40446 
        Create launch_template lt-071e6d6ef4dd40446 version 0
        Create launch_template lt-071e6d6ef4dd40446 version 1
        
        Startup Elastic Load Balancer
        Create Elastic Load Balancer: boto3-client-sdk
        Wait until active ...
        elb created
        
        Startup AutoScaling Instances
        Create launch_configuration boto3-client-sdk
        Create AutoScaling group: boto3-client-sdk
        Attach target groups to AutoScaling group boto3-client-sdk
        Failed with An error occurred (ValidationError) when calling the AttachLoadBalancerTargetGroups operation: Provided Target Groups may not be valid. Please ensure they exist and try again.
                


Teardown tagged secure ASG/EC2/ELB/SNS/VPC service with two zones/instances::

      $ ./aws_service_client_ood.py -a cleanstart -w 'sns-vpc-autoscaling-elb'
        
        Teardown Simple Notification Service
        Delete SNS topic arn:aws:sns:eu-west-1:347924373385:boto3-client-sdk 
        Done
        
        Teardown Elastic Load Balancer
        Delete Elastic Load Balancer arn:aws:elasticloadbalancing:eu-west-1:347924373385:loadbalancer/app/boto3-client-sdk/0e4c3668d93158d1
        
        Teardown AutoScaling
        No auto-scaling notifications found
        Delete AutoScaling group tags boto3-client-sdk
        No auto-scaling policies found
        Delete AutoScaling group boto3-client-sdk
        wait for deletion ...
        Delete launch_configuration boto3-client-sdk
        
        Teardown VPC & Security 
        Found: vpc-00e32a97fa23f8d77
        No vpc endpoints detected
        No vpc connection endpoints detected
        No ec2 instances detected
        Release eipalloc-0d10acbc706530c6f 
        Release eipalloc-06253507adfb1e2be 
        Delete launch template lt-0d9a00f61a36167e7 version 3
        Delete launch template lt-0d9a00f61a36167e7 version 2
        Delete launch template lt-0d9a00f61a36167e7 version 1
        Delete launch_template lt-0d9a00f61a36167e7 boto3-client-sdk
        No network interfaces detected
        Detach igw-031fc8a2792cc2c0e from vpc-00e32a97fa23f8d77 
        Delete internet gateway igw-031fc8a2792cc2c0e 
        Delete subnet-0b448dbf294c6f089 
        Delete subnet-09943b8b22bd88fb4 
        Skipping main route table
        Delete rtb-035f63506a71cf413 
        No nat gateways detected
        Delete entry for acl-03c312f9f283ffa9b 
        Delete entry for acl-03c312f9f283ffa9b 
        Delete entry for acl-03c312f9f283ffa9b 
        Delete entry for acl-03c312f9f283ffa9b 
        Delete acl-03c312f9f283ffa9b 
        Delete entry for acl-0d8ab9847a2a8a84f 
        Delete entry for acl-0d8ab9847a2a8a84f 
        Delete entry for acl-0d8ab9847a2a8a84f 
        Delete entry for acl-0d8ab9847a2a8a84f 
        Delete acl-0d8ab9847a2a8a84f 
        Revoke sg ingress from sg-0bb8d3baee1246265 
        Revoke sg ingress from sg-0bb8d3baee1246265 
        Revoke sg ingress from sg-0bb8d3baee1246265 
        Revoke sg ingress from sg-0bb8d3baee1246265 
        Revoke sg ingress from sg-0bb8d3baee1246265 
        Revoke sg ingress from sg-0bb8d3baee1246265 
        Revoke sg egress sg-0bb8d3baee1246265 
        Revoke sg egress sg-0bb8d3baee1246265 
        Revoke sg egress sg-0bb8d3baee1246265 
        Revoke sg egress sg-0bb8d3baee1246265 
        Revoke sg egress sg-0bb8d3baee1246265 
        Revoke sg egress sg-0bb8d3baee1246265 
        No referencing security groups detected
        Deleting security group sg-0bb8d3baee1246265
        Delete sg-0bb8d3baee1246265 
        Delete vpc-00e32a97fa23f8d77

        $ ./aws_compute_client_ood.py -a clean -w 'sns-vpc-autoscaling-elb'
        
        Teardown Simple Notification Service
        Done
        
        Teardown Elastic Load Balancer
        No Elastic Load Balancer found
        
        Teardown AutoScaling
        No Auto Scaling Groups found
        No Launch Configurations found
        
        Teardown VPC & Security 
        No VPCs found


Teardown various stuff::
        
        $ ./aws_service_client_odd.py -a clean -w 'elb-autoscaling-vpc-sns'
        
        Teardown Simple Notification Service
        Done
        
        Teardown Elastic Load Balancer
        No Elastic Load Balancer found
        
        Teardown AutoScaling
        No Auto Scaling Groups found
        No Launch Configurations found
        
        Teardown VPC & Security 
        No VPCs found

