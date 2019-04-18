================
public-cloud-cli
================


AWS
====

Boto3 Client SDK
======

Usage::
            
    $ ./aws_compute_client_ood.py 

        aws_compute_client_ood.py Usage:
    
    	  -a --action		start | clean | cleanstart
    
    	[ -m --mode		instance | autoscaling ]	 (default: 'instance')
    
    	[ -n --name		<value> ]	Tag Key		 (default: 'ec2_user')
    	[ -i --image		<value> ]	Image ID	 (default: 'ami-0fad7378adf284ce0')
    	[ -y --instance-type	<value> ]	Instance Type	 (default: 't2.micro')
    	[ -h --hibernate	True|False ]	Hibernate	 (default: True)
    	[ -t --tag		<value> ]	Tag value	 (default: 'boto3-client-sdk')
    	[ -z --region		<value> ]	Cloud Region	 (default 'eu-west-1)
    	[ -c --cidr		<value> ]	IPv4 Cidr Block	 (default: '172.35.0.0/24'
    	[ -k --keypair		<value> ]	Key Pair name	 (default: 'ec2_user'
    	[ -d --debug ]				Debug logging	 (default: off
                    
            
Create tagged EC2 Instance VPC::

     $ ./aws_compute_client_ood.py -a start

        Create vpc boto3-client-sdk (dry)
        Create vpc boto3-client-sdk 
        Create tag boto3-client-sdk = boto3-client-sdk for vpc-0f6e544b96b996a68 
        Create internet gateway 
        Create tag boto3-client-sdk = boto3-client-sdk for igw-0dd5b7cfb4700420d 
        Attach igw-0dd5b7cfb4700420d to vpc-0f6e544b96b996a68 
        Create route table for vpc-0f6e544b96b996a68 
        Create tag boto3-client-sdk = boto3-client-sdk for rtb-033d4f78cef695395 
        Create ipv4 route for 0.0.0.0/0 
        Create ipv6 route for ::/0 
        Create subnet for 172.35.0.0/24 
        Create tag boto3-client-sdk = boto3-client-sdk for subnet-0eac2ef3185c81772 
        Map subnet-0eac2ef3185c81772 public-ip-on-launch
        Create network acl for vpc-0f6e544b96b996a68 
        Create tag boto3-client-sdk = boto3-client-sdk for acl-01c1387ea365e37a0 
        Create network acl entry for acl-01c1387ea365e37a0 
        Create network acl entry for acl-01c1387ea365e37a0 
        Associate route table rtb-033d4f78cef695395 to subnet-0eac2ef3185c81772 
        Create tag boto3-client-sdk = boto3-client-sdk for eipalloc-0ded64345ef5fafc4 
        Created elastic ip eipalloc-0ded64345ef5fafc4 for vpc 
        Create security group 
        Create tag boto3-client-sdk = boto3-client-sdk for sg-0fb46caaa85671ddf 
        Authorize sg ingress sg-0fb46caaa85671ddf 
        Authorize sg egress sg-0fb46caaa85671ddf 
        Authorize sg ingress sg-0fb46caaa85671ddf 
        Authorize sg egress sg-0fb46caaa85671ddf 
        Authorize sg ingress sg-0fb46caaa85671ddf 
        Authorize sg egress sg-0fb46caaa85671ddf 
        Create launch_template 
        Create tag boto3-client-sdk = boto3-client-sdk for lt-0c7c29ce912135210 
        Create Instance from lt-0c7c29ce912135210
        Create tag boto3-client-sdk = boto3-client-sdk for i-020e8cdb04dec8310 
        Wait until running ...
        Associate elastic ip eipalloc-0ded64345ef5fafc4 with i-020e8cdb04dec8310 
        created Instance i-020e8cdb04dec8310
 

Teardown tagged EC2 VPC::

      $ ./aws_compute_client_ood.py -a clean

        No VPCs found [dry]
        Found: vpc-035d6904e8df402c4
        No vpc endpoints detected
        No vpc connection endpoints detected
        Delete instance i-075f3cb7605970ff2 
        Terminated 
        Release eipalloc-030e1b3d93567111f 
        Delete launch_template lt-0fdcfd6cb3236e024 boto3-client-sdk
        Detach igw-0b951feb1b64742ee from vpc-035d6904e8df402c4 
        Delete internet gateway igw-0b951feb1b64742ee 
        No network interfaces detected
        Delete subnet-00c9e07f3b7c4aa0e 
        Skipping main route table
        Delete rtb-0f370f547b20482ad 
        No nat gateways detected
        Delete acl-0ce9027d9477930c6 
        Delete acl-0ce9027d9477930c6 
        Delete acl-0ce9027d9477930c6 
        Delete acl-0ce9027d9477930c6 
        Delete acl-0ce9027d9477930c6 
        No referencing security groups detected
        Deleting security group sg-055702e9d44cd5ba7
        Delete sg-055702e9d44cd5ba7 
        Delete vpc-035d6904e8df402c4 
        
      $./aws_compute_client_ood.py -a clean

        No VPCs found [dry]
        No VPCs found


Create tagged AutoScaling VPC::
                
      $ ./aws_compute_client_ood.py -a cleanstart -m autoscaling
        
        Teardown Simple Notification Service 
        Delete SNS topic arn:aws:sns:eu-west-1:347924373385:boto3-client-sdk 
        Done
        
        Teardown VPC & Security 
        Found: vpc-06d7942dcbd65e597
        No vpc endpoints detected
        No vpc connection endpoints detected
        Delete instance i-040459101f8678432 
        Terminated 
        Release eipalloc-095dd3336ccea1b0c 
        Delete launch_template lt-06be976c6f1b753d5 boto3-client-sdk
        Detach igw-0111e5f4c79b7e01c from vpc-06d7942dcbd65e597 
        Delete internet gateway igw-0111e5f4c79b7e01c 
        No network interfaces detected
        Delete subnet-0f261d886c0e4ac7d 
        Skipping main route table
        Delete rtb-0ee099f04c6d8554f 
        No nat gateways detected
        Delete acl-098eb08622f6b4ec7 
        Delete acl-098eb08622f6b4ec7 
        Delete acl-098eb08622f6b4ec7 
        Delete acl-098eb08622f6b4ec7 
        Delete acl-098eb08622f6b4ec7 
        No referencing security groups detected
        Deleting security group sg-0b6d41ff323e297fe
        Delete sg-0b6d41ff323e297fe 
        Delete vpc-06d7942dcbd65e597 
        
        Teardown AutoScaling
        No auto-scaling notifications found
        Delete instance i-040459101f8678432 
        Terminated 
        Delete AutoScaling group tags boto3-client-sdk
        No auto-scaling policies found
        Delete AutoScaling group boto3-client-sdk
        Wait 60s for pending delete ...
        Delete launch_configuration boto3-client-sdk
        
        Startup Simple Notification Service
        Setup Simple Notification Service
        Create SNS topic  boto3-client-sdk
        
        Create VPC boto3-client-sdk
        Startup Virtual Private Cloud & Security
        
        Create tag boto3-client-sdk = boto3-client-sdk for vpc-05644f6b6d0070a24 
        Create internet gateway 
        Create tag boto3-client-sdk = boto3-client-sdk for igw-07e2be21a292b0593 
        Attach igw-07e2be21a292b0593 to vpc-05644f6b6d0070a24 
        Create route table for vpc-05644f6b6d0070a24 
        Create tag boto3-client-sdk = boto3-client-sdk for rtb-0f8173ba2581c5faa 
        Create ipv4 route for 0.0.0.0/0 
        Create ipv6 route for ::/0 
        Create subnet for 172.35.0.0/24 
        Create tag boto3-client-sdk = boto3-client-sdk for subnet-0ecd7f6e961ea8b72 
        Map subnet-0ecd7f6e961ea8b72 public-ip-on-launch
        Create network acl for vpc-05644f6b6d0070a24 
        Create tag boto3-client-sdk = boto3-client-sdk for acl-06463829730035a69 
        Create network acl entry for acl-06463829730035a69 
        Create network acl entry for acl-06463829730035a69 
        Associate route table rtb-0f8173ba2581c5faa to subnet-0ecd7f6e961ea8b72 
        Create tag boto3-client-sdk = boto3-client-sdk for eipalloc-0e63cca39703644fd 
        Created elastic ip eipalloc-0e63cca39703644fd for vpc 
        Create security group 
        Create tag boto3-client-sdk = boto3-client-sdk for sg-009f7d1adbe04aba2 
        Authorize sg ingress sg-009f7d1adbe04aba2 
        Authorize sg egress sg-009f7d1adbe04aba2 
        Authorize sg ingress sg-009f7d1adbe04aba2 
        Authorize sg egress sg-009f7d1adbe04aba2 
        Authorize sg ingress sg-009f7d1adbe04aba2 
        Authorize sg egress sg-009f7d1adbe04aba2 
        Create launch_template 
        Create tag boto3-client-sdk = boto3-client-sdk for lt-0519f26c1f24a698f 
        
        Startup AutoScaling Instances
        Create launch_configuration boto3-client-sdk
        Create AutoScaling group: boto3-client-sdk
        Create tag boto3-client-sdk = boto3-client-sdk for None 
        Create AutoScaling policy boto3-client-sdk
        Create AutoScaling Notification boto3-client-sdk

     
Teardown tagged AutoScaling VPC::
                
      $ ./aws_compute_client_ood.py -a clean -m autoscaling
        
        Teardown Simple Notification Service 
        Delete SNS topic arn:aws:sns:eu-west-1:347924373385:boto3-client-sdk 
        Done
        
        Teardown VPC & Security 
        Found: vpc-06d7942dcbd65e597
        No vpc endpoints detected
        No vpc connection endpoints detected
        Delete instance i-040459101f8678432 
        Terminated 
        Release eipalloc-095dd3336ccea1b0c 
        Delete launch_template lt-06be976c6f1b753d5 boto3-client-sdk
        Detach igw-0111e5f4c79b7e01c from vpc-06d7942dcbd65e597 
        Delete internet gateway igw-0111e5f4c79b7e01c 
        No network interfaces detected
        Delete subnet-0f261d886c0e4ac7d 
        Skipping main route table
        Delete rtb-0ee099f04c6d8554f 
        No nat gateways detected
        Delete acl-098eb08622f6b4ec7 
        Delete acl-098eb08622f6b4ec7 
        Delete acl-098eb08622f6b4ec7 
        Delete acl-098eb08622f6b4ec7 
        Delete acl-098eb08622f6b4ec7 
        No referencing security groups detected
        Deleting security group sg-0b6d41ff323e297fe
        Delete sg-0b6d41ff323e297fe 
        Delete vpc-06d7942dcbd65e597 
        
        Teardown AutoScaling
        No auto-scaling notifications found
        Delete instance i-040459101f8678432 
        Terminated 
        Delete AutoScaling group tags boto3-client-sdk
        No auto-scaling policies found
        Delete AutoScaling group boto3-client-sdk
        Wait 60s for pending delete ...
        Delete launch_configuration boto3-client-sdk

