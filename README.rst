================
cloud-cli
================

EC2 Usage
======
            
            $ ./ec2_client.py
            
            ec2_client.py Usage:
            
            	-a --action	start | clean 
            
            	[ -n --name	Private Cloud Name (default: 'boto3-client-sdk')
            
            	[ -z --region	Cloud Region (default 'eu-west-1)
            
            	[ -c --cidr	IPv4 Cidr Block (default: '172.35.0.0/24'
                        
            
Create EC2 Environment::

            $ ./ec2_client.py -a start

            Create Compute instance in VPC [dry]
            Create vpc (dry)
            Create vpc 
            Create tag vpc-tag = boto3-client-sdk for vpc-031460035ad958412 
            Create tag internet-gateway-tag = boto3-client-sdk for igw-0d10e2128fa05e7eb 
            Create internet gateway 
            Attache igw-0d10e2128fa05e7eb to vpc-031460035ad958412 
            Create tag route-table-tag = boto3-client-sdk for rtb-0dd26a22dc02d7806 
            Create route table for vpc-031460035ad958412 
            Create ipv4 route for 172.35.0.0/24 
            Create ipv6 route for ::/0 
            Create tag subnet-tag = boto3-client-sdk for subnet-0fda057182992e42a 
            Create subnet for 172.35.0.0/24 
            Map subnet-0fda057182992e42a public-ip-on-launch True (dry)
            Create tag network-acl-tag = boto3-client-sdk for acl-06493b14d8cfdd71a 
            Create network acl for vpc-031460035ad958412 
            Create network acl entry for acl-06493b14d8cfdd71a 
            Create network acl entry for acl-06493b14d8cfdd71a 
            Associate route table rtb-0dd26a22dc02d7806 to subnet-0fda057182992e42a 
            Create tag elastic-ip-tag = boto3-client-sdk for eipalloc-07028af9bd61213e6 
            Create elastic ip eipalloc-07028af9bd61213e6 for vpc 
            Create tag security-group-tag = boto3-client-sdk for sg-0ac9db80ee389ba13 
            Create security group 
            Authorize sg ingress sg-0ac9db80ee389ba13 
            Authorize sg ingress sg-0ac9db80ee389ba13 
            Authorize sg ingress sg-0ac9db80ee389ba13 
            Authorize sg egress sg-0ac9db80ee389ba13 
            Authorize sg egress sg-0ac9db80ee389ba13 
            Authorize sg egress sg-0ac9db80ee389ba13 
            Create tag launch-template-tag = boto3-client-sdk for lt-055e69c0ae3257568 
            Create launch_template 
            Create Instance from lt-055e69c0ae3257568
            Associate elastic ip eipalloc-07028af9bd61213e6 with i-0d3fdfac46a2f8f6c 
            created Instance i-0d3fdfac46a2f8f6c i-0d3fdfac46a2f8f6c
            

Clean EC2 Environment::

            $ ./ec2_client.py -a clean

            Tear down EC2 instance and VPC [dry]
            No VPCs found
            
            Tear down EC2 instance and VPC, please be patient
            Found: vpc-031460035ad958412
            No vpc endpoints detected
            No vpc connection endpoints detected
            No ec2 instances detected
            Disassociate elastic ip eipassoc-005af48d2992d5cc3 
            Release eipalloc-07028af9bd61213e6 
            Delete launch_template lt-055e69c0ae3257568 launch-template-tag
            Detache igw-0d10e2128fa05e7eb from vpc-031460035ad958412 
            Delete internet gateway igw-0d10e2128fa05e7eb 
            No network interfaces detected
            Delete subnet-0fda057182992e42a 
            Delete rtb-0dd26a22dc02d7806 
            Skipping main route table
            No nat gateways detected
            Delete acl-06493b14d8cfdd71a 
            Delete acl-06493b14d8cfdd71a 
            Delete acl-06493b14d8cfdd71a 
            Delete acl-06493b14d8cfdd71a 
            Delete acl-06493b14d8cfdd71a 
            No referencing security groups detected
            Deleting security group sg-0ac9db80ee389ba13
            Delete sg-0ac9db80ee389ba13 
            Delete vpc-031460035ad958412 
