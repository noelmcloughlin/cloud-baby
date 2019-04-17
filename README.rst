================
cloud-cli
================

AWS Boto3 Client SDK
======

Usage::
            
          $ ./ec2_client_ood.py
             
            ec2_client_ood.py Usage:
             
            -a --action            start | clean | cleanstart
             
             [ -n --name           <value>      Tag Key              (default: 'boto3-client-sdk')
             [ -t --tag            <value>      Tag Value            (default: 'boto3-client-sdk')
             [ -i --image          <value>      Image ID             (default: 'ami-0fad7378adf284ce0')
             [ -y --instance-type  <value>      Instance Type        (default: 't2.micro')
             [ -h --hibernate      True|False   Instance hiberation  (default: True)
             [ -z --region         <value>      Cloud Region         (default 'eu-west-1)
             [ -c --cidr           <value>      IPv4 CidrBlock       (default: '172.35.0.0/24'
             [ -k --keypair        <value>      KeyPair name         (default: 'ec2_user'
             [ -d --debug                       Debug logging        (default: off)

                        
            
Create tagged EC2 Environment::

         $ ./ec2_client_ood.py -a start

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
 

Clean tagged EC2 Environment::

          $ ./ec2_client_ood.py -a clean

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
            
          $./ec2_client_ood.py -a clean

            No VPCs found [dry]
            No VPCs found
