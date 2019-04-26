==========
cloud-baby
==========

AWS Python Boto3 Client SDK
===========================

Usage::

        $ ./awsbaby.py --help

        Create, configure, and manage Amazon Web Services (AWS) across multiple Availability zones.
        The currently available features are AutoScaling, ELB, VPC, and EC2 services.

        ACTIONS
            -a --choice      start | clean | cleanstart ]        (default: help)
          [ -w --wanted      sns vpc elb autoscaling ec2 sec ]   (default: vpc-sec-ec2)

        
        ARGUMENTS
          [ -c --cidr4       <value> ]    IPv4 Child Cidrs   (default: ['10.0.0.0/25', '10.0.0.128/25'])
          [ -i --image       <value> ]    Image ID           (default: ami-0fad7378adf284ce0)
          [ -y --image-type  <value> ]    Instance Type      (default: t2.micro)
          [ -k --keypair     <value> ]    Key Pair name      (default: ec2_user)
          [ -m --maxcount    <value> ]    Max instances      (default: 2)
          [ -n --name        <value> ]    Name / Tag Key     (default: boto3-client-sdk)
          [ -r --region      <value> ]    Cloud Region       (default: eu-west-1)
          [ -s --sleep       <Boolean> ]  Hibernate          (default: True)
          [ -t --tag         <value> ]    Tag value          (default: boto3-client-sdk)
          [ -i --vpc4        <value> ]    IPv4 Parent Cidr   (default: ['10.0.0.0/24'])
  
       FLAGS
          [ -6 --ip6 ]                    Use IpV6           (default: False)
          [ -d --debug ]
          [ -h --help ]



Create tagged secure EC2/SNS/VPC service::


       $ ./awsbaby.py -k your_keypair -a start
          
          Create a Virtual Private Cloud
          Create VPC boto3-client-sdk
          Create tag boto3-client-sdk = boto3-client-sdk for vpc-06e609e554838bb0d 
          Create security group 
          Create tag boto3-client-sdk = boto3-client-sdk for sg-019de3f43dcaff883 
          Authorize sg ingress sg-019de3f43dcaff883 
          Authorize sg egress sg-019de3f43dcaff883 
          Authorize sg ingress sg-019de3f43dcaff883 
          Authorize sg egress sg-019de3f43dcaff883 
          Authorize sg ingress sg-019de3f43dcaff883 
          Authorize sg egress sg-019de3f43dcaff883 
          
          Create Simple Notification Service Topic
          Create SNS topic  boto3-client-sdk
          
          Create a EC2 compute environment
          Create internet gateway 
          Create tag boto3-client-sdk = boto3-client-sdk for igw-005b3daff2a05134e 
          Attach igw-005b3daff2a05134e to vpc-06e609e554838bb0d 
          Create route table for vpc-06e609e554838bb0d 
          Create tag boto3-client-sdk = boto3-client-sdk for rtb-04c0e3bacc4c526d3 
          Create ip4 route for rtb-04c0e3bacc4c526d3 0.0.0.0/0 
          Create subnet for 10.0.0.0/25 
          Create tag boto3-client-sdk = boto3-client-sdk for subnet-0e23d3e5121b92a96 
          Map subnet-0e23d3e5121b92a96 public-ip-on-launch
          Associate route table rtb-04c0e3bacc4c526d3 to subnet-0e23d3e5121b92a96 
          Create network acl for vpc-06e609e554838bb0d 
          Create tag boto3-client-sdk = boto3-client-sdk for acl-074631017b0e141e2 
          Create network acl entry for acl-074631017b0e141e2 10.0.0.0/25 
          Create network acl entry for acl-074631017b0e141e2 10.0.0.0/25 
          Create subnet for 10.0.0.128/25 
          Create tag boto3-client-sdk = boto3-client-sdk for subnet-09c995ad9102075b6 
          Map subnet-09c995ad9102075b6 public-ip-on-launch
          Associate route table rtb-04c0e3bacc4c526d3 to subnet-09c995ad9102075b6 
          Create network acl for vpc-06e609e554838bb0d 
          Create tag boto3-client-sdk = boto3-client-sdk for acl-0b76e657b0a6c79f4 
          Create network acl entry for acl-0b76e657b0a6c79f4 10.0.0.128/25 
          Create network acl entry for acl-0b76e657b0a6c79f4 10.0.0.128/25 
          Create launch_template 
          Create tag boto3-client-sdk = boto3-client-sdk for lt-0f122d11c9663b9e8 
          Create launch_template lt-0f122d11c9663b9e8 version 0
          Startup EC2 Instance group 0
          Create tag boto3-client-sdk = boto3-client-sdk for i-01411e9c5d652f94d 
          initialized Instance i-01411e9c5d652f94d
          initialized Instance i-0ce60380b15dd6c8f
          Create launch_template lt-0f122d11c9663b9e8 version 1
          Startup EC2 Instance group 1
          Create tag boto3-client-sdk = boto3-client-sdk for i-09f4ee43f92f8e207 
          initialized Instance i-09f4ee43f92f8e207
          initialized Instance i-0d0dc1ec34ad1aec1
          
          Ok
  
  
Teardown tagged secure EC2/SNS/VPC service::
  

       $ ./awsbaby.py -k your_keypair -a clean
  
          Teardown Simple Notification Service
          Delete SNS topic arn:aws:sns:eu-west-1:347924373385:boto3-client-sdk 
          
          Teardown EC2 infrastructure
          Delete instance i-0ce60380b15dd6c8f 
          Terminated 
          Delete instance i-01411e9c5d652f94d 
          Terminated 
          Delete instance i-09f4ee43f92f8e207 
          Terminated 
          Delete instance i-0d0dc1ec34ad1aec1 
          Terminated 
          No elastic ips detected
          Delete launch template lt-0f122d11c9663b9e8 version 3
          Delete launch template lt-0f122d11c9663b9e8 version 2
          Delete launch template lt-0f122d11c9663b9e8 version 1
          Delete launch_template lt-0f122d11c9663b9e8 boto3-client-sdk
          No network interfaces detected
          Detach igw-005b3daff2a05134e from vpc-06e609e554838bb0d 
          Delete internet gateway igw-005b3daff2a05134e 
          Delete subnet-09c995ad9102075b6 
          Delete subnet-0e23d3e5121b92a96 
          Skipping main route table
          Delete rtb-04c0e3bacc4c526d3 
          No nat gateways detected
          Delete entry for acl-0b76e657b0a6c79f4 
          Delete entry for acl-0b76e657b0a6c79f4 
          Delete entry for acl-0b76e657b0a6c79f4 
          Delete entry for acl-0b76e657b0a6c79f4 
          Delete acl-0b76e657b0a6c79f4 
          Delete entry for acl-074631017b0e141e2 
          Delete entry for acl-074631017b0e141e2 
          Delete entry for acl-074631017b0e141e2 
          Delete entry for acl-074631017b0e141e2 
          Delete acl-074631017b0e141e2 
          
          Teardown Security Group
          No referencing security groups detected
          Deleting security group sg-019de3f43dcaff883
          Delete sg-019de3f43dcaff883 
          
          Teardown VPC
          Delete vpc-06e609e554838bb0d 
          
          Teardown Security Group
          No security groups detected
          
          Ok
  
  
Create tagged secure ASG/EC2/ELB/SNS/VPC service with two zones/instances::
  

        $ ./awsbaby.py -k your_keypair -a start -w 'sns-vpc-autoscaling-elb'
          
          Create a Virtual Private Cloud
          Create VPC boto3-client-sdk
          Create tag boto3-client-sdk = boto3-client-sdk for vpc-0a6fd97ca3b099531 
          Create security group 
          Create tag boto3-client-sdk = boto3-client-sdk for sg-00b6ea783220fde88 
          Authorize sg ingress sg-00b6ea783220fde88 
          Authorize sg egress sg-00b6ea783220fde88 
          Authorize sg ingress sg-00b6ea783220fde88 
          Authorize sg egress sg-00b6ea783220fde88 
          Authorize sg ingress sg-00b6ea783220fde88 
          Authorize sg egress sg-00b6ea783220fde88 
          
          Create Simple Notification Service Topic
          Create SNS topic  boto3-client-sdk
          
          Create a EC2 compute environment
          Create internet gateway 
          Create tag boto3-client-sdk = boto3-client-sdk for igw-0cbf42d25568b5432 
          Attach igw-0cbf42d25568b5432 to vpc-0a6fd97ca3b099531 
          Create route table for vpc-0a6fd97ca3b099531 
          Create tag boto3-client-sdk = boto3-client-sdk for rtb-08ad6540092fa44d8 
          Create ip4 route for rtb-08ad6540092fa44d8 0.0.0.0/0 
          Create subnet for 10.0.0.0/25 
          Create tag boto3-client-sdk = boto3-client-sdk for subnet-0de926575ca79f18e 
          Map subnet-0de926575ca79f18e public-ip-on-launch
          Associate route table rtb-08ad6540092fa44d8 to subnet-0de926575ca79f18e 
          Create network acl for vpc-0a6fd97ca3b099531 
          Create tag boto3-client-sdk = boto3-client-sdk for acl-01f84dd3cae89399c 
          Create network acl entry for acl-01f84dd3cae89399c 10.0.0.0/25 
          Create network acl entry for acl-01f84dd3cae89399c 10.0.0.0/25 
          Create subnet for 10.0.0.128/25 
          Create tag boto3-client-sdk = boto3-client-sdk for subnet-02c2bf484c689cf52 
          Map subnet-02c2bf484c689cf52 public-ip-on-launch
          Associate route table rtb-08ad6540092fa44d8 to subnet-02c2bf484c689cf52 
          Create network acl for vpc-0a6fd97ca3b099531 
          Create tag boto3-client-sdk = boto3-client-sdk for acl-0fbefe583e4a568e3 
          Create network acl entry for acl-0fbefe583e4a568e3 10.0.0.128/25 
          Create network acl entry for acl-0fbefe583e4a568e3 10.0.0.128/25 
          Create launch_template 
          Create tag boto3-client-sdk = boto3-client-sdk for lt-0a8fef412c4935fc8 
          Create launch_template lt-0a8fef412c4935fc8 version 0
          Create launch_template lt-0a8fef412c4935fc8 version 1
          
          Create Elastic Load Balancing environment
          Create Elastic Load Balancer: boto3-client-sdk
          Wait until active ...
          Create Tags for arn:aws:elasticloadbalancing:eu-west-1:347924373385:loadbalancer/app/boto3-client-sdk/3814273b7a318209
          Create Target Group for boto3-client-sdk
          Create Tags for arn:aws:elasticloadbalancing:eu-west-1:347924373385:loadbalancer/app/boto3-client-sdk/3814273b7a318209
          Create Listener for boto3-client-sdk
          elb created
          
          Create AutoScaling
          Create launch_configuration boto3-client-sdk
          Create AutoScaling group: boto3-client-sdk
          Attach target groups to AutoScaling group boto3-client-sdk
          Create tag boto3-client-sdk = boto3-client-sdk for auto-scaling-group 
          Create AutoScaling policy boto3-client-sdk
          Create AutoScaling Notification boto3-client-sdk
          
          Ok
  
  
Teardown tagged secure ASG/EC2/ELB/SNS/VPC services with two zones/instances::
  
        $ ./awsbaby.py -k your_keypair -a clean -w 'sns-vpc-autoscaling-elb'
          
        Teardown Simple Notification Service
        Delete SNS topic arn:aws:sns:eu-west-1:347924373385:boto3-client-sdk 
          
        Teardown Elastic Load Balancing
        Delete Listener arn:aws:elasticloadbalancing:eu-west-1:347924373385:listener/app/boto3-client-sdk/3814273b7a318209/a389df5c8093ed08
        Delete Elastic Load Balancer arn:aws:elasticloadbalancing:eu-west-1:347924373385:loadbalancer/app/boto3-client-sdk/3814273b7a318209
          
        Teardown AutoScaling
        Delete Auto Scaling Group boto3-client-sdk Notification arn:aws:sns:eu-west-1:347924373385:boto3-client-sdk
        No auto-scaling policies found
        Delete AutoScaling group boto3-client-sdk
        Delete launch_configuration boto3-client-sdk
        
        Teardown EC2 infrastructure
        No ec2 instances detected
        No elastic ips detected
        Delete launch template lt-0a8fef412c4935fc8 version 3
        Delete launch template lt-0a8fef412c4935fc8 version 2
        Delete launch template lt-0a8fef412c4935fc8 version 1
        Delete launch_template lt-0a8fef412c4935fc8 boto3-client-sdk
        No network interfaces detected
        Detach igw-0cbf42d25568b5432 from vpc-0a6fd97ca3b099531
        Delete internet gateway igw-0cbf42d25568b5432 
        Delete subnet-0de926575ca79f18e 
        Delete subnet-02c2bf484c689cf52 
        Skipping main route table
        Delete rtb-08ad6540092fa44d8 
        No nat gateways detected
        Delete entry for acl-01f84dd3cae89399c 
        Delete entry for acl-01f84dd3cae89399c 
        Delete entry for acl-01f84dd3cae89399c 
        Delete entry for acl-01f84dd3cae89399c 
        Delete acl-01f84dd3cae89399c 
        Delete entry for acl-0fbefe583e4a568e3 
        Delete entry for acl-0fbefe583e4a568e3 
        Delete entry for acl-0fbefe583e4a568e3 
        Delete entry for acl-0fbefe583e4a568e3 
        Delete acl-0fbefe583e4a568e3 
        
        Teardown Security Group
        No referencing security groups detected
        Deleting security group sg-00b6ea783220fde88
        Delete sg-00b6ea783220fde88 
        
        Teardown VPC
        Delete vpc-0a6fd97ca3b099531 
        
        Ok

