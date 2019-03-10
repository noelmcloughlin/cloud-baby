================
boto3utils
================

Usage
======

Clean EC2 Environment::

            $ ./ec2.py -a clean
            
            CLEAN DOWN EC2 ENVIRON dry
            No VPCs found
            
            CLEAN DOWN EC2 ENVIRON for real, please be patient
            No VPCs found
            
Create EC2 Environment::

            $ ./ec2.py -a start
            
            CREATE EC2 ENVIRON dry
            No VPCs found
            
            CREATE EC2 ENVIRON for real, please be patient
            Created vpc 
            Created internet gateway 
            Attached igw-0b6f244d938831127 to vpc-07cd4a06b07e3be51 
            Created route table for vpc-07cd4a06b07e3be51 
            Created ipv4 route for 0.0.0.0/0 
            Created ipv6 route for ::/0 
            Created subnet for 172.35.0.0/24 
            Map subnet subnet-0df31d9358cea4fc3 public-ip-on-launch True 
            Created network acl for vpc-07cd4a06b07e3be51 
            Created network acl entry for acl-0bc53273a0c3af215 
            Created network acl entry for acl-0bc53273a0c3af215 
            Created elastic ip for vpc 
            Created security group 
            Authorized sg ingress sg-0aa4db0c1b254c200 
            Authorized sg ingress sg-0aa4db0c1b254c200 
            Authorized sg ingress sg-0aa4db0c1b254c200 
            Authorized sg egress sg-0aa4db0c1b254c200 
            Authorized sg egress sg-0aa4db0c1b254c200 
            Authorized sg egress sg-0aa4db0c1b254c200 
            Creating instance 
            Associated elastic ip with i-0627ca89af44cc734 
            Associated route table rtb-0ccea9e7070082233 to subnet-0df31d9358cea4fc3 
            created Instance i-0627ca89af44cc734 i-0627ca89af44cc734

Clean EC2 Environment::

            $ ./ec2.py -a clean
            
            CLEAN DOWN EC2 ENVIRON dry
            CLEAN DOWN EC2 ENVIRON for real, please be patient
            Disassociated elastic ip eipassoc-0f0ddecb673216bd8 
            Released eipalloc-001f8ac89d49b637e 99.80.72.164 
            Terminating instance 
            Terminated instance 
            Revoked sg ingress from sg-08b5888e6cf2267ea 
            Revoked sg ingress from sg-08b5888e6cf2267ea 
            Revoked sg ingress from sg-08b5888e6cf2267ea 
            Revoked sg egress sg-08b5888e6cf2267ea 
            Revoked sg egress sg-08b5888e6cf2267ea 
            Revoked sg egress sg-08b5888e6cf2267ea 
            Deleted sg-08b5888e6cf2267ea 
            Detached igw-03dfcf0e8a880ca28 from vpc-0164f4e81a7d7b1e3 
            Deleted internet gateway igw-03dfcf0e8a880ca28 
            Deleted subnet-08c94374fab7f81f4 
            No nat gateways detected
            Deleted acl-0eb611c79eb75bff2 
            Deleted acl-0eb611c79eb75bff2 
            Deleted acl-0eb611c79eb75bff2 
            Deleted route table rtb-0ccea9e7070082233
            Deleted vpc-0164f4e81a7d7b1e3 
