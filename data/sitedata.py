
init = {'cloud': {'catalog': ['vpc', 'sns', 'instance', 'autoscaling', 'elb'],
                  'cidr4': ['172.35.0.0/24', '172.36.0.0/24'],
                  'cidr6': [],
                  'dry': False,
                  'key_pair': 'ec2_token',
                  'name': 'boto3-client-sdk',
                  'network_acls': ['boto3-client-sdk'],
                  'private_ip': None,
                  'private_ips': [],
                  'peer_region': 'eu-west2',
                  'region': 'eu-west-1',
                  'scope': 'sns-vpc-instance',
                  'tag': 'boto3-client-sdk',
                  'zones': ['eu-west-1a', 'eu-west-1b']
                  },

        'service': {'auto_ipv6': True,
                    'ebs_optimized': False,
                    'max_count': 1,
                    'monitor': False,
                    'public_ip': True,
                    'sg_id': None,
                    'sg_ids': [],
                    'subnet_id': None,
                    'subnet_ids': [],
                    'template_ids': [],
                    'tenancy': 'default',
                    'topic_arn': 'boto3-client-sdk'
                    },

        'compute': {'acl_id': None,
                    'eip_id': None,
                    'igw_id': None,
                    'nat_gw_id': None,
                    'peer_vpc_id': None,
                    'rtt_id': None,
                    'vpc_id': None,

                    'acl_ids': [],
                    'eip_ids': [],
                    'instance_ids': [],
                    'lb_arns': [],
                    'nat_gw_ids': [],
                    'rtt_ids': [],
                    'sg_ids': []
                    },

        'image': {'ami_id': 'ami-0fad7378adf284ce0',
                  'ami_type': 't2.micro',
                  'hibernate': True,
                  'user_data': b'''
#!/bin/bash
yum update -y
yum install -y httpd
systemctl enable httpd && systemctl start httpd
usermod -a -G apache ec2_user
chown -R ec2_user:apache /var/www
chmod 2775 /var/www
find /var/www -type d -exec chmod 2775 {} \;
find /var/www -type f -exec chmod 0664 {} \;
echo "Create by AWS Boto3 SDK (hostname: $(hostname))" >> /var/www/html/index.html
'''
                  }
        }
