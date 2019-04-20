
init = {'cloud': {'actions': ['start', 'clean', 'cleanstart'],
                  'catalog': ['vpc', 'sns', 'instance', 'autoscaling', 'elb'],
                  'cidr4_vpc': ['10.0.0.0/24'],
                  'cidr4': ['10.0.0.0/25', '10.0.0.128/25'],
                  'cidr6_vpc': '',
                  'cidr6': [],
                  'ipv4': True,
                  'ipv6': False,
                  'dry': False,
                  'key_pair': 'ec2_user',
                  'name': 'boto3-client-sdk',
                  'network_acls': ['boto3-client-sdk'],
                  'private_ip': None,
                  'private_ips': [],
                  'peer_region': 'eu-west2',
                  'region': 'eu-west-1',
                  'scope': 'sns-vpc-instance',
                  'tag': 'boto3-client-sdk',
                  'zone': None,
                  'zones': ['eu-west-1a', 'eu-west-1b']
                  },

        'service': {'acl_id': None,
                    'acl_ids': [],
                    'auto_ipv6': True,
                    'ebs_optimized': False,
                    'min_count': 1,
                    'max_count': 2,
                    'monitor': False,
                    'public_ip': True,
                    'sg_id': None,
                    'sg_ids': [],
                    'subnet_id': None,
                    'subnet_ids': [],
                    'template_id': None,
                    'template_ids': [],
                    'tenancy': 'default',
                    'topic_arn': 'boto3-client-sdk'
                    },

        'compute': {'eip_id': None,
                    'instance_id': None,
                    'igw_id': None,
                    'nat_gw_id': None,
                    'peer_vpc_id': None,
                    'rtt_id': None,
                    'vpc_id': None,

                    'eip_ids': [],
                    'instance_ids': [],
                    'igw_ids': [],
                    'nat_gw_ids': [],
                    'rtt_ids': [],
                    'sg_ids': []
                    },

        'elb':     {
                    'lb_arn': None,
                    'lb_arns': [],
                    'ip_version': 'ipv4',
                    'lb_type': 'application',
                    'scheme': 'internet-facing'
                    },

        'autoscaling': {'asg_name': 'boto3-client-sdk',
                        'desired_capacity': 2,
                        'hc_type': 'EC2',
                        'resource': 'auto-scaling-group',
                        'notice_types': ['autoscaling:EC2_INSTANCE_LAUNCH',
                                         'autoscaling:EC2_INSTANCE_LAUNCH_ERROR',
                                         'autoscaling:EC2_INSTANCE_TERMINATE',
                                         'autoscaling:EC2_INSTANCE_TERMINATE_ERROR'],
                        'policy_type': 'TargetTrackingScaling',
                        'est_warmup': 90,
                        'metric': 'ASGAverageCPUUtilization',
                        'metric_value': 50,
                        'force_delete': True
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
