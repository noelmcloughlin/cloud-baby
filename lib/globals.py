
ec2_ami='ami-0fad7378adf284ce0'
ec2_ami_type='t2.micro'
ec2_cidr_block='10.0.0.0/16'
ec2_elastic_ip_allocation_id=None
ec2_elastic_ip_association_id=None
ec2_group_name='mygroupname'
ec2_instance_id=None
ec2_internet_gateway_id=None
ec2_project_name='assignment project'
ec2_region_name='eu-west-1'
ec2_sg_id=None
ec2_subnet_id=None
ec2_tenancy='default'
ec2_vpc_id=None
ec2_instance=None
ec2_userdata="""
#!/bin/bash
yum update -y
amazon-linux-extras install -y lamp-mariadb10.2-php7.2 php7.2
yum install -y httpd mariadb-server
systemctl start httpd
systemctl enable httpd
usermod -a -G apache ec2-user
chown -R ec2-user:apache /var/www
chmod 2775 /var/www
find /var/www -type d -exec chmod 2775 {} \;
find /var/www -type f -exec chmod 0664 {} \;
echo "<?php phpinfo(); ?>" > /var/www/html/phpinfo.php
"""
