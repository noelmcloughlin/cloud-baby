#!/usr/bin/env python3
#############################################
# Copyright 2019 NoelMcloughlin
#############################################
#- -- -- - -- -- - - - - -- - - - - -- - - -- --- - - - - ----- - - - -- -- - - - ---  - ---
# create, launch and monitoring a public-facing web server in the Amazon cloud. The web
# server will run on an EC2 instance and display some static content that is stored in S3.
# - - -- - -- - -- ---- -- -- ---- -- -- -- ---- - --- - ---- - - -- - -- - - ---- - - --  -
import sys, os, getopt, subprocess

region='eu-west-1'

def usage():
    print("\n%s Usage:" % os.path.basename(__file__))
    print("\n\t [ -h --host ] ip-address\tAWS EC2 ip address")
    print("\n\t [ -f --file ] filename\t\tFile to put in bucket")
    print("\n\t [ -s --script ] filepath\tHealth check script to run on host")
    print("\n\t [ -k --keypair ] filepath\tPath to keypair file")
    print("\n\t [ -i --instance ] start|clean\tEC2 Instance Startup/Clean")
    print("\n\t [ -n --bucket ] bucketname\tYour bucket name")
    print("\n\t [ -o --object ] start|clean\tS3 Bucket Startup/Clean")
    print("\n")
    print("Example workflow:")
    print("\n %s -i start" % os.path.basename(__file__))
    print("\n %s -o start -n s3-my-unique-bucket-nAmE -f ../files/myimage.jpg" % os.path.basename(__file__))
    print("\n %s -f file/myfile.jpg -s files/check.py -k ~/.aws/ec2_user.pem -h 39.49.59.69" % os.path.basename(__file__))
    print("\n %s -i clean" % os.path.basename(__file__))
    print("\n %s -o clean" % os.path.basename(__file__))
    print("\n")
    sys.exit(2)

def handle(error):
    print(error)

def run(host, script, filename, keypair):
    try:
        if subprocess.run("ssh -i %s -o StrictHostKeyChecking=no ec2-user@%s sudo ~/%s"  % (keypair, host, script), shell=True):
            if subprocess.run(["scp -i %s -o StrictHostKeyChecking=no %s ec2-user@%s:~" % (keypair, script, host)], shell=True):
                if subprocess.run("ssh -i %s -o StrictHostKeyChecking=no ec2-user@%s sudo ~/%s"  % (keypair, host, script), shell=True):
                    print('Webserver is running')
    except getopt.GetoptError as e:
        handle(e)
    
def main(argv):
    try:
        opts, args = getopt.getopt(argv, "h:f:s:k:i:o:n:", ["host=", "file=", "script=", "keypair=", "instance=", "object=", "name="])
    except getopt.GetoptError as e:
        handle(e)

    ### command line arguments ###
    if not opts:
        usage()
    host = script = filename = keypair = name = ''
    target = 'ec2'

    for opt, arg in opts:
        if opt in ("-h", "--host",):
            host = arg.lower()

        elif opt in ("-s", "--script",):
            script = arg.lower()

        elif opt in ("-f", "--file",):
            filename = arg.lower()

        elif opt in ("-k", "--file",):
            keypair = arg.lower()

        elif opt in ("-i", "--instance",):
            if 'start' in arg.lower():
                return subprocess.run("../ec2_client_ood.py -a start", shell=True)   ### START INSTANCE
            elif arg.lower() in ('clean', 'stop',):
                return subprocess.run("../ec2_client_ood.py -a clean", shell=True)   ### STOP INSTANCE
            else:
                usage()

        elif opt in ("-n", "--name",):
            target = 's3'
            name = arg.lower()

        elif opt in ("-o", "--object",):
            target = 's3'
            action = arg.lower()

        else:
            usage()

    if 's3' in target:
        if 'start' in action:
            #### START S3 BUCKET ###
            subprocess.run("./s3.py -a start -n %s -f %s" % (name, filename), shell=True)   ### SETUP S3
            cmd = str('echo \<img src=\\"https://s3-%s.amazonaws.com/%s/%s\\"/\> >/var/www/html/index.html' % (region, name, filename)) 

            #### UPDATE INDEX.HTML ####
            return subprocess.run("ssh -i %s -o StrictHostKeyChecking=no ec2-user@%s 'sudo %s'"  % (keypair, host, cmd), shell=True)
        elif 'clean' in action:
            return subprocess.run("./s3.py -a clean", shell=True)                    ### CLEAN S3
        else:
            usage()

    if 'ec2' in target:
        if 'start' in action:
            return subprocess.run("../ec2.py -a start", shell=True)   ### START INSTANCE
        elif 'clean' in action:
            return subprocess.run("../ec2.py -a clean", shell=True)   ### STOP INSTANCE

    ## RUN OUR USE CASE ##
    run(host, script, filename, keypair, name)

if __name__ == "__main__":
   try:
       main(sys.argv[1:])
   except Exception as e:
       handle(e)
       
exit(0)
