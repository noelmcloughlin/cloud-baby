#!/usr/bin/env python3
### Simple httpd health check script
import subprocess

def main():
    if not subprocess.run("sudo systemctl status httpd", shell=True):
        subprocess.run("sudo systemctl start httpd", shell=True)
    print('Webserver is running')

if __name__ == "__main__":
   try:
       main(sys.argv[1:])
   except Exception as e:
       print("Error %s" % e)
       exit(1)
       
exit(0)
