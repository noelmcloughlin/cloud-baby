#!/usr/bin/env python3
#############################################
# Copyright 2019 noelmcloughlin
#############################################

import sys
try:
    sys.path.append('./aws')
    import boto3_solutions as cloud
except ImportError:
    sys.path.append('../aws')
    import boto3_solutions as cloud


def main(argv):
    solution = cloud.AwsSolution(argv)
    scope = solution.scope

    if 'help' in solution.choice:
        cloud.AwsSolution.usage()

    if 'clean' in solution.choice:
        if 'sns' in scope:
            cloud.SimpleNotificationService.clean(solution)
        if 'elb' in scope:
            cloud.ElasticLoadBalancing.clean(solution)
        if 'autoscaling' in scope:
            cloud.AutoScaling.clean(solution)
        if 'ec2' in scope or 'vpc' in scope:
            cloud.Ec2.clean(solution)
        if 'sec' in scope:
            cloud.SecurityGroup.clean(solution)

    if 'start' in solution.choice:
        solution = cloud.Vpc(solution)
        solution = cloud.SecurityGroup(solution)
        if 'sns' in scope:
            solution = cloud.SimpleNotificationService(solution)
        if 'ec2' in scope or 'vpc' in scope:
            solution = cloud.Ec2(solution)
        if 'elb' in scope:
            solution = cloud.ElasticLoadBalancing(solution)
        if 'autoscaling' in scope:
            solution = cloud.AutoScaling(solution)
        del solution

    print('\nOk\n')


if __name__ == "__main__":
    try:
        main(sys.argv[1:])
    except Exception as problem:
        cloud.AwsSolution.fatal(problem)
exit(0)
