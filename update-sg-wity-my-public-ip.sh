#!/bin/bash

# usage ./$0 <sg-name> <port>

SG_ID=$1
PORT=$2
USER_FOR_DESC=$(aws sts get-caller-identity --query Arn --output text | awk -F'/' '{ print $3 }')

MY_PUBLIC_IPV4=$(curl -s v4.ifconfig.co)
MY_PUBLIC_IPV4_CIDR=$(echo $MY_PUBLIC_IPV4 | awk '{ print $0 "/32" }')

aws ec2 authorize-security-group-ingress \
 --group-id $SG_ID \
 --ip-permissions IpProtocol=tcp,FromPort=$PORT,ToPort=$PORT,IpRanges='[{CidrIp='"$MY_PUBLIC_IPV4_CIDR"',Description='"$USER_FOR_DESC"'}]'
