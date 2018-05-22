#!/bin/bash

# get a list of all aws service prefix used in iam based on the official documentation

SERVICES_LIST_URL="https://docs.aws.amazon.com/IAM/latest/UserGuide"
SERVICES_LIST_PAGE="reference_policies_actions-resources-contextkeys.html"

# this resource is probably better and more accurate:
# https://awspolicygen.s3.amazonaws.com/js/policies.js
# would need some parsing with jq though 

LIST_OF_SERVICES_PAGES=$(curl -s $SERVICES_LIST_URL/$SERVICES_LIST_PAGE |grep "<li><a href=\"" |awk -F"\"" '{ print $2 }')
LIST_OF_SERVICES=$(curl -s $SERVICES_LIST_URL/$SERVICES_LIST_PAGE |grep "<li><a href=\"" |awk -F"\"" '{ print $2 }'|awk -F"list_" '{ print $2 }'|awk -F".html" '{ print $1 }')

OUTPUT_FILE=

for service in $LIST_OF_SERVICES; do
    SERVICE_PREFIX=$(curl -s $SERVICES_LIST_URL/list_$service.html |grep "service prefix:"|awk -F">" '{ print $3 }'|awk -F"<" '{ print $1 }')
    SERVICE_ACTIONS=$(curl -s $SERVICES_LIST_URL/list_$service.html |grep "a\ id=\"$service\-"|awk -F"$service-" '{ print $2 }'|awk -F"\"" '{ print $1 }'|grep -v ^[a-z]|grep -v ^"_")
    for action in $SERVICE_ACTIONS; do
      if [[ $OUTPUT_FILE ]]; then
        echo "$SERVICE_PREFIX:$action" >> $OUTPUT_FILE
      else
        echo "$SERVICE_PREFIX:$action"
      fi
    done
done


# Another method probably better than this one is the one suggested by Scott Piper, getting actions from botocore
# https://github.com/duo-labs/cloudtracker#aws_actionstxt
#
# git clone --depth 1 -b master https://github.com/boto/botocore.git
# find botocore/botocore/data -name *.json | xargs cat | jq -r 'select(.operations != null) as $parent | .operations | keys | .[] | $parent.metadata.endpointPrefix +":"+.' | sort | uniq > aws_actions.txt
