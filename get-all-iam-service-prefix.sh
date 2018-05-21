#!/bin/bash

# get a list of all aws service prefix used in iam

SERVICES_LIST_URL="https://docs.aws.amazon.com/IAM/latest/UserGuide"
SERVICES_LIST_PAGE="reference_policies_actions-resources-contextkeys.html"
LIST_OF_SERVICES_PAGES=$(curl -s $SERVICES_LIST_URL/$SERVICES_LIST_PAGE |grep "<li><a href=\"" |awk -F"\"" '{ print $2 }')

for page in $LIST_OF_SERVICES_PAGES; do
  curl -s $SERVICES_LIST_URL/$page |grep "service prefix:"|awk -F">" '{ print $3 }'|awk -F"<" '{ print $1 }'
done
