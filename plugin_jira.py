"""
A lightweight plugin that shoves alerts into Jira and auto-closes when they are closed

This uses zero libraries (except requests) so it's portable, but is limited on features.
"""

from collections import UserDict
import json

import urllib3
from urllib.parse import quote

http = urllib3.PoolManager()

class JiraAuthComponent(object):
  base_url = None
  username = None
  token = None
  auth = None
  headers = None

  def __init__(self, auth_obj) -> None:
    for k, comp in auth_obj.items():
      setattr(self, k, comp)

    self.headers = urllib3.make_headers(basic_auth=f"{self.username}:{self.token}")
    self.headers.update({'Content-Type': 'application/json'})

    # "successfulSet": [
    #     {
    #         "awsAccountId": "678266338152",
    #         "event": {
    #             "arn": "arn:aws:health:us-east-1::event/RDS/AWS_RDS_OPERATIONAL_NOTIFICATION/AWS_RDS_OPERATIONAL_NOTIFICATION_944b994ccf32b471dc249c36cc521e5a9e335435d501cc5e91626f5d6004aabd",
    #             "service": "RDS",
    #             "eventTypeCode": "AWS_RDS_OPERATIONAL_NOTIFICATION",
    #             "eventTypeCategory": "accountNotification",
    #             "region": "us-east-1",
    #             "startTime": 1687531500.0,
    #             "lastUpdatedTime": 1687541568.097,
    #             "statusCode": "open",
    #             "eventScopeCode": "ACCOUNT_SPECIFIC"
    #         },
    #         "eventDescription": {
    #             "latestDescription": "We have an operating system update available for one or more of your Aurora Serverless v2 instances in the US-EAST-1 Region that contains critical stability fixes. We will automatically update your affected instances in the maintenance window over the 3 weeks following July 25, 2023 00:00 UTC. However, we recommend you manually apply the update at your earliest convenience. The instance(s) will be restarted once the update is applied. \n\nYour impacted Amazon Aurora database instances are listed in the 'Affected resources' tab.\n\nRefer our documentation [1] to learn more about operating system updates. Reach out to your AWS account team or contact AWS Support [2] if you have any questions or require further guidance.\n\n[1] https://docs.aws.amazon.com/AmazonRDS/latest/AuroraUserGuide/USER_UpgradeDBInstance.Maintenance.html#OS_Updates\n[2] https://aws.amazon.com/support"
    #         }
    #     }
    # ],

class JiraAHAObject(object):

  status = None
  issue_type = None
  priority = None
  labels = None
  finder_line = None
  issue = None
  issue_raw = None
  project = None
  resolution_status = None

  def __init__(self, **kwargs) -> None:
    for key, value in kwargs.items():
      setattr(self, key, value)

    self.make_finder_line()
    self.make_object()

  def as_json(self):
    return json.dumps(self.issue)

  def format_body_from_dict(self, inpu):
    output = ""
    for k, v in inpu.items():
      output += f"{k}: {v}\n"

    return output

  def make_finder_line(self):
    self.finder_line = ":".join([
      "DO NOT DELETE LINE",
      self.issue_raw['successfulSet'][0]['event']["arn"],
      self.issue_raw['successfulSet'][0]['event']["region"],
      self.issue_raw['successfulSet'][0]['awsAccountId'],
    ])

  def make_object(self, **kwargs):
    self.make_finder_line()
    self.issue = {
      "fields": {
        "summary": f"AWS Notification: {self.issue_raw['successfulSet'][0]['event']['eventTypeCode']}",
        "issuetype": {
          "id": kwargs.get("issue_type") or self.issue_type
        },
        "project": {
          "key": self.project
        },
        "description": {
          "type": "doc",
          "version": 1,
          "content": [
            {
              "type": "paragraph",
              "content": [
                {
                  "text": self.issue_raw["successfulSet"][0]["eventDescription"]["latestDescription"],
                  "type": "text"
                },
                {
                  "type": "hardBreak"
                },
                {
                  "text": self.format_body_from_dict(self.issue_raw["successfulSet"][0]["event"]),
                  "type": "text"
                },
                {
                  "type": "hardBreak"
                },
                {
                  "text": f"AWS Account: {self.issue_raw['successfulSet'][0]['awsAccountId']}",
                  "type": "text"
                },
                {
                  "type": "hardBreak"
                },
                {
                  "text": self.finder_line,
                  "type": "text"
                }
              ]
            }
          ]
        },
        "priority": {
          "id": kwargs.get("priority") or self.priority,
        },
        # "duedate": duedate,
        # "labels": kwargs.get("labels") or self.labels,
      }
    }

class Jira(object):

  auth = None

  def __init__(self, **kwargs) -> None:
    """
    Initializes a JIRA object based on an Auth config getting passed
    """
    if "auth" in kwargs:
      self.auth = JiraAuthComponent(kwargs["auth"])

  def check_if_issue_exists(self, issue):

    jql = self.jql_for_finderline(issue.project, issue.finder_line)

    url = f"{self.auth.base_url}search?jql={quote(jql)}"
    print(url)

    resp = http.request(
      'GET',
      url,
      headers = self.auth.headers,
      retries = False
    )
    as_json = json.loads(resp.data)
    if as_json["total"] == 0:
      # TODO capture some kind of errors here
      return

    return as_json["issues"][0]["key"]


  def manage_issues(self, issues):
    if not isinstance(issues, list):
      issues = [issues]

    statuses = []
    for issue in issues:
      create_issue_resp = self.create_issue(issue)
      if create_issue_resp:
        print("body", create_issue_resp.status, create_issue_resp.data)
      if issue.status == "resolve":
        resolve_issue_resp = self.resolve_issue(issue)
        if resolve_issue_resp:
          print("body", resolve_issue_resp.status, resolve_issue_resp.data)

        statuses.append(resolve_issue_resp)
      else:
        statuses.append(create_issue_resp)

      # Don't create all issues
      # if issue.status == "resolve":
      #   statuses.append(self.resolve_issue(issue))
      # statuses.append(self.create_issue(issue))

    return statuses

  def create_issue(self, issue):
    issue_exists = self.check_if_issue_exists(issue)
    if issue_exists:
      print(f"Issue already created as {issue_exists}")
      return
    print(issue.as_json())
    return(http.request(
      'POST',
      f"{self.auth.base_url}/issue",
      headers = self.auth.headers,
      body = issue.as_json(),
      retries = False
    ))

  def jql_for_finderline(self, project, finder_line):
    return(f"project = \"{project}\" AND description ~ \"\\\"{finder_line}\\\"\" AND statusCategory != \"Done\"")

  def resolve_issue(self, issue):
    # Find issue by finder line and resolve
    issue_key = self.check_if_issue_exists(issue)
    if not issue_key:
      print("Attempt to resolve issue failed, issue not found")
      return
    resolve_body = {
      "update": {
        "comment": [
          {
            "add": {
              "body": {
                "content": [
                  {
                    "content": [
                      {
                        "text": "Auto-resolved",
                        "type": "text"
                      }
                    ],
                    "type": "paragraph"
                  }
                ],
                "type": "doc",
                "version": 1
              }
            }
          }
        ]
      },
      "transition": {
        "id": issue.resolution_status
      }
    }

    resp = http.request(
      'POST',
      f"{self.auth.base_url}/issue/{issue_key}/transitions",
      headers = self.auth.headers,
      body = json.dumps(resolve_body),
      retries = False
    )
    print(resp.data)
    return resp


def get_org_message_for_jira(event_details, event_type, affected_org_accounts, resources, issue_config):
  """
  issue_config should look like the following (values are your own):
  {
    "priority": 4,
    "default_project": "TSTAM",
    "issue_type": "10002",
    "resolution_status": "41",
    "mappings": {
      "026008842893": "TSTTX",
    }
  }
  """
  issues = []
  for aws_account in affected_org_accounts:
    if "mappings" not in issue_config:
      project = issue_config["default_project"]
    else:
      project = issue_config["mappings"].get(aws_account, issue_config["default_project"])
    issues.append(JiraAHAObject(
      priority=issue_config["priority"],
      issue_type=issue_config["issue_type"],
      project=project,
      resolution_status=issue_config["resolution_status"],
      issue_raw=event_details,
      status=event_type,
    ))

  return issues

if __name__ == "__main__":
  import boto3
  sm = boto3.client("secretsmanager")
  get_secret_value_response_jira = get_secret_value_response_jira = sm.get_secret_value(
      SecretId="JiraInstanceURL"
  )
  jira_config = json.loads(get_secret_value_response_jira["SecretString"])

  jira_auth = {
      "base_url": jira_config["JiraInstanceURL"],
      "username": jira_config["Username"],
      "token": jira_config["Secret"],
  }
  jira = Jira(auth=jira_auth)
  issue = JiraAHAObject(
    priority="4",
    issue_type="10002",
    project="12500",
    issue_raw={'successfulSet': [{'awsAccountId': '542114373238', 'event': {'arn': 'arn:aws:health:us-east-1::event/LAMBDA/AWS_LAMBDA_OPERATIONAL_NOTIFICATION/AWS_LAMBDA_OPERATIONAL_NOTIFICATION_8b5ba7da2804dd3ff5e8e48917d8fcc4ee4a772ebf93c25530ae4fe92ad69de2', 'service': 'LAMBDA', 'eventTypeCode': 'AWS_LAMBDA_OPERATIONAL_NOTIFICATION', 'eventTypeCategory': 'accountNotification', 'region': 'us-east-1', 'startTime': '2023-06-30 07:30:00+00:00', 'lastUpdatedTime': '2023-06-30 07:54:47.580000+00:00', 'statusCode': 'open', 'eventScopeCode': 'ACCOUNT_SPECIFIC'}, 'eventDescription': {'latestDescription': "You are receiving this notification because you have one or more Lambda functions in the US-EAST-1 Region that are being invoked in a recursive loop with other AWS resources.\n\nStarting June 26, 2023, AWS Lambda is launching recursive loop detection. With this launch, Lambda will stop recursive invocations between Amazon SQS, AWS Lambda, and Amazon SNS after 16 recursive calls. If a function is invoked by the same triggering event more than 16 times, Lambda will stop the next invocation and send the event to a Dead-Letter Queue or on-failure destination, if configured.\n\nYour affected Lambda function ARN(s) are listed in the 'Affected resources' tab.\n\nWhat do I need to do?\nTo prevent potential disruptions to your account, we have turned off recursive loop detection for your AWS account so that you can investigate these recursive functions. Please review your functions and their trigger configurations to identify any unintentional recursive patterns.\n\nIf your account has functions that intentionally use recursive patterns, no further action on your part is required. To learn more about recursive loop detection, please refer to Lambda documentation[1].\n\nIf your recursive patterns are unintentional, you can press the “Throttle” button in the Lambda console to scale the funtion concurrency down to zero and break the recursive cycle. Please contact AWS Support [2] in order to turn on recursive loop detection for your AWS Account.\n\n[1] https://docs.aws.amazon.com/lambda/latest/dg/invocation-recursion.html\n[2] https://aws.amazon.com/support"}}], 'failedSet': [], 'ResponseMetadata': {'RequestId': 'c0ccb5b7-75fd-4a56-a007-fcd95265bba3', 'HTTPStatusCode': 200, 'HTTPHeaders': {'x-amzn-requestid': 'c0ccb5b7-75fd-4a56-a007-fcd95265bba3', 'content-type': 'application/x-amz-json-1.1', 'content-length': '2165', 'date': 'Fri, 30 Jun 2023 14:23:17 GMT'}, 'RetryAttempts': 0}}
  )
  issue.finder_line = "DO NOT DELETE LINE:arn:aws:health:us-east-1::event/ELASTICLOADBALANCING/AWS_ELASTICLOADBALANCING_API_ISSUE/AWS_ELASTICLOADBALANCING_API_ISSUE_4b0741ea-402b-5a49-8e1d-4da360f32979:us-east-1:026088843893"

  resp = jira.check_if_issue_exists(issue)
  import ipdb;ipdb.set_trace()

