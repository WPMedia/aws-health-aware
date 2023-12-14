import json
import boto3
import os
import re
import time
import decimal
import socket
import configparser
from dateutil import parser
from datetime import datetime, timedelta
from urllib.parse import urlencode
from urllib.request import Request, urlopen, URLError, HTTPError
from botocore.config import Config
from botocore.exceptions import ClientError
from boto3.dynamodb.conditions import Key, Attr
from messagegenerator import get_message_for_slack, get_org_message_for_slack, get_message_for_chime, \
    get_org_message_for_chime, \
    get_message_for_teams, get_org_message_for_teams, get_message_for_email, get_org_message_for_email, \
    get_detail_for_eventbridge
from plugin_jira import Jira, get_org_message_for_jira

print("boto3 version: ",boto3.__version__)

# query active health API endpoint
health_dns = socket.gethostbyname_ex('global.health.amazonaws.com')
(current_endpoint, global_endpoint, ip_endpoint) = health_dns
health_active_list = current_endpoint.split('.')
health_active_region = health_active_list[1]
print("current health region: ", health_active_region)

# create a boto3 health client w/ backoff/retry
config = Config(
    region_name=health_active_region,
    retries=dict(
        max_attempts=10  # org view apis have a lower tps than the single
        # account apis so we need to use larger
        # backoff/retry values than than the boto defaults
    )
)

# TODO decide if account_name should be blank on error
# Get Account Name
def get_account_name(account_id):
    org_client = get_sts_token('organizations')
    try:
        account_name = org_client.describe_account(AccountId=account_id)['Account']['Name']
    except Exception:
        account_name = account_id
    return account_name

def send_alert(event_details, affected_accounts, affected_entities, event_type):
    slack_url = get_secrets()["slack"]
    teams_url = get_secrets()["teams"]
    chime_url = get_secrets()["chime"]
    SENDER = os.environ['FROM_EMAIL']
    RECIPIENT = os.environ['TO_EMAIL']
    event_bus_name = get_secrets()["eventbusname"]

    #get the list of resources from the array of affected entities
    resources = get_resources_from_entities(affected_entities)

    if "None" not in event_bus_name:
        try:
            print("Sending the alert to Event Bridge")
            send_to_eventbridge(get_detail_for_eventbridge(event_details, affected_entities), event_type, resources, event_bus_name)
        except HTTPError as e:
            print("Got an error while sending message to EventBridge: ", e.code, e.reason)
        except URLError as e:
            print("Server connection failed: ", e.reason)
            pass
    if "hooks.slack.com/services" in slack_url:
        try:
            print("Sending the alert to Slack Webhook Channel")
            send_to_slack(get_message_for_slack(event_details, event_type, affected_accounts, resources, slack_webhook="webhook"), slack_url)
        except HTTPError as e:
            print("Got an error while sending message to Slack: ", e.code, e.reason)
        except URLError as e:
            print("Server connection failed: ", e.reason)
            pass
    if "hooks.slack.com/workflows" in slack_url:
        try:
            print("Sending the alert to Slack Workflows Channel")
            send_to_slack(get_message_for_slack(event_details, event_type, affected_accounts, resources, slack_webhook="workflow"), slack_url)
        except HTTPError as e:
            print("Got an error while sending message to Slack: ", e.code, e.reason)
        except URLError as e:
            print("Server connection failed: ", e.reason)
            pass
    if "office.com/webhook" in teams_url:
        try:
            print("Sending the alert to Teams")
            send_to_teams(get_message_for_teams(event_details, event_type, affected_accounts, resources), teams_url)
        except HTTPError as e:
            print("Got an error while sending message to Teams: ", e.code, e.reason)
        except URLError as e:
            print("Server connection failed: ", e.reason)
            pass
    # validate sender and recipient's email addresses
    if "none@domain.com" not in SENDER and RECIPIENT:
        try:
            print("Sending the alert to the emails")
            send_email(event_details, event_type, affected_accounts, resources)
        except HTTPError as e:
            print("Got an error while sending message to Email: ", e.code, e.reason)
        except URLError as e:
            print("Server connection failed: ", e.reason)
            pass
    if "hooks.chime.aws/incomingwebhooks" in chime_url:
        try:
            print("Sending the alert to Chime channel")
            send_to_chime(get_message_for_chime(event_details, event_type, affected_accounts, resources), chime_url)
        except HTTPError as e:
            print("Got an error while sending message to Chime: ", e.code, e.reason)
        except URLError as e:
            print("Server connection failed: ", e.reason)
            pass

def send_org_alert(event_details, affected_org_accounts, affected_org_entities, event_type):
    slack_url = get_secrets()["slack"]
    teams_url = get_secrets()["teams"]
    chime_url = get_secrets()["chime"]
    jira_config = get_secrets()["jira"]
    SENDER = os.environ['FROM_EMAIL']
    RECIPIENT = os.environ['TO_EMAIL']
    event_bus_name = get_secrets()["eventbusname"]
    print("Top:: Org alert send")
    #get the list of resources from the array of affected entities
    resources = get_resources_from_entities(affected_org_entities)

    if "None" not in event_bus_name:
        try:
            print("Sending the org alert to Event Bridge")
            send_to_eventbridge(
                get_detail_for_eventbridge(event_details, affected_org_entities),
                event_type, resources, event_bus_name)
        except HTTPError as e:
            print("Got an error while sending message to EventBridge: ", e.code, e.reason)
        except URLError as e:
            print("Server connection failed: ", e.reason)
            pass
    if "hooks.slack.com/services" in slack_url:
        try:
            print("Sending the alert to Slack Webhook Channel")
            send_to_slack(
                get_org_message_for_slack(event_details, event_type, affected_org_accounts, resources, slack_webhook="webhook"),
                slack_url)
        except HTTPError as e:
            print("Got an error while sending message to Slack: ", e.code, e.reason)
        except URLError as e:
            print("Server connection failed: ", e.reason)
            pass
    if "hooks.slack.com/workflows" in slack_url:
        try:
            print("Sending the alert to Slack Workflow Channel")
            send_to_slack(
                get_org_message_for_slack(event_details, event_type, affected_org_accounts, resources, slack_webhook="workflow"),
                slack_url)
        except HTTPError as e:
            print("Got an error while sending message to Slack: ", e.code, e.reason)
        except URLError as e:
            print("Server connection failed: ", e.reason)
            pass
    if "office.com/webhook" in teams_url:
        try:
            print("Sending the alert to Teams")
            send_to_teams(
                get_org_message_for_teams(event_details, event_type, affected_org_accounts, resources),
                teams_url)
        except HTTPError as e:
            print("Got an error while sending message to Teams: ", e.code, e.reason)
        except URLError as e:
            print("Server connection failed: ", e.reason)
            pass
    # validate sender and recipient's email addresses
    if "none@domain.com" not in SENDER and RECIPIENT:
        try:
            print("Sending the alert to the emails")
            send_org_email(event_details, event_type, affected_org_accounts, resources)
        except HTTPError as e:
            print("Got an error while sending message to Email: ", e.code, e.reason)
        except URLError as e:
            print("Server connection failed: ", e.reason)
            pass
    if "hooks.chime.aws/incomingwebhooks" in chime_url:
        try:
            print("Sending the alert to Chime channel")
            send_to_chime(
                get_org_message_for_chime(event_details, event_type, affected_org_accounts, resources),
                chime_url)
        except HTTPError as e:
            print("Got an error while sending message to Chime: ", e.code, e.reason)
        except URLError as e:
            print("Server connection failed: ", e.reason)
            pass

    if "JiraInstanceURL" in jira_config:
        jira_auth = {
            "base_url": jira_config["JiraInstanceURL"],
            "username": jira_config["Username"],
            "token": jira_config["Secret"],
        }
        issue_config = json.loads(jira_config["IssueConfig"])
        try:

            send_to_jira(
                get_org_message_for_jira(event_details, event_type, affected_org_accounts, resources, issue_config),
                jira_auth,
            )
        except HTTPError as e:
            print("Got an error while sending message to Jira: ", e.code, e.reason)
        except URLError as e:
            print("Server connection failed: ", e.reason)
            pass


def send_to_slack(message, webhookurl):
    slack_message = message
    req = Request(webhookurl, data=json.dumps(slack_message).encode("utf-8"),
                  headers={'content-type': 'application/json'})
    try:
        response = urlopen(req)
        response.read()
    except HTTPError as e:
        print("Request failed : ", e.code, e.reason)
    except URLError as e:
        print("Server connection failed: ", e.reason, e.reason)


def send_to_chime(message, webhookurl):
    chime_message = {'Content': message}
    req = Request(webhookurl, data=json.dumps(chime_message).encode("utf-8"),
                  headers={"content-Type": "application/json"})
    try:
        response = urlopen(req)
        response.read()
    except HTTPError as e:
        print("Request failed : ", e.code, e.reason)
    except URLError as e:
        print("Server connection failed: ", e.reason, e.reason)


def send_to_teams(message, webhookurl):
    teams_message = message
    req = Request(webhookurl, data=json.dumps(teams_message).encode("utf-8"),
                  headers={"content-type": "application/json"})
    try:
        response = urlopen(req)
        response.read()
    except HTTPError as e:
        print("Request failed : ", e.code, e.reason)
    except URLError as e:
        print("Server connection failed: ", e.reason, e.reason)

def send_to_jira(issues, jira_auth):
    print("Sending the alert to Jira")
    client = Jira(auth=jira_auth)
    responses = client.manage_issues(issues)
    print(responses, "Done Jira")


def send_email(event_details, eventType, affected_accounts, affected_entities):
    SENDER = os.environ['FROM_EMAIL']
    RECIPIENT = os.environ['TO_EMAIL'].split(",")
    #AWS_REGIONS = "us-east-1"
    AWS_REGION = os.environ['AWS_REGION']
    SUBJECT = os.environ['EMAIL_SUBJECT']
    BODY_HTML = get_message_for_email(event_details, eventType, affected_accounts, affected_entities)
    client = boto3.client('ses', region_name=AWS_REGION)
    response = client.send_email(
        Source=SENDER,
        Destination={
            'ToAddresses': RECIPIENT
        },
        Message={
            'Body': {
                'Html': {
                    'Data': BODY_HTML
                },
            },
            'Subject': {
                'Charset': 'UTF-8',
                'Data': SUBJECT,
            },
        },
    )


def send_org_email(event_details, eventType, affected_org_accounts, affected_org_entities):
    SENDER = os.environ['FROM_EMAIL']
    RECIPIENT = os.environ['TO_EMAIL'].split(",")
    #AWS_REGION = "us-east-1"
    AWS_REGION = os.environ['AWS_REGION']
    SUBJECT = os.environ['EMAIL_SUBJECT']
    BODY_HTML = get_org_message_for_email(event_details, eventType, affected_org_accounts, affected_org_entities)
    client = boto3.client('ses', region_name=AWS_REGION)
    response = client.send_email(
        Source=SENDER,
        Destination={
            'ToAddresses': RECIPIENT
        },
        Message={
            'Body': {
                'Html': {
                    'Data': BODY_HTML
                },
            },
            'Subject': {
                'Charset': 'UTF-8',
                'Data': SUBJECT,
            },
        },
    )

# non-organization view affected accounts
def get_health_accounts(health_client, event, event_arn):
    affected_accounts = []
    event_accounts_paginator = health_client.get_paginator('describe_affected_entities')
    event_accounts_page_iterator = event_accounts_paginator.paginate(
        filter = {
            'eventArns': [
                event_arn
            ]
        }
    )
    for event_accounts_page in event_accounts_page_iterator:
        json_event_accounts = json.dumps(event_accounts_page, default=myconverter)
        parsed_event_accounts = json.loads(json_event_accounts)
        try:
          affected_accounts.append(parsed_event_accounts['entities'][0]['awsAccountId'])
        except Exception:
          affected_accounts = []
    return affected_accounts

# organization view affected accounts
def get_health_org_accounts(health_client, event, event_arn):
    affected_org_accounts = []
    event_accounts_paginator = health_client.get_paginator('describe_affected_accounts_for_organization')
    event_accounts_page_iterator = event_accounts_paginator.paginate(
        eventArn=event_arn
    )
    for event_accounts_page in event_accounts_page_iterator:
        json_event_accounts = json.dumps(event_accounts_page, default=myconverter)
        parsed_event_accounts = json.loads(json_event_accounts)
        affected_org_accounts = affected_org_accounts + (parsed_event_accounts['affectedAccounts'])
    return affected_org_accounts

# get the array of affected entities for all affected accounts and return as an array of JSON objects
def get_affected_entities(health_client, event_arn, affected_accounts, is_org_mode):
    affected_entity_array = []

    for account in affected_accounts:

        if is_org_mode:
            event_entities_paginator = health_client.get_paginator('describe_affected_entities_for_organization')
            event_entities_page_iterator = event_entities_paginator.paginate(
                organizationEntityFilters=[
                    {
                        'awsAccountId': account,
                        'eventArn': event_arn
                    }
                ]
            )
        else:
            event_entities_paginator = health_client.get_paginator('describe_affected_entities')
            event_entities_page_iterator = event_entities_paginator.paginate(
                filter = {
                    'eventArns': [
                        event_arn
                    ]
                }
            )

        for event_entities_page in event_entities_page_iterator:
            json_event_entities = json.dumps(event_entities_page, default=myconverter)
            parsed_event_entities = json.loads(json_event_entities)
            for entity in parsed_event_entities['entities']:
                entity.pop("entityArn") #remove entityArn to avoid confusion with the arn of the entityValue (not present)
                entity.pop("eventArn") #remove eventArn duplicate of detail.arn
                entity.pop("lastUpdatedTime") #remove for brevity
                if is_org_mode:
                    entity['awsAccountName'] = get_account_name(entity['awsAccountId'])
                affected_entity_array.append(entity)

    return affected_entity_array

#COMMON
#get the entityValues from the array and return as an array (of strings) for use with chat channels
#don't list entities which are accounts (handled separately for chat applications)
def get_resources_from_entities(affected_entity_array):

    resources = []

    for entity in affected_entity_array:
        if entity['entityValue'] == "UNKNOWN":
            #UNKNOWN indicates a public/non-accountspecific event, no resources
            pass
        elif entity['entityValue'] != "AWS_ACCOUNT" and entity['entityValue'] != entity['awsAccountId']:
            resources.append(entity['entityValue'])
    return resources


# For Customers using AWS Organizations
def update_org_ddb(event_arn, str_update, status_code, event_details, affected_org_accounts, affected_org_entities):
    # open dynamoDB
    dynamodb = boto3.resource("dynamodb")
    ddb_table = os.environ['DYNAMODB_TABLE']
    aha_ddb_table = dynamodb.Table(ddb_table)
    event_latestDescription = event_details['successfulSet'][0]['eventDescription']['latestDescription']
    # set time parameters
    delta_hours = os.environ['EVENT_SEARCH_BACK']
    delta_hours = int(delta_hours)
    delta_hours_sec = delta_hours * 3600

    # formatting time in seconds
    srt_ddb_format_full = "%Y-%m-%d %H:%M:%S"
    str_ddb_format_sec = '%s'
    sec_now = datetime.strftime(datetime.now(), str_ddb_format_sec)

    # check if event arn already exists
    try:
        response = aha_ddb_table.get_item(
            Key={
                'arn': event_arn
            }
        )
    except ClientError as e:
        print(e.response['Error']['Message'])
    else:
        is_item_response = response.get('Item')
        if is_item_response == None:
            print(datetime.now().strftime(srt_ddb_format_full) + ": record not found")
            # write to dynamodb
            response = aha_ddb_table.put_item(
                Item={
                    'arn': event_arn,
                    'lastUpdatedTime': str_update,
                    'added': sec_now,
                    'ttl': int(sec_now) + delta_hours_sec + 86400,
                    # 'ttl': int(sec_now) + 60,

                    'statusCode': status_code,
                    'affectedAccountIDs': affected_org_accounts,
                    'latestDescription': event_latestDescription
                    # Cleanup: DynamoDB entry deleted 24 hours after last update
                }
            )
            affected_org_accounts_details = [
                    f"{get_account_name(account_id)} ({account_id})" for account_id in affected_org_accounts]
            # send to configured endpoints
            if status_code != "closed":
                send_org_alert(event_details, affected_org_accounts_details, affected_org_entities, event_type="create")
            else:
                send_org_alert(event_details, affected_org_accounts_details, affected_org_entities, event_type="resolve")

        else:
            item = response['Item']
            if item['lastUpdatedTime'] != str_update and (item['statusCode'] != status_code or
                                                          item['latestDescription'] != event_latestDescription or
                                                          item['affectedAccountIDs'] != affected_org_accounts):
                print(datetime.now().strftime(srt_ddb_format_full) + ": last Update is different")
                # write to dynamodb
                response = aha_ddb_table.put_item(
                    Item={
                        'arn': event_arn,
                        'lastUpdatedTime': str_update,
                        'added': sec_now,
                        # 'ttl': int(sec_now) + delta_hours_sec + 86400,
                        'ttl': int(sec_now) + 60,

                        'statusCode': status_code,
                        'affectedAccountIDs': affected_org_accounts,
                        'latestDescription': event_latestDescription
                        # Cleanup: DynamoDB entry deleted 24 hours after last update
                    }
                )
                affected_org_accounts_details = [
                    f"{get_account_name(account_id)} ({account_id})" for account_id in affected_org_accounts]
                # send to configured endpoints
                if status_code != "closed":
                    send_org_alert(event_details, affected_org_accounts_details, affected_org_entities, event_type="create")
                else:
                    send_org_alert(event_details, affected_org_accounts_details, affected_org_entities, event_type="resolve")
            else:
                print("No new updates found, checking again in 1 minute.")


# For Customers not using AWS Organizations
def update_ddb(event_arn, str_update, status_code, event_details, affected_accounts, affected_entities):
    # open dynamoDB
    dynamodb = boto3.resource("dynamodb")
    ddb_table = os.environ['DYNAMODB_TABLE']
    aha_ddb_table = dynamodb.Table(ddb_table)
    event_latestDescription = event_details['successfulSet'][0]['eventDescription']['latestDescription']

    # set time parameters
    delta_hours = os.environ['EVENT_SEARCH_BACK']
    delta_hours = int(delta_hours)
    delta_hours_sec = delta_hours * 3600

    # formatting time in seconds
    srt_ddb_format_full = "%Y-%m-%d %H:%M:%S"
    str_ddb_format_sec = '%s'
    sec_now = datetime.strftime(datetime.now(), str_ddb_format_sec)

    # check if event arn already exists
    try:
        response = aha_ddb_table.get_item(
            Key={
                'arn': event_arn
            }
        )
    except ClientError as e:
        print(e.response['Error']['Message'])
    else:
        is_item_response = response.get('Item')
        if is_item_response == None:
            print(datetime.now().strftime(srt_ddb_format_full) + ": record not found")
            # write to dynamodb
            response = aha_ddb_table.put_item(
                Item={
                    'arn': event_arn,
                    'lastUpdatedTime': str_update,
                    'added': sec_now,
                    # 'ttl': int(sec_now) + delta_hours_sec + 86400,
                    'ttl': int(sec_now)+ 60,
                    'statusCode': status_code,
                    'affectedAccountIDs': affected_accounts,
                    'latestDescription': event_latestDescription
                    # Cleanup: DynamoDB entry deleted 24 hours after last update
                }
            )

            affected_accounts_details = affected_accounts

            # send to configured endpoints
            if status_code != "closed":
                send_alert(event_details, affected_accounts_details, affected_entities, event_type="create")
            else:
                send_alert(event_details, affected_accounts_details, affected_entities, event_type="resolve")
        else:
            item = response['Item']
            if item['lastUpdatedTime'] != str_update and (item['statusCode'] != status_code or
                                                          item['latestDescription'] != event_latestDescription or
                                                          item['affectedAccountIDs'] != affected_accounts):
                print(datetime.now().strftime(srt_ddb_format_full) + ": last Update is different")
                # write to dynamodb
                response = aha_ddb_table.put_item(
                    Item={
                        'arn': event_arn,
                        'lastUpdatedTime': str_update,
                        'added': sec_now,
                        'ttl': int(sec_now) + delta_hours_sec + 86400,
                        'statusCode': status_code,
                        'affectedAccountIDs': affected_accounts,
                        'latestDescription': event_latestDescription
                        # Cleanup: DynamoDB entry deleted 24 hours after last update
                    }
                )
                affected_accounts_details = [
                    f"{get_account_name(account_id)} ({account_id})" for account_id in affected_accounts]
                # send to configured endpoints
                if status_code != "closed":
                    send_alert(event_details, affected_accounts_details, affected_entities, event_type="create")
                else:
                    send_alert(event_details, affected_accounts_details, affected_entities, event_type="resolve")
            else:
                print("No new updates found, checking again in 1 minute.")

def get_secrets():
    secret_teams_name = "MicrosoftChannelID"
    secret_slack_name = "SlackChannelID"
    secret_chime_name = "ChimeChannelID"
    secret_jira_name = "JiraInstanceSecret"
    region_name = os.environ['AWS_REGION']
    get_secret_value_response_assumerole = ""
    get_secret_value_response_eventbus = ""
    get_secret_value_response_chime = ""
    get_secret_value_response_teams = ""
    get_secret_value_response_slack = ""
    get_secret_value_response_jira = ""
    event_bus_name = "EventBusName"
    secret_assumerole_name = "AssumeRoleArn"

    # create a Secrets Manager client
    session = boto3.session.Session()
    client = session.client(
        service_name='secretsmanager',
        region_name=region_name
    )
    # Iteration through the configured AWS Secrets
    try:
        get_secret_value_response_teams = client.get_secret_value(
            SecretId=secret_teams_name
        )
    except ClientError as e:
        if e.response['Error']['Code'] == 'AccessDeniedException':
            print("No AWS Secret configured for Teams, skipping")
            teams_channel_id = "None"
        else:
            print("There was an error with the Teams secret: ",e.response)
            teams_channel_id = "None"
    finally:
        if 'SecretString' in get_secret_value_response_teams:
            teams_channel_id = get_secret_value_response_teams['SecretString']
        else:
            teams_channel_id = "None"
    try:
        get_secret_value_response_slack = client.get_secret_value(
            SecretId=secret_slack_name
        )
    except ClientError as e:
        if e.response['Error']['Code'] == 'AccessDeniedException':
            print("No AWS Secret configured for Slack, skipping")
            slack_channel_id = "None"
        else:
            print("There was an error with the Slack secret: ",e.response)
            slack_channel_id = "None"
    finally:
        if 'SecretString' in get_secret_value_response_slack:
            slack_channel_id = get_secret_value_response_slack['SecretString']
        else:
            slack_channel_id = "None"
    try:
        get_secret_value_response_chime = client.get_secret_value(
            SecretId=secret_chime_name
        )
    except ClientError as e:
        if e.response['Error']['Code'] == 'AccessDeniedException':
            print("No AWS Secret configured for Chime, skipping")
            chime_channel_id = "None"
        else:
            print("There was an error with the Chime secret: ",e.response)
            chime_channel_id = "None"
    finally:
        if 'SecretString' in get_secret_value_response_chime:
            chime_channel_id = get_secret_value_response_chime['SecretString']
        else:
            chime_channel_id = "None"
    try:
        get_secret_value_response_assumerole = client.get_secret_value(
            SecretId=secret_assumerole_name
        )
    except ClientError as e:
        if e.response['Error']['Code'] == 'AccessDeniedException':
            print("No AWS Secret configured for Assume Role, skipping")
            assumerole_channel_id = "None"
        else:
            print("There was an error with the Assume Role secret: ",e.response)
            assumerole_channel_id = "None"
    finally:
        if 'SecretString' in get_secret_value_response_assumerole:
            assumerole_channel_id = get_secret_value_response_assumerole['SecretString']
        else:
            assumerole_channel_id = "None"
    # JIRA
    try:
        get_secret_value_response_jira = client.get_secret_value(
            SecretId=secret_jira_name
        )
    except ClientError as e:
        if e.response['Error']['Code'] == 'AccessDeniedException':
            print("No AWS Secret configured for Jira, skipping", e)
            jira_config = "None"
        else:
            print("There was an error with the Jira secret: ",e.response)
            jira_config = "None"
    finally:
        if 'SecretString' in get_secret_value_response_jira:
            jira_config = json.loads(get_secret_value_response_jira["SecretString"])
        else:
            jira_config = "None"

    try:
        get_secret_value_response_eventbus = client.get_secret_value(
            SecretId=event_bus_name
        )
    except ClientError as e:
        if e.response['Error']['Code'] == 'AccessDeniedException':
            print("No AWS Secret configured for EventBridge, skipping")
            eventbus_channel_id = "None"
        else:
            print("There was an error with the EventBridge secret: ",e.response)
            eventbus_channel_id = "None"
    finally:
        if 'SecretString' in get_secret_value_response_eventbus:
            eventbus_channel_id = get_secret_value_response_eventbus['SecretString']
        else:
            eventbus_channel_id = "None"
        secrets = {
            "teams": teams_channel_id,
            "slack": slack_channel_id,
            "chime": chime_channel_id,
            "eventbusname": eventbus_channel_id,
            "ahaassumerole": assumerole_channel_id,
            "jira": jira_config,
        }
        # uncomment below to verify secrets values
        #print("Secrets: ",secrets)
    return secrets


def describe_events(health_client):
    str_ddb_format_sec = '%s'
    # set hours to search back in time for events
    delta_hours = os.environ['EVENT_SEARCH_BACK']
    health_event_type = os.environ['HEALTH_EVENT_TYPE']
    delta_hours = int(delta_hours)
    time_delta = (datetime.now() - timedelta(hours=delta_hours))
    print("Searching for events and updates made after: ", time_delta)
    dict_regions = os.environ['REGIONS']

    str_filter = {
        'lastUpdatedTimes': [
            {
                'from': time_delta
            }
        ]
    }

    if health_event_type == "issue":
        event_type_filter = {'eventTypeCategories': ['issue','investigation']}
        print("AHA will be monitoring events with event type categories as 'issue' only!")
        str_filter.update(event_type_filter)

    if dict_regions != "all regions":
        dict_regions = [region.strip() for region in dict_regions.split(',')]
        print("AHA will monitor for events only in the selected regions: ", dict_regions)
        region_filter = {'regions': dict_regions}
        str_filter.update(region_filter)

    event_paginator = health_client.get_paginator('describe_events')
    event_page_iterator = event_paginator.paginate(filter=str_filter)
    for response in event_page_iterator:
        events = response.get('events', [])
        aws_events = json.dumps(events, default=myconverter)
        aws_events = json.loads(aws_events)
        print('Event(s) Received: ', json.dumps(aws_events))
        if len(aws_events) > 0:  # if there are new event(s) from AWS
            for event in aws_events:
                event_arn = event['arn']
                status_code = event['statusCode']
                str_update = parser.parse((event['lastUpdatedTime']))
                str_update = str_update.strftime(str_ddb_format_sec)

                # get non-organizational view requirements
                affected_accounts = get_health_accounts(health_client, event, event_arn)
                affected_entities = get_affected_entities(health_client, event_arn, affected_accounts, is_org_mode = False)

                # get event details
                event_details = json.dumps(describe_event_details(health_client, event_arn), default=myconverter)
                event_details = json.loads(event_details)
                print("Event Details: ", event_details)
                if event_details['successfulSet'] == []:
                    print("An error occured with account:", event_details['failedSet'][0]['awsAccountId'], "due to:",
                          event_details['failedSet'][0]['errorName'], ":",
                          event_details['failedSet'][0]['errorMessage'])
                    continue
                else:
                    # write to dynamoDB for persistence
                    update_ddb(event_arn, str_update, status_code, event_details, affected_accounts, affected_entities)
        else:
            print("No events found in time frame, checking again in 1 minute.")


def describe_org_events(health_client):
    str_ddb_format_sec = '%s'
    # set hours to search back in time for events
    delta_hours = os.environ.get('EVENT_SEARCH_BACK', "1")
    health_event_type = os.environ.get('HEALTH_EVENT_TYPE', )
    dict_regions = os.environ['REGIONS']
    delta_hours = int(delta_hours)
    time_delta = (datetime.now() - timedelta(hours=delta_hours))
    print("Searching for events and updates made after: ", time_delta)

    str_filter = {
        'lastUpdatedTime': {
            'from': time_delta
        }
    }

    if health_event_type == "issue":
        event_type_filter = {'eventTypeCategories': ['issue','investigation']}
        print("AHA will be monitoring events with event type categories as 'issue' only!")
        str_filter.update(event_type_filter)

    if dict_regions != "all regions":
        dict_regions = [region.strip() for region in dict_regions.split(',')]
        print("AHA will monitor for events only in the selected regions: ", dict_regions)
        region_filter = {'regions': dict_regions}
        str_filter.update(region_filter)

    org_event_paginator = health_client.get_paginator('describe_events_for_organization')
    org_event_page_iterator = org_event_paginator.paginate(filter=str_filter)
    for response in org_event_page_iterator:
        events = response.get('events', [])
        aws_events = json.dumps(events, default=myconverter)
        aws_events = json.loads(aws_events)
        print('Event(s) Received: ', json.dumps(aws_events))
        if len(aws_events) > 0:
            for event in aws_events:
                event_arn = event['arn']
                status_code = event['statusCode']
                str_update = parser.parse((event['lastUpdatedTime']))
                str_update = str_update.strftime(str_ddb_format_sec)

                # get organizational view requirements
                affected_org_accounts = get_health_org_accounts(health_client, event, event_arn)
                if os.environ['ACCOUNT_IDS'] == "None" or os.environ['ACCOUNT_IDS'] == "":
                    affected_org_accounts = affected_org_accounts
                    update_org_ddb_flag=True
                else:
                    account_ids_to_filter = getAccountIDs()
                    if affected_org_accounts != []:
                        focused_org_accounts = [i for i in affected_org_accounts if i not in account_ids_to_filter]
                        print("Focused list is ", focused_org_accounts)
                        if focused_org_accounts != []:
                            update_org_ddb_flag=True
                            affected_org_accounts = focused_org_accounts
                        else:
                            update_org_ddb_flag=False
                            print("Focused Organization Account list is empty")
                    else:
                        update_org_ddb_flag=True

                affected_org_entities = get_affected_entities(health_client, event_arn, affected_org_accounts, is_org_mode = True)
                # get event details
                event_details = json.dumps(describe_org_event_details(health_client, event_arn, affected_org_accounts),
                                        default=myconverter)
                event_details = json.loads(event_details)
                print("Event Details: ", event_details)
                if event_details['successfulSet'] == []:
                    print("An error occured with account:", event_details['failedSet'][0]['awsAccountId'], "due to:",
                        event_details['failedSet'][0]['errorName'], ":",
                        event_details['failedSet'][0]['errorMessage'])
                    continue
                else:
                    # write to dynamoDB for persistence
                    if update_org_ddb_flag:
                        update_org_ddb(event_arn, str_update, status_code, event_details, affected_org_accounts,
                                    affected_org_entities)
        else:
            print("No events found in time frame, checking again in 1 minute.")

def myconverter(json_object):
    if isinstance(json_object, datetime):
        return json_object.__str__()


def describe_event_details(health_client, event_arn):
    response = health_client.describe_event_details(
        eventArns=[event_arn],
    )
    return response


def describe_org_event_details(health_client, event_arn, affected_org_accounts):
    if len(affected_org_accounts) >= 1:
        affected_account_ids = affected_org_accounts[0]
        response = health_client.describe_event_details_for_organization(
            organizationEventDetailFilters=[
                {
                    'awsAccountId': affected_account_ids,
                    'eventArn': event_arn
                }
            ]
        )
        return response
    else:
        response = describe_event_details(health_client, event_arn)
        return response

def eventbridge_generate_entries(message, resources, event_bus):
    return [ {'Source': 'aha', 'DetailType': 'AHA Event', 'Resources': resources, 'Detail': json.dumps(message),
         'EventBusName': event_bus}, ]

def send_to_eventbridge(message, event_type, resources, event_bus):
    print("Sending response to Eventbridge - event_type, event_bus", event_type, event_bus)
    client = boto3.client('events')

    entries = eventbridge_generate_entries(message, resources, event_bus)

    print("Sending entries: ", entries)

    response = client.put_events(Entries=entries)
    print("Response from eventbridge is:", response)

def getAccountIDs():
    account_ids  = ""
    key_file_name = os.environ['ACCOUNT_IDS']
    print("Key filename is - ", key_file_name)
    if os.path.splitext(os.path.basename(key_file_name))[1] == '.csv':
        s3 = boto3.client('s3')
        data = s3.get_object(Bucket=os.environ['S3_BUCKET'], Key=key_file_name)
        account_ids = [account.decode('utf-8') for account in data['Body'].iter_lines()]
    else:
        print("Key filename is not a .csv file")
    print(account_ids)
    return account_ids

def get_sts_token(service):
    assumeRoleArn = get_secrets()["ahaassumerole"]
    boto3_client = None

    if "arn:aws:iam::" in assumeRoleArn:
        ACCESS_KEY = []
        SECRET_KEY = []
        SESSION_TOKEN = []

        sts_connection = boto3.client('sts')

        ct = datetime.now()
        role_session_name = "cross_acct_aha_session"

        acct_b = sts_connection.assume_role(
          RoleArn=assumeRoleArn,
          RoleSessionName=role_session_name,
          DurationSeconds=900,
        )

        ACCESS_KEY    = acct_b['Credentials']['AccessKeyId']
        SECRET_KEY    = acct_b['Credentials']['SecretAccessKey']
        SESSION_TOKEN = acct_b['Credentials']['SessionToken']

        # create service client using the assumed role credentials, e.g. S3
        boto3_client = boto3.client(
          service,
          config=config,
          aws_access_key_id=ACCESS_KEY,
          aws_secret_access_key=SECRET_KEY,
          aws_session_token=SESSION_TOKEN,
        )
        print("Running in member account deployment mode")
    else:
        boto3_client = boto3.client(service, config=config)
        print("Running in management account deployment mode")

    return boto3_client

def manage_expiry_events(events, health_client):
    """
    Capture expiry/remove events and double check that they should be removed
    """
    str_ddb_format_sec = '%s'
    print("Running expiry events handler")
    for event in events:

        event_arn = event["dynamodb"]["OldImage"]["arn"]["S"]
        affected_org_accounts = [i["S"] for i in event["dynamodb"]["OldImage"]["affectedAccountIDs"]["L"]]
        event_details = json.dumps(describe_org_event_details(health_client, event_arn, affected_org_accounts),
                                default=myconverter)
        event_details = json.loads(event_details)
        print("Event Details: ", event_details)
        affected_org_entities = get_affected_entities(health_client, event_arn, affected_org_accounts, is_org_mode = True)

        if event_details['successfulSet'] == []:
            print("An error occured with account:", event_details['failedSet'][0]['awsAccountId'], "due to:",
                event_details['failedSet'][0]['errorName'], ":",
                event_details['failedSet'][0]['errorMessage'])
            continue
        else:
            for item in event_details["successfulSet"]:
                # write to dynamoDB for persistence
                status_code = item["event"]['statusCode']
                str_update = parser.parse((item["event"]['lastUpdatedTime']))
                str_update = str_update.strftime(str_ddb_format_sec)
                update_org_ddb(event_arn, str_update, status_code, event_details, affected_org_accounts,
                            affected_org_entities)


def get_expiry_events(event):
    """
    Look for expiry/remove events so we can double check
    """
    expiry_events = []
    if "Records" in event:
        for record in event["Records"]:
            if record.get("eventName") and record.get("userIdentity"):
                if record["eventName"] == "REMOVE" and \
                record["userIdentity"]["principalId"] == "dynamodb.amazonaws.com" and \
                record["userIdentity"]["type"] == "Service" and \
                record["dynamodb"]["OldImage"]["statusCode"]["S"] != "closed":
                    expiry_events.append(record)
    return expiry_events

def main(event, context):
    print("THANK YOU FOR CHOOSING AWS HEALTH AWARE!")
    health_client = get_sts_token('health')
    org_status = os.environ['ORG_STATUS']
    #str_ddb_format_sec = '%s'
    expiry_events = get_expiry_events(event)

    print("Incoming events", event, expiry_events)

    if expiry_events:
        return manage_expiry_events(expiry_events, health_client)
    # check for AWS Organizations Status
    if org_status == "No":
        #TODO update text below to reflect current functionality
        print("AWS Organizations is not enabled. Only Service Health Dashboard messages will be alerted.")
        describe_events(health_client)
    else:
        print(
            "AWS Organizations is enabled. Personal Health Dashboard and Service Health Dashboard messages will be alerted.")
        describe_org_events(health_client)

if __name__ == "__main__":
    event = {'Records': [{'eventID': '4ddc6d0b19fd21c913a84c6949c9b8b3', 'eventName': 'REMOVE', 'eventVersion': '1.1', 'eventSource': 'aws:dynamodb', 'awsRegion': 'us-east-1', 'dynamodb': {'ApproximateCreationDateTime': 1693511420.0, 'Keys': {'arn': {'S': 'arn:aws:health:us-east-1::event/EVENTS/AWS_EVENTS_INCREASED_API_LATENCIES/AWS_EVENTS_INCREASED_API_LATENCIES_fd55ae84-059a-57ca-9937-554b6ac2ffdf'}}, 'OldImage': {'latestDescription': {'S': 'We are investigating increased API latencies in the US-EAST-1 Region.\n\n[11:58 AM PDT] Between 10:30 AM and 11:25 AM PDT, we experienced increased API latencies in the US-EAST-1 Region. The issue is resolved and the service is operating normally. '}, 'added': {'S': '1693510847'}, 'lastUpdatedTime': {'S': '1693508404'}, 'affectedAccountIDs': {'L': [{'S': '493801680065'}, {'S': '638786611330'}]}, 'arn': {'S': 'arn:aws:health:us-east-1::event/EVENTS/AWS_EVENTS_INCREASED_API_LATENCIES/AWS_EVENTS_INCREASED_API_LATENCIES_fd55ae84-059a-57ca-9937-554b6ac2ffdf'}, 'ttl': {'N': '1693510907'}, 'statusCode': {'S': 'closed'}}, 'SequenceNumber': '282145900000000055288853903', 'SizeBytes': 671, 'StreamViewType': 'NEW_AND_OLD_IMAGES'}, 'userIdentity': {'principalId': 'dynamodb.amazonaws.com', 'type': 'Service'}, 'eventSourceARN': 'arn:aws:dynamodb:us-east-1:317098396095:table/aws-health-aware-DynamoDBTable-ZBTOH6ILIS1G/stream/2023-08-29T17:37:51.132'}]}
    main(event, '')
