import boto3
import time
import json
from uuid import uuid4

from utils.logger import Logger
log = Logger("CSYE6225.log")

def send_validation(email_address):
    sns_client = boto3.client('sns', region_name='us-west-2')
    dynamodb_table = boto3.resource('dynamodb', region_name='us-west-2').Table('csye6225-token')

    token = str(uuid4())
    item = {"UserName": email_address, "token": token, "ExpireTime": int(time.time() + 300), "sendStatus": "Not sent"}
    message = "{\"email\": \"%s\", \"token\": \"%s\", \"message_type\": \"validation\"}" % (email_address, str(token))

    try:
        dynamodb_table.put_item(Item=item)
        sns_client.publish(TopicArn='arn:aws:sns:us-west-2:307355757102:sns-topic-for-lambda',
                           Message=message)
        return True
    except Exception as e:
        log.logger.info("send_validation error!")
        log.logger.info(repr(e))
        return False


def verify_token(email_address, token):
    dynamodb_table = boto3.resource('dynamodb', region_name='us-west-2').Table('csye6225-token')
    try:
        response = dynamodb_table.get_item(Key={"UserName": email_address})
        if "Item" in response.keys():
            item = response['Item']
            true_token = item['token']
            expire_time = item["ExpireTime"]
            if expire_time < int(time.time()):
                return False
            if true_token == token:
                return True
    except Exception:
        return False