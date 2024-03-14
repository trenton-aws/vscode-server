#!/usr/bin/env python3
import os
import boto3
import aws_cdk as cdk

from server.server_stack import VsCodeServerStack


app = cdk.App()
VsCodeServerStack(
    app, 
    "VSCode-Server",
    env=cdk.Environment(
        account=boto3.client('sts').get_caller_identity()["Account"],
        region="us-west-2"
    )
)

app.synth()
