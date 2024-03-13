import aws_cdk as core
import aws_cdk.assertions as assertions

from vs_code_server.vs_code_server_stack import VsCodeServerStack

# example tests. To run these tests, uncomment this file along with the example
# resource in vs_code_server/vs_code_server_stack.py
def test_sqs_queue_created():
    app = core.App()
    stack = VsCodeServerStack(app, "vs-code-server")
    template = assertions.Template.from_stack(stack)

#     template.has_resource_properties("AWS::SQS::Queue", {
#         "VisibilityTimeout": 300
#     })
