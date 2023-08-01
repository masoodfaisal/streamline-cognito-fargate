import aws_cdk as core
import aws_cdk.assertions as assertions

from streamlit_cognito_fargate.streamlit_cognito_fargate_stack import StreamlitCognitoFargateStack

# example tests. To run these tests, uncomment this file along with the example
# resource in streamlit_cognito_fargate/streamlit_cognito_fargate_stack.py
def test_sqs_queue_created():
    app = core.App()
    stack = StreamlitCognitoFargateStack(app, "streamlit-cognito-fargate")
    template = assertions.Template.from_stack(stack)

#     template.has_resource_properties("AWS::SQS::Queue", {
#         "VisibilityTimeout": 300
#     })
