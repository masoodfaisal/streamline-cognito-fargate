from xml import dom
from aws_cdk import (
    
    Stack,
    aws_cognito as cognito,
    aws_ec2 as ec2,
    aws_ecs_patterns as ecs_patterns,
    aws_ecr_assets as ecr_assets,
    aws_elasticloadbalancingv2 as elbv2,
    aws_ecs as ecs,
    aws_iam as iam,
    aws_certificatemanager as acm,
    Duration,
    aws_elasticloadbalancingv2_actions as actions
)
from constructs import Construct
import os






class StreamlitCognitoFargateStack(Stack):

    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        #code image
        docker_image = ecr_assets.DockerImageAsset(self, "FargateAppImage", 
                                                   directory=os.path.join('.', "python-app"),
                                                   file="Dockerfile")


        # Create VPC for Fargate
        vpc = ec2.Vpc(self, "FargateAppVPC", max_azs=2, nat_gateways=1)

        # Creaet Fargate Cluster
        cluster: ecs.Cluster = ecs.Cluster(self, "FargateAppCluster", vpc=vpc, container_insights=True, cluster_name="FargateAppCluster")
        cluster.enable_fargate_capacity_providers()

        # Create Fargate Application load balancer
        load_balancer_sg = ec2.SecurityGroup(self, "FargateAppLoadBalancerSG", vpc=vpc, allow_all_outbound=True)
        load_balancer: elbv2.ApplicationLoadBalancer = elbv2.ApplicationLoadBalancer(self, "FargateAppLoadBalancer", 
                                                             vpc=vpc, 
                                                             internet_facing=True, 
                                                             security_group=load_balancer_sg,
                                                             load_balancer_name="FargateAppLoadBalancer")

        

        # Create Fargate Application load balancer fargate service
        fargate_sg: ec2.SecurityGroup   = ec2.SecurityGroup(self, "FargateAppSG", vpc=vpc, allow_all_outbound=True)
        fargate_sg.add_ingress_rule(load_balancer_sg, ec2.Port.all_tcp(), "Allow from load balancer")

        fargate_sg.add_egress_rule(ec2.Peer.any_ipv4(), ec2.Port.all_tcp(), "Allow to access cognito and ml model and kendra")

        fargate_service: ecs_patterns.ApplicationLoadBalancedFargateService = \
            ecs_patterns.ApplicationLoadBalancedFargateService(self, "FargateAppService",
                                                               cpu=2048,
                                                               memory_limit_mib=8192,
                                                                desired_count=1,
                                                                cluster=cluster,
                                                                task_image_options=ecs_patterns.ApplicationLoadBalancedTaskImageOptions(
                                                                    image = ecs.ContainerImage.from_docker_image_asset(docker_image),
                                                                    enable_logging=True,
                                                                    container_port=8501),
                                                                load_balancer=load_balancer,
                                                                public_load_balancer=True,
                                                                listener_port=80,
                                                                security_groups=[fargate_sg],
                                                                capacity_provider_strategies=[ecs.CapacityProviderStrategy(capacity_provider="FARGATE", base=20, weight=100)],
                                                                runtime_platform=ecs.RuntimePlatform(cpu_architecture=ecs.CpuArchitecture.ARM64, operating_system_family=ecs.OperatingSystemFamily.LINUX)

                                                                )
        
        fargate_service.task_definition.add_to_task_role_policy(iam.PolicyStatement(
            effect=iam.Effect.ALLOW,
            # principals=[iam.AnyPrincipal()],
            actions=["cognito-idp:*", "sagemaker:*", "kendra:*"],
            resources=["*"]
        ))


        scaling = fargate_service.service.auto_scale_task_count(max_capacity=10)
        sixty_seconds: Duration = Duration.seconds(60)
        scaling.scale_on_cpu_utilization("CpuScaling", target_utilization_percent=50, scale_in_cooldown=sixty_seconds, scale_out_cooldown=sixty_seconds)
        scaling.scale_on_memory_utilization("MemoryScaling", target_utilization_percent=50, scale_in_cooldown=sixty_seconds, scale_out_cooldown=sixty_seconds)

        # add cognito integration      

        # Cognito
        user_pool: cognito.UserPool = cognito.UserPool(self, "FargateAppUserPool", self_sign_up_enabled=True, 
                                     sign_in_aliases=cognito.SignInAliases(email=True),
                                     user_pool_name="FargateAppUserPool")
        
        user_pool_domain = user_pool.add_domain("CognitoDomain",
            cognito_domain=cognito.CognitoDomainOptions(
                domain_prefix="fargate-app"
            )
        )        

        user_pool_client = cognito.UserPoolClient(self, "FargateAppUserPoolClient", 
                                                  user_pool=user_pool,
                                                  user_pool_client_name="FargateAppUserPoolClient",
                                                  generate_secret=False,
                                                  auth_flows=cognito.AuthFlow(user_password=True),
                                                o_auth=cognito.OAuthSettings(
                                                    flows=cognito.OAuthFlows(
                                                        authorization_code_grant=True
                                                    ),
                                                    scopes=[cognito.OAuthScope.EMAIL],
                                                    callback_urls=[f"https://{load_balancer.load_balancer_dns_name}/oauth2/idpresponse"
                                                    ]
                                                )                                                  
                                                )
        cfn_client = user_pool_client.node.default_child
        cfn_client.add_property_override("RefreshTokenValidity", 1)
        cfn_client.add_property_override("SupportedIdentityProviders", ["COGNITO"])

        # user_pool_domain = cognito.UserPoolDomain(self, "Domain",
        #                                           domain="fargate-app",
        #                                             user_pool=user_pool,
        #                                             cognito_domain=cognito.CognitoDomainOptions(
        #                                                 domain_prefix="fargate-app"
        #                                             )
        #                                             )

        # certificate = acm.Certificate.from_certificate_arn() 

        # fargate_service.listener.add_certificates("FargateAppCertificate", certificates=[certificate])
        # fargate_service.listener.add_action('Listener', 
        #         action=actions.AuthenticateCognitoAction(
        #             user_pool=user_pool,
        #             user_pool_client=user_pool_client,
        #             user_pool_domain=user_pool_domain,
        #             next=elbv2.ListenerAction.forward([fargate_service.target_group]),
        #             ),
        #     )        

       
        ####################################
        

        # create the target group for the ALB
        # target_group = fargate_service.target_group # elbv2.ApplicationTargetGroup(self, "FargateServiceTargetGroup", 
                                                    #  vpc=vpc, 
                                                    #  port=80, 
                                                    #  target_type=elbv2.TargetType.IP)

        # add the Fargate service to the target group
        # target_group.add_target(fargate_service)

        # add the target group to the listener
        # listener.add_targets("FargateServiceTargetGroup", port=80, targets=[target_group])

        # certificate
        # create a self-signed certificate
        # certificate = acm.DnsValidatedCertificate(self, "FargateServiceCertificate",
        #                                           domain_name="faisal.com",
        #                                           subject_alternative_names=["www.faisal.com"],
        #                                           validation=acm.CertificateValidation.from_dns())

        # # create a Route 53 hosted zone
        # zone = route53.PublicHostedZone(self, "FargateServiceHostedZone",
        #                                 zone_name="faisal.com")

        # # create a CNAME record for the ALB
        # cname_record = route53.CnameRecord(self, "FargateServiceCnameRecord",
        #                                    zone=zone,
        #                                    record_name="www.faisal.com",
        #                                    domain_name=load_balancer.load_balancer_dns_name)

        # # listener = my_load_balancer.add_listener("MyListener",
        # #                                           port=443,
        # #                                           certificates=[elbv2.ListenerCertificate(certificate.certificate_arn)])
        # listener.add_certificates([elbv2.ListenerCertificate(certificate.certificate_arn)])


        # user_pool_client = cognito.UserPoolClient(self, "Client",
        #     user_pool=user_pool,
        
        #     # Required minimal configuration for use with an ELB
        #     generate_secret=True,
        #     auth_flows=cognito.AuthFlow(
        #         user_password=True
        #     ),
        #     o_auth=cognito.OAuthSettings(
        #         flows=cognito.OAuthFlows(
        #             authorization_code_grant=True
        #         ),
        #         scopes=[cognito.OAuthScope.EMAIL],
        #         callback_urls=[f"https://{lb.loadBalancerDnsName}/oauth2/idpresponse"
        #         ]
        #     )
        # )
        #         
        # user_pool_domain = user_pool.add_domain("CognitoDomain",
        #     cognito_domain=cognito.CognitoDomainOptions(
        #         domain_prefix="fargate-app"
        #     )
        # ) 

