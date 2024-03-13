from aws_cdk import Stack
import aws_cdk as cdk
import aws_cdk.aws_cloudfront as cloudfront
import aws_cdk.aws_ec2 as ec2
import aws_cdk.aws_iam as iam
import aws_cdk.aws_s3 as s3
import aws_cdk.aws_ssm as ssm
from constructs import Construct

"""
  Create a VSCode code-server instance with an Amazon CloudFront distribution.
"""
class VsCodeServerStack(Stack):
  def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
    super().__init__(scope, construct_id, **kwargs)

    # Applying default props
    props = {
      'instanceVolumeSize': kwargs.get('instanceVolumeSize', 30),
      'instanceType': kwargs.get('instanceType', 'c7i.xlarge'),
      'homeFolder': kwargs.get('homeFolder', '/projects'),
      'devServerBasePath': kwargs.get('devServerBasePath', 'app'),
      'devServerPort': kwargs.get('devServerPort', 8081),
    }

    # Mappings
    subnets = {
      'VPC': {
        'CIDR': '10.0.0.0/16',
      },
      'PublicOne': {
        'CIDR': '10.0.1.0/24',
      },
      'PublicTwo': {
        'CIDR': '10.0.2.0/24',
      },
      'PrivateOne': {
        'CIDR': '10.0.3.0/24',
      },
      'PrivateTwo': {
        'CIDR': '10.0.4.0/24',
      },
    }
    awsRegions2PrefixListId = {
      'ap-northeast-1': {
        'PrefixList': 'pl-58a04531',
      },
      'ap-northeast-2': {
        'PrefixList': 'pl-22a6434b',
      },
      'ap-south-1': {
        'PrefixList': 'pl-9aa247f3',
      },
      'ap-southeast-1': {
        'PrefixList': 'pl-31a34658',
      },
      'ap-southeast-2': {
        'PrefixList': 'pl-b8a742d1',
      },
      'ca-central-1': {
        'PrefixList': 'pl-38a64351',
      },
      'eu-central-1': {
        'PrefixList': 'pl-a3a144ca',
      },
      'eu-north-1': {
        'PrefixList': 'pl-fab65393',
      },
      'eu-west-1': {
        'PrefixList': 'pl-4fa04526',
      },
      'eu-west-2': {
        'PrefixList': 'pl-93a247fa',
      },
      'eu-west-3': {
        'PrefixList': 'pl-75b1541c',
      },
      'sa-east-1': {
        'PrefixList': 'pl-5da64334',
      },
      'us-east-1': {
        'PrefixList': 'pl-3b927c52',
      },
      'us-east-2': {
        'PrefixList': 'pl-b6a144df',
      },
      'us-west-1': {
        'PrefixList': 'pl-4ea04527',
      },
      'us-west-2': {
        'PrefixList': 'pl-82a045eb',
      },
    }

    # Resources
    ec2KeyPair = ec2.CfnKeyPair(self, 'EC2KeyPair',
          key_name = 'VSCode',
        )

    internetGateway = ec2.CfnInternetGateway(self, 'InternetGateway',
        )

    ssmLogBucket = s3.CfnBucket(self, 'SSMLogBucket',
          access_control = 'Private',
          bucket_encryption = {
            'serverSideEncryptionConfiguration': [
              {
                'serverSideEncryptionByDefault': {
                  'sseAlgorithm': 'AES256',
                },
              },
            ],
          },
          public_access_block_configuration = {
            'blockPublicAcls': True,
            'blockPublicPolicy': True,
            'ignorePublicAcls': True,
            'restrictPublicBuckets': True,
          },
        )
    ssmLogBucket.cfn_options.metadata = {
      'cfn_nag': {
        'rules_to_suppress': [
          {
            'id': 'W35',
            'reason': 'Access logs aren\'t needed for this bucket',
          },
        ],
      },
    }
    ssmLogBucket.cfn_options.deletion_policy = cdk.CfnDeletionPolicy.DELETE

    vpc = ec2.CfnVPC(self, 'VPC',
          cidr_block = subnets['VPC']['CIDR'],
          enable_dns_support = True,
          enable_dns_hostnames = True,
        )

    vsCodeInstanceCachePolicy = cloudfront.CfnCachePolicy(self, 'VSCodeInstanceCachePolicy',
          cache_policy_config = {
            'defaultTtl': 86400,
            'maxTtl': 31536000,
            'minTtl': 1,
            'name': '-'.join([
              'VSCodeServer',
              cdk.Fn.select(4, cdk.Fn.split('-', cdk.Fn.select(2, cdk.Fn.split('/', self.stack_id)))),
            ]),
            'parametersInCacheKeyAndForwardedToOrigin': {
              'cookiesConfig': {
                'cookieBehavior': 'all',
              },
              'enableAcceptEncodingGzip': False,
              'headersConfig': {
                'headerBehavior': 'whitelist',
                'headers': [
                  'Accept-Charset',
                  'Authorization',
                  'Origin',
                  'Accept',
                  'Referer',
                  'Host',
                  'Accept-Language',
                  'Accept-Encoding',
                  'Accept-Datetime',
                ],
              },
              'queryStringsConfig': {
                'queryStringBehavior': 'all',
              },
            },
          },
        )

    vsCodeInstanceRole = iam.CfnRole(self, 'VSCodeInstanceRole',
          assume_role_policy_document = {
            'Version': '2012-10-17',
            'Statement': [
              {
                'Effect': 'Allow',
                'Principal': {
                  'Service': [
                    'ec2.amazonaws.com',
                    'ssm.amazonaws.com',
                    'codecommit.amazonaws.com',
                  ],
                },
                'Action': [
                  'sts:AssumeRole',
                ],
              },
            ],
          },
          managed_policy_arns = [
            f"""arn:{self.partition}:iam::aws:policy/AdministratorAccess""",
          ],
          policies = [
            {
              'policyName': f"""CDKAssumeRolePolicy-{self.region}""",
              'policyDocument': {
                'Version': '2012-10-17',
                'Statement': [
                  {
                    'Effect': 'Allow',
                    'Action': [
                      'sts:AssumeRole',
                    ],
                    'Resource': [
                      f"""arn:{self.partition}:iam::*:role/cdk-*""",
                    ],
                  },
                ],
              },
            },
            {
              'policyName': f"""Codewhisperer-{self.region}""",
              'policyDocument': {
                'Version': '2012-10-17',
                'Statement': [
                  {
                    'Effect': 'Allow',
                    'Action': [
                      'codewhisperer:GenerateRecommendations',
                    ],
                    'Resource': '*',
                  },
                ],
              },
            },
          ],
        )
    vsCodeInstanceRole.cfn_options.metadata = {
      'cfn_nag': {
        'rules_to_suppress': [
          {
            'id': 'W11',
            'reason': 'CodeWhisperer requires \'*\' as a resource, reference https://docs.aws.amazon.com/codewhisperer/latest/userguide/cloud9-setup.html#codewhisperer-IAM-policies',
          },
        ],
      },
    }

    gatewayAttachment = ec2.CfnVPCGatewayAttachment(self, 'GatewayAttachment',
          vpc_id = vpc.ref,
          internet_gateway_id = internetGateway.ref,
        )

    privateSubnetOne = ec2.CfnSubnet(self, 'PrivateSubnetOne',
          cidr_block = subnets['PrivateOne']['CIDR'],
          vpc_id = vpc.ref,
          map_public_ip_on_launch = True,
          availability_zone = cdk.Fn.select(0, cdk.Fn.get_azs('')),
        )

    privateSubnetTwo = ec2.CfnSubnet(self, 'PrivateSubnetTwo',
          cidr_block = subnets['PrivateTwo']['CIDR'],
          vpc_id = vpc.ref,
          map_public_ip_on_launch = True,
          availability_zone = cdk.Fn.select(1, cdk.Fn.get_azs('')),
        )

    publicOneRouteTable = ec2.CfnRouteTable(self, 'PublicOneRouteTable',
          vpc_id = vpc.ref,
        )

    publicSubnetOne = ec2.CfnSubnet(self, 'PublicSubnetOne',
          cidr_block = subnets['PublicOne']['CIDR'],
          vpc_id = vpc.ref,
          map_public_ip_on_launch = True,
          availability_zone = cdk.Fn.select(0, cdk.Fn.get_azs('')),
        )

    publicSubnetTwo = ec2.CfnSubnet(self, 'PublicSubnetTwo',
          cidr_block = subnets['PublicTwo']['CIDR'],
          vpc_id = vpc.ref,
          map_public_ip_on_launch = True,
          availability_zone = cdk.Fn.select(1, cdk.Fn.get_azs('')),
        )

    publicTwoRouteTable = ec2.CfnRouteTable(self, 'PublicTwoRouteTable',
          vpc_id = vpc.ref,
        )

    securityGroup = ec2.CfnSecurityGroup(self, 'SecurityGroup',
          group_description = 'SG for Developer Machine - only allow CloudFront ingress',
          security_group_ingress = [
            {
              'description': 'Allow HTTP from com.amazonaws.global.cloudfront.origin-facing',
              'ipProtocol': 'tcp',
              'fromPort': 80,
              'toPort': 80,
              'sourcePrefixListId': awsRegions2PrefixListId[self.region]['PrefixList'],
            },
          ],
          security_group_egress = [
            {
              'description': 'Allow all outbound traffic',
              'ipProtocol': -1,
              'cidrIp': '0.0.0.0/0',
            },
          ],
          vpc_id = vpc.ref,
        )

    vsCodeInstanceProfile = iam.CfnInstanceProfile(self, 'VSCodeInstanceProfile',
          roles = [
            vsCodeInstanceRole.ref,
          ],
        )

    publicOneRoute = ec2.CfnRoute(self, 'PublicOneRoute',
          route_table_id = publicOneRouteTable.ref,
          destination_cidr_block = '0.0.0.0/0',
          gateway_id = internetGateway.ref,
        )
    publicOneRoute.add_dependency(gatewayAttachment)

    publicOneRouteTableAssoc = ec2.CfnSubnetRouteTableAssociation(self, 'PublicOneRouteTableAssoc',
          route_table_id = publicOneRouteTable.ref,
          subnet_id = publicSubnetOne.ref,
        )

    publicTwoRoute = ec2.CfnRoute(self, 'PublicTwoRoute',
          route_table_id = publicTwoRouteTable.ref,
          destination_cidr_block = '0.0.0.0/0',
          gateway_id = internetGateway.ref,
        )
    publicTwoRoute.add_dependency(gatewayAttachment)

    publicTwoRouteTableAssoc = ec2.CfnSubnetRouteTableAssociation(self, 'PublicTwoRouteTableAssoc',
          route_table_id = publicTwoRouteTable.ref,
          subnet_id = publicSubnetTwo.ref,
        )

    vsCodeInstanceEc2Instance = ec2.CfnInstance(self, 'VSCodeInstanceEC2Instance',
          key_name = ec2KeyPair.ref,
          block_device_mappings = [
            {
              'ebs': {
                'volumeSize': props['instanceVolumeSize'],
                'volumeType': 'gp3',
                'deleteOnTermination': True,
                'encrypted': True,
              },
              'deviceName': '/dev/sda1',
            },
          ],
          monitoring = True,
          subnet_id = publicSubnetOne.ref,
          image_id = '{{resolve:ssm:/aws/service/canonical/ubuntu/server/22.04/stable/current/amd64/hvm/ebs-gp2/ami-id}}',
          instance_type = props['instanceType'],
          security_group_ids = [
            securityGroup.ref,
          ],
          iam_instance_profile = vsCodeInstanceProfile.ref,
          user_data = cdk.Fn.base64(f"""#cloud-config
          hostname: dev
          runcmd:
            - mkdir -p {props['homeFolder']} && chown ubuntu:ubuntu {props['homeFolder']}
          """),
          tags = [
            {
              'key': 'SSMBootstrap',
              'value': True,
            },
          ],
        )

    cloudFrontDistribution = cloudfront.CfnDistribution(self, 'CloudFrontDistribution',
          distribution_config = {
            'enabled': True,
            'httpVersion': 'http2',
            'defaultCacheBehavior': {
              'allowedMethods': [
                'GET',
                'HEAD',
                'OPTIONS',
                'PUT',
                'PATCH',
                'POST',
                'DELETE',
              ],
              'cachePolicyId': vsCodeInstanceCachePolicy.ref,
              'originRequestPolicyId': '216adef6-5c7f-47e4-b989-5492eafa07d3',
              'targetOriginId': f"""CloudFront-{self.stack_name}""",
              'viewerProtocolPolicy': 'allow-all',
            },
            'origins': [
              {
                'domainName': vsCodeInstanceEc2Instance.attr_public_dns_name,
                'id': f"""CloudFront-{self.stack_name}""",
                'customOriginConfig': {
                  'originProtocolPolicy': 'http-only',
                },
              },
            ],
          },
        )

    vsCodeInstanceSsmDoc = ssm.CfnDocument(self, 'VSCodeInstanceSSMDoc',
          document_type = 'Command',
          content = {
            'schemaVersion': '2.2',
            'description': 'Bootstrap VSCode code-server instance',
            'parameters': {
              'architecture': {
                'type': 'String',
                'default': 'amd64',
                'description': 'Instance architecture type',
                'allowedValues': [
                  'arm64',
                  'amd64',
                ],
              },
              'ubuntuVersion': {
                'type': 'String',
                'default': 'jammy',
                'allowedValues': [
                  'focal',
                  'bionic',
                  'jammy',
                ],
              },
              'nodeVersion': {
                'type': 'String',
                'default': 'node_20.x',
                'allowedValues': [
                  'node_21.x',
                  'node_20.x',
                  'node_19.x',
                ],
              },
              'dotNetVersion': {
                'type': 'String',
                'default': 'dotnet-sdk-8.0',
                'allowedValues': [
                  'dotnet-sdk-8.0',
                  'dotnet-sdk-7.0',
                  'dotnet-sdk-8.0',
                ],
              },
            },
            'mainSteps': [
              {
                'action': 'aws:runShellScript',
                'name': 'InstallAWSCLI',
                'inputs': {
                  'runCommand': [
                    'apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y curl unzip',
                    'curl -fsSL https://awscli.amazonaws.com/awscli-exe-linux-$(uname -m).zip -o /tmp/aws-cli.zip',
                    'unzip -q -d /tmp /tmp/aws-cli.zip',
                    'sudo /tmp/aws/install',
                    'rm -rf /tmp/aws',
                    'aws --version',
                  ],
                },
              },
              {
                'action': 'aws:runShellScript',
                'name': 'InstallDocker',
                'inputs': {
                  'runCommand': [
                    'apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y apt-transport-https ca-certificates curl gnupg lsb-release',
                    'curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg',
                    'echo \"deb [signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu {{ ubuntuVersion }} stable\" >> /etc/apt/sources.list.d/docker.list',
                    'apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y docker-ce docker-ce-cli containerd.io',
                    'usermod -aG docker ubuntu',
                    'docker --version',
                  ],
                },
              },
              {
                'action': 'aws:runShellScript',
                'name': 'InstallGit',
                'inputs': {
                  'runCommand': [
                    'add-apt-repository ppa:git-core/ppa',
                    'apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y software-properties-common',
                    'apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y git',
                    'sudo -u ubuntu git config --global user.email \"participant@workshops.aws\"',
                    'sudo -u ubuntu git config --global user.name \"Workshop Participant\"',
                    'sudo -u ubuntu git config --global init.defaultBranch \"main\"',
                    'git --version',
                  ],
                },
              },
              {
                'action': 'aws:runShellScript',
                'name': 'InstallNode',
                'inputs': {
                  'runCommand': [
                    'curl -fsSL https://deb.nodesource.com/gpgkey/nodesource.gpg.key | gpg --dearmor -o /usr/share/keyrings/nodesource-keyring.gpg',
                    'echo \"deb [arch={{ architecture }} signed-by=/usr/share/keyrings/nodesource-keyring.gpg] https://deb.nodesource.com/{{ nodeVersion }} {{ ubuntuVersion }} main\" >> /etc/apt/sources.list.d/nodesource.list',
                    'apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y nodejs',
                  ],
                },
              },
              {
                'action': 'aws:runShellScript',
                'name': 'BuildPython',
                'inputs': {
                  'runCommand': [
                    'apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y build-essential libssl-dev zlib1g-dev libbz2-dev libreadline-dev libsqlite3-dev curl llvm libncursesw5-dev xz-utils tk-dev libxml2-dev libxmlsec1-dev libffi-dev liblzma-dev',
                    'apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y python3-pip',
                    'pip3 install git-remote-codecommit',
                  ],
                },
              },
              {
                'action': 'aws:runShellScript',
                'name': 'UpdateProfile',
                'inputs': {
                  'runCommand': [
                    '#!/bin/bash',
                    'echo LANG=en_US.utf-8 >> /etc/environment',
                    'echo LC_ALL=en_US.UTF-8 >> /etc/environment',
                    'echo \'PATH=$PATH:/usr/local/bin\' >> /home/ubuntu/.bashrc',
                    'echo \'export PATH\' >> /home/ubuntu/.bashrc',
                    f"""echo 'export AWS_REGION={self.region}' >> /home/ubuntu/.bashrc""",
                    f"""echo 'export AWS_ACCOUNTID={self.account}' >> /home/ubuntu/.bashrc""",
                    'echo \'export NEXT_TELEMETRY_DISABLED=1\' >> /home/ubuntu/.bashrc',
                  ],
                },
              },
              {
                'action': 'aws:runShellScript',
                'name': 'ConfigureCodeServer',
                'inputs': {
                  'runCommand': [
                    '#!/bin/bash',
                    'export HOME=/home/ubuntu',
                    'apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y nginx',
                    'curl -fsSL https://code-server.dev/install.sh | sh',
                    'sudo systemctl enable --now code-server@ubuntu',
                    f"""sudo tee /etc/nginx/sites-available/code-server <<EOF
                    server {{
                        listen 80;
                        listen [::]:80;
                        server_name {cloudFrontDistribution.attr_domain_name};
                        location / {{
                          proxy_pass http://localhost:8080/;
                          proxy_set_header Host \$host;
                          proxy_set_header Upgrade \$http_upgrade;
                          proxy_set_header Connection upgrade;
                          proxy_set_header Accept-Encoding gzip;
                        }}
                        location /{props['devServerBasePath']} {{
                          proxy_pass http://localhost:{props['devServerPort']}/{props['devServerBasePath']};
                          proxy_set_header Host \$host;
                          proxy_set_header Upgrade \$http_upgrade;
                          proxy_set_header Connection upgrade;
                          proxy_set_header Accept-Encoding gzip;
                        }}
                        location /myviteapp {{
                          proxy_pass http://localhost:{props['devServerPort']}/myviteapp;
                          proxy_set_header Host \$host;
                          proxy_set_header Upgrade \$http_upgrade;
                          proxy_set_header Connection upgrade;
                          proxy_set_header Accept-Encoding gzip;
                        }}
                    }}
                    EOF
                    """,
                    'sudo tee /home/ubuntu/.config/code-server/config.yaml <<EOF\ncert: false\nauth: password\nhashed-password: \"$(echo -n $(aws sts get-caller-identity --query \"Account\" --output text) | sudo npx argon2-cli -e)\"\nEOF\n',
                    'sudo -u ubuntu --login mkdir -p /home/ubuntu/.local/share/code-server/User/',
                    'sudo -u ubuntu --login touch /home/ubuntu/.local/share/code-server/User/settings.json',
                    f"""sudo tee /home/ubuntu/.local/share/code-server/User/settings.json <<EOF
                    {{
                      "extensions.autoUpdate": false,
                      "extensions.autoCheckUpdates": false,
                      "terminal.integrated.cwd": "{props['homeFolder']}",
                      "security.workspace.trust.startupPrompt": "never",
                      "security.workspace.trust.enabled": false,
                      "security.workspace.trust.banner": "never",
                      "security.workspace.trust.emptyWindow": false,
                      "[python]": {{
                        "editor.defaultFormatter": "ms-python.black-formatter",
                        "editor.formatOnSave": true
                      }},
                      "auto-run-command.rules": [
                        {{
                          "command": "workbench.action.terminal.new"
                        }}
                      ]
                    }}
                    EOF
                    """,
                    'sudo systemctl restart code-server@ubuntu',
                    'sudo ln -s ../sites-available/code-server /etc/nginx/sites-enabled/code-server',
                    'sudo systemctl restart nginx',
                    'sudo -u ubuntu --login code-server --install-extension AmazonWebServices.aws-toolkit-vscode --force',
                    'sudo chown ubuntu /home/ubuntu -R',
                  ],
                },
              },
              {
                'action': 'aws:runShellScript',
                'name': 'InstallGo',
                'inputs': {
                  'runCommand': [
                    'add-apt-repository ppa:longsleep/golang-backports',
                    'apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y golang-go',
                    'sudo chown ubuntu /home/ubuntu -R',
                    'go version',
                  ],
                },
              },
              {
                'action': 'aws:runShellScript',
                'name': 'InstallRust',
                'inputs': {
                  'runCommand': [
                    'add-apt-repository ppa:ubuntu-mozilla-security/rust-next',
                    'apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y rustc cargo',
                    'sudo chown ubuntu /home/ubuntu -R',
                    'rustc --version',
                  ],
                },
              },
              {
                'action': 'aws:runShellScript',
                'name': 'InstallDotnet',
                'inputs': {
                  'runCommand': [
                    'apt-get update && DEBIAN_FRONTEND=noninteractive sudo apt-get install -y {{ dotNetVersion }}',
                    'sudo dotnet tool install -g Microsoft.Web.LibraryManager.Cli',
                    'export PATH=\"$PATH:/home/ubuntu/.dotnet/tools\"',
                    'sudo chown ubuntu /home/ubuntu -R',
                    'dotnet --list-sdks',
                  ],
                },
              },
            ],
          },
        )

    vsCodeInstanceSsmAssociation = ssm.CfnAssociation(self, 'VSCodeInstanceSSMAssociation',
          name = vsCodeInstanceSsmDoc.ref,
          output_location = {
            's3Location': {
              'outputS3BucketName': ssmLogBucket.ref,
              'outputS3KeyPrefix': 'bootstrap',
            },
          },
          targets = [
            {
              'key': 'tag:SSMBootstrap',
              'values': [
                True,
              ],
            },
          ],
        )

    # Outputs
    """
      VSCode-Server Password
    """
    self.password = self.account
    cdk.CfnOutput(self, 'CfnOutputPassword', 
      key = 'Password',
      description = 'VSCode-Server Password',
      export_name = f"""{self.stack_name}-Password""",
      value = str(self.password),
    )

    """
      VSCode-Server URL
    """
    self.url = f"""https://{cloudFrontDistribution.attr_domain_name}/?folder={props['homeFolder']}"""
    cdk.CfnOutput(self, 'CfnOutputURL', 
      key = 'URL',
      description = 'VSCode-Server URL',
      export_name = f"""{self.stack_name}-URL""",
      value = str(self.url),
    )



