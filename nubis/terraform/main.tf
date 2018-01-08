provider "aws" {
  region = "${var.region}"
}

module "info" {
  source      = "github.com/nubisproject/nubis-terraform//info?ref=develop"
  region      = "${var.region}"
  environment = "${var.environment}"
  account     = "${var.account}"
}

module "worker" {
  source            = "github.com/nubisproject/nubis-terraform//worker?ref=develop"
  region            = "${var.region}"
  environment       = "${var.environment}"
  account           = "${var.account}"
  service_name      = "${var.service_name}"
  purpose           = "master"
  ami               = "${var.ami}"
  elb               = "${module.load_balancer.name}"
  instance_type     = "t2.large"
  min_instances     = 3
  max_instances     = 3
  root_storage_size = 64

  security_group        = "${aws_security_group.kops.id}"
  security_group_custom = true

  tags = [
    {
      key                 = "KubernetesCluster"
      value               = "k8s.core.us-west-2.nubis-gozer.nubis.allizom.org"
      propagate_at_launch = true
    },
    {
      key                 = "k8s.io/role/master"
      value               = "1"
      propagate_at_launch = true
    },
  ]
}

module "nodes" {
  source       = "github.com/nubisproject/nubis-terraform//worker?ref=develop"
  region       = "${var.region}"
  environment  = "${var.environment}"
  account      = "${var.account}"
  service_name = "${var.service_name}"
  purpose      = "nodes"
  ami          = "${var.ami}"

  instance_type     = "t2.large"
  min_instances     = 1
  max_instances     = 1
  root_storage_size = 64

  security_group        = "${aws_security_group.nodes.id}"
  security_group_custom = true

  tags = [
    {
      key                 = "KubernetesCluster"
      value               = "k8s.core.us-west-2.nubis-gozer.nubis.allizom.org"
      propagate_at_launch = true
    },
    {
      key                 = "k8s.io/cluster-autoscaler/node-template/label/kops.k8s.io/instancegroup"
      value               = "nodes"
      propagate_at_launch = true
    },
    {
      key                 = "k8s.io/role/node"
      value               = "1"
      propagate_at_launch = true
    },
  ]
}

#  tag = {
#    key                 = "k8s.io/cluster-autoscaler/node-template/label/kops.k8s.io/instancegroup"
#    value               = "master-us-west-2a-1"
#    propagate_at_launch = true
#  }

module "load_balancer" {
  source       = "github.com/nubisproject/nubis-terraform//load_balancer?ref=develop"
  region       = "${var.region}"
  environment  = "${var.environment}"
  account      = "${var.account}"
  service_name = "${var.service_name}"

  # We are a unusual Load Balancer with raw connectivity
  no_ssl_cert        = "1"
  backend_protocol   = "tcp"
  protocol_http      = "tcp"
  protocol_https     = "tcp"
  backend_port_http  = "80"
  backend_port_https = "443"

  health_check_target = "TCP:443"
}

module "dns" {
  source       = "github.com/nubisproject/nubis-terraform//dns?ref=v2.0.1"
  region       = "${var.region}"
  environment  = "${var.environment}"
  account      = "${var.account}"
  service_name = "${var.service_name}"
  target       = "${module.load_balancer.address}"

  prefix = "api"
}

module "kops" {
  source       = "github.com/nubisproject/nubis-terraform//bucket?ref=develop"
  region       = "${var.region}"
  environment  = "${var.environment}"
  account      = "${var.account}"
  service_name = "${var.service_name}"
  purpose      = "kops"
  role         = "${module.worker.role}"
}

# Expects 3 AZs but we can fix
data "aws_availability_zones" "available" {}

resource "aws_ebs_volume" "etcd-events-k8s-core-us-west-2-nubis-gozer-nubis-allizom-org" {
  count             = "${length(data.aws_availability_zones.available.names)}"
  availability_zone = "${data.aws_availability_zones.available.names[count.index]}"
  size              = 20
  type              = "gp2"
  encrypted         = true

  tags = {
    KubernetesCluster    = "k8s.core.us-west-2.nubis-gozer.nubis.allizom.org"
    Name                 = "${count.index + 1}.etcd-events.k8s.core.us-west-2.nubis-gozer.nubis.allizom.org"
    "k8s.io/etcd/events" = "${count.index + 1}/1,2,3"
    "k8s.io/role/master" = "1"
  }
}

resource "aws_ebs_volume" "etcd-main-k8s-core-us-west-2-nubis-gozer-nubis-allizom-org" {
  count             = "${length(data.aws_availability_zones.available.names)}"
  availability_zone = "${data.aws_availability_zones.available.names[count.index]}"
  size              = 20
  type              = "gp2"
  encrypted         = true

  tags = {
    KubernetesCluster    = "k8s.core.us-west-2.nubis-gozer.nubis.allizom.org"
    Name                 = "${count.index + 1}.etcd-main.k8s.core.us-west-2.nubis-gozer.nubis.allizom.org"
    "k8s.io/etcd/main"   = "${count.index + 1}/1,2,3"
    "k8s.io/role/master" = "1"
  }
}

resource "aws_security_group" "kops" {
  name_prefix = "${var.service_name}-${var.arena}-${var.environment}-kops-"

  vpc_id = "${module.info.vpc_id}"

  tags = {
    Name        = "${var.service_name}-${var.arena}-${var.environment}-kops"
    Arena       = "${var.arena}"
    Region      = "${var.region}"
    Environment = "${var.environment}"
    Backup      = "true"
    Shutdown    = "never"
  }

  # Trust itself all the way
  ingress {
    from_port = 0
    to_port   = 0
    protocol  = "-1"
    self      = true
  }

  ingress {
    from_port = 22
    to_port   = 22
    protocol  = "tcp"
    self      = true

    security_groups = [
      "${module.info.ssh_security_group}",
    ]
  }

  # HTTPS from ELB
  ingress {
    from_port = 443
    to_port   = 443
    protocol  = "tcp"

    security_groups = [
      "${module.load_balancer.source_security_group_id}",
    ]
  }

  # HTTP from ELB
  ingress {
    from_port = 80
    to_port   = 80
    protocol  = "tcp"

    security_groups = [
      "${module.load_balancer.source_security_group_id}",
    ]
  }

  # Ingress from nodes

  # IPIP
  ingress {
    from_port = 0
    to_port   = 0
    protocol  = "4"

    security_groups = [
      "${aws_security_group.nodes.id}",
    ]
  }
  ingress {
    from_port = 1
    to_port   = 2379
    protocol  = "tcp"

    security_groups = [
      "${aws_security_group.nodes.id}",
    ]
  }
  ingress {
    from_port = 2382
    to_port   = 4001
    protocol  = "tcp"

    security_groups = [
      "${aws_security_group.nodes.id}",
    ]
  }
  ingress {
    from_port = 4003
    to_port   = 65535
    protocol  = "tcp"

    security_groups = [
      "${aws_security_group.nodes.id}",
    ]
  }
  ingress {
    from_port = 1
    to_port   = 65535
    protocol  = "udp"

    security_groups = [
      "${aws_security_group.nodes.id}",
    ]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_security_group" "nodes" {
  name_prefix = "${var.service_name}-${var.arena}-${var.environment}-nodes-"

  vpc_id = "${module.info.vpc_id}"

  tags = {
    Name        = "${var.service_name}-${var.arena}-${var.environment}-nodes"
    Arena       = "${var.arena}"
    Region      = "${var.region}"
    Environment = "${var.environment}"
    Backup      = "true"
    Shutdown    = "never"
  }

  lifecycle {
    create_before_destroy = true
  }
}

# Nodes trust each other
resource "aws_security_group_rule" "nodes-to-nodes" {
  type                     = "ingress"
  security_group_id        = "${aws_security_group.nodes.id}"
  source_security_group_id = "${aws_security_group.nodes.id}"
  from_port                = 0
  to_port                  = 0
  protocol                 = -1
}

# Master can do anything to nodes
resource "aws_security_group_rule" "nodes-to-outside-world" {
  type              = "egress"
  security_group_id = "${aws_security_group.nodes.id}"

  from_port = 0
  to_port   = 0
  protocol  = -1

  cidr_blocks = ["0.0.0.0/0"]
}

# Master can do anything to nodes
resource "aws_security_group_rule" "master-to-nodes-all" {
  type                     = "ingress"
  security_group_id        = "${aws_security_group.nodes.id}"
  source_security_group_id = "${aws_security_group.kops.id}"
  from_port                = 0
  to_port                  = 0
  protocol                 = -1
}

# Jumphost can ssh in
resource "aws_security_group_rule" "jumphost-to-nodes-ssh" {
  type                     = "ingress"
  security_group_id        = "${aws_security_group.nodes.id}"
  source_security_group_id = "${module.info.ssh_security_group}"
  from_port                = 22
  to_port                  = 22
  protocol                 = "tcp"
}

data "template_file" "config" {
  template = "${file("${path.module}/data/config")}"

  vars {
    BUCKET             = "${module.kops.name}"
    CLUSTER            = "k8s.${var.arena}.${module.info.hosted_zone_name}"
    AVAILABILITY_ZONES = "${join(",",data.aws_availability_zones.available.names)}"
    ZONE_ID            = "${module.info.hosted_zone_id}"
    NETWORK_CIDR       = "${module.info.network_cidr}"
  }
}

data "template_file" "cluster_spec" {
  template = "${file("${path.module}/data/cluster.spec")}"

  vars {
    BUCKET             = "${module.kops.name}"
    CLUSTER            = "k8s.${var.arena}.${module.info.hosted_zone_name}"
    AVAILABILITY_ZONES = "${join(",",data.aws_availability_zones.available.names)}"
    ZONE_ID            = "${module.info.hosted_zone_id}"
    NETWORK_CIDR       = "${module.info.network_cidr}"
  }
}

resource "aws_s3_bucket_object" "config" {
  bucket  = "${module.kops.name}"
  key     = "config"
  content = "${data.template_file.config.rendered}"
  etag    = "${md5(data.template_file.config.rendered)}"
}

resource "aws_s3_bucket_object" "cluster_spec" {
  bucket  = "${module.kops.name}"
  key     = "cluster.spec"
  content = "${data.template_file.cluster_spec.rendered}"
  etag    = "${md5(data.template_file.cluster_spec.rendered)}"
}

resource "aws_iam_role_policy" "kops" {
  name   = "kops"
  role   = "${module.worker.role}"
  policy = "${data.aws_iam_policy_document.kops.json}"
}

resource "aws_iam_role_policy" "nodes" {
  name   = "nodes"
  role   = "${module.nodes.role}"
  policy = "${data.aws_iam_policy_document.nodes.json}"
}

data "aws_iam_policy_document" "nodes" {
  statement {
    sid = "kopsK8sEC2NodePerms"

    actions = [
      "ec2:DescribeInstances",
    ]

    resources = [
      "*",
    ]
  }

  statement {
    sid = "kopsK8sS3GetListBucket"

    actions = [
      "s3:ListBucket",
      "s3:GetBucketLocation",
    ]

    resources = [
      "${module.kops.arn}",
    ]
  }

  statement {
    sid = "kopsK8sS3NodeBucketSelectiveGet"

    actions = [
      "s3:Get*",
    ]

    resources = [
      "${module.kops.arn}/addons/*",
      "${module.kops.arn}/cluster.spec",
      "${module.kops.arn}/config",
      "${module.kops.arn}/instancegroup/*",
      "${module.kops.arn}/pki/issued/*",
      "${module.kops.arn}/pki/private/kube-proxy/*",
      "${module.kops.arn}/pki/private/kubelet/*",
      "${module.kops.arn}/pki/ssh/*",
      "${module.kops.arn}/secrets/dockerconfig",
    ]
  }

  statement {
    sid = "kopsK8sECR"

    actions = [
      "ecr:GetAuthorizationToken",
      "ecr:BatchCheckLayerAvailability",
      "ecr:GetDownloadUrlForLayer",
      "ecr:GetRepositoryPolicy",
      "ecr:DescribeRepositories",
      "ecr:ListImages",
      "ecr:BatchGetImage",
    ]

    resources = [
      "*",
    ]
  }
}

data "aws_iam_policy_document" "kops" {
  statement {
    sid = "kopsK8sEC2MasterPermsDescribeResources"

    actions = [
      "ec2:DescribeInstances",
      "ec2:DescribeRouteTables",
      "ec2:DescribeSecurityGroups",
      "ec2:DescribeSubnets",
      "ec2:DescribeVolumes",
    ]

    resources = [
      "*",
    ]
  }

  statement {
    sid = "kopsK8sEC2MasterPermsTaggedResources"

    actions = [
      "ec2:AttachVolume",
      "ec2:AuthorizeSecurityGroupIngress",
      "ec2:DeleteRoute",
      "ec2:DeleteSecurityGroup",
      "ec2:DeleteVolume",
      "ec2:DetachVolume",
      "ec2:RevokeSecurityGroupIngress",
    ]

    resources = [
      "*",
    ]

    condition {
      test     = "StringEquals"
      variable = "ec2:ResourceTag/KubernetesCluster"

      values = [
        "k8s.core.us-west-2.nubis-gozer.nubis.allizom.org",
      ]
    }
  }

  statement {
    sid = "kopsK8sASMasterPermsAllResources"

    actions = [
      "autoscaling:DescribeAutoScalingGroups",
      "autoscaling:DescribeLaunchConfigurations",
      "autoscaling:DescribeTags",
      "autoscaling:GetAsgForInstance",
    ]

    resources = [
      "*",
    ]
  }

  statement {
    sid = "kopsK8sASMasterPermsTaggedResources"

    actions = [
      "autoscaling:SetDesiredCapacity",
      "autoscaling:TerminateInstanceInAutoScalingGroup",
      "autoscaling:UpdateAutoScalingGroup",
    ]

    resources = [
      "*",
    ]

    condition {
      test     = "StringEquals"
      variable = "autoscaling:ResourceTag/KubernetesCluster"

      values = [
        "k8s.core.us-west-2.nubis-gozer.nubis.allizom.org",
      ]
    }
  }

  statement {
    sid = "kopsK8sELBMasterPermsRestrictive"

    actions = [
      "elasticloadbalancing:AddTags",
      "elasticloadbalancing:AttachLoadBalancerToSubnets",
      "elasticloadbalancing:ApplySecurityGroupsToLoadBalancer",
      "elasticloadbalancing:CreateLoadBalancer",
      "elasticloadbalancing:CreateLoadBalancerPolicy",
      "elasticloadbalancing:CreateLoadBalancerListeners",
      "elasticloadbalancing:ConfigureHealthCheck",
      "elasticloadbalancing:DeleteLoadBalancer",
      "elasticloadbalancing:DeleteLoadBalancerListeners",
      "elasticloadbalancing:DescribeLoadBalancers",
      "elasticloadbalancing:DescribeLoadBalancerAttributes",
      "elasticloadbalancing:DetachLoadBalancerFromSubnets",
      "elasticloadbalancing:DeregisterInstancesFromLoadBalancer",
      "elasticloadbalancing:ModifyLoadBalancerAttributes",
      "elasticloadbalancing:RegisterInstancesWithLoadBalancer",
      "elasticloadbalancing:SetLoadBalancerPoliciesForBackendServer",
    ]

    resources = [
      "*",
    ]
  }

  statement {
    sid = "kopsK8sNLBMasterPermsRestrictive"

    actions = [
      "ec2:DescribeVpcs",
      "elasticloadbalancing:AddTags",
      "elasticloadbalancing:CreateListener",
      "elasticloadbalancing:CreateTargetGroup",
      "elasticloadbalancing:DeleteListener",
      "elasticloadbalancing:DeleteTargetGroup",
      "elasticloadbalancing:DescribeListeners",
      "elasticloadbalancing:DescribeLoadBalancerPolicies",
      "elasticloadbalancing:DescribeTargetGroups",
      "elasticloadbalancing:DescribeTargetHealth",
      "elasticloadbalancing:ModifyListener",
      "elasticloadbalancing:ModifyTargetGroup",
      "elasticloadbalancing:RegisterTargets",
      "elasticloadbalancing:SetLoadBalancerPoliciesOfListener",
    ]

    resources = [
      "*",
    ]
  }

  statement {
    sid = "kopsMasterCertIAMPerms"

    actions = [
      "iam:ListServerCertificates",
      "iam:GetServerCertificate",
    ]

    resources = [
      "*",
    ]
  }

  statement {
    sid = "kopsK8sECR"

    actions = [
      "ecr:GetAuthorizationToken",
      "ecr:BatchCheckLayerAvailability",
      "ecr:GetDownloadUrlForLayer",
      "ecr:GetRepositoryPolicy",
      "ecr:DescribeRepositories",
      "ecr:ListImages",
      "ecr:BatchGetImage",
    ]

    resources = [
      "*",
    ]
  }

  #XXX  
  statement {
    sid = "kopsK8sEC2MasterPermsAllResources"

    actions = [
      "ec2:CreateRoute",
      "ec2:CreateSecurityGroup",
      "ec2:CreateTags",
      "ec2:CreateVolume",
      "ec2:ModifyInstanceAttribute",
    ]

    resources = [
      "*",
    ]
  }

  statement {
    sid = "kopsK8sS3GetListBucket"

    actions = [
      "s3:ListBucket",
      "s3:GetBucketLocation",
    ]

    resources = [
      "${module.kops.arn}",
    ]
  }

  statement {
    sid = "kopsK8sS3MasterBucketFullGet"

    actions = [
      "s3:Get*",
    ]

    resources = [
      "${module.kops.arn}/*",
    ]
  }

  statement {
    sid = "kopsK8sRoute53Change"

    actions = [
      "route53:ChangeResourceRecordSets",
      "route53:ListResourceRecordSets",
      "route53:GetHostedZone",
    ]

    resources = [
      "arn:aws:route53:::hostedzone/Z1VCJ7BPU9BDEO",
    ]
  }

  statement {
    sid = "kopsK8sRoute53GetChanges"

    actions = [
      "route53:GetChange",
    ]

    resources = [
      "arn:aws:route53:::change/*",
    ]
  }

  statement {
    sid = "kopsK8sRoute53ListZones"

    actions = [
      "route53:ListHostedZones",
    ]

    resources = [
      "*",
    ]
  }
}
