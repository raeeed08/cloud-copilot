# Cloud Copilot practice lab.
# Every insecure setting below maps to a Cloud Copilot rule (comment), so you can follow a finding from the
# dashboard back to the exact line that caused it, flip var.secure, re-apply, re-scan and see it resolved.
#
# Cost when insecure: ~$0.15/day (unattached Elastic IP + KMS key, prorated). Destroy when done.

data "aws_caller_identity" "me" {}
data "aws_partition" "p" {}

resource "random_id" "suffix" {
  byte_length = 3
}

locals {
  name   = "ccl-${random_id.suffix.hex}"
  unsafe = !var.secure
}

data "aws_vpc" "default" {
  default = true
}

# =========================================================================== scanner identity (read-only)
# Pattern used in real companies: a role with read-only policies, assumed by a principal with an ExternalId.
resource "random_password" "external_id" {
  length  = 24
  special = false
}

resource "aws_iam_role" "scanner" {
  name = "${local.name}-scanner"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { AWS = aws_iam_user.scanner.arn }
      Action    = "sts:AssumeRole"
      Condition = { StringEquals = { "sts:ExternalId" = random_password.external_id.result } }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "security_audit" {
  role       = aws_iam_role.scanner.name
  policy_arn = "arn:${data.aws_partition.p.partition}:iam::aws:policy/SecurityAudit"
}

resource "aws_iam_role_policy_attachment" "view_only" {
  role       = aws_iam_role.scanner.name
  policy_arn = "arn:${data.aws_partition.p.partition}:iam::aws:policy/job-function/ViewOnlyAccess"
}

resource "aws_iam_role_policy" "cost_read" {
  role = aws_iam_role.scanner.id
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = ["ce:GetCostAndUsage", "ce:GetCostForecast"], Resource = "*" }]
  })
}

# The only thing this user can do is assume the read-only role.
resource "aws_iam_user" "scanner" {
  name = "${local.name}-scanner-user"
}

resource "aws_iam_user_policy" "scanner_assume" {
  user = aws_iam_user.scanner.name
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = "sts:AssumeRole", Resource = aws_iam_role.scanner.arn }]
  })
}

resource "aws_iam_access_key" "scanner" {
  user = aws_iam_user.scanner.name
}

# =========================================================================== S3
resource "aws_s3_bucket" "data" {
  bucket        = "${local.name}-data"
  force_destroy = true
}

resource "aws_s3_bucket_public_access_block" "data" {
  bucket                  = aws_s3_bucket.data.id
  block_public_acls       = var.secure # S3-003 when false (no public policy is ever attached)
  block_public_policy     = var.secure
  ignore_public_acls      = var.secure
  restrict_public_buckets = var.secure
}

resource "aws_s3_bucket_versioning" "data" {
  count  = var.secure ? 1 : 0 # S3-005 when absent
  bucket = aws_s3_bucket.data.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_lifecycle_configuration" "data" {
  count  = var.secure ? 1 : 0 # S3-008 when absent
  bucket = aws_s3_bucket.data.id
  rule {
    id     = "tiering"
    status = "Enabled"
    filter {}
    noncurrent_version_expiration { noncurrent_days = 30 }
    abort_incomplete_multipart_upload { days_after_initiation = 7 }
  }
}

resource "aws_s3_bucket_policy" "tls_only" {
  count      = var.secure ? 1 : 0 # S3-004 when absent
  bucket     = aws_s3_bucket.data.id
  depends_on = [aws_s3_bucket_public_access_block.data]
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "DenyInsecureTransport"
      Effect    = "Deny"
      Principal = "*"
      Action    = "s3:*"
      Resource  = [aws_s3_bucket.data.arn, "${aws_s3_bucket.data.arn}/*"]
      Condition = { Bool = { "aws:SecureTransport" = "false" } }
    }]
  })
}

resource "aws_s3_account_public_access_block" "account" {
  count                   = var.secure && var.account_level_settings ? 1 : 0 # S3-001
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# =========================================================================== network
resource "aws_security_group" "admin" {
  name        = "${local.name}-admin"
  description = "Lab: SSH ${var.secure ? "restricted" : "open to the internet"}"
  vpc_id      = data.aws_vpc.default.id

  ingress {
    description = "SSH"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = var.secure ? ["10.0.0.0/8"] : ["0.0.0.0/0"] # EC2-001
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "db" {
  name        = "${local.name}-db"
  description = "Lab: PostgreSQL ${var.secure ? "from the app tier only" : "open to the internet"}"
  vpc_id      = data.aws_vpc.default.id

  ingress {
    description     = "PostgreSQL"
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    cidr_blocks     = var.secure ? [] : ["0.0.0.0/0"] # EC2-002
    security_groups = var.secure ? [aws_security_group.admin.id] : []
  }
}

resource "aws_eip" "idle" {
  count  = var.secure ? 0 : 1 # COST-003: billed while unassociated
  domain = "vpc"
}

# =========================================================================== compute & storage
resource "aws_ebs_volume" "orphan" {
  count             = var.secure ? 0 : 1 # COST-001 + COST-002 + EBS-002
  availability_zone = "${var.region}a"
  size              = 1
  type              = "gp2"
  encrypted         = false
  tags              = { Name = "${local.name}-orphan" }
}

resource "aws_ebs_encryption_by_default" "this" {
  count   = var.secure && var.account_level_settings ? 1 : 0 # EBS-001
  enabled = true
}

data "aws_ssm_parameter" "al2023" {
  count = var.create_instance ? 1 : 0
  name  = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
}

resource "aws_iam_role" "instance" {
  count = var.create_instance ? 1 : 0
  name  = "${local.name}-instance"
  assume_role_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Principal = { Service = "ec2.amazonaws.com" }, Action = "sts:AssumeRole" }]
  })
}

resource "aws_iam_instance_profile" "instance" {
  count = var.create_instance ? 1 : 0
  name  = "${local.name}-instance"
  role  = aws_iam_role.instance[0].name
}

# Attack path demo: public IP + SSH open + IMDSv1 + instance role. No key pair, so nobody can log in.
resource "aws_instance" "web" {
  count                       = var.create_instance ? 1 : 0
  ami                         = data.aws_ssm_parameter.al2023[0].value
  instance_type               = "t3.micro"
  associate_public_ip_address = true
  vpc_security_group_ids      = [aws_security_group.admin.id]
  iam_instance_profile        = aws_iam_instance_profile.instance[0].name
  metadata_options {
    http_tokens = var.secure ? "required" : "optional" # EC2-005
  }
  root_block_device {
    encrypted   = true
    volume_type = "gp3"
  }
  tags = { Name = "${local.name}-web" }
}

# =========================================================================== identity
resource "aws_iam_user" "dev" {
  name          = "${local.name}-dev"
  force_destroy = true
}

# IAM-004: console password without MFA (harmless permissions: it can only change its own password)
resource "aws_iam_user_login_profile" "dev" {
  count                   = var.secure ? 0 : 1
  user                    = aws_iam_user.dev.name
  password_reset_required = true
}

resource "aws_iam_user_policy_attachment" "dev_direct" {
  count      = var.secure ? 0 : 1 # IAM-008: policy attached to a user instead of a group
  user       = aws_iam_user.dev.name
  policy_arn = "arn:${data.aws_partition.p.partition}:iam::aws:policy/IAMUserChangePassword"
}

resource "aws_iam_group" "devs" {
  name = "${local.name}-devs"
}

resource "aws_iam_group_policy_attachment" "devs" {
  group      = aws_iam_group.devs.name
  policy_arn = "arn:${data.aws_partition.p.partition}:iam::aws:policy/IAMUserChangePassword"
}

resource "aws_iam_user_group_membership" "dev" {
  count  = var.secure ? 1 : 0
  user   = aws_iam_user.dev.name
  groups = [aws_iam_group.devs.name]
}

resource "aws_iam_account_password_policy" "strict" {
  count                          = var.secure && var.account_level_settings ? 1 : 0 # IAM-003
  minimum_password_length        = 14
  password_reuse_prevention      = 24
  require_lowercase_characters   = true
  require_uppercase_characters   = true
  require_numbers                = true
  require_symbols                = true
  allow_users_to_change_password = true
}

resource "aws_accessanalyzer_analyzer" "this" {
  count         = var.secure ? 1 : 0 # IAM-011 (in this region)
  analyzer_name = "${local.name}-analyzer"
}

# =========================================================================== data services
resource "aws_kms_key" "app" {
  description             = "${local.name} application key"
  enable_key_rotation     = var.secure # KMS-001
  deletion_window_in_days = 7
}

resource "aws_dynamodb_table" "sessions" {
  name         = "${local.name}-sessions"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "id"
  attribute {
    name = "id"
    type = "S"
  }
  point_in_time_recovery {
    enabled = var.secure # DDB-001
  }
}

resource "aws_sns_topic" "alerts" {
  name              = "${local.name}-alerts"
  kms_master_key_id = var.secure ? "alias/aws/sns" : null # MSG-001
}

resource "aws_sqs_queue" "jobs" {
  name                    = "${local.name}-jobs"
  sqs_managed_sse_enabled = var.secure # MSG-001
}

resource "aws_ecr_repository" "app" {
  name                 = "${local.name}-app"
  force_delete         = true
  image_tag_mutability = var.secure ? "IMMUTABLE" : "MUTABLE" # ECR-002
  image_scanning_configuration {
    scan_on_push = var.secure # ECR-001
  }
}

resource "aws_cloudwatch_log_group" "app" {
  name              = "/lab/${local.name}/app"
  retention_in_days = var.secure ? 30 : 0 # LOGS-001 (0 = never expire)
}

# =========================================================================== logging (CT-001)
resource "aws_s3_bucket" "trail" {
  count         = var.secure ? 1 : 0
  bucket        = "${local.name}-trail"
  force_destroy = true
}

resource "aws_s3_bucket_public_access_block" "trail" {
  count                   = var.secure ? 1 : 0
  bucket                  = aws_s3_bucket.trail[0].id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_policy" "trail" {
  count  = var.secure ? 1 : 0
  bucket = aws_s3_bucket.trail[0].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AclCheck"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:GetBucketAcl"
        Resource  = aws_s3_bucket.trail[0].arn
      },
      {
        Sid       = "Write"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.trail[0].arn}/AWSLogs/${data.aws_caller_identity.me.account_id}/*"
        Condition = { StringEquals = { "s3:x-amz-acl" = "bucket-owner-full-control" } }
      },
    ]
  })
}

resource "aws_cloudtrail" "main" {
  count                         = var.secure ? 1 : 0
  name                          = "${local.name}-trail"
  s3_bucket_name                = aws_s3_bucket.trail[0].id
  is_multi_region_trail         = true # CT-001
  include_global_service_events = true
  enable_log_file_validation    = true # CT-002
  depends_on                    = [aws_s3_bucket_policy.trail]
}
