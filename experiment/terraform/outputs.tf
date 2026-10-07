# experiment/terraform/outputs.tf

output "s3_bucket_name" {
  value = aws_s3_bucket.driftfinder_test.bucket
}

output "security_group_id" {
  value = aws_security_group.driftfinder_test.id
}

output "iam_policy_arn" {
  value = aws_iam_policy.driftfinder_test.arn
}

output "rds_instance_id" {
  value = aws_db_instance.driftfinder_test.identifier
}

output "ebs_volume_id" {
  value = aws_ebs_volume.driftfinder_test.id
}

output "cloudtrail_name" {
  value = aws_cloudtrail.driftfinder_test.name
}

output "vpc_id" {
  value = aws_vpc.driftfinder_test.id
}

output "kms_key_id" {
  value = aws_kms_key.driftfinder_test.key_id
}

output "kms_key_arn" {
  value = aws_kms_key.driftfinder_test.arn
}

output "ct_log_bucket_name" {
  value = aws_s3_bucket.cloudtrail_logs.bucket
}

output "cloudtrail_cw_log_group_arn" {
  value = "${aws_cloudwatch_log_group.cloudtrail.arn}:*"
}

output "cloudtrail_cw_role_arn" {
  value = aws_iam_role.cloudtrail_cw.arn
}

output "flow_log_role_arn" {
  value = aws_iam_role.flow_logs.arn
}

output "vpc_flow_log_group_name" {
  value = aws_cloudwatch_log_group.flow_logs.name
}
