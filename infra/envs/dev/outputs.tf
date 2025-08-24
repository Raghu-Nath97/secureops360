output "api_endpoint" {
  description = "API Gateway endpoint URL"
  value       = "${aws_api_gateway_rest_api.main.execution_arn}/${var.environment}"
}

output "api_url" {
  description = "Complete API URL"
  value       = "https://${aws_api_gateway_rest_api.main.id}.execute-api.${var.aws_region}.amazonaws.com/${var.environment}"
}

output "kinesis_stream_name" {
  description = "Kinesis stream name"
  value       = aws_kinesis_stream.main.name
}

output "s3_bucket_name" {
  description = "S3 bucket name"
  value       = aws_s3_bucket.data.bucket
}

output "dynamodb_tables" {
  description = "DynamoDB table names"
  value = {
    events_live   = aws_dynamodb_table.events_live.name
    intel_cache   = aws_dynamodb_table.intel_cache.name
    assets_ctx    = aws_dynamodb_table.assets_ctx.name
    model_metrics = aws_dynamodb_table.model_metrics.name
  }
}

output "lambda_function_name" {
  description = "Lambda function name"
  value       = aws_lambda_function.ingest.function_name
}

output "sns_topic_arn" {
  description = "SNS topic ARN"
  value       = aws_sns_topic.alerts.arn
}
