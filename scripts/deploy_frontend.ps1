param(
    [string]$StackName = "scambuster-frontend",
    [string]$Region = "us-east-1"
)

$ErrorActionPreference = "Stop"

$projectRoot = Split-Path -Parent $PSScriptRoot
$templatePath = Join-Path $projectRoot "infra\frontend-template.yaml"
$frontendPath = Join-Path $projectRoot "frontend"

$awsCommand = Get-Command aws -ErrorAction SilentlyContinue
if ($awsCommand) {
    $awsCli = $awsCommand.Source
} else {
    $awsCli = "C:\Program Files\Amazon\AWSCLIV2\aws.exe"
}
if (-not (Test-Path $awsCli)) {
    throw "AWS CLI v2 is required."
}

Write-Host "Deploying frontend infrastructure stack '$StackName'..."
& $awsCli cloudformation deploy `
    --template-file $templatePath `
    --stack-name $StackName `
    --region $Region `
    --no-fail-on-empty-changeset `
    --no-cli-pager
if ($LASTEXITCODE -ne 0) {
    throw "CloudFormation deployment failed."
}

$outputsJson = & $awsCli cloudformation describe-stacks `
    --stack-name $StackName `
    --region $Region `
    --query "Stacks[0].Outputs" `
    --output json `
    --no-cli-pager
if ($LASTEXITCODE -ne 0) {
    throw "Could not read stack outputs."
}

$outputs = $outputsJson | ConvertFrom-Json
$siteBucket = ($outputs | Where-Object OutputKey -eq "SiteBucketName").OutputValue
$distributionId = ($outputs | Where-Object OutputKey -eq "DistributionId").OutputValue
$cloudFrontUrl = ($outputs | Where-Object OutputKey -eq "CloudFrontUrl").OutputValue

if (-not $siteBucket -or -not $distributionId -or -not $cloudFrontUrl) {
    throw "Required stack outputs are missing."
}

Write-Host "Uploading frontend assets..."
& $awsCli s3 sync $frontendPath "s3://$siteBucket" `
    --delete `
    --cache-control "public,max-age=300" `
    --region $Region `
    --no-cli-pager
if ($LASTEXITCODE -ne 0) {
    throw "Frontend asset sync failed."
}

& $awsCli s3 cp (Join-Path $frontendPath "index.html") "s3://$siteBucket/index.html" `
    --cache-control "no-cache" `
    --content-type "text/html; charset=utf-8" `
    --region $Region `
    --no-cli-pager | Out-Null
if ($LASTEXITCODE -ne 0) {
    throw "Could not apply index.html cache metadata."
}

Write-Host "Invalidating CloudFront cache..."
$invalidationId = & $awsCli cloudfront create-invalidation `
    --distribution-id $distributionId `
    --paths "/*" `
    --query "Invalidation.Id" `
    --output text `
    --no-cli-pager
if ($LASTEXITCODE -ne 0) {
    throw "CloudFront invalidation failed."
}

Write-Host "Waiting for the distribution to finish deploying..."
& $awsCli cloudfront wait distribution-deployed `
    --id $distributionId `
    --no-cli-pager
if ($LASTEXITCODE -ne 0) {
    throw "CloudFront did not reach Deployed status."
}

Write-Host "Frontend deployment complete."
Write-Host "Site: $cloudFrontUrl"
Write-Host "Bucket: $siteBucket"
Write-Host "Distribution: $distributionId"
Write-Host "Invalidation: $invalidationId"
