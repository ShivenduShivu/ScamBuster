param(
    [ValidateSet("s3", "cloudfront")]
    [string]$Mode = "s3",
    [string]$StackName,
    [string]$Region = "us-east-1"
)

$ErrorActionPreference = "Stop"

$projectRoot = Split-Path -Parent $PSScriptRoot
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

function Invoke-Aws {
    param([Parameter(ValueFromRemainingArguments = $true)][string[]]$CommandArgs)

    & $awsCli @CommandArgs
    if ($LASTEXITCODE -ne 0) {
        throw "AWS CLI command failed with exit code $LASTEXITCODE."
    }
}

function Get-StackOutputs {
    param([string]$SelectedStackName)

    $outputJson = & $awsCli cloudformation describe-stacks `
        --stack-name $SelectedStackName `
        --region $Region `
        --query "Stacks[0].Outputs" `
        --output json `
        --no-cli-pager
    if ($LASTEXITCODE -ne 0) {
        throw "Could not read stack outputs."
    }
    return $outputJson | ConvertFrom-Json
}

function Get-OutputValue {
    param(
        [object[]]$Outputs,
        [string]$Key
    )

    return ($Outputs | Where-Object OutputKey -eq $Key).OutputValue
}

function Sync-Frontend {
    param([string]$BucketName)

    Invoke-Aws s3 sync $frontendPath "s3://$BucketName" `
        --delete `
        --cache-control "public,max-age=300" `
        --region $Region `
        --no-cli-pager

    $assetMetadata = @(
        @{ Name = "index.html"; ContentType = "text/html; charset=utf-8"; CacheControl = "no-cache" },
        @{ Name = "styles.css"; ContentType = "text/css; charset=utf-8"; CacheControl = "public,max-age=300" },
        @{ Name = "app.js"; ContentType = "application/javascript; charset=utf-8"; CacheControl = "public,max-age=300" },
        @{ Name = "config.js"; ContentType = "application/javascript; charset=utf-8"; CacheControl = "public,max-age=300" }
    )

    foreach ($asset in $assetMetadata) {
        Invoke-Aws s3 cp (Join-Path $frontendPath $asset.Name) "s3://$BucketName/$($asset.Name)" `
            --content-type $asset.ContentType `
            --cache-control $asset.CacheControl `
            --region $Region `
            --no-cli-pager | Out-Null
    }
}

if ($Mode -eq "s3") {
    $selectedStackName = if ($StackName) { $StackName } else { "scambuster-frontend-s3" }
    $templatePath = Join-Path $projectRoot "infra\frontend-s3-website-template.yaml"

    Write-Host "Deploying interim S3 website stack '$selectedStackName'..."
    Invoke-Aws cloudformation deploy `
        --template-file $templatePath `
        --stack-name $selectedStackName `
        --region $Region `
        --no-fail-on-empty-changeset `
        --no-cli-pager

    $outputs = Get-StackOutputs $selectedStackName
    $siteBucket = Get-OutputValue $outputs "SiteBucketName"
    $websiteUrl = Get-OutputValue $outputs "WebsiteUrl"
    if (-not $siteBucket -or -not $websiteUrl) {
        throw "Required S3 website stack outputs are missing."
    }

    Write-Host "Uploading frontend assets..."
    Sync-Frontend $siteBucket

    Write-Host "Frontend deployment complete."
    Write-Host "Mode: s3"
    Write-Host "Site: $websiteUrl"
    Write-Host "Bucket: $siteBucket"
    return
}

$selectedStackName = if ($StackName) { $StackName } else { "scambuster-frontend" }
$templatePath = Join-Path $projectRoot "infra\frontend-template.yaml"

Write-Host "Deploying CloudFront infrastructure stack '$selectedStackName'..."
Invoke-Aws cloudformation deploy `
    --template-file $templatePath `
    --stack-name $selectedStackName `
    --region $Region `
    --no-fail-on-empty-changeset `
    --no-cli-pager

$outputs = Get-StackOutputs $selectedStackName
$siteBucket = Get-OutputValue $outputs "SiteBucketName"
$distributionId = Get-OutputValue $outputs "DistributionId"
$cloudFrontUrl = Get-OutputValue $outputs "CloudFrontUrl"
if (-not $siteBucket -or -not $distributionId -or -not $cloudFrontUrl) {
    throw "Required CloudFront stack outputs are missing."
}

Write-Host "Uploading frontend assets..."
Sync-Frontend $siteBucket

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
Invoke-Aws cloudfront wait distribution-deployed `
    --id $distributionId `
    --no-cli-pager

Write-Host "Frontend deployment complete."
Write-Host "Mode: cloudfront"
Write-Host "Site: $cloudFrontUrl"
Write-Host "Bucket: $siteBucket"
Write-Host "Distribution: $distributionId"
Write-Host "Invalidation: $invalidationId"
