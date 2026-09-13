param(
    [ValidateSet("bedrock", "mock", "rules")]
    [string]$AnalysisMode = "bedrock"
)

$ErrorActionPreference = "Stop"
$Region = "us-east-1"
$StackName = "scambuster-backend"
$ProjectRoot = Split-Path -Parent $PSScriptRoot
$TemplateFile = Join-Path $ProjectRoot "infra\template.yaml"
$PackagedTemplate = Join-Path $ProjectRoot "infra\packaged.yaml"

$AwsCommand = Get-Command aws -ErrorAction SilentlyContinue
if ($AwsCommand) {
    $AwsCli = $AwsCommand.Source
} else {
    $AwsCli = "C:\Program Files\Amazon\AWSCLIV2\aws.exe"
}
if (-not (Test-Path $AwsCli)) {
    throw "AWS CLI v2 is required."
}

function Invoke-Aws {
    param([Parameter(ValueFromRemainingArguments = $true)][string[]]$CommandArgs)

    & $AwsCli @CommandArgs
    if ($LASTEXITCODE -ne 0) {
        throw "AWS CLI command failed with exit code $LASTEXITCODE."
    }
}

$AccountId = (& $AwsCli sts get-caller-identity --region $Region --query Account --output text).Trim()
if ($LASTEXITCODE -ne 0 -or -not $AccountId) {
    throw "Unable to determine the AWS account ID."
}
$ArtifactsBucket = "scambuster-artifacts-$AccountId"

& $AwsCli s3api head-bucket --bucket $ArtifactsBucket --region $Region 2>$null
if ($LASTEXITCODE -ne 0) {
    Invoke-Aws s3api create-bucket --bucket $ArtifactsBucket --region $Region
}

Invoke-Aws s3api put-public-access-block `
    --bucket $ArtifactsBucket `
    --region $Region `
    --public-access-block-configuration '{"BlockPublicAcls":true,"IgnorePublicAcls":true,"BlockPublicPolicy":true,"RestrictPublicBuckets":true}'
Invoke-Aws s3api put-bucket-encryption `
    --bucket $ArtifactsBucket `
    --region $Region `
    --server-side-encryption-configuration '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"AES256"},"BucketKeyEnabled":false}]}'
Invoke-Aws s3api put-bucket-versioning `
    --bucket $ArtifactsBucket `
    --region $Region `
    --versioning-configuration Status=Enabled

$BucketPolicy = @{
    Version = "2012-10-17"
    Statement = @(
        @{
            Sid = "DenyInsecureTransport"
            Effect = "Deny"
            Principal = "*"
            Action = "s3:*"
            Resource = @(
                "arn:aws:s3:::$ArtifactsBucket",
                "arn:aws:s3:::$ArtifactsBucket/*"
            )
            Condition = @{ Bool = @{ "aws:SecureTransport" = "false" } }
        }
    )
} | ConvertTo-Json -Depth 8 -Compress
Invoke-Aws s3api put-bucket-policy `
    --bucket $ArtifactsBucket `
    --region $Region `
    --policy $BucketPolicy

Invoke-Aws cloudformation package `
    --template-file $TemplateFile `
    --s3-bucket $ArtifactsBucket `
    --s3-prefix $StackName `
    --output-template-file $PackagedTemplate `
    --region $Region

Invoke-Aws cloudformation deploy `
    --template-file $PackagedTemplate `
    --stack-name $StackName `
    --capabilities CAPABILITY_IAM `
    --parameter-overrides "AnalysisMode=$AnalysisMode" `
    --no-fail-on-empty-changeset `
    --region $Region

Invoke-Aws cloudformation describe-stacks `
    --stack-name $StackName `
    --region $Region `
    --query 'Stacks[0].{Status:StackStatus,Outputs:Outputs}' `
    --output json
