#!/bin/bash
set -e

PROJECT_NAME="5g-core-analyzer"
AWS_REGION="${AWS_REGION:-us-east-1}"
AWS_ACCOUNT_ID="${AWS_ACCOUNT_ID:-$(aws sts get-caller-identity --query Account --output text)}"

echo "=== 5G Core Analyzer - AWS Marketplace Deployment ==="
echo "Region: $AWS_REGION"
echo "Account: $AWS_ACCOUNT_ID"

# 1. Create ECR repository
echo "[1/5] Creating ECR repository..."
aws ecr create-repository --repository-name $PROJECT_NAME --region $AWS_REGION --image-scanning-configuration scanOnPush=true || true

# 2. Build and push Docker image
echo "[2/5] Building Docker image..."
ECR_URL="$AWS_ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com/$PROJECT_NAME:latest"
aws ecr get-login-password --region $AWS_REGION | docker login --username AWS --password-stdin "$AWS_ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com"
docker build -t $PROJECT_NAME .
docker tag $PROJECT_NAME:latest $ECR_URL
docker push $ECR_URL
echo "  ✅ Image pushed: $ECR_URL"

# 3. Deploy CloudFormation stack
echo "[3/5] Deploying CloudFormation stack..."
aws cloudformation deploy \
    --template-file aws/cloudformation.yaml \
    --stack-name $PROJECT_NAME \
    --parameter-overrides \
        ContainerImage=$ECR_URL \
        AllowedIp="0.0.0.0/0" \
    --capabilities CAPABILITY_IAM CAPABILITY_NAMED_IAM \
    --region $AWS_REGION

# 4. Get outputs
echo "[4/5] Stack outputs:"
aws cloudformation describe-stacks --stack-name $PROJECT_NAME --region $AWS_REGION \
    --query 'Stacks[0].Outputs[].[OutputKey,OutputValue]' --output table

# 5. Instructions
echo "[5/5] Deployment complete!"
echo ""
echo "Next steps:"
echo "  1. Navigate to the LoadBalancerDNS URL from the outputs above"
echo "  2. Create users in the Cognito User Pool"
echo "  3. Upload PCAP files to test the analyzer"
echo ""
echo "To submit to AWS Marketplace:"
echo "  1. Go to AWS Marketplace Management Portal"
echo "  2. Create a 'Container' product with image: $ECR_URL"
echo "  3. Refer to marketplace/aws-listing.json for pricing/details"
