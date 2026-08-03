# AWS Marketplace Seller Guide - 5G Core & IMS Analyzer

## Product Overview

5G Core & IMS E2E Call Flow Correlator is a containerized network analysis tool that parses 3GPP 5G Core and IMS signaling traces, correlates IMSI/MSISDN identities, and generates interactive Mermaid call flow diagrams with real-time error diagnosis.

## Technical Requirements

- **Platform**: Any (containerized)
- **Operating System**: Linux
- **Minimum Instance**: t3.small (2 vCPU, 2GB RAM)
- **Recommended Instance**: t3.medium (2 vCPU, 4GB RAM) or c5.large for production

## Architecture

```
Internet → ALB (HTTP:80) → Fargate Service (HTTP:8000)
                                          ├── /uploads (S3 bucket)
                                          ├── /health (health check)
                                          └── / (FastAPI web UI)
```

## Deployment Steps

### 1. Subscribe via AWS Marketplace
1. Navigate to the AWS Marketplace listing page
2. Click "Continue to Subscribe"
3. Accept the terms and select a pricing tier
4. Click "Continue to Launch"

### 2. Launch via CloudFormation
1. Choose "CloudFormation Template" as the launch method
2. Enter the ECR image URI provided
3. Configure:
   - Container image (pre-populated)
   - Allowed IP CIDR (restrict to your network)
   - VPC configuration
4. Click "Create"

### 3. Configure Authentication
1. After stack creation, navigate to the Cognito User Pool in AWS Console
2. Create user accounts via "Manage User Pool" → "Users and Groups"
3. Configure a domain name for the app client (optional)

### 4. Access the Application
1. Wait 2-3 minutes for health check to pass
2. Navigate to the LoadBalancerDNS output value
3. Sign in with your Cognito credentials

## Pricing

| Tier | Price | Features |
|------|-------|----------|
| Basic | $0.50/hr | Single-user, 5 traces/session |
| Professional | $2.50/hr | Multi-user, unlimited traces, Excel export |
| Enterprise | $10.00/hr | 100 users, premium support |

## Monitoring

- Health checks: `https://LOADBALANCER/health`
- Service metrics: CloudWatch (`ECS` / `ELB` namespaces)
- Logs: CloudWatch `/ecs/5g-core-analyzer`
- Tracing: X-Ray (optional - add `AWS_XRAY_DAEMON_ADDRESS`)

## Troubleshooting

### Health check failures
- Verify tshark is installed in the container
- Check CloudWatch logs for startup errors
- Verify S3 bucket permissions

### PCAP upload fails
- Ensure S3 bucket policy grants ECS task role write access
- Check ECS task role has `AmazonS3FullAccess` or scoped policy

### Mermaid diagrams not rendering
- Mermaid.js loads from CDN (jsdelivr). Ensure outbound internet access from the VPC
- Alternative: Use VPC endpoint for jsdelivr CDN

## Support

Email: support@5g-core-analyzer.example.com
Documentation: https://github.com/5G-Core-Analyzer/docs
