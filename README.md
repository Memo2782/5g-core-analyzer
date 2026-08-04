# 5G Core & IMS E2E Call Flow Correlator

[![Support via PayPal](https://img.shields.io/badge/Support-💝-PayPal-orange?style=flat-square)](https://www.paypal.com/paypalme/morpheusthechoice)
[![License](https://img.shields.io/badge/License-MIT-blue?style=flat-square)](LICENSE)
[![Commercial License](https://img.shields.io/badge/Commercial-License-red?style=flat-square)](LICENSE-ENTERPRISE.txt)

Multi-protocol network analyzer for 3GPP 5G Core (5GC) and IMS (IP Multimedia Subsystem) environments. Uploads PCAP/network traces, correlates signaling, and generates interactive Mermaid call flow diagrams with IMSI/MSISDN tracking.

## 💰 Support & Licensing

- **Free/Open Source**: MIT license for personal and educational use
- **Commercial License**: Required for production/enterprise use — see [LICENSE-ENTERPRISE.txt](LICENSE-ENTERPRISE.txt)
- **Paid Support**: [Buy Now](BUY-NOW.md) or [Sponsor on GitHub](https://github.com/sponsors/guillermopineda)

See [SUPPORT.md](SUPPORT.md) for support tiers and response times.

## Key Features

- **Multi-call flow support**: Upload multiple PCAP files with different IMSI/MSISDN identities; each subscriber's call flow is independently diagnosable via a dropdown selector
- **Interactive Mermaid diagrams**: E2E (5G Core + IMS), standalone 5G Core control plane, and standalone IMS VoNR/VoLTE call flow diagrams
- **IMSI/MSISDN/Call-ID correlation**: Tracks subscriber identities across all network nodes and shows them in diagram notes, alert tables, and error detail modals
- **Error diagnosis**: Maps 3GPP protocol error codes to root causes with troubleshooting guidance
- **Excel export**: Generates premium corporate audit reports with consolidated alerts

## Project Structure

```
5g-core-analyzer/
├── core/
│   ├── pcap_parser.py       # Multi-protocol PCAP parser (HTTP/2, SIP, TCP/UDP)
│   ├── log_processor.py     # 3GPP error code catalog processor
│   └── log_generator.py     # Synthetic log generator for IMSI/MSISDN tracking
├── reports/
│   └── excel_generator.py   # Premium Excel report generator
├── config/
│   └── 3gpp_codes.json      # 3GPP error code catalog
├── tests/
│   ├── test_log_processor.py
│   ├── test_pcap_parser.py
│   └── test_web_app_contract.py
├── generar_trazas.py        # Trace generator (5 diverse call flow profiles)
├── web_app.py               # FastAPI web server
├── main.py                  # CLI auditor for raw log entries
└── venv/                    # Python virtual environment
```

## Installation

```bash
git clone <repo-url>
cd 5g-core-analyzer
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Usage

### Web UI (primary interface)

```bash
python -m uvicorn web_app:app --host 0.0.0.0 --port 8000
```

1. Open `http://localhost:8000`
2. Generate sample traces: `python generar_trazas.py`
3. Upload one or more PCAP files from `data_samples/`
4. Use the **IMSI/MSISDN dropdown** in the tracking header to switch between call flows
5. Each call flow shows distinct Mermaid diagrams, alert tables, and error references

### CLI auditor

```bash
python main.py
```

### Testing

```bash
python -m pytest tests/ -v
```

## Sample Call Flows

| IMSI | Error Profile | Diagram Errors |
|------|--------------|----------------|
| 001010000000001 | IMS SIP 403 only | 403 at SCSCF |
| 001010000000002 | 5G 404 + 504 + IMS 403 | 404 at UDM, 504 at SMF, 403 at SCSCF |
| 001010000000003 | Success | All OK |
| 001010000000004 | 5G 504 + IMS 403 | 504 at SMF, 403 at SCSCF |
| 001010000000005 | 5G 401 + IMS 403 | 401 at AUSF, 403 at SCSCF |

## AWS Deployment (Marketplace-ready)

```bash
# Prerequisites: AWS CLI configured, Docker running
bash deploy_to_aws.sh
```

Deploys via CloudFormation to ECS Fargate with:
- **Application Load Balancer** (public endpoint)
- **Cognito User Pool** (authentication)
- **S3 bucket** (trace storage)
- **CloudWatch logging** (built-in)

**Required IAM permissions:** ECR, ECS, S3, Cognito, CloudFormation

### Docker (local)

```bash
docker-compose up --build
# Open http://localhost:8000
```

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `STORAGE_BUCKET` | (empty) | S3 bucket for trace storage (set in production) |
| `STORAGE_PREFIX` | (empty) | S3 key prefix for uploaded files |

## AWS Marketplace Submission

See `marketplace/` directory for listing metadata and seller guide.

## 💸 Commercial Support & Licensing

| Need | How |
|------|-----|
| Report a bug | [GitHub Issues](https://github.com/Memo2782/5g-core-analyzer/issues) (free) |
| Ask a question | [GitHub Discussions](https://github.com/Memo2782/5g-core-analyzer/discussions) (free) |
| Priority support | [Monthly via PayPal](BUY-NOW.md) ($50/month) |
| Enterprise use | [Commercial license](BUY-NOW.md) ($2,500 one-time via PayPal) |
| Custom features | [Consulting](BUY-NOW.md) ($250/hour via PayPal) |

See [SUPPORT.md](SUPPORT.md) for full support details.

## License

- **Open Source**: MIT (for personal/educational use) — see [LICENSE](LICENSE)
- **Commercial**: Requires paid license — see [LICENSE-ENTERPRISE.txt](LICENSE-ENTERPRISE.txt)
