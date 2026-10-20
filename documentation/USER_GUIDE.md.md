\# OAuthScopeForge Pro — Comprehensive User Guide (v1.0.0)

\#\# Getting Started

OAuthScopeForge Pro operates as an interactive in-browser development studio and as a standalone pre-commit Python CLI tool in CI/CD pipelines.

\---

\#\# 1\. Web Studio Quickstart

1\. Open \`source-code/index.html\` in any modern web browser.  
2\. Select an industry preset from the top dropdown:  
   \- \*\*Enterprise Open Banking FAPI 2.0 & DPoP Policy\*\* (Grade A+ 100/100)  
   \- \*\*Standard B2B SaaS OAuth 2.1 API Gateway\*\* (Grade A 94/100)  
   \- \*\*Vulnerable Legacy OAuth 2.0 (Bearer & Implicit)\*\* (Grade F 18/100)  
3\. Customize your Authorization Server & API Gateway parameters:  
   \- Authorization Server URL  
   \- Target API Endpoint URI & HTTP Request Method (\`POST\`, \`GET\`, \`PUT\`, \`DELETE\`)  
   \- PKCE Code Challenge Method (\`S256\`, \`plain\`, \`none\`)  
   \- Required Scopes (e.g. \`openid profile read:accounts write:payments\`)  
   \- Toggles: Enable DPoP Token Binding (RFC 9449), Disable Implicit Grant, Exact Redirect URI Matching, Verify HTM/HTU Parity, Server Nonce Replay Defense  
4\. Review the \*\*10-Point Scorecard\*\*:  
   \- Verify that your OAuth policy achieves Grade A+ (100/100).  
   \- Review remediation notes for any warnings or critical flaws.  
5\. Use the \*\*Interactive Attack Simulator\*\*:  
   \- Compare how an intercepted Bearer token is replayed from a rogue IP address vs how DPoP rejects requests lacking the client's private key proof.  
6\. Export your Gateway Implementation Code:  
   \- Choose between \*\*Node.js Express DPoP Middleware\*\*, \*\*Python FastAPI DPoP Dependency\*\*, \*\*Go Gin DPoP Validator\*\*, or \*\*Envoy Proxy v3 OAuth2 Filter\*\*.  
   \- Click \*\*Copy Implementation\*\* to paste directly into your project.

\---

\#\# 2\. Using the Standalone Python CLI (\`oauthscopeforge-cli.py\`)

The CLI runs on Python 3.6+ with zero external package dependencies.

\#\#\# Auditing an OAuth Configuration Preset  
\`\`\`bash  
python3 build/oauthscopeforge-cli.py audit \-p presets/enterprise-banking-dpop-oauth21.json  
\`\`\`

\#\#\# Auditing with Strict CI/CD Gating  
\`\`\`bash  
python3 build/oauthscopeforge-cli.py audit \-p presets/enterprise-banking-dpop-oauth21.json \--strict  
\# Exits with 0 on pass, or 1 if score \< 90 or failures exist  
\`\`\`

\#\#\# Inspecting JWT or DPoP Proof Headers  
\`\`\`bash  
python3 build/oauthscopeforge-cli.py inspect "eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2In0..."  
\`\`\`

\#\#\# Generating Gateway Boilerplate  
\`\`\`bash  
python3 build/oauthscopeforge-cli.py generate \--backend node \--endpoint https\://api.bank.com/v1/transfers  
\`\`\`

\---

\#\# 3\. GitHub Actions CI/CD Integration

Prevent insecure OAuth 2.0 configurations (e.g. enabling Implicit Grant or skipping PKCE) from being merged into production:

\`\`\`yaml  
name: OAuth 2.1 Security CI  
on: \[push, pull\_request\]

jobs:  
  audit-oauth:  
    runs-on: ubuntu-latest  
    steps:  
      \- uses: actions/checkout@v4  
      \- name: Set up Python  
        uses: actions/setup-python@v5  
        with:  
          python-version: '3.11'  
      \- name: Run OAuthScopeForge Pro Audit  
        run: |  
          python3 build/oauthscopeforge-cli.py audit \\  
            \-p presets/enterprise-banking-dpop-oauth21.json \\  
            \--strict  
\`\`\`  
