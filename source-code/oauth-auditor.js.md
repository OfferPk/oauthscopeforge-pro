/\*\*  
 \* OAuthScopeForge Pro \- 10-Point Zero-Trust OAuth 2.1 Health Auditor (v1.0.0)  
 \* Evaluates OAuth 2.1 & DPoP architecture configurations against RFC 9449 and security profiles.  
 \*/

(function (root, factory) {  
  if (typeof define \=== 'function' && define.amd) {  
    define(\['./oauth-engine'\], factory);  
  } else if (typeof module \=== 'object' && module.exports) {  
    module.exports \= factory(require('./oauth-engine'));  
  } else {  
    root.OAuthAuditor \= factory(root.OAuthEngine);  
  }  
}(typeof self \!== 'undefined' ? self : this, function (Engine) {  
  'use strict';

  function auditOAuthConfig(config) {  
    const enableDPoP \= config.enableDPoP \!== false;  
    const enforcePkce \= config.enforcePkce \!== false;  
    const pkceMethod \= config.pkceMethod || 'S256';  
    const disableImplicitGrant \= config.disableImplicitGrant \!== false;  
    const disablePasswordGrant \= config.disablePasswordGrant \!== false;  
    const exactRedirectUri \= config.exactRedirectUri \!== false;  
    const verifyHtmHtu \= config.verifyHtmHtu \!== false;  
    const serverNonceActive \= config.serverNonceActive \!== false;  
    const signingAlg \= config.signingAlgorithm || 'ES256';  
    const granularScopes \= config.granularScopes \!== false;  
    const tokenRevocationActive \= config.tokenRevocationActive \!== false;  
    const resourceIndicators \= config.resourceIndicators \!== false;

    const checks \= \[\];

    // 1\. DPoP Proof-of-Possession Token Binding (15 pts)  
    if (enableDPoP) {  
      checks.push({  
        id: 'DPOP\_BINDING',  
        name: 'DPoP Proof-of-Possession (RFC 9449)',  
        weight: 15,  
        score: 15,  
        status: 'PASS',  
        description: 'Sender-constrained token binding via cryptographic JWK thumbprint (cnf.jkt).',  
        details: 'Replaces bearer tokens. Access tokens are bound to client public key; stolen tokens cannot be used without client private key.',  
        remediation: null  
      });  
    } else {  
      checks.push({  
        id: 'DPOP\_BINDING',  
        name: 'DPoP Proof-of-Possession (RFC 9449)',  
        weight: 15,  
        score: 0,  
        status: 'FAIL',  
        description: 'Bearer tokens in use without sender constraint.',  
        details: 'Bearer tokens can be exfiltrated via log leaks or network interception and replayed by unauthorized parties.',  
        remediation: 'Mandate DPoP token type and verify DPoP proof headers on API gateways.'  
      });  
    }

    // 2\. Mandatory PKCE with S256 (15 pts)  
    if (enforcePkce && pkceMethod \=== 'S256') {  
      checks.push({  
        id: 'PKCE\_ENFORCEMENT',  
        name: 'Mandatory PKCE (S256)',  
        weight: 15,  
        score: 15,  
        status: 'PASS',  
        description: 'PKCE strictly required for all clients using S256 code challenge method.',  
        details: 'Prevents authorization code interception attacks across native, SPA, and confidential client flows per OAuth 2.1.',  
        remediation: null  
      });  
    } else if (enforcePkce && pkceMethod \=== 'plain') {  
      checks.push({  
        id: 'PKCE\_ENFORCEMENT',  
        name: 'Mandatory PKCE (S256)',  
        weight: 15,  
        score: 5,  
        status: 'WARN',  
        description: 'PKCE in use with insecure "plain" transformation.',  
        details: 'code\_challenge\_method="plain" does not protect authorization codes against network interception.',  
        remediation: 'Configure code\_challenge\_method="S256" and reject "plain".'  
      });  
    } else {  
      checks.push({  
        id: 'PKCE\_ENFORCEMENT',  
        name: 'Mandatory PKCE (S256)',  
        weight: 15,  
        score: 0,  
        status: 'FAIL',  
        description: 'PKCE not enforced on authorization code flow.',  
        details: 'Authorization codes can be intercepted by malicious apps via custom URI schemes on mobile and desktop OS.',  
        remediation: 'Enforce PKCE S256 for all clients per OAuth 2.1 specification.'  
      });  
    }

    // 3\. Deprecation of Insecure Grants (15 pts)  
    if (disableImplicitGrant && disablePasswordGrant) {  
      checks.push({  
        id: 'INSECURE\_GRANTS',  
        name: 'Insecure Grant Deprecation',  
        weight: 15,  
        score: 15,  
        status: 'PASS',  
        description: 'Implicit Grant and Resource Owner Password (ROPC) completely disabled.',  
        details: 'Complies with OAuth 2.1 and BCP 212\. Eliminates access tokens in URL hash fragments and password exposure to clients.',  
        remediation: null  
      });  
    } else if (disableImplicitGrant && \!disablePasswordGrant) {  
      checks.push({  
        id: 'INSECURE\_GRANTS',  
        name: 'Insecure Grant Deprecation',  
        weight: 15,  
        score: 7,  
        status: 'WARN',  
        description: 'Resource Owner Password Credentials (ROPC) grant still enabled.',  
        details: 'Clients handle plaintext user credentials directly, bypassing MFA and conditional access.',  
        remediation: 'Disable grant\_type="password" and migrate to authorization code with PKCE.'  
      });  
    } else {  
      checks.push({  
        id: 'INSECURE\_GRANTS',  
        name: 'Insecure Grant Deprecation',  
        weight: 15,  
        score: 0,  
        status: 'FAIL',  
        description: 'Implicit Grant (response\_type=token) is enabled\!',  
        details: 'Access tokens leaked via browser history, Referer headers, and proxy access logs.',  
        remediation: 'Immediately disable implicit flow in authorization server settings.'  
      });  
    }

    // 4\. Exact Redirect URI Matching (15 pts)  
    if (exactRedirectUri) {  
      checks.push({  
        id: 'EXACT\_REDIRECT\_URI',  
        name: 'Exact Redirect URI Matching',  
        weight: 15,  
        score: 15,  
        status: 'PASS',  
        description: 'Redirect URIs verified using strict exact string matching.',  
        details: 'Wildcards (\*), subdomain expansion, and path traversal patterns are strictly forbidden per OAuth 2.1.',  
        remediation: null  
      });  
    } else {  
      checks.push({  
        id: 'EXACT\_REDIRECT\_URI',  
        name: 'Exact Redirect URI Matching',  
        weight: 15,  
        score: 0,  
        status: 'FAIL',  
        description: 'Permissive wildcard or partial redirect URI matching detected\!',  
        details: 'Allows open-redirect attacks and authorization code exfiltration to attacker-controlled subdomains.',  
        remediation: 'Configure exact full-path redirect URI validation for all registered clients.'  
      });  
    }

    // 5\. HTTP Method & Target URI Parity (10 pts)  
    if (verifyHtmHtu) {  
      checks.push({  
        id: 'HTM\_HTU\_PARITY',  
        name: 'HTTP Method & Target URI Parity',  
        weight: 10,  
        score: 10,  
        status: 'PASS',  
        description: 'API gateway verifies DPoP "htm" and "htu" claims match actual incoming request.',  
        details: 'Prevents cross-endpoint token swapping (e.g. proof generated for GET /user replayed to DELETE /account).',  
        remediation: null  
      });  
    } else {  
      checks.push({  
        id: 'HTM\_HTU\_PARITY',  
        name: 'HTTP Method & Target URI Parity',  
        weight: 10,  
        score: 2,  
        status: 'FAIL',  
        description: 'Method and URI parity checks disabled in DPoP validation.',  
        details: 'Allows attackers to replay captured DPoP proofs against unintended endpoints.',  
        remediation: 'Validate req.method \=== payload.htm and req.originalUrl \=== payload.htu.'  
      });  
    }

    // 6\. Server Nonce & Freshness Window (10 pts)  
    if (serverNonceActive) {  
      checks.push({  
        id: 'SERVER\_NONCE',  
        name: 'Server Nonce & Replay Defense',  
        weight: 10,  
        score: 10,  
        status: 'PASS',  
        description: 'Server enforces DPoP-Nonce header and bounds proof freshness (\<= 120s).',  
        details: 'Server issues DPoP-Nonce challenge; clients must include it, completely preventing pre-computed or delayed replay attacks.',  
        remediation: null  
      });  
    } else {  
      checks.push({  
        id: 'SERVER\_NONCE',  
        name: 'Server Nonce & Replay Defense',  
        weight: 10,  
        score: 4,  
        status: 'WARN',  
        description: 'DPoP server nonce verification inactive; relies solely on client timestamp.',  
        details: 'Tokens remain replayable within the client timestamp drift window.',  
        remediation: 'Enable DPoP-Nonce challenge header on API responses.'  
      });  
    }

    // 7\. Cryptographic Algorithm Modernity (5 pts)  
    const isModernAlg \= \['ES256', 'ES384', 'ES512', 'EdDSA', 'PS256'\].includes(signingAlg);  
    if (isModernAlg) {  
      checks.push({  
        id: 'CRYPTO\_ALG',  
        name: 'Cryptographic Algorithm Modernity',  
        weight: 5,  
        score: 5,  
        status: 'PASS',  
        description: \`Modern asymmetric curve algorithm enforced (\${signingAlg}).\`,  
        details: 'Elliptic curve or RSA-PSS provides high-performance signature verification with compact keys.',  
        remediation: null  
      });  
    } else {  
      checks.push({  
        id: 'CRYPTO\_ALG',  
        name: 'Cryptographic Algorithm Modernity',  
        weight: 5,  
        score: 2,  
        status: 'WARN',  
        description: \`Legacy algorithm in use: \${signingAlg}.\`,  
        details: 'Consider upgrading to ES256 (NIST P-256) or EdDSA for optimal performance and security.',  
        remediation: 'Configure ES256 as the primary signing algorithm.'  
      });  
    }

    // 8\. Granular Scope Hierarchy & Least Privilege (5 pts)  
    if (granularScopes) {  
      checks.push({  
        id: 'GRANULAR\_SCOPES',  
        name: 'Granular Scope Hierarchy',  
        weight: 5,  
        score: 5,  
        status: 'PASS',  
        description: 'Resource-action scoped tokens (e.g. read:payments, write:transfers).',  
        details: 'Adheres to principle of least privilege, preventing over-scoped access tokens.',  
        remediation: null  
      });  
    } else {  
      checks.push({  
        id: 'GRANULAR\_SCOPES',  
        name: 'Granular Scope Hierarchy',  
        weight: 5,  
        score: 1,  
        status: 'WARN',  
        description: 'Broad wildcard or monolithic scopes detected.',  
        details: 'Over-privileged tokens increase blast radius if compromised.',  
        remediation: 'Define granular resource:action scopes per API route.'  
      });  
    }

    // 9\. Token Revocation & Introspection Support (5 pts)  
    if (tokenRevocationActive) {  
      checks.push({  
        id: 'TOKEN\_REVOCATION',  
        name: 'Token Revocation & Introspection (RFC 7009/7662)',  
        weight: 5,  
        score: 5,  
        status: 'PASS',  
        description: 'Standard revocation and introspection endpoints configured.',  
        details: 'Allows clients to invalidate refresh/access tokens upon logout or session termination.',  
        remediation: null  
      });  
    } else {  
      checks.push({  
        id: 'TOKEN\_REVOCATION',  
        name: 'Token Revocation & Introspection (RFC 7009/7662)',  
        weight: 5,  
        score: 2,  
        status: 'WARN',  
        description: 'Token revocation endpoint not exposed.',  
        details: 'Users cannot explicitly terminate delegated application sessions.',  
        remediation: 'Implement RFC 7009 /oauth/revoke endpoint.'  
      });  
    }

    // 10\. Resource Indicators & Audience Restriction (5 pts)  
    if (resourceIndicators) {  
      checks.push({  
        id: 'RESOURCE\_INDICATORS',  
        name: 'Resource Indicators (RFC 8707)',  
        weight: 5,  
        score: 5,  
        status: 'PASS',  
        description: 'Tokens restricted to specific API resource servers via "aud" claim.',  
        details: 'Prevents access tokens issued for API A from being accepted by API B.',  
        remediation: null  
      });  
    } else {  
      checks.push({  
        id: 'RESOURCE\_INDICATORS',  
        name: 'Resource Indicators (RFC 8707)',  
        weight: 5,  
        score: 2,  
        status: 'WARN',  
        description: 'Global audience token; lacks specific resource server indicators.',  
        details: 'Token can be used across multiple distinct internal microservices.',  
        remediation: 'Include specific "resource" URI parameter during token requests.'  
      });  
    }

    // Calculate score  
    const totalScore \= checks.reduce((acc, c) \=\> acc \+ c.score, 0);  
    const maxScore \= checks.reduce((acc, c) \=\> acc \+ c.weight, 0);  
    const scorePct \= Math.round((totalScore / maxScore) \* 100);

    let grade \= 'F';  
    if (scorePct \>= 97\) grade \= 'A+';  
    else if (scorePct \>= 90\) grade \= 'A';  
    else if (scorePct \>= 80\) grade \= 'B';  
    else if (scorePct \>= 70\) grade \= 'C';  
    else if (scorePct \>= 60\) grade \= 'D';

    return {  
      score: scorePct,  
      grade: grade,  
      passedCount: checks.filter(c \=\> c.status \=== 'PASS').length,  
      warnCount: checks.filter(c \=\> c.status \=== 'WARN').length,  
      failCount: checks.filter(c \=\> c.status \=== 'FAIL').length,  
      checks: checks  
    };  
  }

  return {  
    auditOAuthConfig: auditOAuthConfig  
  };  
}));  
