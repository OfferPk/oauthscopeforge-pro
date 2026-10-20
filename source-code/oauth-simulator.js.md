/\*\*  
 \* OAuthScopeForge Pro \- Interactive DPoP Attack & Defense Simulator (v1.0.0)  
 \* Visualizes Bearer token replay attacks vs DPoP cryptographic sender-constraining defenses.  
 \*/

(function (root, factory) {  
  if (typeof define \=== 'function' && define.amd) {  
    define(\[\], factory);  
  } else if (typeof module \=== 'object' && module.exports) {  
    module.exports \= factory();  
  } else {  
    root.OAuthSimulator \= factory();  
  }  
}(typeof self \!== 'undefined' ? self : this, function () {  
  'use strict';

  function simulateAttack(scenarioType, config) {  
    const isBearerReplay \= scenarioType \=== 'bearer\_vulnerable';  
    const targetEndpoint \= config.apiEndpoint || 'https\://api.bank.com/v1/payments/transfer';  
    const clientJkt \= '0ZcOCORZTXFORZ88912aa\_jkt';  
    const attackerIp \= '198.51.100.44';

    if (isBearerReplay) {  
      return {  
        scenario: 'Bearer Token Exfiltration & Replay Attack (Legacy OAuth 2.0)',  
        isVulnerable: true,  
        summary: 'CRITICAL TOKEN HIJACKING: Intercepted bearer token replayed from unauthorized IP without challenge. Attacker executed unauthorized \$50,000 transfer.',  
        steps: \[  
          {  
            step: 1,  
            title: 'Authorization Code Flow & Bearer Token Issuance',  
            status: 'INFO',  
            description: 'Legitimate client logs in. Authorization server issues standard Bearer access token: "Bearer eyJhbGciOiJSUzI1Ni..." with scope "write:payments".',  
            observations: \[  
              'Token type: Bearer (No cryptographic binding to client)',  
              'Anyone holding the string can impersonate the client'  
            \]  
          },  
          {  
            step: 2,  
            title: 'Network Telemetry Interception / Access Log Exfiltration',  
            status: 'EXPLOITED',  
            description: 'Attacker sniffs access token from an insecure proxy cache, unencrypted telemetry stream, or client-side malware.',  
            observations: \[  
              'Attacker extracts: "Authorization: Bearer eyJhbGciOiJSUzI1Ni..."',  
              'No hardware enclave or client key required to hold token'  
            \]  
          },  
          {  
            step: 3,  
            title: 'Attacker Replay Request from Rogue Host',  
            status: 'EXPLOITED',  
            description: \`Attacker sends POST request to "\${targetEndpoint}" from rogue IP \${attackerIp} with header "Authorization: Bearer eyJhbGci..."\`,  
            observations: \[  
              'Target API receives request from unknown IP address',  
              'API Gateway checks: "Is Bearer token signature valid?" \-\> YES\!',  
              'API Gateway checks: "Is token expired?" \-\> NO\! (50 minutes remaining)'  
            \]  
          },  
          {  
            step: 4,  
            title: 'Privileged Action Execution & Account Draining',  
            status: 'EXPLOITED',  
            description: 'Resource server accepts bearer token without proof of possession and executes fund transfer.',  
            observations: \[  
              'Transaction executed: \$50,000 wire transfer completed',  
              'Zero detection of token theft. Bearer token model failed\!'  
            \]  
          }  
        \]  
      };  
    }

    // Zero-Trust DPoP Protected Scenario  
    return {  
      scenario: 'DPoP Proof-of-Possession Token Binding (RFC 9449 Hardened)',  
      isVulnerable: false,  
      summary: 'SECURE DEFENSE: Token bound to client public key thumbprint. Replay attempt rejected with HTTP 401 Unauthorized (invalid\_dpop\_proof).',  
      steps: \[  
        {  
          step: 1,  
          title: 'Client Key Generation & DPoP Token Binding',  
          status: 'INFO',  
          description: \`Client generates ephemeral P-256 key pair in secure hardware. AS binds access token to client thumbprint: cnf.jkt \= "\${clientJkt}".\`,  
          observations: \[  
            'Token type: DPoP (Sender-Constrained)',  
            \`Bound Thumbprint: cnf.jkt \= "\${clientJkt}"\`  
          \]  
        },  
        {  
          step: 2,  
          title: 'Token Interception & Attacker Replay Attempt',  
          status: 'SECURE',  
          description: \`Attacker steals the DPoP access token string and attempts POST to "\${targetEndpoint}" from rogue IP \${attackerIp}.\`,  
          observations: \[  
            'Attacker attempts to send token with "Authorization: DPoP eyJ..."',  
            'Attacker DOES NOT possess the client private key stored in secure enclave'  
          \]  
        },  
        {  
          step: 3,  
          title: 'Gateway DPoP Proof Verification & Thumbprint Check',  
          status: 'SECURE',  
          description: 'API gateway intercepts request and evaluates mandatory RFC 9449 DPoP headers.',  
          observations: \[  
            'Case 1: Attacker sends request without DPoP header \-\> REJECTED (Missing DPoP header)',  
            'Case 2: Attacker signs own DPoP proof with attacker key \-\> JWK thumbprint does NOT match token cnf.jkt\!',  
            \`Expected jkt: "\${clientJkt}" vs Attacker jkt: "attacker\_bad\_jkt" \-\> MISMATCH\!\`  
          \]  
        },  
        {  
          step: 4,  
          title: 'Instant Replay Mitigation & Security Alert',  
          status: 'SECURE',  
          description: 'API Gateway drops request immediately with HTTP 401 Unauthorized (error="invalid\_dpop\_proof").',  
          observations: \[  
            'HTTP 401 Unauthorized returned to attacker',  
            'Unauthorized wire transfer completely prevented',  
            'Zero financial loss. 100% cryptographic sender-constraining guaranteed.'  
          \]  
        }  
      \]  
    };  
  }

  return {  
    simulateAttack: simulateAttack  
  };  
}));  
