/\*\*  
 \* OAuthScopeForge Pro \- UI Controller & Orchestration (v1.0.0)  
 \*/

(function () {  
  'use strict';

  // DOM Elements  
  const presetSelect \= document.getElementById('presetSelect');  
  const loadPresetBtn \= document.getElementById('loadPresetBtn');  
  const authServerInput \= document.getElementById('authServerInput');  
  const apiEndpointInput \= document.getElementById('apiEndpointInput');  
  const httpMethodSelect \= document.getElementById('httpMethodSelect');  
  const pkceMethodSelect \= document.getElementById('pkceMethodSelect');  
  const scopesInput \= document.getElementById('scopesInput');  
  const scopeTagsContainer \= document.getElementById('scopeTagsContainer');  
  const checkDPoP \= document.getElementById('checkDPoP');  
  const checkDisableImplicit \= document.getElementById('checkDisableImplicit');  
  const checkExactRedirect \= document.getElementById('checkExactRedirect');  
  const checkVerifyHtmHtu \= document.getElementById('checkVerifyHtmHtu');  
  const checkServerNonce \= document.getElementById('checkServerNonce');  
  const checkResourceIndicators \= document.getElementById('checkResourceIndicators');  
  const tokenMetadataBox \= document.getElementById('tokenMetadataBox');

  // Scorecard Elements  
  const gradeBadge \= document.getElementById('gradeBadge');  
  const scoreValue \= document.getElementById('scoreValue');  
  const scoreGradeText \= document.getElementById('scoreGradeText');  
  const auditPassedBadge \= document.getElementById('auditPassedBadge');  
  const passCountEl \= document.getElementById('passCount');  
  const warnCountEl \= document.getElementById('warnCount');  
  const failCountEl \= document.getElementById('failCount');  
  const auditListEl \= document.getElementById('auditList');

  // Simulator Elements  
  const simBearerBtn \= document.getElementById('simBearerBtn');  
  const simDPoPBtn \= document.getElementById('simDPoPBtn');  
  const simTerminalLog \= document.getElementById('simTerminalLog');

  // Tab & Code Elements  
  const tabButtons \= document.querySelectorAll('.tab-btn');  
  const backendCodeOutput \= document.getElementById('backendCodeOutput');  
  const copyCodeBtn \= document.getElementById('copyCodeBtn');

  // Application State  
  let state \= {  
    authServerUrl: 'https\://auth.bank.com',  
    apiEndpoint: 'https\://api.bank.com/v1/payments/transfer',  
    httpMethod: 'POST',  
    pkceMethod: 'S256',  
    enforcePkce: true,  
    requiredScopes: 'openid profile read:accounts write:payments',  
    enableDPoP: true,  
    disableImplicitGrant: true,  
    disablePasswordGrant: true,  
    exactRedirectUri: true,  
    verifyHtmHtu: true,  
    serverNonceActive: true,  
    signingAlgorithm: 'ES256',  
    granularScopes: true,  
    tokenRevocationActive: true,  
    resourceIndicators: true,  
    clientJwk: {  
      kty: 'EC',  
      crv: 'P-256',  
      x: 'f83OJ3D2xFmT4v7Ny-J6P6OQGqT6Xk',  
      y: 'x\_da7W8V7q2D9Y-N6B6A7A9V7M6P'  
    },  
    activeTab: 'node',  
    simScenario: 'dpop'  
  };

  const PRESETS \= {  
    enterprise: {  
      authServerUrl: 'https\://auth.bank.com',  
      apiEndpoint: 'https\://api.bank.com/v1/payments/transfer',  
      httpMethod: 'POST',  
      pkceMethod: 'S256',  
      enforcePkce: true,  
      requiredScopes: 'openid profile read:accounts write:payments',  
      enableDPoP: true,  
      disableImplicitGrant: true,  
      disablePasswordGrant: true,  
      exactRedirectUri: true,  
      verifyHtmHtu: true,  
      serverNonceActive: true,  
      signingAlgorithm: 'ES256',  
      granularScopes: true,  
      tokenRevocationActive: true,  
      resourceIndicators: true,  
      clientJwk: {  
        kty: 'EC',  
        crv: 'P-256',  
        x: 'f83OJ3D2xFmT4v7Ny-J6P6OQGqT6Xk',  
        y: 'x\_da7W8V7q2D9Y-N6B6A7A9V7M6P'  
      }  
    },  
    saas: {  
      authServerUrl: 'https\://id.saascloud.io',  
      apiEndpoint: 'https\://api.saascloud.io/v2/workspaces',  
      httpMethod: 'GET',  
      pkceMethod: 'S256',  
      enforcePkce: true,  
      requiredScopes: 'read:workspaces write:workspaces',  
      enableDPoP: true,  
      disableImplicitGrant: true,  
      disablePasswordGrant: true,  
      exactRedirectUri: true,  
      verifyHtmHtu: true,  
      serverNonceActive: false,  
      signingAlgorithm: 'ES256',  
      granularScopes: true,  
      tokenRevocationActive: true,  
      resourceIndicators: false,  
      clientJwk: {  
        kty: 'EC',  
        crv: 'P-256',  
        x: 'a7b8c9d0e1f2g3h4i5j6k7l8m9n0',  
        y: 'o1p2q3r4s5t6u7v8w9x0y1z2a3b4'  
      }  
    },  
    vulnerable: {  
      authServerUrl: 'http\://legacy-auth.internal',  
      apiEndpoint: 'http\://legacy-api.internal/transfer',  
      httpMethod: 'POST',  
      pkceMethod: 'none',  
      enforcePkce: false,  
      requiredScopes: '\*',  
      enableDPoP: false,  
      disableImplicitGrant: false,  
      disablePasswordGrant: false,  
      exactRedirectUri: false,  
      verifyHtmHtu: false,  
      serverNonceActive: false,  
      signingAlgorithm: 'RS256',  
      granularScopes: false,  
      tokenRevocationActive: false,  
      resourceIndicators: false,  
      clientJwk: null  
    }  
  };

  function init() {  
    bindEvents();  
    renderAll();  
  }

  function bindEvents() {  
    loadPresetBtn.addEventListener('click', () \=\> {  
      const p \= PRESETS\[presetSelect.value\];  
      if (p) {  
        state \= { ...state, ...p };  
        authServerInput.value \= state.authServerUrl;  
        apiEndpointInput.value \= state.apiEndpoint;  
        httpMethodSelect.value \= state.httpMethod;  
        pkceMethodSelect.value \= state.pkceMethod;  
        scopesInput.value \= state.requiredScopes;  
        checkDPoP.checked \= state.enableDPoP;  
        checkDisableImplicit.checked \= state.disableImplicitGrant;  
        checkExactRedirect.checked \= state.exactRedirectUri;  
        checkVerifyHtmHtu.checked \= state.verifyHtmHtu;  
        checkServerNonce.checked \= state.serverNonceActive;  
        checkResourceIndicators.checked \= state.resourceIndicators;  
        renderAll();  
      }  
    });

    authServerInput.addEventListener('input', (e) \=\> {  
      state.authServerUrl \= e.target.value.trim() || 'https\://auth.bank.com';  
      renderAll();  
    });

    apiEndpointInput.addEventListener('input', (e) \=\> {  
      state.apiEndpoint \= e.target.value.trim() || 'https\://api.bank.com/v1/resource';  
      renderAll();  
    });

    httpMethodSelect.addEventListener('change', (e) \=\> {  
      state.httpMethod \= e.target.value;  
      renderAll();  
    });

    pkceMethodSelect.addEventListener('change', (e) \=\> {  
      state.pkceMethod \= e.target.value;  
      state.enforcePkce \= (state.pkceMethod \!== 'none');  
      renderAll();  
    });

    scopesInput.addEventListener('input', (e) \=\> {  
      state.requiredScopes \= e.target.value.trim();  
      state.granularScopes \= \!state.requiredScopes.includes('\*');  
      renderAll();  
    });

    checkDPoP.addEventListener('change', (e) \=\> {  
      state.enableDPoP \= e.target.checked;  
      renderAll();  
    });

    checkDisableImplicit.addEventListener('change', (e) \=\> {  
      state.disableImplicitGrant \= e.target.checked;  
      renderAll();  
    });

    checkExactRedirect.addEventListener('change', (e) \=\> {  
      state.exactRedirectUri \= e.target.checked;  
      renderAll();  
    });

    checkVerifyHtmHtu.addEventListener('change', (e) \=\> {  
      state.verifyHtmHtu \= e.target.checked;  
      renderAll();  
    });

    checkServerNonce.addEventListener('change', (e) \=\> {  
      state.serverNonceActive \= e.target.checked;  
      renderAll();  
    });

    checkResourceIndicators.addEventListener('change', (e) \=\> {  
      state.resourceIndicators \= e.target.checked;  
      renderAll();  
    });

    // Simulator Toggle  
    simBearerBtn.addEventListener('click', () \=\> {  
      state.simScenario \= 'bearer\_vulnerable';  
      simBearerBtn.classList.add('active');  
      simDPoPBtn.classList.remove('active');  
      renderSimulator();  
    });

    simDPoPBtn.addEventListener('click', () \=\> {  
      state.simScenario \= 'dpop';  
      simDPoPBtn.classList.add('active');  
      simBearerBtn.classList.remove('active');  
      renderSimulator();  
    });

    // Tabs  
    tabButtons.forEach(btn \=\> {  
      btn.addEventListener('click', () \=\> {  
        tabButtons.forEach(b \=\> b.classList.remove('active'));  
        btn.classList.add('active');  
        state.activeTab \= btn.getAttribute('data-tab');  
        renderBackendCode();  
      });  
    });

    // Copy Code  
    copyCodeBtn.addEventListener('click', () \=\> {  
      const text \= backendCodeOutput.textContent;  
      navigator.clipboard.writeText(text).then(() \=\> {  
        const orig \= copyCodeBtn.textContent;  
        copyCodeBtn.textContent \= 'Copied\!';  
        setTimeout(() \=\> copyCodeBtn.textContent \= orig, 1500);  
      });  
    });  
  }

  function renderAll() {  
    renderScopeTags();  
    renderTokenMetadata();  
    renderScorecard();  
    renderSimulator();  
    renderBackendCode();  
  }

  function renderScopeTags() {  
    const list \= state.requiredScopes.split(/\\s+/).filter(Boolean);  
    scopeTagsContainer.innerHTML \= list.map(s \=\> \`\<span class="scope-tag"\>\${s}\</span\>\`).join('');  
  }

  function renderTokenMetadata() {  
    const thumbprint \= state.clientJwk ? OAuthEngine.computeJwkThumbprintHex(state.clientJwk) : 'None (Unbound Bearer)';  
    const tokenType \= state.enableDPoP ? 'DPoP (Sender-Constrained RFC 9449)' : 'Bearer (Unconstrained / Vulnerable)';

    tokenMetadataBox.innerHTML \= \`  
      \<div class="token-field"\>\<span class="token-label"\>Token Scheme:\</span\>\<span class="token-val" style="color: \${state.enableDPoP ? 'var(--accent-emerald)' : 'var(--accent-red)'}"\>\${tokenType}\</span\>\</div\>  
      \<div class="token-field"\>\<span class="token-label"\>Client Thumbprint (cnf.jkt):\</span\>\<span class="token-val"\>\${thumbprint}\</span\>\</div\>  
      \<div class="token-field"\>\<span class="token-label"\>Target HTM \&amp; HTU:\</span\>\<span class="token-val"\>\${state.httpMethod} \&bull; \${state.apiEndpoint}\</span\>\</div\>  
      \<div class="token-field"\>\<span class="token-label"\>PKCE Status:\</span\>\<span class="token-val" style="color: \${state.pkceMethod \=== 'S256' ? 'var(--accent-emerald)' : 'var(--accent-red)'}"\>Method: \${state.pkceMethod.toUpperCase()} (\${state.pkceMethod \=== 'S256' ? 'VALID' : 'NON-COMPLIANT'})\</span\>\</div\>  
      \<div class="token-field"\>\<span class="token-label"\>Server Nonce Challenge:\</span\>\<span class="token-val"\>\${state.serverNonceActive ? 'Active (Single-Use DPoP-Nonce)' : 'Disabled (Timestamp drift only)'}\</span\>\</div\>  
    \`;  
  }

  function renderScorecard() {  
    const audit \= OAuthAuditor.auditOAuthConfig(state);

    scoreValue.textContent \= \`\${audit.score} / 100\`;  
    gradeBadge.textContent \= audit.grade;  
    gradeBadge.className \= 'grade-badge';

    if (audit.grade \=== 'A+' || audit.grade \=== 'A') {  
      gradeBadge.classList.add('grade-a');  
      scoreGradeText.textContent \= 'Zero-Trust Sender-Constrained';  
    } else if (audit.grade \=== 'B') {  
      gradeBadge.classList.add('grade-b');  
      scoreGradeText.textContent \= 'Solid Architecture (Minor Nonce/Audience Advisory)';  
    } else if (audit.grade \=== 'C' || audit.grade \=== 'D') {  
      gradeBadge.classList.add('grade-c');  
      scoreGradeText.textContent \= 'Suboptimal Security (Bearer Token or Insecure PKCE)';  
    } else {  
      gradeBadge.classList.add('grade-f');  
      scoreGradeText.textContent \= 'Critical Flaw (Implicit Grant / Token Replay Risk)';  
    }

    auditPassedBadge.textContent \= \`\${audit.passedCount} / \${audit.checks.length} Passed\`;  
    passCountEl.textContent \= audit.passedCount;  
    warnCountEl.textContent \= audit.warnCount;  
    failCountEl.textContent \= audit.failCount;

    // Render list  
    auditListEl.innerHTML \= audit.checks.map(check \=\> {  
      const statusClass \= check.status.toLowerCase();  
      const tagClass \= \`tag-\${statusClass}\`;  
      return \`  
        \<div class="audit-item \${statusClass}"\>  
          \<div class="audit-header-line"\>  
            \<span class="audit-title"\>\${check.name}\</span\>  
            \<span class="audit-tag \${tagClass}"\>\${check.status} (\${check.score}/\${check.weight} pts)\</span\>  
          \</div\>  
          \<div class="audit-desc"\>\${check.description} \${check.details}\</div\>  
          \${check.remediation ? \`\<div class="audit-remed"\>Remediation: \${check.remediation}\</div\>\` : ''}  
        \</div\>  
      \`;  
    }).join('');  
  }

  function renderSimulator() {  
    const sim \= OAuthSimulator.simulateAttack(state.simScenario, state);

    simTerminalLog.innerHTML \= sim.steps.map(s \=\> {  
      let extraHtml \= '';  
      if (s.observations) {  
        extraHtml \= \`\<ul style="margin-left: 20px; margin-top: 4px; color: \${sim.isVulnerable ? '\#fca5a5' : '\#86efac'};"\>  
          \${s.observations.map(obs \=\> \`\<li\>\${obs}\</li\>\`).join('')}  
        \</ul\>\`;  
      }  
      return \`  
        \<div class="log-line"\>  
          \<span class="log-step"\>\[Step \${s.step}\]\</span\>  
          \<span class="\${s.status \=== 'EXPLOITED' ? 'log-warn' : (s.status \=== 'SECURE' ? 'log-pass' : 'log-info')}"\>  
            \<strong\>\${s.title}:\</strong\> \${s.description}  
          \</span\>  
          \${extraHtml}  
        \</div\>  
      \`;  
    }).join('') \+ \`  
      \<div style="margin-top: 10px; padding-top: 8px; border-top: 1px dashed \#374151; font-weight: 700; color: \${sim.isVulnerable ? '\#ef4444' : '\#10b981'};"\>  
        Verdict: \${sim.summary}  
      \</div\>  
    \`;  
  }

  function renderBackendCode() {  
    const configs \= GatewaySynthesizer.synthesizeConfigurations(state);  
    backendCodeOutput.textContent \= configs\[state.activeTab\] || configs.node;  
  }

  if (document.readyState \=== 'loading') {  
    document.addEventListener('DOMContentLoaded', init);  
  } else {  
    init();  
  }  
})();  
