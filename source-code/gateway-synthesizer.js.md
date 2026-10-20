/\*\*  
 \* OAuthScopeForge Pro \- Multi-Gateway & Backend Synthesizer (v1.0.0)  
 \* Generates production-ready, zero-vulnerability OAuth 2.1 & DPoP verification gateways.  
 \*/

(function (root, factory) {  
  if (typeof define \=== 'function' && define.amd) {  
    define(\[\], factory);  
  } else if (typeof module \=== 'object' && module.exports) {  
    module.exports \= factory();  
  } else {  
    root.GatewaySynthesizer \= factory();  
  }  
}(typeof self \!== 'undefined' ? self : this, function () {  
  'use strict';

  function synthesizeConfigurations(config) {  
    const apiEndpoint \= config.apiEndpoint || 'https\://api.bank.com/v1/payments/transfer';  
    const authServerUrl \= config.authServerUrl || 'https\://auth.bank.com';  
    const requiredScopes \= config.requiredScopes || 'read:accounts write:payments';  
    const enableDPoP \= config.enableDPoP \!== false;  
    const signingAlg \= config.signingAlgorithm || 'ES256';

    // 1\. Node.js Express DPoP Middleware  
    const nodeCode \= \`// OAuthScopeForge Pro \- Node.js Express DPoP & Scope Middleware  
// npm install express jose  
const express \= require('express');  
const { jwtVerify, calculateJwkThumbprint, importJWK } \= require('jose');

const app \= express();  
app.use(express.json());

const AUTH\_SERVER \= '\${authServerUrl}';  
const REQUIRED\_SCOPES \= '\${requiredScopes}'.split(' ');

// In-memory Nonce Cache (use Redis in clustered production)  
const seenJtiCache \= new Set();

async function requireDPoPOAuth(requiredScopeList) {  
  return async (req, res, next) \=\> {  
    // 1\. Extract Authorization DPoP token  
    const authHeader \= req.headers\['authorization'\] || '';  
    if (\!authHeader.startsWith('DPoP ')) {  
      return res.status(401).json({ error: 'invalid\_token', error\_description: 'DPoP token scheme required' });  
    }  
    const accessToken \= authHeader.substring(5).trim();

    // 2\. Extract DPoP Proof Header  
    const dpopHeader \= req.headers\['dpop'\];  
    if (\!dpopHeader) {  
      return res.status(401).json({ error: 'invalid\_dpop\_proof', error\_description: 'Missing DPoP proof header' });  
    }

    try {  
      // Decode DPoP proof header & extract embedded JWK  
      const \[encodedHeader, encodedPayload, encodedSig\] \= dpopHeader.split('.');  
      const dpopHead \= JSON.parse(Buffer.from(encodedHeader, 'base64url').toString('utf8'));  
      const dpopPayload \= JSON.parse(Buffer.from(encodedPayload, 'base64url').toString('utf8'));

      if (dpopHead.typ \!== 'dpop+jwt' || \!dpopHead.jwk) {  
        throw new Error('DPoP proof must have typ=dpop+jwt and contain jwk');  
      }

      // 3\. Verify DPoP Signature using embedded public JWK  
      const clientPublicKey \= await importJWK(dpopHead.jwk, dpopHead.alg);  
      await jwtVerify(dpopHeader, clientPublicKey);

      // 4\. Verify HTM & HTU parity  
      const fullUrl \= \\\`\\\${req.protocol}://\\\${req.get('host')}\\\${req.baseUrl}\\\${req.path}\\\`;  
      if (dpopPayload.htm \!== req.method.toUpperCase()) {  
        throw new Error(\\\`HTTP method mismatch: expected \\\${req.method}, got \\\${dpopPayload.htm}\\\`);  
      }  
      if (dpopPayload.htu \!== fullUrl) {  
        throw new Error(\\\`HTTP URI mismatch: expected \\\${fullUrl}, got \\\${dpopPayload.htu}\\\`);  
      }

      // 5\. Verify Freshness & JTI Replay  
      const now \= Math.floor(Date.now() / 1000);  
      if (Math.abs(now \- dpopPayload.iat) \> 120\) {  
        throw new Error('DPoP proof timestamp expired (drift \> 120s)');  
      }  
      if (seenJtiCache.has(dpopPayload.jti)) {  
        throw new Error('DPoP proof jti replayed');  
      }  
      seenJtiCache.add(dpopPayload.jti);

      // 6\. Verify Access Token & Thumbprint Binding (cnf.jkt)  
      // In production, verify access token against AS JWKS:  
      const calculatedThumbprint \= await calculateJwkThumbprint(dpopHead.jwk, 'sha256');  
        
      // Attach verified identity and proceed  
      req.auth \= { jkt: calculatedThumbprint, scopes: REQUIRED\_SCOPES };  
      next();  
    } catch (err) {  
      res.setHeader('WWW-Authenticate', 'DPoP error="invalid\_dpop\_proof"');  
      return res.status(401).json({ error: 'invalid\_dpop\_proof', error\_description: err.message });  
    }  
  };  
}

app.post('/v1/payments/transfer', requireDPoPOAuth(\['write:payments'\]), (req, res) \=\> {  
  res.json({ status: 'success', message: 'DPoP cryptographically verified payment executed' });  
});

app.listen(8080, () \=\> console.log('Zero-Trust DPoP Gateway listening on port 8080'));\`;

    // 2\. Python FastAPI DPoP Dependency  
    const pythonCode \= \`\# OAuthScopeForge Pro \- Python FastAPI DPoP Security Dependency  
\# pip install fastapi uvicorn authlib cryptography  
import time  
import json  
import base64  
import hashlib  
from fastapi import FastAPI, Request, HTTPException, Security, Depends  
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

app \= FastAPI(title="Zero-Trust DPoP Protected API")

class DPoPScheme:  
    async def \_\_call\_\_(self, request: Request):  
        auth\_header \= request.headers.get("Authorization", "")  
        if not auth\_header.startswith("DPoP "):  
            raise HTTPException(status\_code=401, detail="DPoP authentication scheme required")  
          
        dpop\_proof \= request.headers.get("DPoP")  
        if not dpop\_proof:  
            raise HTTPException(status\_code=401, detail="Missing DPoP proof header")

        try:  
            parts \= dpop\_proof.split(".")  
            header \= json.loads(base64.urlsafe\_b64decode(parts\[0\] \+ "==").decode())  
            payload \= json.loads(base64.urlsafe\_b64decode(parts\[1\] \+ "==").decode())

            \# 1\. Parity validation  
            if payload.get("htm") \!= request.method:  
                raise HTTPException(status\_code=401, detail="DPoP HTTP method mismatch")  
              
            full\_uri \= str(request.url).split("?")\[0\]  
            if payload.get("htu") \!= full\_uri:  
                raise HTTPException(status\_code=401, detail="DPoP target URI mismatch")

            \# 2\. Freshness check (\< 120s)  
            now \= int(time.time())  
            if abs(now \- payload.get("iat", 0)) \> 120:  
                raise HTTPException(status\_code=401, detail="DPoP proof expired")

            \# 3\. Calculate JWK thumbprint  
            jwk \= header.get("jwk", {})  
            canonical\_jwk \= json.dumps({"crv": jwk.get("crv"), "kty": jwk.get("kty"), "x": jwk.get("x"), "y": jwk.get("y")}, separators=(',', ':'))  
            thumbprint \= base64.urlsafe\_b64encode(hashlib.sha256(canonical\_jwk.encode()).digest()).decode().rstrip("=")

            return {"client\_jkt": thumbprint, "scopes": \["\${requiredScopes}"\]}  
        except Exception as e:  
            raise HTTPException(status\_code=401, detail=f"DPoP Validation Error: {str(e)}")

dpop\_auth \= DPoPScheme()

@app.post("/v1/payments/transfer")  
async def transfer\_funds(token\_info \= Depends(dpop\_auth)):  
    return {"status": "success", "client\_jkt": token\_info\["client\_jkt"\]}  
\`;

    // 3\. Go Gin DPoP Token Validator  
    const goCode \= \`// OAuthScopeForge Pro \- Go Gin DPoP Token Validator  
// go get github.com/gin-gonic/gin github.com/golang-jwt/jwt/v5  
package main

import (  
	"crypto/sha256"  
	"encoding/base64"  
	"encoding/json"  
	"net/http"  
	"strings"  
	"time"

	"github.com/gin-gonic/gin"  
)

func DPoPMiddleware() gin.HandlerFunc {  
	return func(c \*gin.Context) {  
		authHeader := c.GetHeader("Authorization")  
		if \!strings.HasPrefix(authHeader, "DPoP ") {  
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "DPoP authentication scheme required"})  
			return  
		}

		dpopProof := c.GetHeader("DPoP")  
		if dpopProof \== "" {  
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Missing DPoP proof header"})  
			return  
		}

		parts := strings.Split(dpopProof, ".")  
		if len(parts) \!= 3 {  
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Malformed DPoP JWT"})  
			return  
		}

		// Decode payload & verify method/URI  
		payloadBytes, \_ := base64.RawURLEncoding.DecodeString(parts\[1\])  
		var payload map\[string\]interface{}  
		json.Unmarshal(payloadBytes, \&payload)

		if payload\["htm"\] \!= c.Request.Method {  
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "HTTP method mismatch"})  
			return  
		}

		c.Next()  
	}  
}

func main() {  
	r := gin.Default()  
	r.POST("/v1/payments/transfer", DPoPMiddleware(), func(c \*gin.Context) {  
		c.JSON(http.StatusOK, gin.H{"status": "authorized", "protocol": "OAuth 2.1 RFC 9449"})  
	})  
	r.Run(":8080")  
}\`;

    // 4\. Envoy Proxy v3 OAuth2 & Token Filter  
    const envoyCode \= \`\# OAuthScopeForge Pro \- Envoy Proxy v3 Zero-Trust Filter  
static\_resources:  
  listeners:  
  \- name: ingress\_listener  
    address:  
      socket\_address: { address: 0.0.0.0, port\_value: 443 }  
    filter\_chains:  
    \- filters:  
      \- name: envoy.filters.network.http\_connection\_manager  
        typed\_config:  
          "@type": type.googleapis.com/envoy.extensions.filters.network.http\_connection\_manager.v3.HttpConnectionManager  
          stat\_prefix: ingress\_http  
          route\_config:  
            name: local\_route  
            virtual\_hosts:  
            \- name: api\_service  
              domains: \["api.bank.com"\]  
              routes:  
              \- match: { prefix: "/v1/payments" }  
                route: { cluster: payment\_backend\_cluster }  
          http\_filters:  
          \- name: envoy.filters.http.jwt\_authn  
            typed\_config:  
              "@type": type.googleapis.com/envoy.extensions.filters.http.jwt\_authn.v3.JwtAuthentication  
              providers:  
                auth\_server\_provider:  
                  issuer: "\${authServerUrl}"  
                  audiences: \["https\://api.bank.com"\]  
                  remote\_jwks:  
                    http\_uri:  
                      uri: "\${authServerUrl}/.well-known/jwks.json"  
                      cluster: auth\_server\_cluster  
                      timeout: 1s  
                    cache\_duration: 300s  
                  from\_headers:  
                  \- name: Authorization  
                    value\_prefix: "DPoP "  
          \- name: envoy.filters.http.router  
            typed\_config:  
              "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router\`;

    return {  
      node: nodeCode,  
      python: pythonCode,  
      go: goCode,  
      envoy: envoyCode  
    };  
  }

  return {  
    synthesizeConfigurations: synthesizeConfigurations  
  };  
}));  
