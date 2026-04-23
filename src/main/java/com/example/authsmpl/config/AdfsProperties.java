package com.example.authsmpl.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Component
@ConfigurationProperties(prefix = "adfs")
public class AdfsProperties {

    private String issuer;
    private String jwksUri;
    private String audience;
    private long jwksRefreshCooldownSeconds = 300;

    public String getIssuer() { return issuer; }
    public void setIssuer(String issuer) { this.issuer = issuer; }

    public String getJwksUri() { return jwksUri; }
    public void setJwksUri(String jwksUri) { this.jwksUri = jwksUri; }

    public String getAudience() { return audience; }
    public void setAudience(String audience) { this.audience = audience; }

    public long getJwksRefreshCooldownSeconds() { return jwksRefreshCooldownSeconds; }
    public void setJwksRefreshCooldownSeconds(long v) { this.jwksRefreshCooldownSeconds = v; }
}
