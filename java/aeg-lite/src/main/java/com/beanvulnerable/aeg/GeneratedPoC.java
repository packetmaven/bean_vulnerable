package com.beanvulnerable.aeg;

import com.beanvulnerable.aeg.domain.Vulnerability;

public class GeneratedPoC {
    private final String pocId;
    private final Vulnerability vulnerability;
    private final String pocCode;
    private final String vulnerabilityType;

    private boolean layer1Verified;
    private boolean layer2Verified;
    private boolean layer3Verified;
    private VerificationStatus verificationStatus = VerificationStatus.NOT_VERIFIED;
    private String verificationError;

    public GeneratedPoC(String pocId, Vulnerability vulnerability,
                        String pocCode, String vulnerabilityType) {
        this.pocId = pocId;
        this.vulnerability = vulnerability;
        this.pocCode = pocCode;
        this.vulnerabilityType = vulnerabilityType;
    }

    public String getPocId() {
        return pocId;
    }

    public Vulnerability getVulnerability() {
        return vulnerability;
    }

    public String getPocCode() {
        return pocCode;
    }

    public String getVulnerabilityType() {
        return vulnerabilityType;
    }

    public boolean isLayer1Verified() {
        return layer1Verified;
    }

    public void setLayer1Verified(boolean layer1Verified) {
        this.layer1Verified = layer1Verified;
    }

    public boolean isLayer2Verified() {
        return layer2Verified;
    }

    public void setLayer2Verified(boolean layer2Verified) {
        this.layer2Verified = layer2Verified;
    }

    public boolean isLayer3Verified() {
        return layer3Verified;
    }

    public void setLayer3Verified(boolean layer3Verified) {
        this.layer3Verified = layer3Verified;
    }

    public VerificationStatus getVerificationStatus() {
        return verificationStatus;
    }

    public void setVerificationStatus(VerificationStatus verificationStatus) {
        this.verificationStatus = verificationStatus;
    }

    public String getVerificationError() {
        return verificationError;
    }

    public void setVerificationError(String verificationError) {
        this.verificationError = verificationError;
    }
}
