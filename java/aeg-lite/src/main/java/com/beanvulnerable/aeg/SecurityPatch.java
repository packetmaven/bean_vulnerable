package com.beanvulnerable.aeg;

import com.beanvulnerable.aeg.domain.Vulnerability;

public class SecurityPatch {
    private final Vulnerability vulnerability;
    private final String vulnerableCode;
    private final String patchedCode;
    private final String synthesisMethod;
    private final String templateId;

    private boolean layer1Verified;
    private boolean layer2Verified;
    private boolean layer3Verified;
    private VerificationStatus verificationStatus = VerificationStatus.NOT_VERIFIED;

    public SecurityPatch(Vulnerability vulnerability, String vulnerableCode,
                         String patchedCode, String synthesisMethod,
                         String templateId) {
        this.vulnerability = vulnerability;
        this.vulnerableCode = vulnerableCode;
        this.patchedCode = patchedCode;
        this.synthesisMethod = synthesisMethod;
        this.templateId = templateId;
    }

    public Vulnerability getVulnerability() {
        return vulnerability;
    }

    public String getVulnerableCode() {
        return vulnerableCode;
    }

    public String getPatchedCode() {
        return patchedCode;
    }

    public String getSynthesisMethod() {
        return synthesisMethod;
    }

    public String getTemplateId() {
        return templateId;
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
}
