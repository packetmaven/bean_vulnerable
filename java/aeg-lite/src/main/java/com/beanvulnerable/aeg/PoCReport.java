package com.beanvulnerable.aeg;

public class PoCReport {
    private final GeneratedPoC poc;
    private String vulnerabilityType;
    private String severity;
    private String impact;
    private String mitigation;
    private String poCCode;
    private VerificationStatus verificationStatus;
    private boolean layer1Verified;
    private boolean layer2Verified;
    private boolean layer3Verified;

    public PoCReport(GeneratedPoC poc) {
        this.poc = poc;
    }

    public GeneratedPoC getPoc() {
        return poc;
    }

    public String getVulnerabilityType() {
        return vulnerabilityType;
    }

    public void setVulnerabilityType(String vulnerabilityType) {
        this.vulnerabilityType = vulnerabilityType;
    }

    public String getSeverity() {
        return severity;
    }

    public void setSeverity(String severity) {
        this.severity = severity;
    }

    public String getImpact() {
        return impact;
    }

    public void setImpact(String impact) {
        this.impact = impact;
    }

    public String getMitigation() {
        return mitigation;
    }

    public void setMitigation(String mitigation) {
        this.mitigation = mitigation;
    }

    public String getPoCCode() {
        return poCCode;
    }

    public void setPoCCode(String poCCode) {
        this.poCCode = poCCode;
    }

    public VerificationStatus getVerificationStatus() {
        return verificationStatus;
    }

    public void setVerificationStatus(VerificationStatus verificationStatus) {
        this.verificationStatus = verificationStatus;
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
}
