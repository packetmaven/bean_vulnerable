package com.beanvulnerable.aeg;

public class PatchReport {
    private final SecurityPatch patch;
    private String vulnerabilityType;
    private String severity;
    private double confidence;
    private String vulnerableCode;
    private String patchedCode;
    private String explanation;
    private String bestPractices;
    private VerificationStatus verificationStatus;
    private boolean layer1Verified;
    private boolean layer2Verified;
    private boolean layer3Verified;

    public PatchReport(SecurityPatch patch) {
        this.patch = patch;
    }

    public SecurityPatch getPatch() {
        return patch;
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

    public double getConfidence() {
        return confidence;
    }

    public void setConfidence(double confidence) {
        this.confidence = confidence;
    }

    public String getVulnerableCode() {
        return vulnerableCode;
    }

    public void setVulnerableCode(String vulnerableCode) {
        this.vulnerableCode = vulnerableCode;
    }

    public String getPatchedCode() {
        return patchedCode;
    }

    public void setPatchedCode(String patchedCode) {
        this.patchedCode = patchedCode;
    }

    public String getExplanation() {
        return explanation;
    }

    public void setExplanation(String explanation) {
        this.explanation = explanation;
    }

    public String getBestPractices() {
        return bestPractices;
    }

    public void setBestPractices(String bestPractices) {
        this.bestPractices = bestPractices;
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
