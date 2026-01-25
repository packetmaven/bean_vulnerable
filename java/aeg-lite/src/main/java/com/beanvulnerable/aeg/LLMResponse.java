package com.beanvulnerable.aeg;

public class LLMResponse {
    private final boolean successful;
    private final String content;

    public LLMResponse(boolean successful, String content) {
        this.successful = successful;
        this.content = content;
    }

    public boolean isSuccessful() {
        return successful;
    }

    public String getContent() {
        return content;
    }
}
