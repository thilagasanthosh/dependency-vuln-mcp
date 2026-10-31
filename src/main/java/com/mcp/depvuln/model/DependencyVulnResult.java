package com.mcp.depvuln.model;

import java.util.List;

public record DependencyVulnResult(
        Dependency dependency,
        List<Vulnerability> vulnerabilities
) {
    public boolean hasVulnerabilities() { return !vulnerabilities.isEmpty(); }
}
