package com.mcp.depvuln.model;

import java.util.List;

public record ScanReport(
        String pomFile,
        int totalDependencies,
        int vulnerableDependencies,
        int criticalCount,
        int highCount,
        int mediumCount,
        int lowCount,
        List<DependencyVulnResult> findings,
        List<String> skipped
) {
    public boolean isClean() { return vulnerableDependencies == 0; }

    public String summary() {
        if (isClean()) return "✅ No vulnerabilities found in " + totalDependencies + " dependencies.";
        return String.format(
            "🚨 %d vulnerable dependencies (%d critical, %d high, %d medium, %d low) out of %d total.",
            vulnerableDependencies, criticalCount, highCount, mediumCount, lowCount, totalDependencies);
    }
}
