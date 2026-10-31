package com.mcp.depvuln.model;

public record Dependency(
        String groupId,
        String artifactId,
        String version,
        String scope
) {
    public String osvEcosystem() { return "Maven"; }
    public String osvPackageName() { return groupId + ":" + artifactId; }
    @Override public String toString() { return groupId + ":" + artifactId + ":" + version; }
}
