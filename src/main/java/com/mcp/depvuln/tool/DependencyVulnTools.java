package com.mcp.depvuln.tool;

import com.mcp.depvuln.client.OsvClient;
import com.mcp.depvuln.client.PomParser;
import com.mcp.depvuln.model.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.ai.tool.annotation.Tool;
import org.springframework.ai.tool.annotation.ToolParam;
import org.springframework.stereotype.Component;

import java.util.*;

/**
 * MCP tools exposed to Claude:
 *  1. scanPomFile     — scan a pom.xml for CVEs
 *  2. getVulnDetails  — details for one CVE/GHSA ID
 *  3. suggestFix      — min safe version + pom.xml snippet
 */
@Component
public class DependencyVulnTools {

    private static final Logger log = LoggerFactory.getLogger(DependencyVulnTools.class);

    private final PomParser pomParser;
    private final OsvClient osvClient;

    public DependencyVulnTools(PomParser pomParser, OsvClient osvClient) {
        this.pomParser = pomParser;
        this.osvClient = osvClient;
    }

    @Tool(description = """
            Scan a Maven pom.xml file for known CVE vulnerabilities using the free OSV.dev database.
            Provide the absolute path to the pom.xml file.
            Returns severity counts and details for each vulnerable dependency including fix versions.
            """)
    public ScanReport scanPomFile(
            @ToolParam(description = "Absolute path to the pom.xml file, e.g. /Users/thilaga/myproject/pom.xml")
            String pomPath) {

        log.info("Scanning pom.xml: {}", pomPath);
        PomParser.ParseResult parsed;
        try {
            parsed = pomParser.parse(pomPath);
        } catch (Exception e) {
            log.error("Failed to parse pom.xml: {}", e.getMessage());
            return new ScanReport(pomPath, 0, 0, 0, 0, 0, 0,
                    List.of(), List.of("ERROR parsing pom.xml: " + e.getMessage()));
        }

        List<Dependency> deps = parsed.dependencies();
        List<String> skipped = parsed.skipped();

        if (deps.isEmpty()) return new ScanReport(pomPath, 0, 0, 0, 0, 0, 0, List.of(), skipped);

        Map<Dependency, List<Vulnerability>> osvResults = osvClient.batchCheck(deps);

        List<DependencyVulnResult> findings = new ArrayList<>();
        int critical = 0, high = 0, medium = 0, low = 0;

        for (Map.Entry<Dependency, List<Vulnerability>> entry : osvResults.entrySet()) {
            if (!entry.getValue().isEmpty()) {
                findings.add(new DependencyVulnResult(entry.getKey(), entry.getValue()));
                for (Vulnerability v : entry.getValue()) {
                    switch (v.severity().toUpperCase()) {
                        case "CRITICAL" -> critical++;
                        case "HIGH"     -> high++;
                        case "MEDIUM"   -> medium++;
                        case "LOW"      -> low++;
                    }
                }
            }
        }

        findings.sort(Comparator.comparingInt(r ->
                -r.vulnerabilities().stream()
                        .mapToInt(v -> severityOrder(v.severity()))
                        .max().orElse(0)));

        return new ScanReport(pomPath, deps.size(), findings.size(),
                critical, high, medium, low, findings, skipped);
    }

    @Tool(description = """
            Get details for a specific vulnerability by ID (CVE-xxxx or GHSA-xxxx-xxxx-xxxx).
            Returns a link to the full OSV advisory.
            """)
    public VulnDetail getVulnDetails(
            @ToolParam(description = "Vulnerability ID, e.g. CVE-2023-20860 or GHSA-xxxx-xxxx-xxxx")
            String vulnId) {

        String url = "https://osv.dev/vulnerability/" + vulnId;
        return new VulnDetail(vulnId,
                "Visit " + url + " for full advisory details, affected ranges, and patch notes.", url);
    }

    @Tool(description = """
            Given a vulnerable dependency, return the corrected pom.xml XML snippet
            with the minimum safe version to fix the CVE.
            """)
    public FixSuggestion suggestFix(
            @ToolParam(description = "Maven groupId, e.g. org.springframework") String groupId,
            @ToolParam(description = "Maven artifactId, e.g. spring-web") String artifactId,
            @ToolParam(description = "Current version in pom.xml, e.g. 6.0.0") String currentVersion,
            @ToolParam(description = "Fixed version from scanPomFile, e.g. 6.0.7") String fixedVersion) {

        if (fixedVersion == null || fixedVersion.isBlank()) {
            return new FixSuggestion(groupId, artifactId, currentVersion, null,
                    "No fix version available yet for " + groupId + ":" + artifactId +
                    ". Monitor https://osv.dev for updates.", null);
        }

        String snippet = String.format("""
                <dependency>
                    <groupId>%s</groupId>
                    <artifactId>%s</artifactId>
                    <version>%s</version>  <!-- was: %s — upgraded to fix CVE -->
                </dependency>""", groupId, artifactId, fixedVersion, currentVersion);

        String advice = String.format(
                "Upgrade %s:%s from %s → %s. Run `mvn clean verify` to confirm.",
                groupId, artifactId, currentVersion, fixedVersion);

        return new FixSuggestion(groupId, artifactId, currentVersion, fixedVersion, advice, snippet);
    }

    public record VulnDetail(String id, String description, String url) {}

    public record FixSuggestion(
            String groupId, String artifactId,
            String currentVersion, String fixedVersion,
            String advice, String pomSnippet) {}

    private int severityOrder(String severity) {
        return switch (severity.toUpperCase()) {
            case "CRITICAL" -> 4;
            case "HIGH"     -> 3;
            case "MEDIUM"   -> 2;
            case "LOW"      -> 1;
            default         -> 0;
        };
    }
}
