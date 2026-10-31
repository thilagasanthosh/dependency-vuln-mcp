package com.mcp.depvuln.client;

import com.mcp.depvuln.model.Dependency;
import com.mcp.depvuln.model.Vulnerability;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;

import java.util.*;

/**
 * Calls the free OSV.dev batch API to check Maven dependencies for known CVEs.
 * No API key required. https://google.github.io/osv.dev/post-v1-querybatch/
 */
@Component
public class OsvClient {

    private static final Logger log = LoggerFactory.getLogger(OsvClient.class);
    private static final int BATCH_SIZE = 1000;

    private final RestClient restClient;

    public OsvClient(@Value("${osv.api.base-url}") String baseUrl) {
        this.restClient = RestClient.builder()
                .baseUrl(baseUrl)
                .defaultHeader("Content-Type", "application/json")
                .build();
    }

    public Map<Dependency, List<Vulnerability>> batchCheck(List<Dependency> dependencies) {
        Map<Dependency, List<Vulnerability>> results = new LinkedHashMap<>();
        for (int i = 0; i < dependencies.size(); i += BATCH_SIZE) {
            List<Dependency> batch = dependencies.subList(i, Math.min(i + BATCH_SIZE, dependencies.size()));
            results.putAll(checkBatch(batch));
        }
        return results;
    }

    @SuppressWarnings("unchecked")
    private Map<Dependency, List<Vulnerability>> checkBatch(List<Dependency> deps) {
        List<Map<String, Object>> queries = deps.stream()
                .map(dep -> Map.<String, Object>of(
                        "package", Map.of("name", dep.osvPackageName(), "ecosystem", dep.osvEcosystem()),
                        "version", dep.version() != null ? dep.version() : ""))
                .toList();

        Map<String, Object> requestBody = Map.of("queries", queries);

        Map<String, Object> response;
        try {
            response = restClient.post()
                    .uri("/querybatch")
                    .body(requestBody)
                    .retrieve()
                    .body(Map.class);
        } catch (Exception e) {
            log.error("OSV batch query failed: {}", e.getMessage());
            Map<Dependency, List<Vulnerability>> empty = new LinkedHashMap<>();
            deps.forEach(d -> empty.put(d, List.of()));
            return empty;
        }

        Map<Dependency, List<Vulnerability>> results = new LinkedHashMap<>();
        List<Map<String, Object>> resultList = (List<Map<String, Object>>) response.getOrDefault("results", List.of());

        for (int i = 0; i < deps.size(); i++) {
            Dependency dep = deps.get(i);
            List<Vulnerability> vulns = new ArrayList<>();
            if (i < resultList.size()) {
                Map<String, Object> result = resultList.get(i);
                List<Map<String, Object>> osvs = (List<Map<String, Object>>) result.getOrDefault("vulns", List.of());
                for (Map<String, Object> osv : osvs) vulns.add(parseVulnerability(osv));
            }
            results.put(dep, vulns);
        }
        return results;
    }

    @SuppressWarnings("unchecked")
    private Vulnerability parseVulnerability(Map<String, Object> osv) {
        String id = (String) osv.getOrDefault("id", "UNKNOWN");
        String summary = (String) osv.getOrDefault("summary", "No summary available");

        String severity = "UNKNOWN";
        double cvssScore = 0.0;

        List<Map<String, Object>> severities = (List<Map<String, Object>>) osv.getOrDefault("severity", List.of());
        for (Map<String, Object> s : severities) {
            String type = (String) s.getOrDefault("type", "");
            if (type.startsWith("CVSS")) {
                severity = "UNKNOWN";
                break;
            }
        }

        Map<String, Object> dbSpecific = (Map<String, Object>) osv.getOrDefault("database_specific", Map.of());
        String dbSev = (String) dbSpecific.getOrDefault("severity", "");
        if (!dbSev.isEmpty()) severity = dbSev.toUpperCase();

        String fixedVersion = extractFixedVersion(osv);
        List<String> aliases = (List<String>) osv.getOrDefault("aliases", List.of());
        String osvUrl = "https://osv.dev/vulnerability/" + id;

        return new Vulnerability(id, summary, severity, cvssScore, fixedVersion, aliases, osvUrl);
    }

    @SuppressWarnings("unchecked")
    private String extractFixedVersion(Map<String, Object> osv) {
        List<Map<String, Object>> affected = (List<Map<String, Object>>) osv.getOrDefault("affected", List.of());
        for (Map<String, Object> aff : affected) {
            List<Map<String, Object>> ranges = (List<Map<String, Object>>) aff.getOrDefault("ranges", List.of());
            for (Map<String, Object> range : ranges) {
                String type = (String) range.getOrDefault("type", "");
                if ("ECOSYSTEM".equals(type) || "SEMVER".equals(type)) {
                    List<Map<String, Object>> events = (List<Map<String, Object>>) range.getOrDefault("events", List.of());
                    for (Map<String, Object> event : events) {
                        if (event.containsKey("fixed")) return (String) event.get("fixed");
                    }
                }
            }
        }
        return null;
    }
}
