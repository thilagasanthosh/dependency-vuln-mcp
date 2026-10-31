package com.mcp.depvuln.client;

import com.mcp.depvuln.model.Dependency;
import org.apache.maven.model.Model;
import org.apache.maven.model.io.xpp3.MavenXpp3Reader;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.io.FileReader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;

/**
 * Parses a Maven pom.xml into a list of Dependency objects.
 * Resolves property placeholders like ${spring.version}.
 * BOM-managed deps with no explicit version are reported as skipped.
 */
@Component
public class PomParser {

    private static final Logger log = LoggerFactory.getLogger(PomParser.class);

    public ParseResult parse(String pomPath) throws Exception {
        Path path = Path.of(pomPath);
        if (!Files.exists(path)) {
            throw new IllegalArgumentException("pom.xml not found at: " + pomPath);
        }

        MavenXpp3Reader reader = new MavenXpp3Reader();
        Model model;
        try (FileReader fr = new FileReader(path.toFile())) {
            model = reader.read(fr);
        }

        Properties props = model.getProperties();
        if (model.getParent() != null) props.setProperty("project.parent.version", model.getParent().getVersion());
        if (model.getVersion() != null) props.setProperty("project.version", model.getVersion());

        List<Dependency> resolved = new ArrayList<>();
        List<String> skipped = new ArrayList<>();

        for (org.apache.maven.model.Dependency dep : model.getDependencies()) {
            String groupId    = resolve(dep.getGroupId(), props);
            String artifactId = resolve(dep.getArtifactId(), props);
            String version    = dep.getVersion() != null ? resolve(dep.getVersion(), props) : null;
            String scope      = dep.getScope() != null ? dep.getScope() : "compile";

            if (version == null || version.startsWith("${")) {
                skipped.add(groupId + ":" + artifactId + " (BOM-managed, version not resolved)");
            } else {
                resolved.add(new Dependency(groupId, artifactId, version, scope));
            }
        }

        if (model.getDependencyManagement() != null) {
            for (org.apache.maven.model.Dependency dep : model.getDependencyManagement().getDependencies()) {
                String groupId    = resolve(dep.getGroupId(), props);
                String artifactId = resolve(dep.getArtifactId(), props);
                String version    = dep.getVersion() != null ? resolve(dep.getVersion(), props) : null;
                String scope      = dep.getScope() != null ? dep.getScope() : "compile";

                if (version != null && !version.startsWith("${")) {
                    boolean alreadyAdded = resolved.stream()
                            .anyMatch(d -> d.groupId().equals(groupId) && d.artifactId().equals(artifactId));
                    if (!alreadyAdded) {
                        resolved.add(new Dependency(groupId, artifactId, version, scope));
                    }
                }
            }
        }

        log.info("Parsed pom.xml: {} resolved, {} skipped", resolved.size(), skipped.size());
        return new ParseResult(resolved, skipped);
    }

    private String resolve(String value, Properties props) {
        if (value == null) return null;
        if (!value.startsWith("${")) return value;
        String key = value.substring(2, value.length() - 1);
        return props.getProperty(key, value);
    }

    public record ParseResult(List<Dependency> dependencies, List<String> skipped) {}
}
