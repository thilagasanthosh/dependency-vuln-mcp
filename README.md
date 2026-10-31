# Dependency Vulnerability MCP Server (Spring Boot + Spring AI)

A local MCP server that lets Claude scan your Maven `pom.xml` for known CVE vulnerabilities.
**No API key. No account. No cost.** Backed by the free [OSV.dev](https://osv.dev) database.

## Tools exposed to Claude

| Tool | What it does |
|---|---|
| `scanPomFile(pomPath)` | Scan a pom.xml — checks deps with explicit versions against OSV.dev |
| `getVulnDetails(vulnId)` | Full advisory for one CVE or GHSA ID |
| `suggestFix(groupId, artifactId, currentVersion, fixedVersion)` | Ready-to-paste pom.xml snippet |

---

## ⚠️ pom.xml alone vs. full dependency tree — read this first

### What `scanPomFile` checks
It reads your `pom.xml` and checks every dependency that has an **explicit version** written in the file.

### What it misses
Most Spring Boot projects use the **Spring Boot BOM (Bill of Materials)** — the `<parent>` block sets versions for dozens of libraries (Tomcat, Jackson, Netty, Logback…) so you don't write them yourself. Those libraries have **no version in your pom.xml**, so the scanner cannot check them from the file alone.

**Example:** if your pom.xml has:
```xml
<parent>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-parent</artifactId>
    <version>3.2.5</version>   <!-- ← this controls ~60 library versions -->
</parent>

<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-web</artifactId>
    <!-- no <version> here — controlled by the BOM above -->
</dependency>
```
The scanner will skip `spring-boot-starter-web` because there is no version to check.

### For a complete scan — run `dependency:list` first

```bash
# Run once in your project terminal:
./mvnw dependency:list -DoutputFile=/tmp/deps.txt -DincludeScope=runtime -q
cat /tmp/deps.txt
```

Then paste the output into Claude. Claude will use `scanPomFile` for any dep with an explicit version, and use the resolved list for the rest. This gives you full coverage including transitives.

### Quick guide: which approach to use?

| Your pom.xml style | Best approach |
|---|---|
| All deps have explicit `<version>` tags | `scanPomFile` alone is enough |
| Uses Spring Boot parent / BOM (most projects) | Run `dependency:list` + paste output |
| Want 100% coverage including transitives | Run OWASP plugin (see below) |

---

## Example conversation with Claude

**Basic scan (explicit versions only):**
```
You: Scan /path/to/your/project/pom.xml for vulnerabilities
Claude: Checked 5 explicitly versioned deps. 1 vulnerable found.
        ⚠️ jackson-databind 2.14.0 — CVE-2023-35116 · Fix: 2.14.2
        Note: 7 BOM-managed deps were skipped — run dependency:list for full coverage.
```

**Full scan (after running dependency:list):**
```
You: Here is my full dependency list: [paste output]
     Now check for CVEs.
Claude: Checked all 34 resolved dependencies including transitives.
        🚨 spring-web 6.0.0 — CVE-2023-20860 (Critical) · Fix: 6.0.7
        ⚠️  jackson-databind 2.14.0 — CVE-2023-35116 (High) · Fix: 2.14.2
```

**Get the fix:**
```
You: Give me the pom.xml snippet to fix spring-web
Claude: <dependency>
            <groupId>org.springframework</groupId>
            <artifactId>spring-web</artifactId>
            <version>6.0.7</version>  <!-- was: 6.0.0 -->
        </dependency>
```

---

## Alternative: OWASP dependency-check (gold standard)

For a full automated scan including all transitives, run the OWASP Maven plugin directly.
No MCP needed — it produces an HTML report:

```bash
./mvnw org.owasp:dependency-check-maven:check
# Report at: target/dependency-check-report.html
open target/dependency-check-report.html
```

This tool is complementary to (not a replacement for) this MCP.

---

## Stack

- Java 21, Spring Boot 3.5, Spring AI 1.1 (`spring-ai-starter-mcp-server-webmvc`)
- Apache Maven Model for pom.xml parsing
- [OSV.dev batch API](https://google.github.io/osv.dev/post-v1-querybatch/) — free, no auth

## Build

```bash
mvn clean package -DskipTests
# → target/dependency-vuln-mcp-1.0.0.jar
```

## Connect to Claude Desktop

Open `~/Library/Application Support/Claude/claude_desktop_config.json` and add:

```json
{
  "mcpServers": {
    "dep-vuln": {
      "command": "/path/to/java21/bin/java",
      "args": [
        "-jar",
        "/path/to/dependency-vuln-mcp/target/dependency-vuln-mcp-1.0.0.jar",
        "--spring.profiles.active=stdio"
      ]
    }
  }
}
```

Find your Java 21 path and replace the placeholders above:
```bash
# macOS — prints your Java 21 home, e.g. /Library/Java/JavaVirtualMachines/temurin-21.jdk/Contents/Home
/usr/libexec/java_home -v 21

# Linux
dirname $(dirname $(readlink -f $(which java)))
```
Set `"command"` to that path + `/bin/java`, and set the jar `"args"` path to wherever you cloned this repo.

Quit Claude Desktop (⌘Q) and reopen. `dep-vuln` will appear in Settings → Developer.

## Connect to Claude Code (HTTP)

```bash
mvn spring-boot:run          # terminal 1 — start server
claude mcp add --transport http dep-vuln http://localhost:8080/mcp   # terminal 2
claude                        # ask: "scan my pom.xml for CVEs"
```

## Roadmap

- [ ] `resolveDependencyTree` tool — runs `mvn dependency:list` as a subprocess so Claude gets full transitive versions automatically (no manual paste needed)
- [ ] Spring Boot BOM upgrade advisor (one parent version bump closes N CVEs)
- [ ] CycloneDX / SPDX SBOM export
- [ ] Multi-module Maven project support
- [ ] AWS ECS Express deployment for team use
