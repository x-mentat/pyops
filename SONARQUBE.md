# Local SonarQube Security Check Setup

## Quick Start

1. **Start SonarQube and run security scan:**
   ```bash
   docker-compose up
   ```

2. **Access SonarQube Dashboard:**
   - Open browser: `http://localhost:9000`
   - Default credentials: `admin` / `admin`

3. **View Results:**
   - Navigate to Projects → icinga2-checks
   - Review Security Hotspots, Vulnerabilities, and Code Quality issues

## Manual Scan (without docker-compose)

If you prefer to run the scanner separately:

```bash
# Start SonarQube only
docker-compose up sonarqube

# In another terminal, run scanner
docker run --rm -v $(pwd):/usr/src --network icinga2_sonarnet \
  sonarsource/sonar-scanner-cli:latest \
  sonar-scanner \
  -Dsonar.projectKey=icinga2-checks \
  -Dsonar.sources=/usr/src \
  -Dsonar.host.url=http://sonarqube:9000 \
  -Dsonar.login=admin
```

## Configuration Files

- **docker-compose.yml** - Orchestrates SonarQube + Scanner containers
- **sonar-project.properties** - Project scanning configuration
  - Includes Python files: `check_synology.py`, `check_fujitsu.py`, `app.py`
  - Excludes virtual environments and templates
  - Enables security hotspot detection

## Security Scanning Includes

- **Vulnerabilities** - Known security issues
- **Hotspots** - Code requiring security review
- **Code Smells** - Quality and maintainability issues
- **Bugs** - Potential runtime errors

## Stop Services

```bash
docker-compose down
```

## Clean Up (Remove Volumes)

```bash
docker-compose down -v
```

## Troubleshooting

- **Port 9000 already in use:** Change `ports: - "9000:9000"` in docker-compose.yml
- **Scanner can't connect:** Ensure `sonarqube` service is healthy before scanner starts
- **No results:** Check `sonar-project.properties` paths match your actual files
