# Rotz

![Rotz](./img/rayders.png)

> **Rotz** is a modular recon and vulnerability automation framework that chains subdomain discovery, DNS analysis, live probing, content enumeration, JavaScript analysis, fuzzing, and vulnerability filtering into a reproducible workflow.

<br>

## Features

- **Multi-Source Subdomain Enumeration:** Subfinder, Chaos, GitHub, PureDNS
- **DNS Intelligence:** DNSX records, TXT/SPF checks, CNAME discovery, reverse DNS
- **Live Host Probing:** httpx-based resolution and live endpoints
- **Content Enumeration:** gau, katana, paramspider, arjun, uro, unfurl
- **JavaScript Analysis:** subjs, LinkFinder, JSScanner, nuclei JS checks
- **Fuzzing:** Gobuster directory fuzzing + VHOST fuzzing workflows
- **Vulnerability Filtering:** gf patterns, Dalfox discovery
- **Docker Support:** consistent environment with Ansible-based provisioning

<br>

## Repository Structure

- `workflows/`: task pipelines (subdomains, dns, content, javascript, fuzzing, vulns)
- `config/`: tool configs (subfinder, puredns, notify, gf patterns)
- `input/`: target scope inputs
- `output/`: generated results
- `wordlists/`: wordlists for enumeration/fuzzing

<br>

## Dependencies

The environment is provisioned via playbook.yml (Ansible). It installs:

- Go-based tools: subfinder, chaos, httpx, dnsx, nuclei, gau, katana, puredns, notify, and others
- Python tools: arjun, shodan, uro, LinkFinder, JSScanner, ParamSpider
- Node.js + js-beautify
- System utilities: jq, curl, git, etc.

<br>

## Configuration Files

Required configuration files:

- config/notify/provider-config.yaml
- config/puredns/resolvers.txt
- config/subfinder/provider-config.yaml

GF patterns are expected in `./gf` (mounted into the container).

<br>

## Environment Variables (.env)

Create a .env file in the project root:

```
PDCP_API_KEY=token
GITHUB_TOKEN=gtoken
SHODAN_API_KEY=token
```

<br>

## Docker Usage

### Build and Run (Test Environment)

```bash
export DOCKER_API_VERSION=1.41
docker compose -f docker-compose.test.yml build --progress=plain
```

Run an interactive container:

```bash
docker run -it \
	--env-file .env \
	-v $(pwd)/input:/app/input \
	-v $(pwd)/workflows:/app/workflows \
	-v $(pwd)/wordlists:/app/wordlists \
	-v $(pwd)/output:/app/output \
    -v $(pwd)/gf:/app/gf \
	-v $(pwd)/scripts:/app/scripts \
	raydersonthestorm-test-environment bash
```

Clean Docker cache and volumes:

```bash
sudo docker system prune -a --volumes
```

<br>

## Docker Compose Usage

Standard compose run:

```bash
docker compose up
```

Test compose run:

```bash
docker compose -f docker-compose.test.yml up
```

<br>


## Disclaimer

This project is intended for authorized security testing only. Always obtain explicit permission before scanning any target.

