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

## Recon CLI (`recon.py`)

`recon.py` is a didactic, single-command orchestrator. It accepts one domain or a
domain list and runs the most relevant stages, reusing the scripts in
`workflows/*/src` as building blocks.

```bash
chmod +x recon.py

# one domain
./recon.py -d example.com

# several domains and a deeper preset
./recon.py -d example.com -d example.com.br --preset deep --screenshots both

# scope from a file, bounded content enumeration
./recon.py -dL scope.txt -n client --max-hosts 50 --stages subdomains,probe,content,javascript

# passive, no brute force
./recon.py -d example.com --passive

# what is available in this environment?
./recon.py --check -d example.com

# what does each stage do?
./recon.py --explain
```

Stages: `subdomains`, `asn`, `dns`, `infra`, `probe`, `content`, `javascript`,
`fuzz`, `vulns`. Presets: `passive`, `web` (default), `deep`, `full`,
`subdomains`.

Useful options:

| Option | Purpose |
|---|---|
| `-d/--domain`, `-dL/--domains-file` | target domain(s) |
| `--stages`, `--preset`, `--exclude-stage` | pipeline selection |
| `--passive`, `--no-bruteforce` | avoid active enumeration |
| `--scope`, `--exclude`, `--no-scope-filter` | scope control |
| `--max-hosts` | cap hosts used by content/JS/fuzzing |
| `--threads`, `--timeout`, `--retries` | httpx tuning |
| `-H/--header`, `--cookie`, `--user-agent` | authenticated probes |
| `--screenshots`, `--js-download`, `--js-nuclei` | content/JS options |
| `--ports`, `--top-ports`, `--rate-limit` | port scanning |
| `--wordlist-subdomains`, `--wordlist-dirs`, `--resolvers` | wordlists/resolvers |
| `--gf-patterns`, `--dalfox` | vulnerability triage |
| `--resume`, `--dry-run`, `--check` | operational control |

Each target is written to `<output>/<target>/` with subdomains, DNS, IPs,
URLs, JavaScript, fuzzing and vulnerability buckets. The run always ends with:

- `_recon/summary.md` — funnel counts, technologies, status codes, interesting
  subdomains, open ports, gf classes, DNS/SPF issues and next steps.
- `_recon/summary.json` — the same data in machine-readable form.
- `_recon/inventory.jsonl` — httpx fingerprint records.
- `_recon/recon.log` — every command and its output.

<br>

## Repository Structure

- `recon.py`: didactic CLI orchestrator (domain or domain-list input)
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

