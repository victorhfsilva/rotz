"""Gera um workflow Rayder a partir de respostas interativas.

Para o orquestrador didatico por dominio/lista, use ../recon.py.
"""

import os
import sys
import json
import argparse
import yaml

def get_input(prompt, default):
    user_input = input(f"{prompt} [{default}]: ").strip()
    return user_input if user_input else default

def str_to_bool(value):
    if isinstance(value, bool):
        return value
    return str(value).lower() in ("true", "1", "yes", "y", "t")

def generate_vars(args_map):
    root = os.path.abspath(args_map['ROOT'])
    target = args_map['TARGET']
    org = args_map['ORGANIZATION']
    
    vars_config = {
        "ROOT": root,
        "TARGET": target,
        "INPUT_ORGANIZATION": org,
        "INPUT_DOMAINS": f"{root}/input/{target}/domains.txt",
        "INPUT_IPS": f"{root}/input/{target}/ips.txt",

        "SUBDOMAIN_OUTPUT_PATH": f"{root}/output/{target}/subs",
        "SUBDOMAIN_OUTPUT_FILE": f"{root}/output/{target}/subs/all.subs.txt",
        "LIVE_SUBDOOMAINS_FILE": f"{root}/output/{target}/subs/all.live.subs.txt",
        "SUBDOMAIN_WORDLIST": f"{root}/wordlists/subdomains/subdomains-top1million-5000.txt",
        "SUBDOMAIN_SCRIPTS_FOLDER": f"{root}/workflows/subdomains/src",
        "SUBDOMAIN_WORKFLOWS_FOLDER": f"{root}/workflows/subdomains",
        
        "ORGANIZATION_SCRIPTS_FOLDER": f"{root}/workflows/organization/src",
        "ORGANIZATION_WORKFLOWS_FOLDER": f"{root}/workflows/organization",

        "IPS_OUTPUT_PATH": f"{root}/output/{target}/ips",
        "IPS_OUTPUT_FILE": f"{root}/output/{target}/ips/all.ips.txt",
        "INFRASTRUCTURE_SCRIPTS_FOLDER": f"{root}/workflows/infrastructure/src",
        "INFRASTRUCTURE_WORKFLOWS_FOLDER": f"{root}/workflows/infrastructure",
        
        "DNS_OUTPUT_PATH": f"{root}/output/{target}/dns",
        "DNS_SCRIPTS_FOLDER": f"{root}/workflows/dns/src",
        "DNS_WORKFLOWS_FOLDER": f"{root}/workflows/dns",

        "SUBDOMAIN_RESOLUTION_SCRIPTS_FOLDER": f"{root}/workflows/probing/src",
        "SUBDOMAIN_RESOLUTION_WORKFLOWS_FOLDER": f"{root}/workflows/probing",

        "CONTENT_OUTPUT_PATH": f"{root}/output/{target}/content",
        "CONTENT_SCRIPTS_FOLDER": f"{root}/workflows/content/src",
        "CONTENT_WORKFLOWS_FOLDER": f"{root}/workflows/content",
        "ALL_URLS_FILE": f"{root}/output/{target}/content/urls/all.urls.txt",
        "CLEANED_URLS_FILE": f"{root}/output/{target}/content/urls/all.cleaned.urls.txt",
        "GAU_URLS_FILE": f"{root}/output/{target}/content/urls/all.gau.urls.txt",
        "KATANA_URLS_FILE": f"{root}/output/{target}/content/urls/all.katana.urls.txt",
        "PARAMS_URLS_FILE": f"{root}/output/{target}/content/urls/all.params.urls.txt",

        "JS_OUTPUT_PATH": f"{root}/output/{target}/content/javascript",
        "JS_URLS_FILE": f"{root}/output/{target}/content/urls/all.js.urls.txt",
        "SELECTED_JS_FILES": f"{root}/output/{target}/content/javascript/all.javascript.txt",
        "JS_DOWNLOAD_FOLDER": f"{root}/output/{target}/content/javascript/downloads",
        "JS_SCRIPTS_FOLDER": f"{root}/workflows/javascript/src",
        "JS_WORKFLOWS_FOLDER": f"{root}/workflows/javascript",
        "JS_REGEX_FILE": "/opt/JSScanner/Regex.txt",

        "FUZZING_OUTPUT_PATH": f"{root}/output/{target}/content/fuzzing",
        "GIT_OUTPUT_PATH": f"{root}/output/{target}/content/fuzzing/git",
        "CEWL_OUTPUT_PATH": f"{root}/output/{target}/content/wordlists/cewl",
        "WORDLISTS_OUTPUT_PATH": f"{root}/output/{target}/content/wordlists",
        "DIRECTORY_WORDLIST": f"{root}/wordlists/directories/fuzz-Bo0oM.txt",
        "PATH_WORDLIST": f"{root}/output/{target}/content/wordlists/all.paths.txt",
        "WORDS_WORDLIST": f"{root}/output/{target}/content/wordlists/all.words.txt",
        "FUZZING_SCRIPTS_FOLDER": f"{root}/workflows/fuzzing/src",
        "FUZZING_WORKFLOWS_FOLDER": f"{root}/workflows/fuzzing",

        "VULNERABILITY_OUTPUT_PATH": f"{root}/output/{target}/content/vuln",
        "VULNERABILITY_SCRIPTS_FOLDER": f"{root}/workflows/vulns/src",
        "VULNERABILITY_WORKFLOWS_FOLDER": f"{root}/workflows/vulns",
    }

    bool_keys = [
        "SUBDOMAIN_NOTIFY", "SUBDOMAIN_BRUTEFORCE", "ORGANIZATION_SCAN", 
        "ORGANIZATION_NOTIFY", "DNS_NOTIFY", "SUBDOMAIN_RESOLUTION_NOTIFY",
        "CONTENT_NOTIFY", "CONTENT_ACTIVE", "JS_NOTIFY", "JS_ACTIVE",
        "JS_NUCLEI", "JS_DOWNLOAD", "FUZZING_ACTIVE", "FUZZING_NOTIFY"
    ]
    
    for key in bool_keys:
        vars_config[key] = str_to_bool(args_map.get(key, True))

    return vars_config

def main():
    parser = argparse.ArgumentParser(description="Rayders Complete Workflow Generator")
    parser.add_argument("-f", "--file", help="Input JSON/YAML file")
    parser.add_argument("--root", help="Path to ROOT")
    parser.add_argument("--target", help="Target name")
    parser.add_argument("--org", help="Organization name")
    
    args = parser.parse_args()
    data = {}

    if args.file:
        with open(args.file, 'r') as f:
            data = json.load(f) if args.file.endswith('.json') else yaml.safe_load(f)

    if not args.file and not (args.root and args.target):
        print("--- Rayders Configuration Setup ---")
        data['ROOT'] = get_input("Path to ROOT folder", os.getcwd())
        data['TARGET'] = get_input("Target name (slug)", "hackthissite")
        data['ORGANIZATION'] = get_input("Organization name", "HackThisSite")
        
        print("\n--- Boolean Options (y/n) ---")
        data['SUBDOMAIN_BRUTEFORCE'] = get_input("Enable Subdomain Bruteforce?", "y")
        data['ORGANIZATION_SCAN'] = get_input("Enable Organization Scan?", "n")
        data['CONTENT_ACTIVE'] = get_input("Enable Content Enumeration?", "y")
        data['JS_ACTIVE'] = get_input("Enable JS Analysis?", "y")
        data['FUZZING_ACTIVE'] = get_input("Enable Fuzzing?", "y")
        data['SUBDOMAIN_NOTIFY'] = get_input("Enable Notifications?", "y")
        for k in ["ORGANIZATION_NOTIFY", "DNS_NOTIFY", "CONTENT_NOTIFY", "JS_NOTIFY", "FUZZING_NOTIFY"]:
            data[k] = data['SUBDOMAIN_NOTIFY']
    else:
        if args.root: data['ROOT'] = args.root
        if args.target: data['TARGET'] = args.target
        if args.org: data['ORGANIZATION'] = args.org

    final_vars = generate_vars(data)
    target_name = final_vars['TARGET']
    output_filename = f"{target_name}.yaml"

    # Estrutura completa do Workflow
    workflow = {
        "vars": final_vars,
        "parallel": False,
        "modules": [
            {
                "name": "subdomain_enum",
                "cmds": ["rayder -q -w {{SUBDOMAIN_WORKFLOWS_FOLDER}}/subdomain_enum.yaml INPUT_DOMAINS={{INPUT_DOMAINS}} SUBDOMAIN_OUTPUT_PATH={{SUBDOMAIN_OUTPUT_PATH}} SUBDOMAIN_NOTIFY={{SUBDOMAIN_NOTIFY}} SUBDOMAIN_BRUTEFORCE={{SUBDOMAIN_BRUTEFORCE}} SUBDOMAIN_WORDLIST={{SUBDOMAIN_WORDLIST}} SUBDOMAIN_SCRIPTS_FOLDER={{SUBDOMAIN_SCRIPTS_FOLDER}} SUBDOMAIN_WORKFLOWS_FOLDER={{SUBDOMAIN_WORKFLOWS_FOLDER}}"]
            },
            {
                "name": "organization_enum",
                "cmds": ["if [ \"{{ORGANIZATION_SCAN}}\" = \"true\" ]; then rayder -q -w {{ORGANIZATION_WORKFLOWS_FOLDER}}/organization_enum.yaml INPUT_DOMAINS={{INPUT_DOMAINS}} INPUT_ORGANIZATION={{INPUT_ORGANIZATION}} IPS_OUTPUT_PATH={{IPS_OUTPUT_PATH}} ORGANIZATION_NOTIFY={{ORGANIZATION_NOTIFY}} ORGANIZATION_WORKFLOWS_FOLDER={{ORGANIZATION_WORKFLOWS_FOLDER}} ORGANIZATION_SCRIPTS_FOLDER={{ORGANIZATION_SCRIPTS_FOLDER}} ; fi"]
            },
            {
                "name": "infrastructure_enum",
                "cmds": ["rayder -q -w {{INFRASTRUCTURE_WORKFLOWS_FOLDER}}/infrastructure_enum.yaml  INPUT_IPS={{INPUT_IPS}} IPS_OUTPUT_PATH={{IPS_OUTPUT_PATH}} SUBDOMAIN_OUTPUT_PATH={{SUBDOMAIN_OUTPUT_PATH}} INFRASTRUCTURE_NOTIFY={{NOTIFY}} INFRASTRUCTURE_SCRIPTS_FOLDER={{INFRASTRUCTURE_SCRIPTS_FOLDER}} INFRASTRUCTURE_WORKFLOWS_FOLDER={{INFRASTRUCTURE_WORKFLOWS_FOLDER}}"]
            },
            {
                "name": "dns_enum",
                "cmds": ["rayder -q -w {{DNS_WORKFLOWS_FOLDER}}/dns_enum.yaml INPUT_DOMAINS={{INPUT_DOMAINS}} SUBDOMAIN_OUTPUT_FILE={{SUBDOMAIN_OUTPUT_FILE}} IPS_OUTPUT_FILE={{IPS_OUTPUT_FILE}} DNS_OUTPUT_PATH={{DNS_OUTPUT_PATH}} DNS_NOTIFY={{DNS_NOTIFY}} DNS_SCRIPTS_FOLDER={{DNS_SCRIPTS_FOLDER}} DNS_WORKFLOWS_FOLDER={{DNS_WORKFLOWS_FOLDER}}"]
            },
            {
                "name": "subdomain_resolution",
                "cmds": ["rayder -q -w {{SUBDOMAIN_RESOLUTION_WORKFLOWS_FOLDER}}/subdomain_resolution.yaml SUBDOMAIN_OUTPUT_FILE={{SUBDOMAIN_OUTPUT_FILE}} SUBDOMAIN_OUTPUT_PATH={{SUBDOMAIN_OUTPUT_PATH}} SUBDOMAIN_RESOLUTION_NOTIFY={{SUBDOMAIN_RESOLUTION_NOTIFY}} SUBDOMAIN_RESOLUTION_SCRIPTS_FOLDER={{SUBDOMAIN_RESOLUTION_SCRIPTS_FOLDER}} SUBDOMAIN_RESOLUTION_WORKFLOWS_FOLDER={{SUBDOMAIN_RESOLUTION_WORKFLOWS_FOLDER}}"]
            },
            {
                "name": "content_enumeration",
                "cmds": ["rayder -q -w {{CONTENT_WORKFLOWS_FOLDER}}/content_enumeration.yaml LIVE_SUBDOOMAINS_FILE={{LIVE_SUBDOOMAINS_FILE}} ALL_URLS_FILE={{ALL_URLS_FILE}} GAU_URLS_FILE={{GAU_URLS_FILE}} KATANA_URLS_FILE={{KATANA_URLS_FILE}} PARAMS_URLS_FILE={{PARAMS_URLS_FILE}} JS_URLS_FILE={{JS_URLS_FILE}} CLEANED_URLS_FILE={{CLEANED_URLS_FILE}} CONTENT_OUTPUT_PATH={{CONTENT_OUTPUT_PATH}} CONTENT_NOTIFY={{CONTENT_NOTIFY}} CONTENT_ACTIVE={{CONTENT_ACTIVE}} CONTENT_SCRIPTS_FOLDER={{CONTENT_SCRIPTS_FOLDER}} CONTENT_WORKFLOWS_FOLDER={{CONTENT_WORKFLOWS_FOLDER}}"]
            },
            {
                "name": "javascript_enum",
                "cmds": ["rayder -q -w {{JS_WORKFLOWS_FOLDER}}/javascript_enum.yaml JS_URLS_FILE={{JS_URLS_FILE}} SELECTED_JS_FILES={{SELECTED_JS_FILES}} JS_OUTPUT_PATH={{JS_OUTPUT_PATH}} JS_NOTIFY={{JS_NOTIFY}} JS_ACTIVE={{JS_ACTIVE}} JS_NUCLEI={{JS_NUCLEI}} JS_DOWNLOAD={{JS_DOWNLOAD}} JS_DOWNLOAD_FOLDER={{JS_DOWNLOAD_FOLDER}} JS_SCRIPTS_FOLDER={{JS_SCRIPTS_FOLDER}} JS_WORKFLOWS_FOLDER={{JS_WORKFLOWS_FOLDER}} JS_REGEX_FILE={{JS_REGEX_FILE}} SUBDOMAIN_OUTPUT_FILE={{SUBDOMAIN_OUTPUT_FILE}} ALL_URLS_FILE={{ALL_URLS_FILE}}"]
            },
            {
                "name": "fuzzing",
                "cmds": ["rayder -q -w {{FUZZING_WORKFLOWS_FOLDER}}/fuzzing.yaml FUZZING_OUTPUT_PATH={{FUZZING_OUTPUT_PATH}} GIT_OUTPUT_PATH={{GIT_OUTPUT_PATH}} CEWL_OUTPUT_PATH={{CEWL_OUTPUT_PATH}} WORDLISTS_OUTPUT_PATH={{WORDLISTS_OUTPUT_PATH}} LIVE_SUBDOOMAINS_FILE={{LIVE_SUBDOOMAINS_FILE}} SUBDOMAIN_WORDLIST={{SUBDOMAIN_WORDLIST}} DIRECTORY_WORDLIST={{DIRECTORY_WORDLIST}} PATH_WORDLIST={{PATH_WORDLIST}} WORDS_WORDLIST={{WORDS_WORDLIST}} ALL_URLS_FILE={{ALL_URLS_FILE}} FUZZING_ACTIVE={{FUZZING_ACTIVE}} FUZZING_NOTIFY={{FUZZING_NOTIFY}} FUZZING_SCRIPTS_FOLDER={{FUZZING_SCRIPTS_FOLDER}} FUZZING_WORKFLOWS_FOLDER={{FUZZING_WORKFLOWS_FOLDER}}"]
            },
            {
                "name": "vulnerability_scan",
                "cmds": ["rayder -q -w {{VULNERABILITY_WORKFLOWS_FOLDER}}/vulnerability_scan.yaml VULNERABILITY_OUTPUT_PATH={{VULNERABILITY_OUTPUT_PATH}} CLEANED_URLS_FILE={{CLEANED_URLS_FILE}} VULNERABILITY_SCRIPTS_FOLDER={{VULNERABILITY_SCRIPTS_FOLDER}} VULNERABILITY_WORKFLOWS_FOLDER={{VULNERABILITY_WORKFLOWS_FOLDER}}"]
            }
        ]
    }

    with open(output_filename, 'w') as yf:
        yaml.dump(workflow, yf, default_flow_style=False, sort_keys=False)

    print(f"\n[+] Workflow generated: {output_filename}")
    print(f"[!] You can now rub: rayder -w {output_filename}")

if __name__ == "__main__":
    main()