# Nmap Crew

CrewAI-based Nmap workflow that scans a target, analyzes results, maps potential CVEs, and writes a Markdown report.

## Installation

Ensure you have Python >=3.10 <3.14 installed on your system. This project uses [UV](https://docs.astral.sh/uv/) for dependency management and package handling, offering a seamless setup and execution experience.

First, if you haven't already, install uv:

```bash
pip install uv
```

Next, navigate to your project directory and install the dependencies:

(Optional) Lock the dependencies and install them by using the CLI command:
```bash
crewai install
```
### Customizing

**Add your `OPENAI_API_KEY` into the `.env` file**

- Modify `src/nmap/config/agents.yaml` to define your agents
- Modify `src/nmap/config/tasks.yaml` to define your tasks
- Modify `src/nmap/crew.py` to add your own logic, tools and specific args
- Modify `src/nmap/main.py` to add custom inputs for your agents and tasks

## Running the Project

To kickstart your crew of AI agents and begin task execution, run this from the root folder of your project:

```bash
$ crewai run
```

This command initializes the nmap Crew if you use crew tasks directly.

However, this project provides a CLI that orchestrates the full scan→analyze→report flow:

```bash
python -m nmap.main <target> "nmap scan target"
# or after installing as a package:
nmap_crew <target> "nmap scan target"
```

Flags:
- `--timeout <seconds>` per-command timeout (default 600)
- `--no-llm` disable LLM analysis and use rule-based analysis only

Output:
- A single Markdown report saved under `3_crew/nmap/reports/` named `nmap_report_<target>_<timestamp>.md`.
- The CLI prints the absolute path and success status.

## Understanding Your Crew

Agents defined in `src/nmap/config/agents.yaml`:
- Security Manager: orchestrates the workflow and additional scan decisions.
- Nmap Scanner: proposes scan strategies and syntax.
- Kali Linux Command Agent: executes commands and returns structured output.
- Nmap Results Analyst: analyzes raw Nmap output and drafts the analysis.

Tasks are defined in `src/nmap/config/tasks.yaml`. The CLI uses deterministic scanning and then calls the Results Analyst to enrich the analysis.

## Support

For support, questions, or feedback regarding the Nmap Crew or crewAI.
- Visit our [documentation](https://docs.crewai.com)
- Reach out to us through our [GitHub repository](https://github.com/joaomdmoura/crewai)
- [Join our Discord](https://discord.com/invite/X4JWnZnxPb)
- [Chat with our docs](https://chatg.pt/DWjSBZn)

Notes:
- This project parses Nmap output and uses a small local regex-to-CVE mapping in `knowledge/cve_mappings.txt` for inference. Always validate CVE applicability.
- The Results Analyst uses your configured LLM (via `OPENAI_API_KEY`) unless `--no-llm` is provided.

Let's create wonders together with the power and simplicity of crewAI.
