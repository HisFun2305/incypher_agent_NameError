# Installation

## Local setup (PowerShell)

```powershell
git clone https://github.com/HisFun2305/incypher_agent_NameError.git
cd incypher_agent_NameError
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
Copy-Item .env.example .env
```

Configure `.env` with your credentials. For SOCLAAS, follow [https://dochub.comp.nus.edu.sg/cf/guides/soclaas/start](https://dochub.comp.nus.edu.sg/cf/guides/soclaas/start) (You need to be on NUS wifi or be logged into the NUS VPN):

```dotenv
IN_CYPHER_DOCKER_PLATFORM_AVAILABLE=false
SOCLAAS_API_KEY=your_soclass_api_key
SOCLAAS_BASE_URL=https://your-soclass-compatible-api/v1
CTFD_API_TOKEN=your_ctfd_token
PLATFORM_URL=https://hackathon.in-cypher.com
TEAM_KEY=your_team_key
```

### Optional local CyberChef support

The file solver's CyberChef adapter uses a small local Node.js application
rather than a remote server. Its `package.json`, runner, and `node_modules`
stay together under `tools/file_solve_tools/cyberchef_runner`; install its
dependencies there when that tool is needed:

```powershell
Push-Location tools/file_solve_tools/cyberchef_runner
npm install
Pop-Location
```
## Arena deployment

The arena runs a pushed Docker image unattended. Build for Linux x86_64, push
the newest `:latest` image to your team registry repository, and let the next
arena cycle run it. At runtime, the arena injects `CTF_TOKEN`/`CTFD_TOKEN` and
`CTF_BASE`/`CTFD_URL`; this agent accepts those aliases for its CTFd settings.

URL challenges are deployed autonomously through CTFd's container deployment
endpoint when `IN_CYPHER_DOCKER_PLATFORM_AVAILABLE=true`. The returned
`url`, `connection_url`, or `connection_info` must be an HTTP(S) URL and is
stored as `challenge_url`. There is no interactive URL prompt, because arena
runs are unattended.

### Downloaded executable support

The remote solver container registers workspace-local ELF and PE challenge
artifacts for the bounded `run_executable` solver action only after every
discovered ZIP archive has been expanded. Each successful `extract_zip` action
is recorded; after no archives remain pending, executable artifacts (including
ZIP extractions) are marked executable for the container user and recorded in
the challenge context. The action still has bounded arguments, input, output,
and runtime; the container must support the artifact's executable format.
Menu-driven binaries can be handled with stateful start, send, receive, and
close actions during one solver invocation. Each process session has a
180-second wall-clock lifetime by default while individual reads remain capped
at 15 seconds. Set `FILE_SOLVER_EXECUTABLE_SESSION_SECONDS` to a value from 15
to 600 seconds when a challenge needs more interaction time.

The file solver also supports bounded gzip expansion, audio spectral summaries
and parameterized FSK decoding, plus read-only ext4 inspection through
`debugfs` when that local utility is available.

## Docker setup

```powershell
docker build -t incypher-agent:latest .
docker run --rm -it `
  -e IN_CYPHER_DOCKER_PLATFORM_AVAILABLE="false" `
  -e SOCLAAS_API_KEY="your_soclass_api_key" `
  -e SOCLAAS_BASE_URL="https://your-soclass-compatible-api/v1" `
  -e CTFD_API_TOKEN="your_ctfd_token" `
  -e PLATFORM_URL="https://hackathon.in-cypher.com" `
  -e TEAM_KEY="your_team_key" `
  --name agent_runner `
  incypher-agent:latest
```

## Module diagram

For a concise reference of the public methods, see [METHODS.md](METHODS.md).

```mermaid
classDiagram
    class agent_py {
        +_delegate(challenge_type, chal_ID) str | None
        +main()
    }
    class ctfd_api_py {
        +CTFdClient
        +get_challenges()
        +get_challenge_details()
        +prepare_challenge_context()
        +identify_challenge_type()
        +extract_challenge_description()
        +download_challenge_files()
        +get_challenge_url()
        +connect_challenge_tcp()
        +submit_flag()
    }
    class preflight_py {
        +main()
        +check_soclaas_connection()
        +check_challenge_url_connection()
        +check_challenge_tcp_connection()
        +check_context_retrieval()
        +check_challenge_file_download()
        +check_context_sqlite_connection()
    }
    class context_py {
        <<JSON dictionaries; non-negative IDs: challenges; negative IDs: shared context>>
        +store_context(context, chal_ID)
        +get_context(chal_ID) dict | None
        +update_context(context, chal_ID)
        +append_context_list(values, field, chal_ID)
        +store_artifact_paths(filepaths, chal_ID)
        +delete_context(chal_ID)
        +store_name()
        +get_name()
        +store_chal_file_path()
        +get_chal_file_path()
    }
    class config_py {
        +load_dotenv()
    }
    class llm_router_py {
        +call_openai()
        +call_multimodal_openai(prompt, image_paths, model_name)
        +list_openai_models()
    }
    class converter_py {
        +convert_audio_file(audio_path, conversion_type, output_path, chal_ID) Path
        +extract_zip_archive(archive_path, chal_ID, output_directory) list~Path~
    }
    class web_chal_py {
        +web_chal_solver(chal_ID) str | None
    }
    class port_chal_py {
        +port_chal_solver(chal_ID) str | None
    }
    class file_chal_py {
        +file_chal_solver(chal_ID) str | None
    }
    class tcp_client_py {
        +connect_tcp()
        +interact_tcp()
    }
    class http_client_py {
        +create_session()
        +interact_http()
        +request_json()
        +graphql_query()
    }
    class webpage_access_helpers_py {
        +get_form_json()
        +submit_form()
        +validate_form_json()
        +extract_flag()
    }
    class flags_py {
        +extract_flag(text) str | None
    }
    class solver_py {
        +connect()
    }

    agent_py --> ctfd_api_py : retrieves challenge data
    agent_py --> context_py : stores JSON challenge context
    agent_py --> web_chal_py : delegates URL challenge
    agent_py --> port_chal_py : delegates TCP challenge
    agent_py --> file_chal_py : delegates file challenge
    web_chal_py --> agent_py : str flag (solved) or None (retry)
    port_chal_py --> agent_py : str flag (solved) or None (retry)
    file_chal_py --> agent_py : str flag (solved) or None (retry)
    preflight_py --> ctfd_api_py : verifies API data
    preflight_py --> context_py : verifies SQLite storage
    preflight_py --> llm_router_py : verifies SOCLAas connectivity
    ctfd_api_py --> config_py : loads credentials
    ctfd_api_py --> context_py : reads prepared challenge data
    ctfd_api_py --> tcp_client_py : opens platform TCP connection
    llm_router_py --> config_py : loads credentials
    tcp_client_py --> solver_py : opens TCP connection
    web_chal_py --> context_py : reads and updates JSON context
    web_chal_py --> llm_router_py : classifies web subtype
    web_chal_py --> http_client_py : creates challenge session
    web_chal_py --> webpage_access_helpers_py : discovers and submits forms
    webpage_access_helpers_py --> context_py : stores validated schema
    port_chal_py --> context_py : reads challenge context
    port_chal_py --> ctfd_api_py : requests challenge TCP connection
    port_chal_py --> flags_py : validates exact flag format
    file_chal_py --> context_py : reads challenge context
    converter_py --> context_py : records converted file paths
    webpage_access_helpers_py --> flags_py : validates exact flag format
```
