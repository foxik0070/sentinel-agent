# Gitea Actions Runner — nastavení pro sentinel-agent

CI (`.gitea/workflows/ci.yaml`) potřebuje registrovaný `act_runner`, který obsluhuje
repozitář `lukas/sentinel-agent`. Job zůstává ve stavu **„Čekání"**, dokud žádný
runner s odpovídajícím scope a labelem job nepřevezme.

- **Instance URL:** `http://gitea.example.com`
- **Workflow label:** `ubuntu-latest` (image musí mít Python 3 + Node.js)

## Proč job visí

Runner, který už obsluhuje repo `Sentinel`, je pravděpodobně **scoped jen na to
repo**. Runner scope se určuje podle toho, kde byl v Gitea UI vygenerován
registrační token:

| Kde token vygenerovat | Scope runneru |
|-----------------------|---------------|
| *Site Administration → Actions → Runners* | celá instance (všechna repa) |
| *User/Org Settings → Actions → Runners* | všechna repa uživatele `lukas` |
| *Repo Settings → Actions → Runners* | jen dané repo |

**Doporučení:** vygeneruj token na úrovni **uživatele `lukas`** (User Settings →
Actions → Runners → *Create new runner*), pak jeden runner obslouží i budoucí repa.

## Varianta A — Docker (doporučeno, izolované od stávajícího runneru)

Na hostu s Dockerem (Gitea server má Docker — CI repa Sentinel jím běží):

```bash
mkdir -p /opt/gitea-runner && cd /opt/gitea-runner
cat > docker-compose.yml <<'YAML'
services:
  runner:
    image: gitea/act_runner:latest
    restart: always
    environment:
      GITEA_INSTANCE_URL: "http://gitea.example.com"
      GITEA_RUNNER_REGISTRATION_TOKEN: "<REGISTRAČNÍ_TOKEN>"
      GITEA_RUNNER_NAME: "sentinel-agent-runner"
      # label -> image, který má python3 i node
      GITEA_RUNNER_LABELS: "ubuntu-latest:docker://catthehacker/ubuntu:act-latest"
    volumes:
      - ./data:/data
      - /var/run/docker.sock:/var/run/docker.sock
YAML
docker compose up -d
docker compose logs -f    # ověř řádek "Runner registered successfully"
```

## Varianta B — binárka + systemd (host bez Dockeru)

```bash
# 1) stáhni act_runner (arch dle hostu: amd64 / arm64)
ARCH=$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')
VER=0.2.11
sudo curl -fsSL -o /usr/local/bin/act_runner \
  "https://gitea.com/gitea/act_runner/releases/download/v${VER}/act_runner-${VER}-linux-${ARCH}"
sudo chmod +x /usr/local/bin/act_runner

# 2) registrace (label:host = job běží přímo na hostu; host musí mít python3 + node)
sudo mkdir -p /opt/gitea-runner && cd /opt/gitea-runner
sudo act_runner register --no-interactive \
  --instance http://gitea.example.com \
  --token "<REGISTRAČNÍ_TOKEN>" \
  --name sentinel-agent-runner \
  --labels "ubuntu-latest:host"

# 3) systemd služba
sudo tee /etc/systemd/system/act_runner.service >/dev/null <<'UNIT'
[Unit]
Description=Gitea Act Runner
After=network-online.target
Wants=network-online.target

[Service]
WorkingDirectory=/opt/gitea-runner
ExecStart=/usr/local/bin/act_runner daemon
Restart=always
RestartSec=5
User=root

[Install]
WantedBy=multi-user.target
UNIT
sudo systemctl daemon-reload
sudo systemctl enable --now act_runner
```

> **Pozn.:** v host-módu (`:host`) musí mít host `node` (pro `actions/checkout`,
> `actions/setup-python`) a `python3`. Docker varianta A je robustnější, protože
> vše dodá image `catthehacker/ubuntu:act-latest`.

## Ověření

1. V Gitea UI: *Repo → Settings → Actions → Runners* — nový runner je **Online**
   (zelený) s labelem `ubuntu-latest`.
2. Znovu spusť poslední workflow (*Actions → běh → Re-run*) nebo pushni commit.
   Job `test` přejde z „Čekání" na „Running" a doběhne zeleně.

## Odstranění

- Docker: `cd /opt/gitea-runner && docker compose down -v`
- systemd: `sudo systemctl disable --now act_runner && sudo rm /etc/systemd/system/act_runner.service /usr/local/bin/act_runner`
- V UI smaž runner v *Settings → Actions → Runners*.
