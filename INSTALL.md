# ShieldMendAI Installation

## Requirements

- Ubuntu 22.04+
- Root or sudo access
- Internet connection
- Telegram Bot Token

## Quick Install

```bash
git clone https://github.com/shieldmendai/shieldmendai-core.git
cd shieldmendai-core
bash install.sh
```

## Configuration

Edit:

```text
config.yaml
```

Add:

- Telegram Bot Token
- Telegram Chat ID
- Services to monitor

## Start

```bash
sudo systemctl start shieldmendai
sudo systemctl enable shieldmendai
```

## Verify

```bash
shieldmendai status
```
