<p align="center">
  <img src="https://user-images.githubusercontent.com/6550035/46709024-9b23ad00-cbf6-11e8-9fb2-ca8b20b7dbec.jpg" width="408px" border="0" alt="croc">
  <br>
  <a href="https://github.com/pynchroid/croc/releases/latest"><img src="https://img.shields.io/github/v/release/pynchroid/croc" alt="Version"></a>
  <a href="https://github.com/pynchroid/croc/actions/workflows/ci.yml"><img src="https://github.com/pynchroid/croc/actions/workflows/ci.yml/badge.svg" alt="Build Status"></a>
</p>

## About

This is a hardened fork of [schollz/croc](https://github.com/schollz/croc) with improved resilience, modern cryptography, and better support for large multi-hour transfers.

`croc` is a tool that allows any two computers to simply and securely transfer files and folders. AFAIK, *croc* is the only CLI file-transfer tool that does **all** of the following:

- Allows **any two computers** to transfer data (using a relay)
- Provides **end-to-end encryption** (using PAKE)
- Enables easy **cross-platform** transfers (Windows, Linux, Mac)
- Allows **multiple file** transfers
- Allows **resuming transfers** that are interrupted
- No need for local server or port-forwarding
- **IPv6-first** with IPv4 fallback
- Can **use a proxy**, like Tor

### What's different in this fork

- **Automatic retry with exponential backoff** — dropped connections are retried up to 5 times by default (configurable with `--retry`)
- **Activity-based timeouts** — connections stay alive as long as data is flowing (no more hard 3-hour ceiling killing your movie library transfer)
- **TCP keepalive** — detects dead connections and prevents NAT/firewall timeouts
- **Modern cryptography** — Argon2id KDF (replaces PBKDF2 with 100 iterations) + XChaCha20-Poly1305 (replaces AES-GCM) + 16-byte salts + HKDF key rotation for long sessions
- **Per-file completion tracking** — multi-file transfers write a `.croc-progress` manifest so retries and restarts skip already-finished files
- **Configurable cipher/KDF** — `--cipher` and `--kdf` flags let you choose between modern and legacy crypto

For more information about the original `croc`, see [the blog post](https://schollz.com/tinker/croc6/) or read [this interview](https://console.substack.com/p/console-91).

![Example](src/install/customization.gif)

## Install

Download the [latest release for your system](https://github.com/pynchroid/croc/releases/latest) from the releases page.

### On Windows (PowerShell)

```powershell
Invoke-WebRequest -Uri "https://github.com/pynchroid/croc/releases/latest/download/croc_Windows-64bit.zip" -OutFile "$env:TEMP\croc.zip"
Expand-Archive -Path "$env:TEMP\croc.zip" -DestinationPath "$env:USERPROFILE\croc" -Force
Write-Host "croc installed to $env:USERPROFILE\croc\croc.exe"
```

To add it to your PATH permanently:

```powershell
$crocPath = "$env:USERPROFILE\croc"
$currentPath = [Environment]::GetEnvironmentVariable("Path", "User")
if ($currentPath -notlike "*$crocPath*") {
    [Environment]::SetEnvironmentVariable("Path", "$currentPath;$crocPath", "User")
    Write-Host "Added $crocPath to PATH. Restart PowerShell to use 'croc' from anywhere."
}
```

### On macOS

```bash
curl -sL https://github.com/pynchroid/croc/releases/latest/download/croc_macOS-ARM64.tar.gz | tar xz
sudo mv croc /usr/local/bin/
```

For Intel Macs, replace `macOS-ARM64` with `macOS-64bit`.

### On Linux

```bash
curl -sL https://github.com/pynchroid/croc/releases/latest/download/croc_Linux-64bit.tar.gz | tar xz
sudo mv croc /usr/local/bin/
```

Other architectures: replace `Linux-64bit` with `Linux-ARM64`, `Linux-ARM`, or `Linux-RISCV64`.

### Build from Source

Requires [Go 1.25+](https://go.dev/dl/):

```bash
git clone https://github.com/pynchroid/croc.git
cd croc
go build -o croc .
```

On Windows (PowerShell):

```powershell
git clone https://github.com/pynchroid/croc.git
cd croc
go build -o croc.exe .
```

## Usage

To send a file, simply do:

```bash
$ croc send [file(s)-or-folder]
Sending 'file-or-folder' (X MB)
Code is: code-phrase
```

Then, to receive the file (or folder) on another computer, run:

```bash
croc code-phrase
```

The code phrase is used to establish password-authenticated key agreement ([PAKE](https://en.wikipedia.org/wiki/Password-authenticated_key_agreement)) which generates a secret key for the sender and recipient to use for end-to-end encryption.

### Customizations & Options

#### Retry and Long Transfers

Retry and long-session support is built in — no flags needed. Just run `croc send` and it handles the rest:

- **20 automatic retries** with exponential backoff (3s → 6s → 12s → ... → 5min cap)
- **2-hour idle timeout** that resets on every successful read/write, so active transfers run indefinitely
- **Per-file progress tracking** via `.croc-progress` manifest — interrupted multi-file transfers automatically skip already-completed files on retry

```bash
# Just works — retry and timeout are built in
croc send my-movie-library/
croc <code-phrase>
```

To customize the defaults:

| Flag | Default | Description |
|------|---------|-------------|
| `--retry` | `20` | Number of retry attempts on connection failure (0 = no retry) |
| `--retry-wait` | `3` | Base wait in seconds between retries (exponential backoff) |
| `--timeout` | `120` | Inactivity timeout in minutes (resets on every successful read/write) |

#### Encryption Options

By default, this fork uses Argon2id for key derivation and XChaCha20-Poly1305 for encryption. To use legacy cryptography (for compatibility with upstream croc):

```bash
# Both sender and receiver must use the same settings
croc --cipher aes-gcm --kdf pbkdf2 send file.txt
croc --cipher aes-gcm --kdf pbkdf2 <code-phrase>
```

| Flag | Default | Options |
|------|---------|---------|
| `--cipher` | `xchacha20` | `xchacha20` (recommended), `aes-gcm` (legacy) |
| `--kdf` | `argon2id` | `argon2id` (recommended), `pbkdf2` (legacy) |

> **Note:** Both sender and receiver must use the same `--cipher` and `--kdf` settings. This fork is not compatible with upstream croc by default due to the cryptography changes. Use `--cipher aes-gcm --kdf pbkdf2` for backward compatibility.

#### Using `croc` on Linux or macOS

On Linux and macOS, the sending and receiving process is slightly different to avoid [leaking the secret via the process name](https://nvd.nist.gov/vuln/detail/CVE-2023-43621). You will need to run `croc` with the secret as an environment variable. For example, to receive with the secret `***`:

```bash
CROC_SECRET=*** croc
```

For single-user systems, the default behavior can be permanently enabled by running:

```bash
croc --classic
```

#### Custom Code Phrase

You can send with your own code phrase (must be at least 6 characters):

```bash
croc send --code [code-phrase] [file(s)-or-folder]
```

#### Allow Overwriting Without Prompt

To automatically overwrite files without prompting, use the `--overwrite` flag:

```bash
croc --yes --overwrite <code>
```

#### Excluding Folders

To exclude folders from being sent, use the `--exclude` flag with comma-delimited exclusions:

```bash
croc send --exclude "node_modules,.venv" [folder]
```

#### Use Pipes - stdin and stdout

You can pipe to `croc`:

```bash
cat [filename] | croc send
```

To receive the file to `stdout`, you can use:

```bash
croc --yes [code-phrase] > out
```

#### Send Text

To send URLs or short text, use:

```bash
croc send --text "hello world"
```

#### Send Multiple Files

You can send multiple files directly by listing the files and/or folders:

```bash
croc send [file1] [file2] [file3] [folder1] [folder2]
```

#### Show QR Code

To show QR code (for mobile devices), use:

```bash
croc send --qr [file(s)-or-folder]
```

#### Use a Proxy

You can send files via a proxy by adding `--socks5`:

```bash
croc --socks5 "127.0.0.1:9050" send SOMEFILE
```

#### Change Encryption Curve

To choose a different elliptic curve for encryption, use the `--curve` flag:

```bash
croc --curve p521 <codephrase>
```

#### Change Hash Algorithm

For faster hashing, use the `imohash` algorithm:

```bash
croc send --hash imohash SOMEFILE
```

#### Clipboard Options

By default, the code phrase is copied to your clipboard. To disable this:

```bash
croc --disable-clipboard send [filename]
```

To copy the full command with the secret as an environment variable (useful on Linux/macOS):

```bash
croc --extended-clipboard send [filename]
```

This copies the full command like `CROC_SECRET="code-phrase" croc` (including any relay/pass flags).

#### Quiet Mode

To suppress all output (useful for scripts and automation):

```bash
croc --quiet send [filename]
```

#### Self-host Relay

You can run your own relay:

```bash
croc relay
```

By default, it uses TCP ports 9009-9013. You can customize the ports (e.g., `croc relay --ports 1111,1112`), but at least **2** ports are required.

To send files using your relay:

```bash
croc --relay "myrelay.example.com:9009" send [filename]
```

#### Self-host Relay with Docker

You can also run a relay with Docker:

```bash
docker run -d -p 9009-9013:9009-9013 -e CROC_PASS='YOURPASSWORD' docker.io/schollz/croc
```

To send files using your custom relay:

```bash
croc --pass YOURPASSWORD --relay "myreal.example.com:9009" send [filename]
```

To use custom ports, set `CROC_PORTS` (comma-separated) or `CROC_PORT` (base port):

```bash
docker run -d -p 9010-9011:9010-9011 -e CROC_PORTS='9010,9011' -e CROC_PASS='YOURPASSWORD' docker.io/schollz/croc
```

## Acknowledgements

This fork is based on the excellent work of [@schollz](https://github.com/schollz) and the [original croc project](https://github.com/schollz/croc). Special thanks to:

- [@schollz](https://github.com/schollz) for creating croc
- [@warner](https://github.com/warner) for the [idea](https://github.com/magic-wormhole/magic-wormhole)
- [@tscholl2](https://github.com/tscholl2) for the [encryption gists](https://gist.github.com/tscholl2/dc7dc15dc132ea70a98e8542fefffa28)
- [@skorokithakis](https://github.com/skorokithakis) for [proxying two connections](https://www.stavros.io/posts/proxying-two-connections-go/)

And many more!
