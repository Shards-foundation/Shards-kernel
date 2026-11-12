# Native Android/Termux acceptance (operator-run; not a CI simulation)

This probe refuses ordinary Ubuntu/GitHub-hosted CI or a Linux container.
It requires native Termux's `PREFIX`, Android's real `/system/bin/getprop` and read-only `/system/build.prop`,
a package installed in `site-packages`, SQLite restart integrity and,
optionally, the live local Qwen endpoint and externally signed harmless permit.

## On the Android phone

In the native Termux app, install trusted dependencies and verify the
`shards-kernel==0.1.3` package using your normal operator procedure.
The current development files are on the separate acceptance branch:

```bash
pkg update && pkg install -y python git
python -m pip install "shards-kernel[crypto]==0.1.3"
git clone --branch feat/dual-host-acceptance-20261112 --depth 1 \
  https://github.com/Shards-foundation/Shards-kernel.git "$HOME/shards-phase3-acceptance"
cd "$HOME/shards-phase3-acceptance"
python scripts/acceptance/termux_device_probe.py --qwen \
  --json-out "$HOME/termux-phase3-evidence.json"
```

**This is a partial acceptance probe**. `--qwen` requires the actual
llama.cpp/OpenAI-compatible service already listening on 127.0.0.1:8080.
No model token permits direct execution and the probe asks the model only
to propose `add(17,25)`.

For the full on-device signed execution, use a **separately protected**
issuer host. Verify the public key fingerprint *out of band*, have a
human approve the exact `add(17,25)` proposal, securely transfer the
proposal + signed permit to Termux, then run before the permit expires:

```bash
python scripts/acceptance/termux_device_probe.py --qwen --execute \
  --public-key-hex 'YOUR_EXTERNAL_PUBLIC_KEY_HEX' \
  --fingerprint 'OUT_OF_BAND_SHA256_FINGERPRINT' \
  --proposal "$HOME/proposal.json" \
  --permit "$HOME/permit.json" \
  --json-out "$HOME/termux-phase3-signed-evidence.json"
```

The placeholders are **public values or local filenames**, never private
keys. Do not paste private signing keys, account tokens or full audit files
into a chat. It will fail closed if the publisher key differs from the
existing enrolled public key or if a signer private file appears in the v3
state directory. A real phone test remains `NOT_VERIFIED` until its output
is independently inspected; neither this script nor GitHub CI can attest
the hardware or issuer's human approval.

Use the operator's secure evidence channel for the redacted JSON; do not
treat a self-reported OS property as hardware attestation.
