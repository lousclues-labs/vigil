# Vigil Baseline -- Quickstart

## What you'll have in 5 minutes

- Vigil monitoring your critical system files.
- Daemon running and responding to changes in real-time.
- Verified baseline with a fingerprint you can record.

## Step 1. Install

### Arch Linux (AUR)

```bash
yay -S vigil-baseline
```

### From source

```bash
cargo install vigil-baseline
```

### From git

```bash
git clone https://github.com/lousclues-labs/vigil.git
cd vigil
cargo build --release
sudo install -m 755 target/release/vigil /usr/bin/vigil
sudo install -m 755 target/release/vigild /usr/bin/vigild
```

## Step 2. Initialize

```bash
sudo vigil welcome
```

This walks you through selecting watch paths, building the baseline,
and starting the daemon. Takes about 90 seconds.

If you prefer defaults without the interactive flow:

```bash
sudo vigil init
```

## Step 3. Verify

```bash
sudo vigil check
```

On a clean system this shows zero changes. That's the point. The
baseline matches reality.

## Step 4. Start the daemon

```bash
sudo systemctl enable --now vigild
```

Vigil is now watching your filesystem in real-time.

Verify it's running:

```bash
vigil status
```

## What now?

- Got an alert? See [Cookbook](COOKBOOK.md#i-got-an-alert-what-do-i-do).
- Package update coming? See [Cookbook](COOKBOOK.md#package-updates).
- Want to tune watch paths? See [Configuration](CONFIGURATION.md#watch-groups).
- Curious how it works? See [Principles](PRINCIPLES.md).
