# pbgopy
`pbgopy` acts like [pbcopy/pbpaste](https://www.unix.com/man-page/osx/1/pbcopy/) but for multiple devices. It lets you share data across devices like you copy and paste.

## Installation
Binary releases are available through [here](https://github.com/nakabonne/pbgopy/releases).

## Usage
First up, you start the pbgopy server, which acts as a shared clipboard for devices. It listens on port 9090 by default.

```bash
pbgopy serve
```

Put the address of the host where the `pbgopy serve` process is running into `PBGOPY_SERVER` environment variable.

```bash
export PBGOPY_SERVER=http://192.168.11.5:9090
pbgopy copy <foo.png
```

Then paste it on another device:

```bash
export PBGOPY_SERVER=http://192.168.11.5:9090
pbgopy paste >foo.png
```

### TTL
You can set TTL for the cache. Give `0s` for disabling it. Default is `24h`.

```bash
pbgopy serve --ttl 10m
```

### End-to-end encryption
This tool aims to share data quickly, even if it's done in insecure communication, hence it doesn't come with the ability to communicate securely.
If you want end-to-end encryption, work with external tools. For instance, with openssl:

```bash
echo hello | openssl aes-256-cbc -e | pbgopy copy
```

Then decrypt the pasted one:

```bash
pbgopy paste | openssl aes-256-cbc -d
```

## Inspired By
- [nwtgck/piping-server](https://github.com/nwtgck/piping-server)
- [bradwood/glsnip](https://github.com/bradwood/glsnip)
