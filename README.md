# pbgopy
[![Release](https://img.shields.io/github/release/nakabonne/pbgopy.svg?color=orange&style=flat-square)](https://github.com/nakabonne/pbgopy/releases/latest)
[![go.dev reference](https://img.shields.io/badge/go.dev-reference-007d9c?logo=go&logoColor=white&style=flat-square)](https://pkg.go.dev/mod/github.com/nakabonne/pbgopy?tab=packages)

`pbgopy` acts like [pbcopy/pbpaste](https://www.unix.com/man-page/osx/1/pbcopy/) but for multiple devices. It lets you share data across devices like you copy and paste.

![Demo](assets/demo.gif)

## Installation
Binary releases are available through [here](https://github.com/nakabonne/pbgopy/releases).

#### MacOS

```
brew install nakabonne/pbgopy/pbgopy
```

#### RHEL/CentOS

```
rpm -ivh https://github.com/nakabonne/pbgopy/releases/download/v0.2.0/pbgopy_0.2.0_linux_amd64.rpm
```

#### Debian/Ubuntu

```
wget https://github.com/nakabonne/pbgopy/releases/download/v0.2.0/pbgopy_0.2.0_linux_amd64.deb
apt install ./pbgopy_0.2.0_linux_amd64.deb
```

#### Arch Linux

AUR package is available: [pbgopy](https://aur.archlinux.org/packages/pbgopy/)

```
yay pbgopy
```

#### Nix

```
nix-shell -p nixpkgs.pbgopy
```

#### Go

```
go get github.com/nakabonne/pbgopy
```

#### Docker

```
docker run --rm nakabonne/pbgopy pbgopy help
```

## Usage
First up, you start the pbgopy server which works as a shared clipboard for devices. It listens on port 9090 by default.
You must allow access to this port for each device you want to share data with.

```bash
pbgopy serve
```

Populate the address of the host where the above process is running into the `PBGOPY_SERVER` environment variable. Then put the data entered in STDIN into the server with:

```bash
export PBGOPY_SERVER=http://host.xz:9090
pbgopy copy <foo.png
```

Paste it on another device with:

```bash
export PBGOPY_SERVER=http://host.xz:9090
pbgopy paste >foo.png
```


### End-to-end encryption
`pbgopy` comes with a built-in ability to encrypt/decrypt with a common key, hence allows you to perform end-to-end encryption without working with external tools.

```bash
pbgopy copy -p your-password <secret.txt
```

Then decrypt with the same password:

```bash
pbgopy paste -p your-password
```

### Authentication
You can perform a minimum of authentication via an HTTP Basic Authentication.

```bash
pbgopy serve -a user:pass
```

```bash
pbgopy copy -a user:pass <foo.png
```

```bash
pbgopy paste -a user:pass >foo.png
```

### TTL
You can set TTL for the cache. Give `0s` for disabling it. Default is `24h`.

```bash
pbgopy serve --ttl 10m
```

## Inspired By
- [nwtgck/piping-server](https://github.com/nwtgck/piping-server)
- [bradwood/glsnip](https://github.com/bradwood/glsnip)
