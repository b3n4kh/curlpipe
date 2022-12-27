# Curlpipe

Heavily inspired by https://www.idontplaydarts.com/2016/04/detecting-curl-pipe-bash-server-side/ from @Phil

## Usage

Bash:
```bash
python -m pip install -e .
python -m curlpipe
```

Docker:
```bash
docker run --name curlpipe --rm -it -p 127.0.0.1:5555:5555 ghcr.io/b3n4kh/curlpipe
```

Compose:
```bash
docker-compose up -d
```

### Configuration

Can be configured via Environment variables, following is a complete list and their defaults:

`HOST=0.0.0.0`
`PORT=5555`
`SOCKET_TIMEOUT=10`
`BUFFER_SIZE=87380`
`MAX_PADDING=32`
`SCRIPTS_DIR="scripts/"`
