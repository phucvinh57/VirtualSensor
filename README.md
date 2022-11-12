# Virtual sensor (refactor version)

## Prerequisites

- `docker` v20.10.21
- `docker-compose` v1.29.2
- `rustc` v1.64.0
- `rustup` v1.25.1
- `cargo` v1.64.0

Visit these links to install [docker](https://docs.docker.com/engine/install/ubuntu/), [docker-compose](https://docs.docker.com/compose/install/other/) and [rust toolchain](https://www.rust-lang.org/tools/install).

## Init project

First, set up kafka & redis:

```bash
docker-compose up -d
```

Second, build a project to binary executable file named `sensor`:

```make
make build
```

Finally, run `sensor` with root permission and a config file.

```make
sudo ./sensor <Your config file.toml>
```

You can use `SampleConfig.toml` as a config template.

## Configs description


