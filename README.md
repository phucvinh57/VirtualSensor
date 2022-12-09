# Virtual sensor (refactor version)

## Prerequisites

* `docker` v20.10.21
* `docker-compose` v1.29.2
* `rustc` v1.64.0
* `rustup` v1.25.1
* `cargo` v1.64.0

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

Third, copy `.env.example` to `.env` then modify redis/kafka connection url.

```bash
cp .env.example .env
```

Finally, run `sensor` with root permission and a config file. If config file's path is not specified, `config.toml` is selected as default.

```make
./sensor [:Your config file.toml>]
```

You can use `SampleConfig.toml` as a config template.

## Configs description

* `old_kernel`: kernel's version is under 4.1 or not
* `capture_size_limit`
* `capture_thread_receive_timeout`: in nano seconds
* `control_command_receive_timeout`: in nano seconds
* `cpu_to_capture`: Cpu string to capture, this only affect task dead event, but need to be larger than total cpu so thing works correctly. The string also need to be smaller than 32 characters
* `dev_flag`: If true, sensor will write data to a file named `result.json`, otherwise publish data to kafka
* `publish_msg_interval`: Time interval for publishing data to kafka
* `monitor_targets`: Array
  * `container_name`
  * `pid_list`
* `filter`: Filter rules for reading data. If an attribute in filter is set to false, for example `unit_timestamp` = `false`, the read data will not have field `unit_timestamp` in its body.

## Program description

The main process has two threads.

* A thread subscribes to redis to listen configuration changes.
  * If it receives a message, it will change the configs in runtime and then save to config file.
  * The message body must have format like `sampleConfig.json`. If not, an error will be returned.
  * Currently, the topic is hardcode `/update/config/1915940`
* Another thread reads monitoring data and sends to kafka every `publish_msg_interval` seconds. Currently, the topic is hardcode `/monitoring/1915940`
