# f660-stats-exporter

This is a Prometheus exporter for ZTE F660 GPON ONT Router.

It scrapes the Web UI and exports the scraped data for Prometheus.

## Compiling

```
mkdir build/
go build -o build/f660-exporter *.go
```

## Usage

```
usage: f660-exporter [<flags>]

Flags:
  -h, --help               Show context-sensitive help (also try --help-long and --help-man).
      --web.listen-address=":9161"  
                           Address to listen on for web interface and telemetry.
      --web.telemetry-path="/metrics"  
                           Path under which to expose metrics.
      --f660.host="http://192.168.1.1/"  
                           ZTE F660 Router host
      --f660.user="user"   User for logging into admin panel
      --f660.pass="user"   User password
      --log.level=info     Only log messages with the given severity or above. One of: [debug, info, warn, error]
      --log.format=logfmt  Output format of log messages. One of: [logfmt, json]
      --version            Show application version.
```
