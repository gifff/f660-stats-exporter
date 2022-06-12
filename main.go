package main

import (
	"net/http"
	"net/http/cookiejar"
	"os"
	"strings"

	"github.com/gifff/f660-stats-exporter/scraper"
	"github.com/go-kit/log/level"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/common/promlog"
	"github.com/prometheus/common/promlog/flag"
	"github.com/prometheus/common/version"
	"github.com/prometheus/exporter-toolkit/web"
	"gopkg.in/alecthomas/kingpin.v2"
)

func main() {
	var (
		listenAddress = kingpin.Flag("web.listen-address", "Address to listen on for web interface and telemetry.").Default(":9161").String()
		metricsPath   = kingpin.Flag("web.telemetry-path", "Path under which to expose metrics.").Default("/metrics").String()
		host          = kingpin.Flag("f660.host", "ZTE F660 Router host").Default("http://192.168.1.1/").String()
		user          = kingpin.Flag("f660.user", "User for logging into admin panel").Default("user").String()
		pass          = kingpin.Flag("f660.pass", "User password").Default("user").String()
	)
	promlogConfig := &promlog.Config{}
	flag.AddFlags(kingpin.CommandLine, promlogConfig)
	kingpin.Version(version.Print("f660_exporter"))
	kingpin.HelpFlag.Short('h')
	kingpin.Parse()

	logger := promlog.New(promlogConfig)

	// host must end with '/'
	baseURL := *host
	if !strings.HasSuffix(baseURL, "/") {
		baseURL = baseURL + "/"
	}

	cj, err := cookiejar.New(nil)
	if err != nil {
		level.Error(logger).Log("msg", "Error starting HTTP server", "err", err)

		os.Exit(1)
	}

	scrpr := &scraper.Scraper{
		BaseURL:   baseURL,
		CookieJar: cj,

		User: *user,
		Pass: *pass,
	}
	exporter := NewExporter(scrpr)
	prometheus.MustRegister(exporter)
	prometheus.MustRegister(version.NewCollector("f660_exporter"))

	http.Handle(*metricsPath, promhttp.Handler())
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<html>
             <head><title>ZTE F660 Exporter</title></head>
             <body>
             <h1>ZTE F660 Exporter</h1>
             <p><a href='` + *metricsPath + `'>Metrics</a></p>
             </body>
             </html>`))
	})
	srv := &http.Server{Addr: *listenAddress}
	if err := web.ListenAndServe(srv, "", logger); err != nil {
		level.Error(logger).Log("msg", "Error starting HTTP server", "err", err)

		os.Exit(1)
	}
}
