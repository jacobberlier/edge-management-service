package main

import (
	"flag"
	"go.uber.org/zap"

	"github.build.ge.com/PredixEdgeOS/management-service/config"
	"github.build.ge.com/PredixEdgeOS/management-service/handlers"
)

var zapstd, _ = zap.NewProduction()

func main() {
	logger := zapstd.Sugar()
	defer logger.Sync() // flushes buffer, if any
	var path string
	flag.StringVar(&path, "config", "", "Configuration file path")
	flag.Parse()
	logger.Debugf("location config: ", path+"/ecs.json")

	var cfg config.Config
	var err error
	if path != "" {
		file := path + "/ecs.json"
		if cfg, err = config.NewConfig(file); err != nil {
			logger.Fatalf("Error loading config: %s", err)
		}
		if "" == cfg.UnixSocketPath {
			logger.Fatalf("Unix Domain Socket must be specified: %s", err)
		}
		logger.Debugf("Starting handlers...")
		handlers.Start(cfg)
	} else {
		flag.Usage()
	}
}
