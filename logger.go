package vrrp

import (
	"github.com/sirupsen/logrus"
)

var logger *logrus.Logger

func init() {
	logger = logrus.New()
	logger.SetLevel(logrus.DebugLevel)
}

func SetLogLevel(level logrus.Level) {
	logger.SetLevel(level)
}
