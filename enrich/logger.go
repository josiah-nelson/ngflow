package enrich

import "github.com/sirupsen/logrus"

var log = logrus.New()

func SetLogger(l *logrus.Logger) {
	if l != nil {
		log = l
	}
}
