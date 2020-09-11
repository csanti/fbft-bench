package main_test

import (
	"testing"

	"github.com/csanti/onet/log"
	"github.com/csanti/onet/simul"
)

func TestMain(m *testing.M) {
	log.MainTest(m)
}

func TestSimulation(t *testing.T) {
	simul.Start("test.toml")
}
