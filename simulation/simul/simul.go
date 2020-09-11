package main

import (
	// Service needs to be imported here to be instantiated.
	_ "github.com/csanti/fbft-bench/simulation"
	"github.com/csanti/onet/simul"
)

func main() {
	simul.Start()
}
