package common

import "testing"

// TestCoinToBaseUnits verifies WH-M4: conversion rounds to the nearest base unit
// rather than truncating.
func TestCoinToBaseUnits(t *testing.T) {
	cases := []struct {
		in   float64
		want int64
	}{
		{1.0, 100000000},
		{1.5, 150000000},
		{0.29, 29000000}, // truncation used to yield 28999999
		{0.00000001, 1},
		{0, 0},
	}
	for _, c := range cases {
		if got := CoinToBaseUnits(c.in); got != c.want {
			t.Fatalf("CoinToBaseUnits(%v) = %d, want %d", c.in, got, c.want)
		}
	}
}
