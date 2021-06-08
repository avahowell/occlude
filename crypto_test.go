package occlude

import (
	"errors"
	"fmt"
	"math/big"
	"testing"
	"time"

	ristretto "github.com/gtank/ristretto255"
)

func timingAnalysis(a func(), b func(), n int) error {
	type timingData struct {
		a []time.Duration
		b []time.Duration
	}
	t := timingData{}
	for i := 0; i < n; i++ {
		s := time.Now()
		a()
		t.a = append(t.a, time.Since(s))
		s = time.Now()
		b()
		t.b = append(t.b, time.Since(s))
	}
	var sumA time.Duration
	var sumB time.Duration
	for i := range t.a {
		sumA += t.a[i]
		sumB += t.b[i]
	}
	sumA /= time.Duration(len(t.a))
	sumB /= time.Duration(len(t.b))
	fmt.Printf("average runtime duration: A: %v, B: %v, delta %v\n", sumA, sumB, sumA-sumB)

	var diff time.Duration
	if sumA > sumB {
		diff = sumA - sumB
	} else {
		diff = sumB - sumA
	}
	diff /= (sumA + sumB) / 2
	diff *= 100

	fmt.Println(diff)
	if diff > 1 {
		return errors.New("non constant time")
	}
	return nil
}

// Verify that crucial group operations are constant-time.
func TestRistrettoTiming(t *testing.T) {
	// test scalar mult
	x1 := randomScalar()
	x2 := randomScalar()
	f1 := func() {
		new(ristretto.Element).ScalarBaseMult(x1)
	}
	f2 := func() {
		new(ristretto.Element).ScalarBaseMult(x2)
	}
	t.Log(timingAnalysis(f1, f2, 10000))
	x3 := new(ristretto.Scalar).Zero()
	x4 := randomScalar()
	f3 := func() {
		new(ristretto.Scalar).Multiply(x4, x4)
	}
	f4 := func() {
		new(ristretto.Scalar).Multiply(x3, x3)
	}
	t.Log(timingAnalysis(f3, f4, 10000))

	b0 := new(big.Int).SetInt64(0)
	b1, _ := new(big.Int).SetString("211", 10)
	b2, _ := new(big.Int).SetString("123936747564", 10)
	b3, _ := new(big.Int).SetString("1928371298376128370", 10)

	f1 = func() {
		new(big.Int).Exp(b0, b2, b3)
	}
	f2 = func() {
		new(big.Int).Exp(b1, b3, b3)
	}
	f3 = func() {
		new(big.Int).Exp(b2, b1, b3)
	}
	f4 = func() {
		new(big.Int).Exp(b0, b0, b3)
	}
	t.Log(timingAnalysis(f1, f2, 10000))
	t.Log(timingAnalysis(f2, f3, 10000))
	t.Log(timingAnalysis(f3, f4, 10000))
}
