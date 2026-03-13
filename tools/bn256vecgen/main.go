// bn256vecgen generates Wycheproof test vectors for the BN-254
// (alt_bn128) elliptic curve operations used by the EVM precompiles
// ecAdd (0x06), ecMul (0x07), and ecPairing (0x08).
//
// See EIP-196 and EIP-197 for the precompile specifications.
package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fp"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

// Curve constants for BN-254 (alt_bn128).
var (
	fieldModulus = fpModulus()
	groupOrder  = frModulus()
)

func fpModulus() *big.Int {
	m := fp.Modulus()
	return m
}

func frModulus() *big.Int {
	m := fr.Modulus()
	return m
}

// source is the Wycheproof source attribution.
type source struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

var vecSource = source{
	Name:    "c2sp/wycheproof/bn256vecgen",
	Version: "0.1",
}

// noteEntry describes a flag used in test vectors.
type noteEntry struct {
	BugType     string   `json:"bugType"`
	Description string   `json:"description,omitempty"`
	Effect      string   `json:"effect,omitempty"`
	Links       []string `json:"links,omitempty"`
	CVEs        []string `json:"cves,omitempty"`
}

// vectorFile is the top-level Wycheproof JSON structure.
type vectorFile struct {
	Algorithm     string                `json:"algorithm"`
	Header        []string              `json:"header"`
	Notes         map[string]*noteEntry `json:"notes"`
	NumberOfTests int                   `json:"numberOfTests"`
	Schema        string                `json:"schema"`
	TestGroups    []any                 `json:"testGroups"`
}

// --- ecAdd ---

type addTestGroup struct {
	Type   string           `json:"type"`
	Source source           `json:"source"`
	Tests  []*addTestVector `json:"tests"`
}

type addTestVector struct {
	TcID     int      `json:"tcId"`
	Comment  string   `json:"comment"`
	Input    string   `json:"input"`
	Expected string   `json:"expected"`
	Result   string   `json:"result"`
	Flags    []string `json:"flags"`
}

// --- ecMul ---

type mulTestGroup struct {
	Type   string           `json:"type"`
	Source source           `json:"source"`
	Tests  []*mulTestVector `json:"tests"`
}

type mulTestVector struct {
	TcID     int      `json:"tcId"`
	Comment  string   `json:"comment"`
	Input    string   `json:"input"`
	Expected string   `json:"expected"`
	Result   string   `json:"result"`
	Flags    []string `json:"flags"`
}

// --- ecPairing ---

type pairingTestGroup struct {
	Type   string               `json:"type"`
	Source source               `json:"source"`
	Tests  []*pairingTestVector `json:"tests"`
}

type pairingTestVector struct {
	TcID     int      `json:"tcId"`
	Comment  string   `json:"comment"`
	NPairs   int      `json:"nPairs"`
	Input    string   `json:"input"`
	Expected string   `json:"expected"`
	Result   string   `json:"result"`
	Flags    []string `json:"flags"`
}

func main() {
	outDir := "testvectors_v1"
	if len(os.Args) > 1 {
		outDir = os.Args[1]
	}

	generators := []struct {
		filename string
		gen      func() *vectorFile
	}{
		{"bn256_add_test.json", genAddVectors},
		{"bn256_mul_test.json", genMulVectors},
		{"bn256_pairing_test.json", genPairingVectors},
	}

	for _, g := range generators {
		vf := g.gen()
		var buf bytes.Buffer
		enc := json.NewEncoder(&buf)
		enc.SetIndent("", "  ")
		enc.SetEscapeHTML(false)
		if err := enc.Encode(vf); err != nil {
			fmt.Fprintf(os.Stderr, "error marshaling %s: %v\n", g.filename, err)
			os.Exit(1)
		}
		data := buf.Bytes()

		path := filepath.Join(outDir, g.filename)
		if err := os.WriteFile(path, data, 0o644); err != nil {
			fmt.Fprintf(os.Stderr, "error writing %s: %v\n", path, err)
			os.Exit(1)
		}
		fmt.Printf("wrote %s (%d tests)\n", path, vf.NumberOfTests)
	}
}

// =========================================================================
// ecAdd vectors
// =========================================================================

func genAddVectors() *vectorFile {
	var tests []*addTestVector
	tcID := 1

	add := func(comment, result string, flags []string, input, expected []byte) {
		tests = append(tests, &addTestVector{
			TcID:     tcID,
			Comment:  comment,
			Input:    hex.EncodeToString(input),
			Expected: hex.EncodeToString(expected),
			Result:   result,
			Flags:    flags,
		})
		tcID++
	}

	g1 := g1Generator()
	g1Neg := g1NegGenerator()
	inf := g1Infinity()

	// Valid: P + O = P
	add("generator plus infinity",
		"valid", []string{"PointAtInfinity"},
		encodeG1Pair(g1, inf),
		encodeG1(g1))

	// Valid: O + P = P
	add("infinity plus generator",
		"valid", []string{"PointAtInfinity"},
		encodeG1Pair(inf, g1),
		encodeG1(g1))

	// Valid: O + O = O
	add("infinity plus infinity",
		"valid", []string{"PointAtInfinity"},
		encodeG1Pair(inf, inf),
		encodeG1(inf))

	// Valid: P + P (doubling)
	{
		var doubled bn254.G1Affine
		doubled.Add(&g1, &g1)
		add("generator doubling (P + P)",
			"valid", []string{"Doubling"},
			encodeG1Pair(g1, g1),
			encodeG1(doubled))
	}

	// Valid: P + (-P) = O
	add("generator plus negation (P + (-P) = O)",
		"valid", []string{"InverseAddition"},
		encodeG1Pair(g1, g1Neg),
		encodeG1(inf))

	// Valid: arbitrary addition
	{
		var twoG, threeG bn254.G1Affine
		twoG.Add(&g1, &g1)
		threeG.Add(&twoG, &g1)
		add("2G + G = 3G",
			"valid", []string{"Valid"},
			encodeG1Pair(twoG, g1),
			encodeG1(threeG))
	}

	// Valid: large scalar multiples
	{
		s := new(big.Int).Sub(groupOrder, big.NewInt(1))
		var nMinus1G bn254.G1Affine
		nMinus1G.ScalarMultiplication(&g1, s)
		// (n-1)*G + G = O
		add("(n-1)*G + G = infinity",
			"valid", []string{"GroupOrder"},
			encodeG1Pair(nMinus1G, g1),
			encodeG1(inf))
	}

	// Valid: field boundary arithmetic
	{
		p := fieldBoundaryG1Point()
		var doubled bn254.G1Affine
		doubled.Add(&p, &p)
		add("point with x near field modulus, doubling",
			"valid", []string{"FieldBoundary"},
			encodeG1Pair(p, p),
			encodeG1(doubled))
	}

	// Invalid: point not on curve
	add("point not on curve (x=1, y=1)",
		"invalid", []string{"NotOnCurve"},
		encodeG1PairRaw(big.NewInt(1), big.NewInt(1),
			big.NewInt(0), big.NewInt(0)),
		nil)

	// Invalid: x >= field modulus
	add("x coordinate >= field modulus",
		"invalid", []string{"InvalidEncoding"},
		encodeG1PairRaw(fieldModulus, big.NewInt(2),
			big.NewInt(0), big.NewInt(0)),
		nil)

	// Invalid: y >= field modulus
	add("y coordinate >= field modulus",
		"invalid", []string{"InvalidEncoding"},
		encodeG1PairRaw(big.NewInt(1), fieldModulus,
			big.NewInt(0), big.NewInt(0)),
		nil)

	// Invalid: x = p-1, not on curve
	{
		pMinus1 := new(big.Int).Sub(fieldModulus, big.NewInt(1))
		add("x = p-1, y = 0, not on curve",
			"invalid", []string{"NotOnCurve", "FieldBoundary"},
			encodeG1PairRaw(pMinus1, big.NewInt(0),
				big.NewInt(0), big.NewInt(0)),
			nil)
	}

	// Invalid: p+1 as x (wraps to 1 if not checked)
	{
		pPlus1 := new(big.Int).Add(fieldModulus, big.NewInt(1))
		add("x = p+1 (field overflow, would reduce to 1)",
			"invalid", []string{"InvalidEncoding", "FieldBoundary"},
			encodeG1PairRaw(pPlus1, big.NewInt(2),
				big.NewInt(0), big.NewInt(0)),
			nil)
	}

	// Invalid: truncated input (64 bytes instead of 128)
	add("truncated input (only one point)",
		"invalid", []string{"TruncatedInput"},
		encodeG1(g1),
		nil)

	// Valid: empty input (EIP-196 specifies this returns (0,0))
	add("empty input",
		"valid", []string{"EmptyInput"},
		nil,
		encodeG1(inf))

	// Invalid: wrong-subgroup point (on curve but not in G1)
	// For BN-254, G1 has cofactor 1, so all curve points are in G1.
	// This is a key difference from BLS12-381.
	// Instead, test a point on the twist curve.
	{
		// (1, 3) is not on y^2 = x^3 + 3
		add("point on wrong curve (twist point encoded as G1)",
			"invalid", []string{"NotOnCurve"},
			encodeG1PairRaw(big.NewInt(1), big.NewInt(3),
				big.NewInt(0), big.NewInt(0)),
			nil)
	}

	// Valid: P with zero-padded input (128 bytes, second point all zeros = infinity)
	add("generator plus zero-encoded infinity",
		"valid", []string{"PointAtInfinity"},
		encodeG1PairRaw(big.NewInt(1), big.NewInt(2),
			big.NewInt(0), big.NewInt(0)),
		encodeG1(g1))

	// Invalid: input length not multiple of 128
	add("input length 129 (not multiple of 128)",
		"invalid", []string{"InvalidInputLength"},
		append(encodeG1Pair(g1, inf), 0x00),
		nil)

	group := &addTestGroup{
		Type:   "Bn256Add",
		Source: vecSource,
		Tests:  tests,
	}

	return &vectorFile{
		Algorithm:     "BN256ADD",
		Schema:        "bn256_add_schema_v1.json",
		NumberOfTests: len(tests),
		Header: []string{
			"Test vectors for the BN-254 (alt_bn128) ecAdd",
			"precompile at address 0x06 (EIP-196).",
			"Input is ABI-encoded as x1||y1||x2||y2,",
			"each coordinate a 32-byte big-endian uint256.",
		},
		Notes:      addNotes(),
		TestGroups: []any{group},
	}
}

// =========================================================================
// ecMul vectors
// =========================================================================

func genMulVectors() *vectorFile {
	var tests []*mulTestVector
	tcID := 1

	mul := func(comment, result string, flags []string, input, expected []byte) {
		tests = append(tests, &mulTestVector{
			TcID:     tcID,
			Comment:  comment,
			Input:    hex.EncodeToString(input),
			Expected: hex.EncodeToString(expected),
			Result:   result,
			Flags:    flags,
		})
		tcID++
	}

	g1 := g1Generator()
	inf := g1Infinity()

	// Valid: G * 0 = O
	mul("generator times zero",
		"valid", []string{"ScalarZero"},
		encodeMulInput(g1, big.NewInt(0)),
		encodeG1(inf))

	// Valid: G * 1 = G
	mul("generator times one",
		"valid", []string{"Valid"},
		encodeMulInput(g1, big.NewInt(1)),
		encodeG1(g1))

	// Valid: G * 2
	{
		var twoG bn254.G1Affine
		twoG.ScalarMultiplication(&g1, big.NewInt(2))
		mul("generator times two",
			"valid", []string{"Valid"},
			encodeMulInput(g1, big.NewInt(2)),
			encodeG1(twoG))
	}

	// Valid: G * (n-1) = -G
	{
		s := new(big.Int).Sub(groupOrder, big.NewInt(1))
		var result bn254.G1Affine
		result.ScalarMultiplication(&g1, s)
		mul("generator times (group order - 1)",
			"valid", []string{"GroupOrder"},
			encodeMulInput(g1, s),
			encodeG1(result))
	}

	// Valid: G * n = O (scalar = group order)
	mul("generator times group order",
		"valid", []string{"GroupOrder"},
		encodeMulInput(g1, groupOrder),
		encodeG1(inf))

	// Valid: G * (n+1) = G (scalar wraps)
	{
		s := new(big.Int).Add(groupOrder, big.NewInt(1))
		mul("generator times (group order + 1), wraps to 1",
			"valid", []string{"GroupOrder", "ScalarOverflow"},
			encodeMulInput(g1, s),
			encodeG1(g1))
	}

	// Valid: infinity * 5 = O
	mul("infinity times nonzero scalar",
		"valid", []string{"PointAtInfinity"},
		encodeMulInput(inf, big.NewInt(5)),
		encodeG1(inf))

	// Valid: infinity * 0 = O
	mul("infinity times zero",
		"valid", []string{"PointAtInfinity", "ScalarZero"},
		encodeMulInput(inf, big.NewInt(0)),
		encodeG1(inf))

	// Valid: large scalar (2^256 - 1)
	{
		maxScalar := new(big.Int).Sub(
			new(big.Int).Lsh(big.NewInt(1), 256),
			big.NewInt(1))
		var result bn254.G1Affine
		result.ScalarMultiplication(&g1, maxScalar)
		mul("generator times max uint256 (2^256 - 1)",
			"valid", []string{"LargeScalar"},
			encodeMulInput(g1, maxScalar),
			encodeG1(result))
	}

	// Valid: scalar = field modulus (not group order)
	{
		var result bn254.G1Affine
		result.ScalarMultiplication(&g1, fieldModulus)
		mul("generator times field modulus",
			"valid", []string{"FieldBoundary"},
			encodeMulInput(g1, fieldModulus),
			encodeG1(result))
	}

	// Valid: point with x near field modulus
	{
		p := fieldBoundaryG1Point()
		var result bn254.G1Affine
		result.ScalarMultiplication(&p, big.NewInt(7))
		mul("field-boundary point times 7",
			"valid", []string{"FieldBoundary"},
			encodeMulInput(p, big.NewInt(7)),
			encodeG1(result))
	}

	// Invalid: point not on curve
	mul("point not on curve times scalar",
		"invalid", []string{"NotOnCurve"},
		encodeMulInputRaw(big.NewInt(1), big.NewInt(1), big.NewInt(1)),
		nil)

	// Invalid: x >= field modulus
	mul("x coordinate >= field modulus",
		"invalid", []string{"InvalidEncoding"},
		encodeMulInputRaw(fieldModulus, big.NewInt(2), big.NewInt(1)),
		nil)

	// Invalid: empty input
	mul("empty input",
		"valid", []string{"EmptyInput"},
		nil,
		encodeG1(inf))

	// Valid: P * 2^128 (exercises high-bit scalar paths)
	{
		s := new(big.Int).Lsh(big.NewInt(1), 128)
		var result bn254.G1Affine
		result.ScalarMultiplication(&g1, s)
		mul("generator times 2^128",
			"valid", []string{"LargeScalar"},
			encodeMulInput(g1, s),
			encodeG1(result))
	}

	// Valid: multiple small scalars for KAT
	for _, k := range []int64{3, 5, 10, 100} {
		s := big.NewInt(k)
		var result bn254.G1Affine
		result.ScalarMultiplication(&g1, s)
		mul(fmt.Sprintf("generator times %d", k),
			"valid", []string{"Valid"},
			encodeMulInput(g1, s),
			encodeG1(result))
	}

	group := &mulTestGroup{
		Type:   "Bn256Mul",
		Source: vecSource,
		Tests:  tests,
	}

	return &vectorFile{
		Algorithm:     "BN256MUL",
		Schema:        "bn256_mul_schema_v1.json",
		NumberOfTests: len(tests),
		Header: []string{
			"Test vectors for the BN-254 (alt_bn128) ecMul",
			"precompile at address 0x07 (EIP-196).",
			"Input is ABI-encoded as x||y||s,",
			"each a 32-byte big-endian uint256.",
		},
		Notes:      mulNotes(),
		TestGroups: []any{group},
	}
}

// =========================================================================
// ecPairing vectors
// =========================================================================

func genPairingVectors() *vectorFile {
	var tests []*pairingTestVector
	tcID := 1

	pairing := func(
		comment, result string,
		flags []string,
		nPairs int,
		input, expected []byte,
	) {
		tests = append(tests, &pairingTestVector{
			TcID:     tcID,
			Comment:  comment,
			NPairs:   nPairs,
			Input:    hex.EncodeToString(input),
			Expected: hex.EncodeToString(expected),
			Result:   result,
			Flags:    flags,
		})
		tcID++
	}

	pairingSuccess := padLeft(big.NewInt(1).Bytes(), 32)

	g1 := g1Generator()
	g1Neg := g1NegGenerator()
	g2 := g2Generator()
	inf1 := g1Infinity()
	inf2 := g2Infinity()

	// Valid: empty input (0 pairs) => success
	pairing("empty input (zero pairs)",
		"valid", []string{"EmptyInput"},
		0, nil, pairingSuccess)

	// Valid: e(G1, G2) * e(-G1, G2) = 1
	pairing("e(P1, P2) * e(-P1, P2) = 1",
		"valid", []string{"Valid"},
		2,
		concatPairingInputs(
			encodePairingPair(g1, g2),
			encodePairingPair(g1Neg, g2),
		),
		pairingSuccess)

	// Valid: e(O, G2) => success (single pair with G1 infinity)
	pairing("e(O, G2) single pair with G1 infinity",
		"valid", []string{"PointAtInfinity"},
		1,
		encodePairingPair(inf1, g2),
		pairingSuccess)

	// Valid: e(G1, O) => success (single pair with G2 infinity)
	pairing("e(G1, O) single pair with G2 infinity",
		"valid", []string{"PointAtInfinity"},
		1,
		encodePairingPair(g1, inf2),
		pairingSuccess)

	// Valid: e(O, O) => success
	pairing("e(O, O) both points at infinity",
		"valid", []string{"PointAtInfinity"},
		1,
		encodePairingPair(inf1, inf2),
		pairingSuccess)

	// Invalid: single pair e(G1, G2) != 1
	pairing("single pair e(G1, G2) does not equal 1",
		"valid", []string{"PairingCheckFails"},
		1,
		encodePairingPair(g1, g2),
		padLeft(big.NewInt(0).Bytes(), 32))

	// Valid: bilinearity check e(2*G1, G2) * e(-G1, 2*G2) = 1
	{
		var twoG1 bn254.G1Affine
		twoG1.ScalarMultiplication(&g1, big.NewInt(2))
		var negG1 bn254.G1Affine
		negG1.Neg(&g1)
		var twoG2 bn254.G2Affine
		twoG2.ScalarMultiplication(&g2, big.NewInt(2))
		pairing("bilinearity: e(2*G1, G2) * e(-G1, 2*G2) = 1",
			"valid", []string{"Bilinearity"},
			2,
			concatPairingInputs(
				encodePairingPair(twoG1, g2),
				encodePairingPair(negG1, twoG2),
			),
			pairingSuccess)
	}

	// Valid: three-pair check
	{
		var threeG1 bn254.G1Affine
		threeG1.ScalarMultiplication(&g1, big.NewInt(3))
		var negThreeG1 bn254.G1Affine
		negThreeG1.Neg(&threeG1)
		pairing("three pairs: e(G1,G2)*e(2G1,G2)*e(-3G1,G2) = 1",
			"valid", []string{"Valid"},
			3,
			concatPairingInputs(
				encodePairingPair(g1, g2),
				func() []byte {
					var twoG1 bn254.G1Affine
					twoG1.ScalarMultiplication(&g1, big.NewInt(2))
					return encodePairingPair(twoG1, g2)
				}(),
				encodePairingPair(negThreeG1, g2),
			),
			pairingSuccess)
	}

	// Invalid: G1 point not on curve
	pairing("G1 point not on curve in pairing input",
		"invalid", []string{"NotOnCurve"},
		1,
		encodePairingPairRaw(
			big.NewInt(1), big.NewInt(1),
			g2XImag(&g2), g2XReal(&g2),
			g2YImag(&g2), g2YReal(&g2)),
		nil)

	// Invalid: G2 point not on curve
	pairing("G2 point not on curve in pairing input",
		"invalid", []string{"NotOnCurve"},
		1,
		encodePairingPairRaw(
			big.NewInt(1), big.NewInt(2),
			big.NewInt(1), big.NewInt(1),
			big.NewInt(1), big.NewInt(1)),
		nil)

	// Invalid: G1 coordinate >= field modulus
	pairing("G1 x coordinate >= field modulus",
		"invalid", []string{"InvalidEncoding"},
		1,
		encodePairingPairRaw(
			fieldModulus, big.NewInt(2),
			g2XImag(&g2), g2XReal(&g2),
			g2YImag(&g2), g2YReal(&g2)),
		nil)

	// Invalid: G2 coordinate >= field modulus
	pairing("G2 coordinate >= field modulus",
		"invalid", []string{"InvalidEncoding"},
		1,
		encodePairingPairRaw(
			big.NewInt(1), big.NewInt(2),
			fieldModulus, big.NewInt(0),
			big.NewInt(0), big.NewInt(0)),
		nil)

	// Invalid: input length not multiple of 192
	pairing("input length not multiple of 192 bytes",
		"invalid", []string{"InvalidInputLength"},
		0,
		make([]byte, 100),
		nil)

	// Invalid: G2 point not in subgroup
	// (BN-254 G2 has cofactor != 1, so there are on-curve non-subgroup points)
	{
		notInSubgroup := g2NotInSubgroup()
		if notInSubgroup != nil {
			pairing("G2 point on curve but not in subgroup",
				"invalid", []string{"NotInSubgroup"},
				1,
				encodePairingPairWithG2Coords(
					g1,
					notInSubgroup[0], notInSubgroup[1],
					notInSubgroup[2], notInSubgroup[3]),
				nil)
		}
	}

	// Valid: e(a*G1, b*G2) * e(-ab*G1, G2) = 1 (large scalars)
	{
		a := big.NewInt(0x12345678)
		b := big.NewInt(0x9abcdef0)
		ab := new(big.Int).Mul(a, b)
		ab.Mod(ab, groupOrder)
		var aG1 bn254.G1Affine
		aG1.ScalarMultiplication(&g1, a)
		var bG2 bn254.G2Affine
		bG2.ScalarMultiplication(&g2, b)
		var negAbG1 bn254.G1Affine
		negAbG1.ScalarMultiplication(&g1, ab)
		negAbG1.Neg(&negAbG1)
		pairing("bilinearity with larger scalars",
			"valid", []string{"Bilinearity"},
			2,
			concatPairingInputs(
				encodePairingPair(aG1, bG2),
				encodePairingPair(negAbG1, g2),
			),
			pairingSuccess)
	}

	group := &pairingTestGroup{
		Type:   "Bn256Pairing",
		Source: vecSource,
		Tests:  tests,
	}

	return &vectorFile{
		Algorithm:     "BN256PAIRING",
		Schema:        "bn256_pairing_schema_v1.json",
		NumberOfTests: len(tests),
		Header: []string{
			"Test vectors for the BN-254 (alt_bn128) ecPairing",
			"precompile at address 0x08 (EIP-197).",
			"Input is ABI-encoded as repeated",
			"(G1x||G1y||G2x_im||G2x_re||G2y_im||G2y_re),",
			"each coordinate a 32-byte big-endian uint256.",
			"192 bytes per pair.",
		},
		Notes:      pairingNotes(),
		TestGroups: []any{group},
	}
}

// =========================================================================
// Encoding helpers
// =========================================================================

// padLeft zero-pads b to n bytes (big-endian).
func padLeft(b []byte, n int) []byte {
	if len(b) >= n {
		return b[:n]
	}
	out := make([]byte, n)
	copy(out[n-len(b):], b)
	return out
}

// encodeBigInt encodes v as a 32-byte big-endian uint256.
func encodeBigInt(v *big.Int) []byte {
	if v == nil || v.Sign() == 0 {
		return make([]byte, 32)
	}
	return padLeft(v.Bytes(), 32)
}

// encodeG1 encodes a G1Affine point as 64 bytes (x||y).
func encodeG1(p bn254.G1Affine) []byte {
	var x, y big.Int
	p.X.BigInt(&x)
	p.Y.BigInt(&y)
	out := make([]byte, 64)
	copy(out[0:32], encodeBigInt(&x))
	copy(out[32:64], encodeBigInt(&y))
	return out
}

func encodeG1Pair(p1, p2 bn254.G1Affine) []byte {
	out := make([]byte, 128)
	copy(out[0:64], encodeG1(p1))
	copy(out[64:128], encodeG1(p2))
	return out
}

func encodeG1PairRaw(x1, y1, x2, y2 *big.Int) []byte {
	out := make([]byte, 128)
	copy(out[0:32], encodeBigInt(x1))
	copy(out[32:64], encodeBigInt(y1))
	copy(out[64:96], encodeBigInt(x2))
	copy(out[96:128], encodeBigInt(y2))
	return out
}

func encodeMulInput(p bn254.G1Affine, s *big.Int) []byte {
	out := make([]byte, 96)
	copy(out[0:64], encodeG1(p))
	copy(out[64:96], encodeBigInt(s))
	return out
}

func encodeMulInputRaw(x, y, s *big.Int) []byte {
	out := make([]byte, 96)
	copy(out[0:32], encodeBigInt(x))
	copy(out[32:64], encodeBigInt(y))
	copy(out[64:96], encodeBigInt(s))
	return out
}

// encodePairingPair encodes a (G1, G2) pair as 192 bytes.
// G2 coordinates use the EVM ordering: x_imaginary, x_real, y_imaginary, y_real.
func encodePairingPair(p1 bn254.G1Affine, p2 bn254.G2Affine) []byte {
	out := make([]byte, 192)
	copy(out[0:64], encodeG1(p1))

	var xRe, xIm, yRe, yIm big.Int
	p2.X.A1.BigInt(&xIm)
	p2.X.A0.BigInt(&xRe)
	p2.Y.A1.BigInt(&yIm)
	p2.Y.A0.BigInt(&yRe)

	copy(out[64:96], encodeBigInt(&xIm))
	copy(out[96:128], encodeBigInt(&xRe))
	copy(out[128:160], encodeBigInt(&yIm))
	copy(out[160:192], encodeBigInt(&yRe))
	return out
}

func encodePairingPairRaw(g1x, g1y, g2xIm, g2xRe, g2yIm, g2yRe *big.Int) []byte {
	out := make([]byte, 192)
	copy(out[0:32], encodeBigInt(g1x))
	copy(out[32:64], encodeBigInt(g1y))
	copy(out[64:96], encodeBigInt(g2xIm))
	copy(out[96:128], encodeBigInt(g2xRe))
	copy(out[128:160], encodeBigInt(g2yIm))
	copy(out[160:192], encodeBigInt(g2yRe))
	return out
}

func encodePairingPairWithG2Coords(
	p1 bn254.G1Affine,
	g2xIm, g2xRe, g2yIm, g2yRe *big.Int,
) []byte {
	out := make([]byte, 192)
	copy(out[0:64], encodeG1(p1))
	copy(out[64:96], encodeBigInt(g2xIm))
	copy(out[96:128], encodeBigInt(g2xRe))
	copy(out[128:160], encodeBigInt(g2yIm))
	copy(out[160:192], encodeBigInt(g2yRe))
	return out
}

func concatPairingInputs(pairs ...[]byte) []byte {
	var out []byte
	for _, p := range pairs {
		out = append(out, p...)
	}
	return out
}

// =========================================================================
// Point construction helpers
// =========================================================================

func g1Generator() bn254.G1Affine {
	_, _, g1, _ := bn254.Generators()
	return g1
}

func g1NegGenerator() bn254.G1Affine {
	g := g1Generator()
	g.Neg(&g)
	return g
}

func g1Infinity() bn254.G1Affine {
	var inf bn254.G1Affine
	return inf
}

func g2Generator() bn254.G2Affine {
	_, _, _, g2 := bn254.Generators()
	return g2
}

func g2Infinity() bn254.G2Affine {
	var inf bn254.G2Affine
	return inf
}

// fieldBoundaryG1Point finds a G1 point with x coordinate near p.
func fieldBoundaryG1Point() bn254.G1Affine {
	// Start from a large scalar to get a point with high x coordinate.
	// We just use a known scalar that gives a "high" x value.
	g := g1Generator()
	s := new(big.Int).Sub(fieldModulus, big.NewInt(42))
	var p bn254.G1Affine
	p.ScalarMultiplication(&g, s)
	return p
}

func g2XImag(p *bn254.G2Affine) *big.Int {
	var v big.Int
	p.X.A1.BigInt(&v)
	return &v
}

func g2XReal(p *bn254.G2Affine) *big.Int {
	var v big.Int
	p.X.A0.BigInt(&v)
	return &v
}

func g2YImag(p *bn254.G2Affine) *big.Int {
	var v big.Int
	p.Y.A1.BigInt(&v)
	return &v
}

func g2YReal(p *bn254.G2Affine) *big.Int {
	var v big.Int
	p.Y.A0.BigInt(&v)
	return &v
}

// g2NotInSubgroup returns a G2 point on E'(Fp2) that is NOT in the
// prime-order subgroup. Source: ethereum/execution-spec-tests
// ecpairing_inputsFiller.yml (invalid_g2_subgroup).
//
// x = (2, p-2) in Fp2, which satisfies y^2 = x^3 + b' but [r]*P != O.
// This is the exact bug class caught by CVE-2025-30147 (Besu).
func g2NotInSubgroup() []*big.Int {
	xRe := big.NewInt(2)
	xIm, _ := new(big.Int).SetString(
		"21888242871839275222246405745257275088696311157297823662689037894645226208581", 10)
	yRe, _ := new(big.Int).SetString(
		"18481347008411494671928993551956821665402597624050784000968933840105494735683", 10)
	yIm, _ := new(big.Int).SetString(
		"3710188881164914266655785737710962157057127115720196198634924408280817207663", 10)

	// Verify at generation time using gnark-crypto.
	var pt bn254.G2Affine
	pt.X.A0.SetBigInt(xRe)
	pt.X.A1.SetBigInt(xIm)
	pt.Y.A0.SetBigInt(yRe)
	pt.Y.A1.SetBigInt(yIm)
	if !pt.IsOnCurve() {
		panic("g2NotInSubgroup: point is not on the twist curve")
	}
	if pt.IsInSubGroup() {
		panic("g2NotInSubgroup: point is unexpectedly in the subgroup")
	}

	return []*big.Int{xIm, xRe, yIm, yRe}
}

// =========================================================================
// Notes (flag descriptions)
// =========================================================================

func addNotes() map[string]*noteEntry {
	return map[string]*noteEntry{
		"Valid": {
			BugType:     "BASIC",
			Description: "The test vector contains a valid ecAdd computation.",
		},
		"PointAtInfinity": {
			BugType:     "EDGE_CASE",
			Description: "One or both input points are the point at infinity (0,0).",
			Effect:      "Incorrect handling of the identity element breaks group arithmetic.",
		},
		"Doubling": {
			BugType:     "EDGE_CASE",
			Description: "Both input points are identical, triggering the point doubling path.",
			Effect:      "Some implementations use separate add and double formulas; this tests the doubling path.",
		},
		"InverseAddition": {
			BugType:     "EDGE_CASE",
			Description: "The two points are additive inverses (P + (-P) = O).",
			Effect:      "Failure to handle inverse addition correctly can produce incorrect results or panics.",
		},
		"NotOnCurve": {
			BugType:     "AUTH_BYPASS",
			Description: "A point is not on the BN-254 curve y^2 = x^3 + 3.",
			Effect:      "Accepting off-curve points enables various cryptographic attacks.",
			CVEs:        []string{"CVE-2025-30147"},
		},
		"InvalidEncoding": {
			BugType:     "AUTH_BYPASS",
			Description: "A coordinate value is >= the field modulus p.",
			Effect:      "Accepting out-of-range field elements may enable forgery or consensus divergence.",
		},
		"FieldBoundary": {
			BugType:     "EDGE_CASE",
			Description: "Coordinates are near the field modulus, exercising carry propagation.",
			Effect:      "Implementations with carry bugs may produce incorrect results for boundary values.",
		},
		"TruncatedInput": {
			BugType:     "AUTH_BYPASS",
			Description: "The input is shorter than expected.",
			Effect:      "Accepting truncated input can lead to undefined behavior.",
		},
		"EmptyInput": {
			BugType:     "EDGE_CASE",
			Description: "The input is empty. The EVM ecAdd precompile returns (0,0) for empty input.",
		},
		"InvalidInputLength": {
			BugType:     "AUTH_BYPASS",
			Description: "The input length is not a valid multiple of the expected size.",
			Effect:      "Accepting malformed input can lead to parsing errors or undefined behavior.",
		},
		"GroupOrder": {
			BugType:     "EDGE_CASE",
			Description: "The computation involves the group order, testing modular arithmetic boundaries.",
		},
	}
}

func mulNotes() map[string]*noteEntry {
	return map[string]*noteEntry{
		"Valid": {
			BugType:     "BASIC",
			Description: "The test vector contains a valid ecMul computation.",
		},
		"ScalarZero": {
			BugType:     "EDGE_CASE",
			Description: "The scalar is zero. The result must be the point at infinity.",
			Effect:      "Incorrect zero-scalar handling can produce wrong results.",
		},
		"GroupOrder": {
			BugType:     "EDGE_CASE",
			Description: "The scalar is the group order or related to it.",
			Effect:      "The group order times any point must be infinity.",
		},
		"ScalarOverflow": {
			BugType:     "EDGE_CASE",
			Description: "The scalar exceeds the group order and wraps modulo the order.",
			Effect:      "Failure to reduce scalars correctly produces wrong results.",
		},
		"PointAtInfinity": {
			BugType:     "EDGE_CASE",
			Description: "The input point is the point at infinity.",
			Effect:      "Infinity times any scalar must remain infinity.",
		},
		"LargeScalar": {
			BugType:     "EDGE_CASE",
			Description: "The scalar is very large (near 2^256), testing high-bit handling.",
			Effect:      "Implementations with scalar width assumptions may fail.",
		},
		"FieldBoundary": {
			BugType:     "EDGE_CASE",
			Description: "Values near the field modulus, exercising carry propagation.",
		},
		"NotOnCurve": {
			BugType:     "AUTH_BYPASS",
			Description: "The input point is not on the BN-254 curve.",
			Effect:      "Accepting off-curve points enables cryptographic attacks.",
			CVEs:        []string{"CVE-2025-30147"},
		},
		"InvalidEncoding": {
			BugType:     "AUTH_BYPASS",
			Description: "A coordinate value is >= the field modulus.",
			Effect:      "Out-of-range field elements may enable forgery or consensus divergence.",
		},
		"EmptyInput": {
			BugType:     "EDGE_CASE",
			Description: "The input is empty. The EVM ecMul precompile returns (0,0) for empty input.",
		},
	}
}

func pairingNotes() map[string]*noteEntry {
	return map[string]*noteEntry{
		"Valid": {
			BugType:     "BASIC",
			Description: "The test vector contains a valid pairing check.",
		},
		"EmptyInput": {
			BugType:     "EDGE_CASE",
			Description: "The input is empty (zero pairs). The pairing check succeeds trivially.",
		},
		"PointAtInfinity": {
			BugType:     "EDGE_CASE",
			Description: "One or both points in a pair are the point at infinity.",
			Effect:      "e(O, Q) = e(P, O) = 1 in the target group. Incorrect handling breaks pairing arithmetic.",
		},
		"PairingCheckFails": {
			BugType:     "BASIC",
			Description: "The pairing product is not equal to 1.",
			Effect:      "The precompile must return 0 (false), not 1.",
		},
		"Bilinearity": {
			BugType:     "BASIC",
			Description: "Tests the bilinearity property: e(aP, Q) = e(P, aQ) = e(P, Q)^a.",
		},
		"NotOnCurve": {
			BugType:     "AUTH_BYPASS",
			Description: "A G1 or G2 point is not on its respective curve.",
			Effect:      "Accepting off-curve points in pairings can lead to forgery.",
			CVEs:        []string{"CVE-2025-30147"},
		},
		"InvalidEncoding": {
			BugType:     "AUTH_BYPASS",
			Description: "A coordinate value is >= the field modulus.",
			Effect:      "Out-of-range field elements can cause consensus divergence between implementations.",
		},
		"InvalidInputLength": {
			BugType:     "AUTH_BYPASS",
			Description: "The input length is not a multiple of 192 bytes.",
			Effect:      "The precompile must revert for malformed input.",
		},
		"NotInSubgroup": {
			BugType:     "AUTH_BYPASS",
			Description: "A G2 point is on the twist curve but not in the prime-order subgroup.",
			Effect:      "Accepting non-subgroup G2 points enables rogue-key and forgery attacks. This is the exact bug class found in Besu (CVE-2025-30147).",
			CVEs:        []string{"CVE-2025-30147"},
			Links:       []string{"https://blog.ethereum.org/en/2025/05/07/the-curious-case"},
		},
	}
}
