// Copyright 2020 ConsenSys Software Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Code generated by gnark DO NOT EDIT

package cs

import (
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/fxamacker/cbor/v2"
	"io"
	"math/big"
	"os"
	"strings"

	"github.com/AlexandreBelling/gnark/backend"
	"github.com/AlexandreBelling/gnark/backend/witness"
	"github.com/AlexandreBelling/gnark/frontend/schema"
	"github.com/AlexandreBelling/gnark/notinternal/backend/compiled"
	"github.com/AlexandreBelling/gnark/notinternal/backend/ioutils"

	"github.com/consensys/gnark-crypto/ecc/bw6-633/fr"

	bw6_633witness "github.com/AlexandreBelling/gnark/notinternal/backend/bw6-633/witness"
)

// SparseR1CS represents a Plonk like circuit
type SparseR1CS struct {
	compiled.SparseR1CS

	Coefficients []fr.Element // coefficients in the constraints
	loggerOut    io.Writer
}

// NewSparseR1CS returns a new SparseR1CS and sets r1cs.Coefficient (fr.Element) from provided big.Int values
func NewSparseR1CS(ccs compiled.SparseR1CS, coefficients []big.Int) *SparseR1CS {
	cs := SparseR1CS{
		SparseR1CS:   ccs,
		Coefficients: make([]fr.Element, len(coefficients)),
		loggerOut:    os.Stdout,
	}
	for i := 0; i < len(coefficients); i++ {
		cs.Coefficients[i].SetBigInt(&coefficients[i])
	}

	return &cs
}

// Solve sets all the wires.
// solution.values =  [publicInputs | secretInputs | internalVariables ]
// witness: contains the input variables
// it returns the full slice of wires
func (cs *SparseR1CS) Solve(witness []fr.Element, opt backend.ProverConfig) ([]fr.Element, error) {

	// set the slices holding the solution.values and monitoring which variables have been solved
	nbVariables := cs.NbInternalVariables + cs.NbSecretVariables + cs.NbPublicVariables

	expectedWitnessSize := int(cs.NbPublicVariables + cs.NbSecretVariables)
	if len(witness) != expectedWitnessSize {
		return make([]fr.Element, nbVariables), fmt.Errorf(
			"invalid witness size, got %d, expected %d = %d (public) + %d (secret)",
			len(witness),
			expectedWitnessSize,
			cs.NbPublicVariables,
			cs.NbSecretVariables,
		)
	}

	// keep track of wire that have a value
	solution, err := newSolution(nbVariables, opt.HintFunctions, cs.Coefficients)
	if err != nil {
		return solution.values, err
	}

	// solution.values = [publicInputs | secretInputs | internalVariables ] -> we fill publicInputs | secretInputs
	copy(solution.values, witness)
	for i := 0; i < len(witness); i++ {
		solution.solved[i] = true
	}

	// keep track of the number of wire instantiations we do, for a sanity check to ensure
	// we instantiated all wires
	solution.nbSolved += len(witness)

	// defer log printing once all solution.values are computed
	defer solution.printLogs(opt.LoggerOut, cs.Logs)

	// batch invert the coefficients to avoid many divisions in the solver
	coefficientsNegInv := fr.BatchInvert(cs.Coefficients)
	for i := 0; i < len(coefficientsNegInv); i++ {
		coefficientsNegInv[i].Neg(&coefficientsNegInv[i])
	}

	// loop through the constraints to solve the variables
	for i := 0; i < len(cs.Constraints); i++ {
		if err := cs.solveConstraint(cs.Constraints[i], &solution, coefficientsNegInv); err != nil {
			return solution.values, fmt.Errorf("constraint %d: %w", i, err)
		}
		if err := cs.checkConstraint(cs.Constraints[i], &solution); err != nil {
			errMsg := err.Error()
			if dID, ok := cs.MDebug[i]; ok {
				errMsg = solution.logValue(cs.DebugInfo[dID])
			}
			return solution.values, fmt.Errorf("constraint #%d is not satisfied: %s", i, errMsg)
		}
	}

	// sanity check; ensure all wires are marked as "instantiated"
	if !solution.isValid() {
		panic("solver didn't instantiate all wires")
	}

	return solution.values, nil

}

// computeHints computes wires associated with a hint function, if any
// if there is no remaining wire to solve, returns -1
// else returns the wire position (L -> 0, R -> 1, O -> 2)
func (cs *SparseR1CS) computeHints(c compiled.SparseR1C, solution *solution) (int, error) {
	r := -1
	lID, rID, oID := c.L.WireID(), c.R.WireID(), c.O.WireID()

	if (c.L.CoeffID() != 0 || c.M[0].CoeffID() != 0) && !solution.solved[lID] {
		// check if it's a hint
		if hint, ok := cs.MHints[lID]; ok {
			if err := solution.solveWithHint(lID, hint); err != nil {
				return -1, err
			}
		} else {
			r = 0
		}

	}

	if (c.R.CoeffID() != 0 || c.M[1].CoeffID() != 0) && !solution.solved[rID] {
		// check if it's a hint
		if hint, ok := cs.MHints[rID]; ok {
			if err := solution.solveWithHint(rID, hint); err != nil {
				return -1, err
			}
		} else {
			r = 1
		}
	}

	if (c.O.CoeffID() != 0) && !solution.solved[oID] {
		// check if it's a hint
		if hint, ok := cs.MHints[oID]; ok {
			if err := solution.solveWithHint(oID, hint); err != nil {
				return -1, err
			}
		} else {
			r = 2
		}
	}
	return r, nil
}

// solveConstraint solve any unsolved wire in given constraint and update the solution
// a SparseR1C may have up to one unsolved wire (excluding hints)
// if it doesn't, then this function returns and does nothing
func (cs *SparseR1CS) solveConstraint(c compiled.SparseR1C, solution *solution, coefficientsNegInv []fr.Element) error {

	lro, err := cs.computeHints(c, solution)
	if err != nil {
		return err
	}
	if lro == -1 {
		// no unsolved wire
		// can happen if the constraint contained only hint wires.
		return nil
	}
	if lro == 1 { // we solve for R: u1L+u2R+u3LR+u4O+k=0 => R(u2+u3L)+u1L+u4O+k = 0
		if !solution.solved[c.L.WireID()] {
			panic("L wire should be instantiated when we solve R")
		}
		var u1, u2, u3, den, num, v1, v2 fr.Element
		u3.Mul(&cs.Coefficients[c.M[0].CoeffID()], &cs.Coefficients[c.M[1].CoeffID()])
		u1.Set(&cs.Coefficients[c.L.CoeffID()])
		u2.Set(&cs.Coefficients[c.R.CoeffID()])
		den.Mul(&u3, &solution.values[c.L.WireID()]).Add(&den, &u2)

		v1 = solution.computeTerm(c.L)
		v2 = solution.computeTerm(c.O)
		num.Add(&v1, &v2).Add(&num, &cs.Coefficients[c.K])

		// TODO find a way to do lazy div (/ batch inversion)
		num.Div(&num, &den).Neg(&num)
		solution.set(c.L.WireID(), num)
		return nil
	}

	if lro == 0 { // we solve for L: u1L+u2R+u3LR+u4O+k=0 => L(u1+u3R)+u2R+u4O+k = 0
		if !solution.solved[c.R.WireID()] {
			panic("R wire should be instantiated when we solve L")
		}
		var u1, u2, u3, den, num, v1, v2 fr.Element
		u3.Mul(&cs.Coefficients[c.M[0].CoeffID()], &cs.Coefficients[c.M[1].CoeffID()])
		u1.Set(&cs.Coefficients[c.L.CoeffID()])
		u2.Set(&cs.Coefficients[c.R.CoeffID()])
		den.Mul(&u3, &solution.values[c.R.WireID()]).Add(&den, &u1)

		v1 = solution.computeTerm(c.R)
		v2 = solution.computeTerm(c.O)
		num.Add(&v1, &v2).Add(&num, &cs.Coefficients[c.K])

		// TODO find a way to do lazy div (/ batch inversion)
		num.Div(&num, &den).Neg(&num)
		solution.set(c.L.WireID(), num)
		return nil

	}
	// O we solve for O
	var o fr.Element
	cID, vID, _ := c.O.Unpack()

	l := solution.computeTerm(c.L)
	r := solution.computeTerm(c.R)
	m0 := solution.computeTerm(c.M[0])
	m1 := solution.computeTerm(c.M[1])

	// o = - ((m0 * m1) + l + r + c.K) / c.O
	o.Mul(&m0, &m1).Add(&o, &l).Add(&o, &r).Add(&o, &cs.Coefficients[c.K])
	o.Mul(&o, &coefficientsNegInv[cID])

	solution.set(vID, o)

	return nil
}

// IsSolved returns nil if given witness solves the SparseR1CS and error otherwise
// this method wraps cs.Solve() and allocates cs.Solve() inputs
func (cs *SparseR1CS) IsSolved(witness *witness.Witness, opts ...backend.ProverOption) error {
	opt, err := backend.NewProverConfig(opts...)
	if err != nil {
		return err
	}

	v := witness.Vector.(*bw6_633witness.Witness)
	_, err = cs.Solve(*v, opt)
	return err
}

// GetConstraints return a list of constraint formatted as in the paper
// https://eprint.iacr.org/2019/953.pdf section 6 such that
// qL⋅xa + qR⋅xb + qO⋅xc + qM⋅(xaxb) + qC == 0
// each constraint is thus decomposed in [5]string with
// 		[0] = qL⋅xa
//		[1] = qR⋅xb
//		[2] = qO⋅xc
//		[3] = qM⋅(xaxb)
//		[4] = qC
func (cs *SparseR1CS) GetConstraints() [][]string {
	r := make([][]string, 0, len(cs.Constraints))
	for _, c := range cs.Constraints {
		fc := cs.formatConstraint(c)
		r = append(r, fc[:])
	}
	return r
}

// r[0] = qL⋅xa
// r[1] = qR⋅xb
// r[2] = qO⋅xc
// r[3] = qM⋅(xaxb)
// r[4] = qC
func (cs *SparseR1CS) formatConstraint(c compiled.SparseR1C) (r [5]string) {
	isZeroM := (c.M[0].CoeffID() == compiled.CoeffIdZero) && (c.M[1].CoeffID() == compiled.CoeffIdZero)

	var sbb strings.Builder
	cs.termToString(c.L, &sbb, false)
	r[0] = sbb.String()

	sbb.Reset()
	cs.termToString(c.R, &sbb, false)
	r[1] = sbb.String()

	sbb.Reset()
	cs.termToString(c.O, &sbb, false)
	r[2] = sbb.String()

	if isZeroM {
		r[3] = "0"
	} else {
		sbb.Reset()
		sbb.WriteString(cs.Coefficients[c.M[0].CoeffID()].String())
		sbb.WriteString("⋅")
		sbb.WriteByte('(')
		cs.termToString(c.M[0], &sbb, true)
		sbb.WriteString(" × ")
		cs.termToString(c.M[1], &sbb, true)
		sbb.WriteByte(')')
		r[3] = sbb.String()
	}

	r[4] = cs.Coefficients[c.K].String()

	return
}

func (cs *SparseR1CS) termToString(t compiled.Term, sbb *strings.Builder, vOnly bool) {
	if !vOnly {
		tID := t.CoeffID()
		if tID == compiled.CoeffIdOne {
			// do nothing, just print the variable
			sbb.WriteString("1")
		} else if tID == compiled.CoeffIdMinusOne {
			// print neg sign
			sbb.WriteString("-1")
		} else if tID == compiled.CoeffIdZero {
			sbb.WriteByte('0')
			return
		} else {
			sbb.WriteString(cs.Coefficients[tID].String())
		}
		sbb.WriteString("⋅")
	}

	vID := t.WireID()
	visibility := t.VariableVisibility()

	switch visibility {
	case schema.Internal:
		if _, isHint := cs.MHints[vID]; isHint {
			sbb.WriteString(fmt.Sprintf("hv%d", vID-cs.NbPublicVariables-cs.NbSecretVariables))
		} else {
			sbb.WriteString(fmt.Sprintf("v%d", vID-cs.NbPublicVariables-cs.NbSecretVariables))
		}
	case schema.Public:
		sbb.WriteString(fmt.Sprintf("p%d", vID))
	case schema.Secret:
		sbb.WriteString(fmt.Sprintf("s%d", vID-cs.NbPublicVariables))
	default:
		sbb.WriteString("<?>")
	}
}

// checkConstraint verifies that the constraint holds
func (cs *SparseR1CS) checkConstraint(c compiled.SparseR1C, solution *solution) error {
	l := solution.computeTerm(c.L)
	r := solution.computeTerm(c.R)
	m0 := solution.computeTerm(c.M[0])
	m1 := solution.computeTerm(c.M[1])
	o := solution.computeTerm(c.O)

	// l + r + (m0 * m1) + o + c.K == 0
	var t fr.Element
	t.Mul(&m0, &m1).Add(&t, &l).Add(&t, &r).Add(&t, &o).Add(&t, &cs.Coefficients[c.K])
	if !t.IsZero() {
		return fmt.Errorf("qL⋅xa + qR⋅xb + qO⋅xc + qM⋅(xaxb) + qC != 0 → %s + %s + %s + (%s × %s) + %s != 0",
			l.String(),
			r.String(),
			o.String(),
			m0.String(),
			m1.String(),
			cs.Coefficients[c.K].String(),
		)
	}
	return nil

}

// FrSize return fr.Limbs * 8, size in byte of a fr element
func (cs *SparseR1CS) FrSize() int {
	return fr.Limbs * 8
}

// GetNbCoefficients return the number of unique coefficients needed in the R1CS
func (cs *SparseR1CS) GetNbCoefficients() int {
	return len(cs.Coefficients)
}

// CurveID returns curve ID as defined in gnark-crypto (ecc.BW6-633)
func (cs *SparseR1CS) CurveID() ecc.ID {
	return ecc.BW6_633
}

// WriteTo encodes SparseR1CS into provided io.Writer using cbor
func (cs *SparseR1CS) WriteTo(w io.Writer) (int64, error) {
	_w := ioutils.WriterCounter{W: w} // wraps writer to count the bytes written
	enc, err := cbor.CoreDetEncOptions().EncMode()
	if err != nil {
		return 0, err
	}
	encoder := enc.NewEncoder(&_w)

	// encode our object
	err = encoder.Encode(cs)
	return _w.N, err
}

// ReadFrom attempts to decode SparseR1CS from io.Reader using cbor
func (cs *SparseR1CS) ReadFrom(r io.Reader) (int64, error) {
	dm, err := cbor.DecOptions{
		MaxArrayElements: 134217728,
		MaxMapPairs:      134217728,
	}.DecMode()
	if err != nil {
		return 0, err
	}
	decoder := dm.NewDecoder(r)
	err = decoder.Decode(cs)
	return int64(decoder.NumBytesRead()), err
}

// SetLoggerOutput replace existing logger output with provided one
// default uses os.Stdout
// if nil is provided, logs are not printed
func (cs *SparseR1CS) SetLoggerOutput(w io.Writer) {
	cs.loggerOut = w
}
