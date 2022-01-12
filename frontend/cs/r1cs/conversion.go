/*
Copyright © 2020 ConsenSys

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package r1cs

import (
	"github.com/AlexandreBelling/gnark/frontend"
	bls12377r1cs "github.com/AlexandreBelling/gnark/notinternal/backend/bls12-377/cs"
	bls12381r1cs "github.com/AlexandreBelling/gnark/notinternal/backend/bls12-381/cs"
	bls24315r1cs "github.com/AlexandreBelling/gnark/notinternal/backend/bls24-315/cs"
	bn254r1cs "github.com/AlexandreBelling/gnark/notinternal/backend/bn254/cs"
	bw6633r1cs "github.com/AlexandreBelling/gnark/notinternal/backend/bw6-633/cs"
	bw6761r1cs "github.com/AlexandreBelling/gnark/notinternal/backend/bw6-761/cs"
	"github.com/AlexandreBelling/gnark/notinternal/backend/compiled"
	"github.com/consensys/gnark-crypto/ecc"
)

// Compile constructs a rank-1 constraint sytem
func (cs *r1CS) Compile() (frontend.CompiledConstraintSystem, error) {

	// wires = public wires  | secret wires | internal wires

	// setting up the result
	res := compiled.R1CS{
		CS:          cs.CS,
		Constraints: cs.Constraints,
	}
	res.NbPublicVariables = len(cs.Public)
	res.NbSecretVariables = len(cs.Secret)

	// for Logs, DebugInfo and hints the only thing that will change
	// is that ID of the wires will be offseted to take into account the final wire vector ordering
	// that is: public wires  | secret wires | internal wires

	// offset variable ID depeneding on visibility
	shiftVID := func(oldID int, visibility compiled.Visibility) int {
		switch visibility {
		case compiled.Internal:
			return oldID + res.NbPublicVariables + res.NbSecretVariables
		case compiled.Public:
			return oldID
		case compiled.Secret:
			return oldID + res.NbPublicVariables
		}
		return oldID
	}

	// we just need to offset our ids, such that wires = [ public wires  | secret wires | internal wires ]
	offsetIDs := func(l compiled.LinearExpression) {
		for j := 0; j < len(l); j++ {
			_, vID, visibility := l[j].Unpack()
			l[j].SetWireID(shiftVID(vID, visibility))
		}
	}

	for i := 0; i < len(res.Constraints); i++ {
		offsetIDs(res.Constraints[i].L.LinExp)
		offsetIDs(res.Constraints[i].R.LinExp)
		offsetIDs(res.Constraints[i].O.LinExp)
	}

	// we need to offset the ids in the hints
	shiftedMap := make(map[int]*compiled.Hint)

	// we need to offset the ids in the hints
HINTLOOP:
	for _, hint := range cs.MHints {
		ws := make([]int, len(hint.Wires))
		// we set for all outputs in shiftedMap. If one shifted output
		// is in shiftedMap, then all are
		for i, vID := range hint.Wires {
			ws[i] = shiftVID(vID, compiled.Internal)
			if _, ok := shiftedMap[ws[i]]; i == 0 && ok {
				continue HINTLOOP
			}
		}
		inputs := make([]interface{}, len(hint.Inputs))
		copy(inputs, hint.Inputs)
		for j := 0; j < len(inputs); j++ {
			switch t := inputs[j].(type) {
			case compiled.Variable:
				tmp := make(compiled.LinearExpression, len(t.LinExp))
				copy(tmp, t.LinExp)
				offsetIDs(tmp)
				inputs[j] = tmp
			case compiled.LinearExpression:
				tmp := make(compiled.LinearExpression, len(t))
				copy(tmp, t)
				offsetIDs(tmp)
				inputs[j] = tmp
			default:
				inputs[j] = t
			}
		}
		ch := &compiled.Hint{ID: hint.ID, Inputs: inputs, Wires: ws}
		for _, vID := range ws {
			shiftedMap[vID] = ch
		}
	}
	res.MHints = shiftedMap

	// we need to offset the ids in Logs & DebugInfo
	for i := 0; i < len(cs.Logs); i++ {

		for j := 0; j < len(res.Logs[i].ToResolve); j++ {
			_, vID, visibility := res.Logs[i].ToResolve[j].Unpack()
			res.Logs[i].ToResolve[j].SetWireID(shiftVID(vID, visibility))
		}
	}
	for i := 0; i < len(cs.DebugInfo); i++ {

		for j := 0; j < len(res.DebugInfo[i].ToResolve); j++ {
			_, vID, visibility := res.DebugInfo[i].ToResolve[j].Unpack()
			res.DebugInfo[i].ToResolve[j].SetWireID(shiftVID(vID, visibility))
		}
	}

	switch cs.CurveID {
	case ecc.BLS12_377:
		return bls12377r1cs.NewR1CS(res, cs.Coeffs), nil
	case ecc.BLS12_381:
		return bls12381r1cs.NewR1CS(res, cs.Coeffs), nil
	case ecc.BN254:
		return bn254r1cs.NewR1CS(res, cs.Coeffs), nil
	case ecc.BW6_761:
		return bw6761r1cs.NewR1CS(res, cs.Coeffs), nil
	case ecc.BW6_633:
		return bw6633r1cs.NewR1CS(res, cs.Coeffs), nil
	case ecc.BLS24_315:
		return bls24315r1cs.NewR1CS(res, cs.Coeffs), nil
	case ecc.UNKNOWN:
		return &res, nil
	default:
		panic("not implemtented")
	}
}
