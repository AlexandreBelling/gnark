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

package bandersnatch

import (
	"errors"
	"math/big"

	"github.com/AlexandreBelling/gnark/notinternal/utils"
	"github.com/consensys/gnark-crypto/ecc"
	bandersnatch "github.com/consensys/gnark-crypto/ecc/bls12-381/twistededwards/bandersnatch"
)

// EdCurve stores the info on the chosen edwards curve
type EdCurve struct {
	A, D, Cofactor, Order, BaseX, BaseY big.Int
	ID                                  ecc.ID
}

var constructors map[ecc.ID]func() EdCurve

func init() {
	constructors = map[ecc.ID]func() EdCurve{
		ecc.BLS12_381: newBandersnatch,
	}
}

// NewEdCurve returns an Edwards curve parameters
func NewEdCurve(id ecc.ID) (EdCurve, error) {
	if constructor, ok := constructors[id]; ok {
		return constructor(), nil
	}
	return EdCurve{}, errors.New("unknown curve id")
}

// -------------------------------------------------------------------------------------------------
// constructors

func newBandersnatch() EdCurve {

	edcurve := bandersnatch.GetEdwardsCurve()
	edcurve.Cofactor.FromMont()

	return EdCurve{
		A:        utils.FromInterface(edcurve.A),
		D:        utils.FromInterface(edcurve.D),
		Cofactor: utils.FromInterface(edcurve.Cofactor),
		Order:    utils.FromInterface(edcurve.Order),
		BaseX:    utils.FromInterface(edcurve.Base.X),
		BaseY:    utils.FromInterface(edcurve.Base.Y),
		ID:       ecc.BLS12_381,
	}

}
