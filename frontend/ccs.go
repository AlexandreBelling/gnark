// Copyright 2020 ConsenSys AG
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

package frontend

import (
	"io"

	"github.com/AlexandreBelling/gnark/notinternal/backend/compiled"
	"github.com/consensys/gnark-crypto/ecc"
)

// CompiledConstraintSystem interface that a compiled (=typed, and correctly routed)
// should implement.
type CompiledConstraintSystem interface {
	io.WriterTo
	io.ReaderFrom

	// GetNbVariables return number of internal, secret and public Variables
	GetNbVariables() (internal, secret, public int)
	GetNbConstraints() int
	GetNbCoefficients() int

	CurveID() ecc.ID
	FrSize() int

	// ToHTML generates a human readable representation of the constraint system
	ToHTML(w io.Writer) error

	// GetCounters return the collected constraint counters, if any
	GetCounters() []compiled.Counter
}
