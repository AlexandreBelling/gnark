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

package witness

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"

	"github.com/AlexandreBelling/gnarkfrontend"
	"github.com/AlexandreBelling/gnark/notinternal/backend/compiled"
	"github.com/AlexandreBelling/gnark/notinternal/parser"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"

	curve "github.com/consensys/gnark-crypto/ecc/bn254"
)

type Witness []fr.Element

// WriteTo encodes witness to writer (implements io.WriterTo)
func (witness *Witness) WriteTo(w io.Writer) (int64, error) {
	// encode slice length
	if err := binary.Write(w, binary.BigEndian, uint32(len(*witness))); err != nil {
		return 0, err
	}

	enc := curve.NewEncoder(w)
	for i := 0; i < len(*witness); i++ {
		if err := enc.Encode(&(*witness)[i]); err != nil {
			return enc.BytesWritten() + 4, err
		}
	}
	return enc.BytesWritten() + 4, nil
}

// LimitReadFrom decodes witness from reader; first 4 bytes (uint32) must equal to expectedSize
// this method won't read more than expectedSize * size(fr.Element)
func (witness *Witness) LimitReadFrom(r io.Reader, expectedSize int) (int64, error) {

	var buf [4]byte
	if read, err := io.ReadFull(r, buf[:4]); err != nil {
		return int64(read), err
	}
	sliceLen := binary.BigEndian.Uint32(buf[:4])
	if int(sliceLen) != expectedSize {
		return 4, errors.New("invalid witness size")
	}

	if len(*witness) != int(sliceLen) {
		*witness = make([]fr.Element, sliceLen)
	}

	lr := io.LimitReader(r, int64(expectedSize*fr.Limbs*8))
	dec := curve.NewDecoder(lr)

	for i := 0; i < int(sliceLen); i++ {
		if err := dec.Decode(&(*witness)[i]); err != nil {
			return dec.BytesRead() + 4, err
		}
	}

	return dec.BytesRead() + 4, nil
}

// FromFullAssignment extracts the full witness [ public | secret ]
func (witness *Witness) FromFullAssignment(w frontend.Circuit) error {
	nbSecret, nbPublic := count(w)

	if len(*witness) < (nbPublic + nbSecret) {
		(*witness) = make(Witness, nbPublic+nbSecret)
	} else {
		(*witness) = (*witness)[:nbPublic+nbSecret]
	}

	var i, j int // indexes for secret / public variables
	i = nbPublic // offset

	var collectHandler parser.LeafHandler = func(visibility compiled.Visibility, name string, tInput reflect.Value) error {
		v := tInput.Interface().(frontend.Variable)

		if v == nil {
			return fmt.Errorf("when parsing variable %s: missing assignment", name)
		}

		if visibility == compiled.Secret {
			if _, err := (*witness)[i].SetInterface(v); err != nil {
				return fmt.Errorf("when parsing variable %s: %v", name, err)
			}
			i++
		} else if visibility == compiled.Public {
			if _, err := (*witness)[j].SetInterface(v); err != nil {
				return fmt.Errorf("when parsing variable %s: %v", name, err)
			}
			j++
		}
		return nil
	}
	return parser.Visit(w, "", compiled.Unset, collectHandler, tVariable)
}

// FromPublicAssignment extracts the public part of witness
func (witness *Witness) FromPublicAssignment(w frontend.Circuit) error {
	_, nbPublic := count(w)

	// note: does not contain ONE_WIRE for Groth16
	if len(*witness) < (nbPublic) {
		(*witness) = make(Witness, nbPublic)
	} else {
		(*witness) = (*witness)[:nbPublic]
	}
	var j int // index for public variables

	var collectHandler parser.LeafHandler = func(visibility compiled.Visibility, name string, tInput reflect.Value) error {
		if visibility == compiled.Public {
			v := tInput.Interface().(frontend.Variable)

			if v == nil {
				return fmt.Errorf("when parsing variable %s: missing assignment", name)
			}

			if _, err := (*witness)[j].SetInterface(v); err != nil {
				return fmt.Errorf("when parsing variable %s: %v", name, err)
			}
			j++
		}
		return nil
	}
	return parser.Visit(w, "", compiled.Unset, collectHandler, tVariable)
}

func count(w frontend.Circuit) (nbSecret, nbPublic int) {
	var collectHandler parser.LeafHandler = func(visibility compiled.Visibility, name string, tInput reflect.Value) error {
		if visibility == compiled.Secret {
			nbSecret++
		} else if visibility == compiled.Public {
			nbPublic++
		}
		return nil
	}

	err := parser.Visit(w, "", compiled.Unset, collectHandler, tVariable)
	if err != nil {
		panic("count handler doesn't return an error -- this panic should not happen")
	}
	return
}

// ToJSON extracts the full witness [ public | secret ] and returns a JSON string
// or an error if it can't convert values to field elements
func ToJSON(w frontend.Circuit) (string, error) {
	nbSecret, nbPublic := count(w)

	type jsonStruct struct {
		Public map[string]string
		Secret map[string]string
	}

	toPrint := jsonStruct{
		Public: make(map[string]string, nbPublic),
		Secret: make(map[string]string, nbSecret),
	}

	var e fr.Element

	var collectHandler parser.LeafHandler = func(visibility compiled.Visibility, name string, tInput reflect.Value) error {
		v := tInput.Interface().(frontend.Variable)

		if visibility == compiled.Secret {
			if v == nil {
				toPrint.Secret[name] = "<nil>"
			} else {
				if _, err := e.SetInterface(v); err != nil {
					return fmt.Errorf("when parsing variable %s: %v", name, err)
				}
				toPrint.Secret[name] = e.String()
			}
		} else if visibility == compiled.Public {
			if v == nil {
				toPrint.Public[name] = "<nil>"
			} else {
				if _, err := e.SetInterface(v); err != nil {
					return fmt.Errorf("when parsing variable %s: %v", name, err)
				}
				toPrint.Public[name] = e.String()
			}
		}
		return nil
	}
	if err := parser.Visit(w, "", compiled.Unset, collectHandler, tVariable); err != nil {
		return "", err
	}

	prettyJSON, err := json.MarshalIndent(toPrint, "", "    ")
	if err != nil {
		return "", err
	}
	return string(prettyJSON), nil
}

var tVariable reflect.Type

func init() {
	tVariable = reflect.ValueOf(struct{ A frontend.Variable }{}).FieldByName("A").Type()
}
