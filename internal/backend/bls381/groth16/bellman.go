package groth16

import (
	"errors"
	"io"
	"strconv"

	"github.com/consensys/gnark/backend"
	curve "github.com/consensys/gurvy/bls381"
	"github.com/consensys/gurvy/bls381/fr"
)

func (vk *VerifyingKey) FromBellmanVerifyingKey(bvk *BellmanVerifyingKey) {
	vk.E = curve.FinalExponentiation(curve.MillerLoop(bvk.G1.Alpha, bvk.G2.Beta))
	vk.G2.GammaNeg.Neg(&bvk.G2.Gamma)
	vk.G2.DeltaNeg.Neg(&bvk.G2.Delta)
	vk.G1.K = make([]curve.G1Affine, len(bvk.G1.Ic))
	copy(vk.G1.K, bvk.G1.Ic)
	vk.PublicInputs = make([]string, len(vk.G1.K))
	vk.PublicInputs[0] = backend.OneWire

	// gnark expects inputs to be named
	// we create dummy keys that match the ordering of the input encoding
	// from bellman
	for i := 1; i < len(vk.PublicInputs); i++ {
		vk.PublicInputs[i] = strconv.Itoa(i)
	}
}

type BellmanVerifyingKey struct {
	G1 struct {
		Alpha/*, Beta, Delta*/ curve.G1Affine
		Ic []curve.G1Affine
	}
	G2 struct {
		Beta, Gamma, Delta curve.G2Affine
	}
}

func (vk *BellmanVerifyingKey) ReadFrom(r io.Reader) (n int64, err error) {

	// note: this is how bellman encodes the verifying key
	// however, our test vectors don't encode G1.Beta, G1.Delta and the length of ic

	// writer.write_all(self.alpha_g1.to_uncompressed().as_ref())?;
	// writer.write_all(self.beta_g1.to_uncompressed().as_ref())?;
	// writer.write_all(self.beta_g2.to_uncompressed().as_ref())?;
	// writer.write_all(self.gamma_g2.to_uncompressed().as_ref())?;
	// writer.write_all(self.delta_g1.to_uncompressed().as_ref())?;
	// writer.write_all(self.delta_g2.to_uncompressed().as_ref())?;
	// writer.write_u32::<BigEndian>(self.ic.len() as u32)?;
	// for ic in &self.ic {
	// 	writer.write_all(ic.to_uncompressed().as_ref())?;
	// }

	// first part, the points
	{
		dec := curve.NewDecoder(r)

		toDecode := []interface{}{
			&vk.G1.Alpha,
			// &vk.G1.Beta,
			&vk.G2.Beta,
			&vk.G2.Gamma,
			// &vk.G1.Delta,
			&vk.G2.Delta,
		}

		for _, v := range toDecode {
			if err := dec.Decode(v); err != nil {
				return dec.BytesRead(), err
			}
		}
		n += dec.BytesRead()
	}

	// the slice len is encoded slightly differently
	{
		// var buf [4]byte
		// var read int
		// read, err = io.ReadFull(r, buf[:])
		// n += int64(read)
		// if err != nil {
		// 	return
		// }
		// lPublicInputs := binary.BigEndian.Uint32(buf[:4])
		// vk.G1.Ic = make([]curve.G1Affine, lPublicInputs)
		dec := curve.NewDecoder(r)
		var p curve.G1Affine
		for {
			err := dec.Decode(&p)
			if err == io.EOF {
				break
			}
			if err != nil {
				return n + dec.BytesRead(), err
			}
			vk.G1.Ic = append(vk.G1.Ic, p)
		}
		n += dec.BytesRead()
	}

	return
}

func decodeInputs(b []byte) (witness map[string]interface{}, err error) {
	witness = make(map[string]interface{})
	var r []fr.Element
	const frSize = fr.Limbs * 8
	if (len(b) % frSize) != 0 {
		return nil, errors.New("invalid input size")
	}
	r = make([]fr.Element, len(b)/frSize)
	offset := 0
	for i := 0; i < len(r); i++ {
		r[i].SetBytes(b[offset : offset+frSize])
		witness[strconv.Itoa(i+1)] = r[i]
	}

	return
}
