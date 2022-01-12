package frontend

import (
	"fmt"
	"sync"

	"github.com/AlexandreBelling/gnark/backend"
)

var (
	backends  = make(map[backend.ID]NewBuilder)
	backendsM sync.RWMutex
)

// RegisterDefaultBuilder registers a frontend f for a backend b. This registration
// ensures that a correct frontend system is chosen for a specific backend when
// compiling a circuit. The method does not check that the compiler for that
// frontend is already registered and the compiler is looked up during compile
// time. It is an error to double-assign a frontend to a single backend and the
// mehod panics.
//
// /!\ This is highly experimental and may change in upcoming releases /!\
func RegisterDefaultBuilder(b backend.ID, builder NewBuilder) {
	if b == backend.UNKNOWN {
		panic("can not assign builder to unknown backend")
	}

	// a frontend may be assigned before a compiler to that frontend is
	// registered. we perform frontend compiler lookup during compilation.
	backendsM.Lock()
	defer backendsM.Unlock()
	if _, ok := backends[b]; ok {
		panic(fmt.Sprintf("double frontend registration for backend '%s'", b))
	}
	backends[b] = builder
}
