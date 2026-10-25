package attack

import (
	"math/big"
	"slices"
)

// Reflectors are separate in Model; only rotor slots with overlapping catalog
// domains participate, even when the input fixes their wheel choices.
func overlappingWheelSlots(slots []Slot) []int {
	var indices []int
	for i, slot := range slots {
		overlaps := false
		for j, other := range slots {
			if i == j {
				continue
			}
			for _, wheel := range slot.Wheels {
				if slices.Contains(other.Wheels, wheel) {
					overlaps = true
					break
				}
			}
			if overlaps {
				break
			}
		}
		if overlaps {
			indices = append(indices, i)
		}
	}
	return indices
}

// Only wheel tuples are enumerated (at most 8^3 for the bundled models).
// Positions, rings, reflectors and disjoint wheel domains remain a product.
func distinctWheelAssignments(slots []Slot, input []InputSlot, indices []int) *big.Int {
	count := new(big.Int)
	one := big.NewInt(1)
	used := map[string]bool{}
	var visit func(int)
	visit = func(depth int) {
		if depth == len(indices) {
			count.Add(count, one)
			return
		}
		i := indices[depth]
		wheels := slots[i].Wheels
		if input[i].Wheel != nil {
			wheels = []string{*input[i].Wheel}
		}
		for _, wheel := range wheels {
			if used[wheel] {
				continue
			}
			used[wheel] = true
			visit(depth + 1)
			delete(used, wheel)
		}
	}
	visit(0)
	return count
}
