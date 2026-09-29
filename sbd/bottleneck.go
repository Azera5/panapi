package sbd


// *** API ***

// port of "sharedBottleneckDetection" function in "umcc/scheduler_sbd.go"
func FindSharedBottleneck(paths [][]InterfaceID, affectedIdx []int) []InterfaceID {

	isAffected := make(map[int]bool, len(affectedIdx))
	for _, idx := range affectedIdx {
		isAffected[idx] = true
	}

	// first part: creating the intersection of interfaces paths from suspicious paths
	var intersection []InterfaceID
	first := true
	for idx, ifaces := range paths {
		if !isAffected[idx] {
			continue
		}
		if first {
			intersection = append(intersection, ifaces...)
			first = false
		} else {
			intersection = intersectInterfaces(intersection, ifaces)
		}
	}

	// second part: subtract interfaces from *un*suspicious paths to correct our selection
	for idx, ifaces := range paths {
		if isAffected[idx] {
			continue
		}
		intersection = differenceInterfaces(intersection, ifaces)
		if len(intersection) == 2 {
			break
		}
	}

	return intersection
}

// adaptation of "sharedBottleneckDetection" function in "umcc/scheduler_sbd.go"
func FilterPathsByBottleneck(paths [][]InterfaceID, bottleneck []InterfaceID) (clean, affected [][]InterfaceID) {
	for _, ifaces := range paths {
		if containsAny(ifaces, bottleneck) {
			affected = append(affected, ifaces)
		} else {
			clean = append(clean, ifaces)
		}
	}
	return clean, affected
}


// *** Set logic helpers ***

func containsAny(a, b []InterfaceID) bool {
	for _, x := range a {
		for _, y := range b {
			if x == y {
				return true
			}
		}
	}
	return false
}

func intersectInterfaces(a, b []InterfaceID) []InterfaceID {
	seen := make(map[InterfaceID]bool, len(a))
	for _, x := range a {
		seen[x] = true
	}
	var out []InterfaceID
	for _, y := range b {
		if seen[y] {
			out = append(out, y)
		}
	}
	return out
}

func differenceInterfaces(a, b []InterfaceID) []InterfaceID {
	exclude := make(map[InterfaceID]bool, len(b))
	for _, x := range b {
		exclude[x] = true
	}
	var out []InterfaceID
	for _, x := range a {
		if !exclude[x] {
			out = append(out, x)
		}
	}
	return out
}
