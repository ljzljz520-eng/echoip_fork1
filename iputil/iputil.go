package iputil

import (
	"math/big"
	"net"
	"strings"
)

func LookupAddr(ip net.IP) (string, error) {
	names, err := net.LookupAddr(ip.String())
	if err != nil || len(names) == 0 {
		return "", err
	}
	// Always return unrooted name
	return strings.TrimRight(names[0], "."), nil
}

func ToDecimal(ip net.IP) *big.Int {
	i := big.NewInt(0)
	if to4 := ip.To4(); to4 != nil {
		i.SetBytes(to4)
	} else {
		i.SetBytes(ip)
	}
	return i
}
