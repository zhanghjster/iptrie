package iptrie

import (
	"encoding/binary"
	"fmt"
	"math"
	"net"
)

const (
	IPv4 = 1
	IPv6 = 4

	BytePerUint32 = 4
	BitsPerUint32 = 32
)

var (
	ErrInvalidIP           = fmt.Errorf("invalid ip")
	ErrInvalidBitPosition  = fmt.Errorf("invalid bit position")
	ErrVersionMismatch     = fmt.Errorf("network input ver mismatch")
	ErrNoGreatestCommonBit = fmt.Errorf("no greatest common bit")
)

type NetworkNumber struct {
	parts [4]uint32
	ver   int
}

func NewNetworkNumber(ip net.IP) *NetworkNumber {
	if number, err := IpToNetworkNumber(ip); err != nil {
		return nil
	} else {
		return &number
	}
}

func IpToNetworkNumber(ip net.IP) (number NetworkNumber, err error) {
	if ip == nil {
		return number, ErrInvalidIP
	}

	var ipBytes net.IP
	if ipBytes = ip.To4(); ipBytes != nil {
		number.ver = IPv4
	} else if ipBytes = ip.To16(); ipBytes != nil {
		number.ver = IPv6
	} else {
		return number, ErrInvalidIP
	}

	for i := 0; i < number.ver; i++ {
		idx := i * net.IPv4len
		number.parts[i] = binary.BigEndian.Uint32(ipBytes[idx : idx+net.IPv4len])
	}

	return
}

func (n *NetworkNumber) Version() int {
	return n.ver
}

func (n NetworkNumber) ToIP() net.IP {
	ip := make(net.IP, n.ver*BytePerUint32)
	for i := 0; i < n.ver; i++ {
		idx := i * net.IPv4len
		binary.BigEndian.PutUint32(ip[idx:idx+net.IPv4len], n.parts[i])
	}
	if len(ip) == net.IPv4len {
		ip = net.IPv4(ip[0], ip[1], ip[2], ip[3])
	}
	return ip
}

func (n NetworkNumber) Equal(n1 NetworkNumber) bool {
	if n.ver != n1.ver || n.parts[0] != n1.parts[0] {
		return false
	}

	return n.ver == IPv4 ||
		n.parts[1] == n1.parts[1] &&
			n.parts[2] == n1.parts[2] &&
			n.parts[3] == n1.parts[3]
}

func (n *NetworkNumber) BitAt(position uint) (uint32, error) {
	if int(position) > n.ver*BitsPerUint32-1 {
		return 0, ErrInvalidBitPosition
	}
	idx := n.ver - 1 - int(position/BitsPerUint32)
	rShift := position & (BitsPerUint32 - 1)
	return (n.parts[idx] >> rShift) & 1, nil
}

func (n *NetworkNumber) LastCommonBitPosition(n1 *NetworkNumber) (uint, error) {
	if n.ver != n1.ver {
		return 0, ErrVersionMismatch
	}
	for i := 0; i < n.ver; i++ {
		mask := uint32(1) << 31
		pos := uint(31)
		for ; mask > 0; mask >>= 1 {
			if n.parts[i]&mask != n1.parts[i]&mask {
				if i == 0 && pos == 31 {
					return 0, ErrNoGreatestCommonBit
				}
				return (pos + 1) + uint(BitsPerUint32)*uint(n.ver-i-1), nil
			}
			pos--
		}
	}
	return 0, nil
}

type NetworkMask struct {
	NetworkNumber
	ones int
}

func (m *NetworkMask) Equal(m1 *NetworkMask) bool {
	return m.NetworkNumber.Equal(m1.NetworkNumber) && m.ones == m1.ones
}

func (m *NetworkMask) Ones() int {
	return m.ones
}

type Network struct {
	Number NetworkNumber
	Mask   NetworkMask
}

func NewNetwork(ipNet net.IPNet) *Network {
	var number = NewNetworkNumber(ipNet.IP)
	var mask = NewNetworkNumber(net.IP(ipNet.Mask))
	if number == nil || mask == nil {
		return nil
	}
	var ones, _ = ipNet.Mask.Size()
	return &Network{
		Number: *number,
		Mask:   NetworkMask{ones: ones, NetworkNumber: *mask},
	}
}

func (n *Network) Version() int {
	return n.Number.Version()
}

func (n *Network) Contains(nn *NetworkNumber) bool {
	if n.Mask.ver != nn.ver ||
		nn.parts[0]&n.Mask.parts[0] != n.Number.parts[0] {
		return false
	}

	return nn.ver == IPv4 ||
		nn.parts[1]&n.Mask.parts[1] == n.Number.parts[1] &&
			nn.parts[2]&n.Mask.parts[2] == n.Number.parts[2] &&
			nn.parts[3]&n.Mask.parts[3] == n.Number.parts[3]
}

func (n *Network) LastCommonBitPosition(n1 *Network) (uint, error) {
	maskSize := n.Mask.ones
	if maskSize1 := n1.Mask.ones; maskSize1 < maskSize {
		maskSize = maskSize1
	}
	maskPosition := n1.Number.ver*BitsPerUint32 - maskSize
	lcb, err := n.Number.LastCommonBitPosition(&n1.Number)
	if err != nil {
		return 0, err
	}
	return uint(math.Max(float64(maskPosition), float64(lcb))), nil
}

func (n *Network) Equal(n1 *Network) bool {
	return n.Number.Equal(n1.Number) && n.Mask.Equal(&n1.Mask)
}

func (n *Network) String() string {
	ipNet := net.IPNet{
		IP:   n.Number.ToIP(),
		Mask: net.IPMask(n.Mask.NetworkNumber.ToIP()),
	}
	return ipNet.String()
}
