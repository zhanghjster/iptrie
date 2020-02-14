package iptrie

import (
	"math"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
)

func newNetworkNumberFromParts(n [4]uint32, v int) *NetworkNumber {
	return &NetworkNumber{parts: n, ver: v}
}
func newNetworkMaskFromParts(n [4]uint32, v int) *NetworkMask {
	return &NetworkMask{NetworkNumber: *(newNetworkNumberFromParts(n, v))}
}
func nextIP(ip net.IP) net.IP {
	var n = NewNetworkNumber(ip)
	if n == nil {
		return nil
	}
	return nextNetworkNumber(*n).ToIP()
}

func nextNetworkNumber(number NetworkNumber) *NetworkNumber {
	var newNumber = number
	for i := newNumber.Version() - 1; i >= 0; i-- {
		newNumber.parts[i]++
		if newNumber.parts[i] > 0 {
			break
		}
	}
	return &newNumber
}

func previousNetworkNumber(number NetworkNumber) *NetworkNumber {
	var newNumber = number
	for i := newNumber.ver - 1; i >= 0; i-- {
		newNumber.parts[i]--
		if newNumber.parts[i] < math.MaxUint32 {
			break
		}
	}
	return &newNumber
}

func previousIP(ip net.IP) net.IP {
	var n = NewNetworkNumber(ip)
	if n == nil {
		return nil
	}
	return previousNetworkNumber(*n).ToIP()
}
func TestNewNetworkNumber(t *testing.T) {
	cases := []struct {
		ip   net.IP
		nn   *NetworkNumber
		name string
	}{
		{nil, nil, "nil input"},
		{net.IP([]byte{1, 1, 1, 1, 1}), nil, "bad input"},
		{net.ParseIP("128.0.0.0"), newNetworkNumberFromParts([4]uint32{2147483648}, IPv4), "IPv4"},
		{
			net.ParseIP("2001:0db8::ff00:0042:8329"),
			newNetworkNumberFromParts([4]uint32{536939960, 0, 65280, 4358953}, IPv6),
			"IPv6",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.nn, NewNetworkNumber(tc.ip))
		})
	}
}

func TestNetworkNumberBit(t *testing.T) {
	cases := []struct {
		ip   *NetworkNumber
		ones map[uint]bool
		name string
	}{
		{NewNetworkNumber(net.ParseIP("128.0.0.0")), map[uint]bool{31: true}, "128.0.0.0"},
		{NewNetworkNumber(net.ParseIP("1.1.1.1")), map[uint]bool{0: true, 8: true, 16: true, 24: true}, "1.1.1.1"},
		{NewNetworkNumber(net.ParseIP("8000::")), map[uint]bool{127: true}, "8000::"},
		{NewNetworkNumber(net.ParseIP("8000::8000")), map[uint]bool{127: true, 15: true}, "8000::8000"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for i := uint(0); i < uint(tc.ip.ver)*BitsPerUint32; i++ {
				bit, err := tc.ip.BitAt(i)
				assert.NoError(t, err)
				if _, isOne := tc.ones[i]; isOne {
					assert.Equal(t, uint32(1), bit)
				} else {
					assert.Equal(t, uint32(0), bit)
				}
			}
		})
	}
}

func TestNetworkNumberBitError(t *testing.T) {
	cases := []struct {
		ip       *NetworkNumber
		position uint
		err      error
		name     string
	}{
		{NewNetworkNumber(net.ParseIP("128.0.0.0")), 0, nil, "IPv4 index in bound"},
		{NewNetworkNumber(net.ParseIP("128.0.0.0")), 31, nil, "IPv4 index in bound"},
		{NewNetworkNumber(net.ParseIP("128.0.0.0")), 32, ErrInvalidBitPosition, "IPv4 index out of bounds"},
		{NewNetworkNumber(net.ParseIP("8000::")), 0, nil, "IPv6 index in bound"},
		{NewNetworkNumber(net.ParseIP("8000::")), 127, nil, "IPv6 index in bound"},
		{NewNetworkNumber(net.ParseIP("8000::")), 128, ErrInvalidBitPosition, "IPv6 index out of bounds"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := tc.ip.BitAt(tc.position)
			assert.Equal(t, tc.err, err)
		})
	}
}

func TestNetworkNumberEqual(t *testing.T) {
	cases := []struct {
		n1     *NetworkNumber
		n2     *NetworkNumber
		equals bool
		name   string
	}{
		{
			newNetworkNumberFromParts([4]uint32{math.MaxUint32}, IPv4),
			newNetworkNumberFromParts([4]uint32{math.MaxUint32}, IPv4),
			true,
			"IPv4 equals",
		},
		{
			newNetworkNumberFromParts([4]uint32{math.MaxUint32}, IPv4),
			newNetworkNumberFromParts([4]uint32{math.MaxUint32 - 1}, IPv4),
			false,
			"IPv4 does not equal",
		},
		{
			newNetworkNumberFromParts([4]uint32{1, 1, 1, 1}, IPv6),
			newNetworkNumberFromParts([4]uint32{1, 1, 1, 1}, IPv6),
			true,
			"IPv6 equals",
		},
		{
			newNetworkNumberFromParts([4]uint32{1, 1, 1, 1}, IPv6),
			newNetworkNumberFromParts([4]uint32{1, 1, 1, 2}, IPv6),
			false,
			"IPv6 does not equal",
		},
		{
			newNetworkNumberFromParts([4]uint32{1}, IPv4),
			newNetworkNumberFromParts([4]uint32{1, 2, 3, 4}, IPv6),
			false,
			"Version mismatch",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.equals, tc.n1.Equal(*tc.n2))
		})
	}
}

func TestNetworkNumberNext(t *testing.T) {
	cases := []struct {
		ip   string
		next string
		name string
	}{
		{"0.0.0.0", "0.0.0.1", "IPv4 basic"},
		{"0.0.0.255", "0.0.1.0", "IPv4 rollover"},
		{"0.255.255.255", "1.0.0.0", "IPv4 consecutive rollover"},
		{"8000::0", "8000::1", "IPv6 basic"},
		{"0::ffff", "0::1:0", "IPv6 rollover"},
		{"0:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "1::", "IPv6 consecutive rollover"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ip := NewNetworkNumber(net.ParseIP(tc.ip))
			expected := NewNetworkNumber(net.ParseIP(tc.next))
			assert.Equal(t, expected, nextNetworkNumber(*ip))
		})
	}
}

func TestNetworkNumberPrevious(t *testing.T) {
	cases := []struct {
		ip       string
		previous string
		name     string
	}{
		{"0.0.0.1", "0.0.0.0", "IPv4 basic"},
		{"0.0.1.0", "0.0.0.255", "IPv4 rollover"},
		{"1.0.0.0", "0.255.255.255", "IPv4 consecutive rollover"},
		{"8000::1", "8000::0", "IPv6 basic"},
		{"0::1:0", "0::ffff", "IPv6 rollover"},
		{"1::0", "0:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "IPv6 consecutive rollover"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ip := NewNetworkNumber(net.ParseIP(tc.ip))
			expected := NewNetworkNumber(net.ParseIP(tc.previous))
			assert.Equal(t, *expected, previousNetworkNumber(*ip))
		})
	}
}

func TestLeastCommonBitPositionForNetworks(t *testing.T) {
	cases := []struct {
		ip1      *NetworkNumber
		ip2      *NetworkNumber
		position uint
		err      error
		name     string
	}{
		{
			newNetworkNumberFromParts([4]uint32{2147483648}, IPv4),
			newNetworkNumberFromParts([4]uint32{3221225472, 0, 0, 0}, IPv6),
			0, ErrVersionMismatch, "Version mismatch",
		},
		{
			newNetworkNumberFromParts([4]uint32{2147483648}, IPv4),
			newNetworkNumberFromParts([4]uint32{3221225472}, IPv4),
			31, nil, "IPv4 31st position",
		},
		{
			newNetworkNumberFromParts([4]uint32{2147483648}, IPv4),
			newNetworkNumberFromParts([4]uint32{2147483648}, IPv4),
			0, nil, "IPv4 0th position",
		},
		{
			newNetworkNumberFromParts([4]uint32{2147483648}, IPv4),
			newNetworkNumberFromParts([4]uint32{1}, IPv4),
			0, ErrNoGreatestCommonBit, "IPv4 diverge at first bit",
		},
		{
			newNetworkNumberFromParts([4]uint32{2147483648, 0, 0, 0}, IPv6),
			newNetworkNumberFromParts([4]uint32{3221225472, 0, 0, 0}, IPv6),
			127, nil, "IPv6 127th position",
		},
		{
			newNetworkNumberFromParts([4]uint32{2147483648, 1, 1, 1}, IPv6),
			newNetworkNumberFromParts([4]uint32{2147483648, 1, 1, 1}, IPv6),
			0, nil, "IPv6 0th position",
		},
		{
			newNetworkNumberFromParts([4]uint32{2147483648, 0, 0, 0}, IPv6),
			newNetworkNumberFromParts([4]uint32{0, 0, 0, 1}, IPv6),
			0, ErrNoGreatestCommonBit, "IPv6 diverge at first bit",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pos, err := tc.ip1.LastCommonBitPosition(tc.ip2)
			assert.Equal(t, tc.err, err)
			assert.Equal(t, tc.position, pos)
		})
	}
}

func TestNetworkMasked(t *testing.T) {
	cases := []struct {
		network       string
		mask          int
		maskedNetwork string
	}{
		{"192.168.0.0/16", 16, "192.168.0.0/16"},
		{"192.168.0.0/16", 14, "192.168.0.0/14"},
		{"192.168.0.0/16", 18, "192.168.0.0/18"},
		{"192.168.0.0/16", 8, "192.0.0.0/8"},
		{"8000::/128", 96, "8000::/96"},
		{"8000::/128", 128, "8000::/128"},
		{"8000::/96", 112, "8000::/112"},
		{"8000:ffff::/96", 16, "8000::/16"},
	}
	for _, testcase := range cases {
		_, network, _ := net.ParseCIDR(testcase.network)
		_, expected, _ := net.ParseCIDR(testcase.maskedNetwork)
		n1 := NewNetwork(*network)
		e1 := NewNetwork(*expected)
		assert.True(t, e1.String() == maskedNetwork(n1, testcase.mask).String())
	}
}

func maskedNetwork(n *Network, ones int) *Network {
	mask := net.CIDRMask(ones, n.Number.ver*BitsPerUint32)
	return NewNetwork(net.IPNet{
		IP:   n.Number.ToIP().Mask(mask),
		Mask: mask,
	})
}

func TestNetworkEqual(t *testing.T) {
	cases := []struct {
		n1    string
		n2    string
		equal bool
		name  string
	}{
		{"192.128.0.0/24", "192.128.0.0/24", true, "IPv4 equals"},
		{"192.128.0.0/24", "192.128.0.0/23", false, "IPv4 not equals"},
		{"8000::/24", "8000::/24", true, "IPv6 equals"},
		{"8000::/24", "8000::/23", false, "IPv6 not equals"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, ipNet1, _ := net.ParseCIDR(tc.n1)
			_, ipNet2, _ := net.ParseCIDR(tc.n2)
			assert.Equal(t, tc.equal, NewNetwork(*ipNet1).Equal(NewNetwork(*ipNet2)))
		})
	}
}

func TestNetworkContains(t *testing.T) {
	cases := []struct {
		network string
		firstIP string
		lastIP  string
		name    string
	}{
		{"192.168.0.0/24", "192.168.0.0", "192.168.0.255", "192.168.0.0/24 contains"},
		{"8000::0/120", "8000::0", "8000::ff", "8000::0/120 contains"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, net1, _ := net.ParseCIDR(tc.network)
			network := NewNetwork(*net1)
			ip := NewNetworkNumber(net.ParseIP(tc.firstIP))
			lastIP := NewNetworkNumber(net.ParseIP(tc.lastIP))
			assert.False(t, network.Contains(previousNetworkNumber(*ip)))
			assert.False(t, network.Contains(nextNetworkNumber(*lastIP)))
			for !ip.Equal(*nextNetworkNumber(*lastIP)) {
				assert.True(t, network.Contains(ip))
				ipNext := nextNetworkNumber(*ip)
				ip = ipNext
			}
		})
	}

}

func TestNetworkContainsVersionMismatch(t *testing.T) {
	cases := []struct {
		network string
		ip      string
		name    string
	}{
		{"192.168.0.0/24", "8000::0", "IPv6 in IPv4 network"},
		{"8000::0/120", "192.168.0.0", "IPv4 in IPv6 network"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, net1, _ := net.ParseCIDR(tc.network)
			network := NewNetwork(*net1)
			assert.False(t, network.Contains(NewNetworkNumber(net.ParseIP(tc.ip))))
		})
	}

}

func TestNetworkCovers(t *testing.T) {
	cases := []struct {
		network string
		covers  string
		result  bool
		name    string
	}{
		{"10.0.0.0/24", "10.0.0.1/25", true, "contains"},
		{"10.0.0.0/24", "11.0.0.1/25", false, "not contains"},
		{"10.0.0.0/16", "10.0.0.0/15", false, "prefix false"},
		{"10.0.0.0/15", "10.0.0.0/16", true, "prefix true"},
		{"10.0.0.0/15", "10.0.0.0/15", true, "same"},
		{"10::0/15", "10.0.0.0/15", false, "ip ver mismatch"},
		{"10::0/15", "10::0/16", true, "ipv6"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, n, _ := net.ParseCIDR(tc.network)
			network := NewNetwork(*n)
			_, n, _ = net.ParseCIDR(tc.covers)
			cv := NewNetwork(*n)
			assert.Equal(t, tc.result, covers(*network, *cv))
		})
	}
}

func covers(n, o Network) bool {
	if n.Number.ver != o.Number.ver {
		return false
	}
	nMaskSize := n.Mask.ones
	oMaskSize := o.Mask.ones
	return n.Contains(&o.Number) && nMaskSize <= oMaskSize
}

func TestNetworkLeastCommonBitPosition(t *testing.T) {
	cases := []struct {
		cidr1       string
		cidr2       string
		expectedPos uint
		expectedErr error
		name        string
	}{
		{"0.0.1.0/24", "0.0.0.0/24", uint(9), nil, "IPv4 diverge before mask pos"},
		{"0.0.0.0/24", "0.0.0.0/24", uint(8), nil, "IPv4 diverge after mask pos"},
		{"0.0.0.128/24", "0.0.0.0/16", uint(16), nil, "IPv4 different mask pos"},
		{"128.0.0.0/24", "0.0.0.0/24", 0, ErrNoGreatestCommonBit, "IPv4 diverge at 1st pos"},
		{"8000::/96", "8000::1:0:0/96", uint(33), nil, "IPv6 diverge before mask pos"},
		{"8000::/96", "8000::8:0/96", uint(32), nil, "IPv6 diverge after mask pos"},
		{"8000::/96", "8000::/95", uint(33), nil, "IPv6 different mask pos"},
		{"ffff::0/24", "0::1/24", 0, ErrNoGreatestCommonBit, "IPv6 diverge at 1st pos"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, cidr1, err := net.ParseCIDR(c.cidr1)
			assert.NoError(t, err)
			_, cidr2, err := net.ParseCIDR(c.cidr2)
			assert.NoError(t, err)
			n1 := NewNetwork(*cidr1)
			pos, err := n1.LastCommonBitPosition(NewNetwork(*cidr2))
			if c.expectedErr != nil {
				assert.Equal(t, c.expectedErr, err)
			} else {
				assert.Equal(t, c.expectedPos, pos)
			}
		})
	}
}

func TestMask(t *testing.T) {
	cases := []struct {
		mask   *NetworkMask
		ip     *NetworkNumber
		masked *NetworkNumber
		err    error
		name   string
	}{
		{
			newNetworkMaskFromParts([4]uint32{math.MaxUint32}, IPv4),
			&NetworkNumber{[4]uint32{math.MaxUint32}, IPv4},
			&NetworkNumber{[4]uint32{math.MaxUint32}, IPv4},
			nil,
			"nop IPv4 mask",
		},
		{
			newNetworkMaskFromParts([4]uint32{math.MaxUint32 - math.MaxUint16}, IPv4),
			&NetworkNumber{[4]uint32{math.MaxUint16 + 1}, IPv4},
			&NetworkNumber{[4]uint32{math.MaxUint16 + 1}, IPv4},
			nil,
			"nop IPv4 mask",
		},
		{
			newNetworkMaskFromParts([4]uint32{math.MaxUint32 - math.MaxUint16}, IPv4),
			&NetworkNumber{[4]uint32{math.MaxUint32}, IPv4},
			&NetworkNumber{[4]uint32{math.MaxUint32 - math.MaxUint16}, IPv4},
			nil,
			"IPv4 masked",
		},
		{
			newNetworkMaskFromParts([4]uint32{math.MaxUint32, 0, 0, 0}, IPv4),
			&NetworkNumber{[4]uint32{math.MaxUint32, 0, 0, 0}, IPv4},
			&NetworkNumber{[4]uint32{math.MaxUint32, 0, 0, 0}, IPv4},
			nil,
			"nop IPv6 mask",
		},
		{
			newNetworkMaskFromParts([4]uint32{math.MaxUint32 - math.MaxUint16, 0, 0, 0}, IPv6),
			&NetworkNumber{[4]uint32{math.MaxUint16 + 1, 0, 0, 0}, IPv6},
			&NetworkNumber{[4]uint32{math.MaxUint16 + 1, 0, 0, 0}, IPv6},
			nil,
			"nop IPv6 mask",
		},
		{
			newNetworkMaskFromParts([4]uint32{math.MaxUint32 - math.MaxUint16, 0, 0, 0}, IPv6),
			&NetworkNumber{[4]uint32{math.MaxUint32, 0, 0, 0}, IPv6},
			&NetworkNumber{[4]uint32{math.MaxUint32 - math.MaxUint16, 0, 0, 0}, IPv6},
			nil,
			"IPv6 masked",
		},
		{
			newNetworkMaskFromParts([4]uint32{math.MaxUint32}, IPv4),
			&NetworkNumber{[4]uint32{math.MaxUint32, 0}, IPv6},
			nil, ErrVersionMismatch, "Version mismatch"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			masked, err := mask(*tc.mask, *tc.ip)
			assert.Equal(t, tc.masked, masked)
			assert.Equal(t, tc.err, err)
		})
	}
}

func mask(m NetworkMask, n NetworkNumber) (*NetworkNumber, error) {
	var result NetworkNumber
	if m.ver != n.ver {
		return nil, ErrVersionMismatch
	}
	result.ver = m.ver
	result.parts[0] = m.parts[0] & n.parts[0]
	if m.ver == IPv6 {
		result.parts[1] = m.parts[1] & n.parts[1]
		result.parts[2] = m.parts[2] & n.parts[2]
		result.parts[3] = m.parts[3] & n.parts[3]
	}
	return &result, nil
}

func TestNextIP(t *testing.T) {
	cases := []struct {
		ip   string
		next string
		name string
	}{
		{"0.0.0.0", "0.0.0.1", "IPv4 basic"},
		{"0.0.0.255", "0.0.1.0", "IPv4 rollover"},
		{"0.255.255.255", "1.0.0.0", "IPv4 consecutive rollover"},
		{"8000::0", "8000::1", "IPv6 basic"},
		{"0::ffff", "0::1:0", "IPv6 rollover"},
		{"0:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "1::", "IPv6 consecutive rollover"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, net.ParseIP(tc.next), nextIP(net.ParseIP(tc.ip)))
		})
	}
}

func TestPreviousIP(t *testing.T) {
	cases := []struct {
		ip   string
		next string
		name string
	}{
		{"0.0.0.1", "0.0.0.0", "IPv4 basic"},
		{"0.0.1.0", "0.0.0.255", "IPv4 rollover"},
		{"1.0.0.0", "0.255.255.255", "IPv4 consecutive rollover"},
		{"8000::1", "8000::0", "IPv6 basic"},
		{"0::1:0", "0::ffff", "IPv6 rollover"},
		{"1::0", "0:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "IPv6 consecutive rollover"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, net.ParseIP(tc.next), previousIP(net.ParseIP(tc.ip)))
		})
	}
}

func BenchmarkNetworkNumberBitIPv4(b *testing.B) {
	benchmarkNetworkNumberBit(b, "52.95.110.1", 6)
}
func BenchmarkNetworkNumberBitIPv6(b *testing.B) {
	benchmarkNetworkNumberBit(b, "2600:1ffe:e000::", 44)
}

func BenchmarkNetworkNumberEqualIPv4(b *testing.B) {
	benchmarkNetworkNumberEqual(b, "52.95.110.1", "52.95.110.1")
}

func BenchmarkNetworkNumberEqualIPv6(b *testing.B) {
	benchmarkNetworkNumberEqual(b, "2600:1ffe:e000::", "2600:1ffe:e000::")
}

func BenchmarkNetworkContainsIPv4(b *testing.B) {
	benchmarkNetworkContains(b, "52.95.110.0/24", "52.95.110.1")
}

func BenchmarkNetworkContainsIPv6(b *testing.B) {
	benchmarkNetworkContains(b, "2600:1ffe:e000::/40", "2600:1ffe:f000::")
}

func benchmarkNetworkNumberBit(b *testing.B, ip string, pos uint) {
	nn := NewNetworkNumber(net.ParseIP(ip))
	for n := 0; n < b.N; n++ {
		nn.BitAt(pos)
	}
}

func benchmarkNetworkNumberEqual(b *testing.B, ip1 string, ip2 string) {
	nn1 := NewNetworkNumber(net.ParseIP(ip1))
	nn2 := NewNetworkNumber(net.ParseIP(ip2))
	for n := 0; n < b.N; n++ {
		nn1.Equal(*nn2)
	}
}

func benchmarkNetworkContains(b *testing.B, cidr string, ip string) {
	nn := NewNetworkNumber(net.ParseIP(ip))
	_, ipNet, _ := net.ParseCIDR(cidr)
	network := NewNetwork(*ipNet)
	for n := 0; n < b.N; n++ {
		network.Contains(nn)
	}
}
