package iptrie

import (
	"fmt"
	"net"
)

var (
	Nil = -1
)

type Entry struct {
	Network string
	Label   Label
}

type Label struct {
	Isp, Loc string
}

type labPtr struct {
	isp, loc ptr
}

var emptyLabel = labPtr{ptr{Nil, 0}, ptr{Nil, 0}}

type ptr struct {
	s, l int
}

func (p *ptr) Equal(p1 *ptr) bool {
	return p.s == p1.s && p.l == p1.l
}

type Trie struct {
	ver    int
	nodes  []node
	labels []byte
}

func New(v int) *Trie { return &Trie{ver: v} }

func (t *Trie) Init(entries []Entry) error {
	var pBuf = make(map[string]ptr)
	var toPtr = func(str string) ptr {
		if _, ok := pBuf[str]; !ok {
			t.labels = append(t.labels, []byte(str)...)
			pBuf[str] = ptr{l: len(str), s: len(t.labels) - len(str)}
		}
		return pBuf[str]
	}
	var labelToPtr = func(l Label) labPtr {
		return labPtr{isp: toPtr(l.Isp), loc: toPtr(l.Loc)}
	}

	_, rootNet, _ := net.ParseCIDR("0.0.0.0/0")
	if t.ver == IPv6 {
		_, rootNet, _ = net.ParseCIDR("0::0/0")
	}

	var rootNode = t.newNode(*NewNetwork(*rootNet), labelToPtr(Label{Isp: "any", Loc: "any"}), 0)

	for _, cfg := range entries {
		var _, ipNet, err = net.ParseCIDR(cfg.Network)
		if err != nil {
			return fmt.Errorf("parse cidr of %s err %s", cfg.Network, err)
		}

		var network = NewNetwork(*ipNet)
		if network == nil {
			return fmt.Errorf("network of %s is nil", cfg.Network)
		}

		if err := rootNode.maybeInsert(*network, labelToPtr(cfg.Label), t); err != nil {
			return err
		}
	}

	return nil
}

func (t *Trie) Match(ip net.IP) (ok bool, label Label, err error) {
	number, err := IpToNetworkNumber(ip)
	if err != nil {
		return false, label, ErrInvalidIP
	}

	return t.nodeAt(0).matchNetwork(&number, t)
}

func (t *Trie) newNode(network Network, label labPtr, gap uint) *node {
	t.nodes = append(t.nodes, node{
		myIdx:    Nil,
		childIdx: [2]int{Nil, Nil},
		gap:      gap,
		network:  network,
		label:    label,
	})

	idx := len(t.nodes) - 1
	node := &t.nodes[idx]
	node.myIdx = idx

	return node
}

func (t *Trie) nodeAt(idx int) *node {
	if idx < 0 || idx >= len(t.nodes) {
		return nil
	}
	return &t.nodes[idx]
}

func (t *Trie) labelAt(pos labPtr) (ret Label, ok bool) {
	if ret.Isp, ok = t.strAt(pos.isp); !ok {
		return ret, false
	}
	if ret.Loc, ok = t.strAt(pos.loc); !ok {
		return ret, false
	}
	return
}

func (t *Trie) strAt(p ptr) (string, bool) {
	var s, l = p.s, p.l
	if s > 0 && s+l <= len(t.labels) {
		return string(t.labels[s : s+l]), true
	}
	return "", false
}

// 19*4 bytes
type node struct {
	gap      uint
	myIdx    int
	childIdx [2]int

	network Network
	label   labPtr
}

func (n *node) matchNetwork(nn *NetworkNumber, t *Trie) (ok bool, label Label, err error) {
	if n == nil || !n.network.Contains(nn) || n.childBitPosition() < 0 {
		return
	}

	bit, err := n.childBitOf(nn)

	fmt.Printf("node %p %s, child bit %d, child idx is %d\n", n, n.network.String(), bit, n.childIdx[bit])

	if err != nil {
		return false, label, err
	} else if child := t.nodeAt(n.childIdx[bit]); child != nil {
		fmt.Printf("child %p %s\n", child, child.network.String())
		// 深度优先，取底层match节点label
		return child.matchNetwork(nn, t)
	}

	fmt.Printf("ok %t\n", ok)
	// 子节点没有label, 返回本节点可能存在的label
	if !ok {
		label, ok = t.labelAt(n.label)
	}

	return
}

func (n *node) maybeInsert(network Network, label labPtr, t *Trie) error {
	if n.network.Equal(&network) {
		n.label = label
		return nil
	}

	// 根据network计算子节点位置bit
	var bit, err = n.childBitOf(&network.Number)
	if err != nil {
		return err
	}

	// 计算bit处子节点索引
	var cIdx = n.childIdx[bit]
	if cIdx == Nil {
		fmt.Printf("node %p %s insert new node %s\n", n, n.network.String(), network.String())
		return n.insert(bit, t.newNode(network, label, uint(network.Mask.Ones())), t)
	}

	// 获取子节点指针
	var child = t.nodeAt(cIdx)
	if child == nil {
		return fmt.Errorf("node at %d is nil", cIdx)
	}

	// 判断是否需要分裂child
	lcb, err := network.LastCommonBitPosition(&child.network)
	if err != nil {
		return err
	}

	// 需要分裂
	if int(lcb) > child.childBitPosition()+1 {
		// 分裂出新的子节点child
		child = t.newNode(network, emptyLabel, n.bitsLength()-lcb)

		// 将child挂载到n下，并将n的bit位子节点挂载child下
		if err := n.insert(bit, child, t); err != nil {
			return err
		}
	}

	// 将label插入到child下
	return child.maybeInsert(network, label, t)
}

func (n *node) insert(bit uint32, node *node, t *Trie) error {
	cIdx := n.childIdx[bit]
	if cIdx != Nil {
		child := t.nodeAt(cIdx)
		if child == nil {
			return fmt.Errorf("node at %d is nil", cIdx)
		}

		// 计算child在node子节点的位置
		cBit, err := node.childBitOf(&child.network.Number)
		if err != nil {
			return fmt.Errorf("child bit of %s is %s", child.network.String(), err)
		}

		// 将child挂载到node下
		if err := node.insert(cBit, child, t); err != nil {
			return err
		}
	}

	// node挂载到n下
	t.nodes[n.myIdx].childIdx[bit] = node.myIdx

	return nil
}

func (n *node) childBitOf(ip *NetworkNumber) (uint32, error) {
	return ip.BitAt(uint(n.childBitPosition()))
}

func (n *node) childBitPosition() int {
	return int(n.bitsLength()-n.gap) - 1
}

func (n *node) bitsLength() uint {
	return BitsPerUint32 * uint(n.network.Version())
}
