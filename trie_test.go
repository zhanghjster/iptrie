package iptrie

import (
	"encoding/json"
	"log"
	"net"
	"os"
	"testing"
)

type IspLoc struct {
	Isp string `json:"isp"`
	Loc string `json:"loc"`
}

// 1. 准确性
func TestTrie_Init(t *testing.T) {
	var f, err = os.Open("isp_loc_v4.json")
	if err != nil {
		t.Fatal(err)
	}

	var datas map[string]IspLoc
	if err = json.NewDecoder(f).Decode(&datas); err != nil {
		t.Fatal(err)
	}

	var entries []Entry
	for key, label := range datas {
		if IpVer(key) != IPv4 {
			continue
		}
		entries = append(entries, Entry{
			Network: key,
			Label:   Label{Isp: label.Isp, Loc: label.Loc},
		})
		break
	}

	var trie = New(IPv4)
	if err := trie.Init(entries); err != nil {
		log.Fatal(err)
	}

	ok, lb, err := trie.Match(net.ParseIP("1.0.0.1"))
	if err != nil {
		t.Log(err)
	}

	for _, node := range trie.nodes {
		t.Logf("node %s 0idx %d 1idx %d", node.network.String(), node.childIdx[0], node.childIdx[1])
	}

	t.Logf("ok is %t", ok)
	t.Logf("label is %s", lb.Isp+"-"+lb.Loc)
}
