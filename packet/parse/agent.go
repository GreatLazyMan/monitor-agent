package main

import (
	"fmt"
	"log"
	"net"
	"sort"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type TcpPacket struct {
	BeginTime int64
	EndTime   int64
	Cost      float64
	StreamID  string
	FinAck    int8
	Fin       bool
}

// generateStreamID 生成标准化流标识符（双向流量统一处理）
func generateStreamID(ip1 net.IP, port1 uint16, ip2 net.IP, port2 uint16) string {
	// 比较IP地址大小
	if compareIPs(ip1, ip2) > 0 {
		ip1, ip2 = ip2, ip1
		port1, port2 = port2, port1
	} else if compareIPs(ip1, ip2) == 0 && port1 > port2 {
		port1, port2 = port2, port1
	}
	return fmt.Sprintf("%s:%d-%s:%d", ip1, port1, ip2, port2)
}

// compareIPs 比较两个IP地址（支持IPv4/IPv6）
func compareIPs(a, b net.IP) int {
	a = a.To16()
	b = b.To16()
	for i := 0; i < len(a); i++ {
		if a[i] < b[i] {
			return -1
		} else if a[i] > b[i] {
			return 1
		}
	}
	return 0
}

func main() {
	// 打开PCAP文件
	handle, err := pcap.OpenOffline("example.pcap")
	if err != nil {
		log.Fatal("无法打开PCAP文件:", err)
	}
	defer handle.Close()

	// 创建数据包源
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	streamMap := make(map[string]*TcpPacket) // 存储TCP流
	streamSlice := make([]*TcpPacket, 0)     // 存储TCP流

	// 遍历所有数据包
	for packet := range packetSource.Packets() {
		// 解析IP层（支持IPv4和IPv6）
		packetTimestamp := packet.Metadata().Timestamp.UnixMicro()
		var srcIP, dstIP net.IP
		if ipv4 := packet.Layer(layers.LayerTypeIPv4); ipv4 != nil {
			ip, _ := ipv4.(*layers.IPv4)
			srcIP, dstIP = ip.SrcIP, ip.DstIP
		} else if ipv6 := packet.Layer(layers.LayerTypeIPv6); ipv6 != nil {
			ip, _ := ipv6.(*layers.IPv6)
			srcIP, dstIP = ip.SrcIP, ip.DstIP
		} else {
			continue // 跳过非IP数据包
		}

		// 解析TCP层
		tcpLayer := packet.Layer(layers.LayerTypeTCP)
		if tcpLayer == nil {
			continue // 跳过非TCP数据包
		}
		tcp, _ := tcpLayer.(*layers.TCP)
		srcPort := uint16(tcp.SrcPort)
		dstPort := uint16(tcp.DstPort)

		// 生成标准化流标识符
		streamID := generateStreamID(srcIP, srcPort, dstIP, dstPort)
		if tcp.SYN && !tcp.ACK {
			streamMap[streamID] = &TcpPacket{
				BeginTime: packetTimestamp,
				StreamID:  streamID,
			}
		} else if tcp.RST {
			if p, ok := streamMap[streamID]; ok && p.BeginTime != 0 {
				p.EndTime = packetTimestamp
				p.Cost = float64(packetTimestamp-p.BeginTime) / float64(1e6)
				fmt.Println("RST$$$$$$$$$$$$$$$$")
				streamSlice = append(streamSlice, p)
			}
		} else if tcp.FIN {
			if p, ok := streamMap[streamID]; ok && p.BeginTime != 0 && !p.Fin {
				p.Fin = true
				p.FinAck = 0
			}
		} else if tcp.ACK {
			if p, ok := streamMap[streamID]; ok && p.Fin && p.BeginTime != 0 {
				p.FinAck += 1
				if p.FinAck == 2 {
					p.EndTime = packetTimestamp
					p.Cost = float64(p.EndTime-p.BeginTime) / float64(1e6)
					fmt.Println("$$$$$$$$$$$$$$$$", p.StreamID)
					streamSlice = append(streamSlice, p)
				}
			}
		}
	}
	sort.Slice(streamSlice, func(i, j int) bool {
		return streamSlice[i].Cost < streamSlice[j].Cost
	})

	for _, p := range streamSlice {
		fmt.Println("#######################")
		fmt.Println(p.StreamID, ":", p.Cost)
	}
}
