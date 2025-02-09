package main

import (
	"fmt"
	"log"
	"os"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
)

func main() {
	// 定义要捕获的网络接口
	iface := "ens33"
	// 定义保存的 PCAP 文件路径
	outputFile := "captured.pcap"

	// 打开网络接口进行抓包
	handle, err := pcap.OpenLive(iface, 65536, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	filter := "(tcp and port 80) or port 53 or icmp"
	err = handle.SetBPFFilter(filter)
	if err != nil {
		log.Fatal(err)
	}

	// 创建 PCAP 文件
	file, err := os.Create(outputFile)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	// 创建 PCAP 写入器
	w := pcapgo.NewWriter(file)
	// 写入 PCAP 文件头
	err = w.WriteFileHeader(65536, handle.LinkType())
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("开始在接口 %s 上抓包，将保存到 %s\n", iface, outputFile)

	// 创建数据包源
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	// 循环捕获数据包
	for packet := range packetSource.Packets() {
		// 获取数据包的时间戳、长度等信息
		ts := packet.Metadata().Timestamp
		length := packet.Metadata().Length
		captureLength := packet.Metadata().CaptureLength
		data := packet.Data()

		// 将数据包写入 PCAP 文件
		err := w.WritePacket(gopacket.CaptureInfo{
			Timestamp:     ts,
			CaptureLength: captureLength,
			Length:        length,
		}, data)
		if err != nil {
			log.Println("写入数据包时出错:", err)
		}

		// 这里可以添加退出条件，例如捕获一定数量的数据包或达到一定时间后退出
		// 示例：捕获 10 秒后退出
		if time.Since(time.Now()) > 10*time.Second {
			break
		}
	}

	fmt.Println("抓包结束，数据已保存到", outputFile)
}
