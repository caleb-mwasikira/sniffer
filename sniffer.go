package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/charmbracelet/huh"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
)

var (
	device       string
	filter       string
	snapshot_len int  = 1024
	promiscuous  bool = false
	err          error
	timeout      time.Duration = 30 * time.Second
	handle       *pcap.Handle
	packet_count int = 0
	project_path string
)

func init() {
	_, file, _, _ := runtime.Caller(0)
	project_path = filepath.Dir(file)
}

// prompts the user to select a network device to sniff on
func selectNetworkDevice() string {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatalf("failed to list network interfaces: %v", err)
	}

	options := []huh.Option[string]{}
	for _, device := range devices {
		options = append(options, huh.NewOption(device.Name, device.Name))
	}

	var device string
	err = huh.NewSelect[string]().
		Title("Select network device to listen on: ").
		Options(options...).
		Value(&device).Run()
	if err != nil {
		log.Fatalf("input error; %v", err)
	}

	return device
}

func main() {
	// parse cmdline flags
	flag.StringVar(&device, "i", "", "interface/device to sniff on")
	flag.StringVar(&filter, "f", "", "BPF filter to set on incoming packets")
	flag.Parse()

	if len(device) == 0 {
		device = selectNetworkDevice()
	}

	// open device in live capture mode
	fmt.Printf("starting sniffer on interface '%v' ...\n", device)
	handle, err = pcap.OpenLive(device, int32(snapshot_len), promiscuous, timeout)
	if err != nil {
		log.Fatalf("error opening network interface; %v", err)
	}
	defer handle.Close()

	if len(filter) == 0 {
		// select BPF filter
		err = huh.NewInput().
			Title("Enter BPF filter: ").
			Value(&filter).Run()
		if err != nil {
			log.Fatalf("input error; %v", err)
		}
	}

	err = handle.SetBPFFilter(filter)
	if err != nil {
		log.Fatalf("error setting BPF filter; %v", err)
	}

	// create new output pcap file and write header
	filename := strings.ReplaceAll(filter, " ", "_")
	fpath := path.Join(project_path, fmt.Sprintf("%v.pcap", filename))
	fmt.Printf("saving network packets to file %v ...\n", fpath)

	file, err := os.Create(fpath)
	if err != nil {
		log.Fatalf("error creating output pcap file; %v", err)
	}
	pcap_writer := pcapgo.NewWriter(file)
	pcap_writer.WriteFileHeader(uint32(snapshot_len), layers.LinkTypeEthernet)
	defer file.Close()

	packetSrc := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSrc.Packets() {
		pcap_writer.WritePacket(packet.Metadata().CaptureInfo, packet.Data())

		// only capture 50 packets and the stop
		if packet_count > 50 {
			break
		}
		packet_count++
	}
}
