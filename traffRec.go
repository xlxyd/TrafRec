package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"math/rand"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
)

var (
	deviceName  string
	promiscuous bool = false
	err         error
	timeout     time.Duration = -1 * time.Second
	handle      *pcap.Handle
	bpfFilter   string
	snaplen     uint32 = 1600
)

var (
	// Define a channel to signal when the command has completed
	timer    = make(chan time.Time) //timer
	timerVar uint
	//Define a channel to signal start command
	start = make(chan struct{})
	//Flag to list interfaces
	inputListInterfacesFlag bool
	//Vars of execution
	inputExec     string
	inputListFile string
)

// Initialize flags
func init() {
	flag.StringVar(&deviceName, "i", "...", "Specify interface -i [interface name]")
	flag.StringVar(&bpfFilter, "f", "", "Specify BPF filter -f [filter]")
	flag.StringVar(&inputExec, "e", "", "Specify command to start -e [name]")
	flag.StringVar(&inputListFile, "l", "", "Specify list of commands -l [name]")

	flag.UintVar(&timerVar, "t", 0, "Specify timeout of exiting recording -t uint")

	flag.BoolVar(&inputListInterfacesFlag, "list", false, "List interfaces with -list")
	flag.Parse()

	//Edit debug data to print flags

	if flag_count := flag.NFlag(); flag_count == 0 {
		fmt.Fprintf(os.Stderr, "Usage of %s:\n", os.Args[0])
		flag.PrintDefaults()
		fmt.Println()
		//Edit to be good
		fmt.Println(`Example: .\trafRec.exe -i "-eth0" -f "host 192.168.106.125" -e "ping google" -t 1`)
		fmt.Println(`Example: .\trafRec.exe -i "-eth0" -f "host 192.168.106.125" -l ".\commands.list" -t 4`)
		fmt.Println()
		os.Exit(0)
	}

	if inputListInterfacesFlag {
		listInterfaces()
		os.Exit(0)
	}
}

func main() {

	log.SetFlags(log.Lmicroseconds)
	//log.Println("DEBUG:", "main func: Starting main function")

	if inputExec == "" && inputListFile != "" {
		//log.Println("DEBUG:", "main func: List file specified", inputListFile)
		//parsing list
		commandsList := getCommandsFromList()

		//log.Println("DEBUG:", "main func: Content of commandsList", commandsList)

		for _, command := range commandsList {

			log.Println("DEBUG:", "main func: Processing command", command)

			go recordTraff()
			startCommand(command)
		}

	} else if inputExec != "" && inputListFile == "" {

		log.Println("DEBUG:", "main func: Processing command", inputExec)

		command := getCommandsFromFlag()
		go recordTraff()
		startCommand(command)

	} else if inputExec != "" && inputListFile != "" {
		//process both list and single command but for now do nothing
		log.Fatalln("List and command was specified ... Exiting")
	}

}

// Open file - read and get slice of slices of command args
func getCommandsFromList() [][]string {

	commandsList := [][]string{}

	file, err := os.Open(inputListFile)
	if err != nil {
		log.Fatalln(err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		fmt.Println(scanner.Text())
		command := strings.Fields(scanner.Text())
		commandsList = append(commandsList, command)
	}
	return commandsList
}

// Open file - read and get slice of command args
func getCommandsFromFlag() []string {
	command := strings.Fields(inputExec)
	return command
}

func listInterfaces() {
	vers := pcap.Version()
	fmt.Println(vers)

	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatalln("FATAL: ", err)
	}

	fmt.Println("INTERFACES:")

	for indx, inFace := range devices {
		for _, iFace := range inFace.Addresses {
			fmt.Println(indx, "Name:", inFace.Name, "IP:", iFace.IP)
		}
	}
}

func recordTraff() {

	//log.Println("DEBUG:", "recordTraff func: Entered function")

	// Open output pcap file and write header
	f, _ := os.Create(strconv.Itoa(rand.Intn(99999999)+99999999) + ".pcap")
	w := pcapgo.NewWriter(f)
	w.WriteFileHeader(snaplen, layers.LinkTypeEthernet)
	defer f.Close()

	// Open the device for capturing
	handle, err = pcap.OpenLive(deviceName, int32(snaplen), promiscuous, timeout)
	if err != nil {
		fmt.Printf("Error opening device %s: %v", deviceName, err)
		os.Exit(1)
	}
	defer handle.Close()

	// Start processing packets
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	//start command
	start <- struct{}{}

outerloop:
	for packet := range packetSource.Packets() {
		// Process packet here
		//fmt.Println(packet)
		w.WritePacket(packet.Metadata().CaptureInfo, packet.Data())

		// Check if the command has completed
		select {
		case <-timer:
			break outerloop
		default:
			// If not, continue recording
		}
	}
}

func startCommand(command []string) {

	//log.Println("DEBUG:", "startCommand func: Entered function")

	<-start

	//log.Println("DEBUG:", "startCommand func: Recived start chan")

	time.Sleep(1 * time.Second)

	cmd := exec.Command(command[0], command[1:]...)
	//Start command
	err = cmd.Start()

	if err != nil {
		log.Println("ERROR: Got problem starting command:", command, err)
	}
	//Wait till end of command
	err = cmd.Wait()
	if err != nil {
		log.Println("ERROR: Got problem while waiting end of command:", command, err)
	}

	//log.Println("DEBUG:", "startCommand func: Command execution completed")
	//log.Println("DEBUG:", "startCommand func: Status code:", cmd.ProcessState.ExitCode(), "isExited:", cmd.ProcessState.Exited())
	//log.Println("DEBUG:", "startCommand func: isSuccess:", cmd.ProcessState.Success())

	if cmd.ProcessState.ExitCode() != 0 {
		log.Println("ERROR::::::::::::::::::::COMMAND ENDS WITH BAD STATUS::::::::::::::::::::", cmd)
	}

	timer := time.After(time.Duration(timerVar) * time.Second)
	<-timer
	//log.Println("DEBUG:", "startCommand func: Recived timer chan. Exiting function")

}
