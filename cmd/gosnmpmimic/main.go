package main

import "os"
import "strings"
import "io/ioutil"
import "regexp"
import "github.com/sirupsen/logrus"
import "github.com/slayercat/gosnmp"
import "github.com/slayercat/GoSNMPServer"
import "github.com/slayercat/GoSNMPServer/mibImps"
import "fmt"
import "strconv"
import "net"
import "compress/bzip2"
import "encoding/hex"
import "bufio"

import "github.com/urfave/cli/v2"

var mimicMibs []*GoSNMPServer.PDUValueControlItem

func makeApp() *cli.App {
	return &cli.App{
		Name:        "gosnmpserver",
		Description: "an example server of gosnmp",
		Commands: []*cli.Command{
			{
				Name:    "RunServer",
				Aliases: []string{"run-server"},
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "logLevel", Value: "info"},
					&cli.StringFlag{Name: "community", Value: "public"},
					&cli.StringFlag{Name: "bindTo", Value: "127.0.0.1:1161"},
					&cli.StringFlag{Name: "v3Username", Value: "testuser"},
					&cli.StringFlag{Name: "v3AuthenticationPassphrase", Value: "testauth"},
					&cli.StringFlag{Name: "v3PrivacyPassphrase", Value: "testpriv"},
					&cli.StringFlag{Name: "OidCaptureFile", Value: "cisco7513.txt"},
				},
				Action: runServer,
			},
		},
	}
}

func LoadSNMPRec(fname string) {
	f, err := os.OpenFile(fname, 0, 0)
	if err != nil {
		panic(err)
	}
	defer f.Close()
	// create a reader
	br := bufio.NewReader(f)
	// create a bzip2.reader, using the reader we just created
	cr := bzip2.NewReader(br)
	data, err := ioutil.ReadAll(cr)
	if err != nil {
		panic(err)
	}
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		items := strings.Split(line, "|")
		if len(items) < 3 {
			continue
		}
		oid := items[0]
		valType := items[1]
		val := items[2]
		if strings.Contains(valType, "x") || strings.Contains(valType, "X") {
			if valType != "64x" && valType != "64X" {
				dVal, err := hex.DecodeString(val)
				if err != nil {
					panic(err)
				}
				val = string(dVal)
			}
		}

		switch {
		case valType == "2":
			valI, _ := strconv.Atoi(val)
			pdu := GoSNMPServer.PDUValueControlItem{
				OID:  oid,
				Type: gosnmp.Integer,
				OnGet: func() (value interface{}, err error) {
					return GoSNMPServer.Asn1IntegerWrap(valI), nil
				},
				Document: "....",
			}
			mimicMibs = append(mimicMibs, &pdu)

		case valType == "65":
			valI, _ := strconv.Atoi(val)
			pdu := GoSNMPServer.PDUValueControlItem{
				OID:  oid,
				Type: gosnmp.Counter32,
				OnGet: func() (value interface{}, err error) {
					return GoSNMPServer.Asn1Counter32Wrap(uint(valI)), nil
				},
				Document: "....",
			}
			mimicMibs = append(mimicMibs, &pdu)
		case valType == "70":
			valI, _ := strconv.Atoi(val)
			pdu := GoSNMPServer.PDUValueControlItem{
				OID:  oid,
				Type: gosnmp.Counter64,
				OnGet: func() (value interface{}, err error) {
					return GoSNMPServer.Asn1Counter64Wrap(uint64(valI)), nil
				},
				Document: "....",
			}
			mimicMibs = append(mimicMibs, &pdu)
		case valType == "66":
			valI, _ := strconv.Atoi(val)
			pdu := GoSNMPServer.PDUValueControlItem{
				OID:  oid,
				Type: gosnmp.Gauge32,
				OnGet: func() (value interface{}, err error) {
					return GoSNMPServer.Asn1Gauge32Wrap(uint(valI)), nil
				},
				Document: "....",
			}
			mimicMibs = append(mimicMibs, &pdu)
		case valType == "64x":
			bytes, _ := hex.DecodeString(val)
			if len(bytes) == 4 {
				bytes = append(make([]byte, 12), bytes...)
			}
			fmt.Println("IP: bytes length -> ", len(bytes))
			ip := net.IP(bytes)
			pdu := GoSNMPServer.PDUValueControlItem{
				OID:  oid,
				Type: gosnmp.IPAddress,
				OnGet: func() (value interface{}, err error) {
					return GoSNMPServer.Asn1IPAddressWrap(ip), nil
				},
				Document: "....",
			}
			mimicMibs = append(mimicMibs, &pdu)
		case valType == "6":
			pdu := GoSNMPServer.PDUValueControlItem{
				OID:  oid,
				Type: gosnmp.ObjectIdentifier,
				OnGet: func() (value interface{}, err error) {
					return GoSNMPServer.Asn1ObjectIdentifierWrap(val), nil
				},
				Document: "....",
			}
			mimicMibs = append(mimicMibs, &pdu)

		case valType == "4" || valType == "4x":
			val = strings.Replace(val, `"`, "", -1)
			pdu := GoSNMPServer.PDUValueControlItem{
				OID:  oid,
				Type: gosnmp.OctetString,
				OnGet: func() (value interface{}, err error) {
					return GoSNMPServer.Asn1ObjectIdentifierWrap(val), nil
				},
				Document: "....",
			}
			mimicMibs = append(mimicMibs, &pdu)
		case valType == "67":
			valI, _ := strconv.Atoi(val)
			pdu := GoSNMPServer.PDUValueControlItem{
				OID:  oid,
				Type: gosnmp.TimeTicks,
				OnGet: func() (value interface{}, err error) {
					return GoSNMPServer.Asn1TimeTicksWrap(uint32(valI)), nil
				},
				Document: "....",
			}
			mimicMibs = append(mimicMibs, &pdu)
		}
	}
}

func LoadSNMPWalk(fname string) {
	data, err := ioutil.ReadFile(fname)
	if err != nil {
		panic(err)
	}
	re, err := regexp.Compile(`(.*?) = (.*?): (.*)`)
	if err != nil {
		panic(err)
	}
	matches := re.FindAllStringSubmatch(string(data), -1)
	for _, match := range matches {
		fmt.Printf("oid: %v type: %v value: %v\n", match[1], match[2], match[3])
		oid := match[1]
		valType := match[2]
		val := match[3]
		if valType != "STRING" {
			re, err := regexp.Compile(`\((.*)\)`)
			if err != nil {
				panic(err)
			}
			for _, m := range re.FindAllStringSubmatch(val, -1) {
				fmt.Printf("Updating val %s as %v\n", val, m[1])
				val = string(m[1])
			}
		}

		switch {
		case valType == "INTEGER":
			valI, _ := strconv.Atoi(val)
			pdu := GoSNMPServer.PDUValueControlItem{
				OID:  oid,
				Type: gosnmp.Integer,
				OnGet: func() (value interface{}, err error) {
					return GoSNMPServer.Asn1IntegerWrap(valI), nil
				},
				Document: "....",
			}
			mimicMibs = append(mimicMibs, &pdu)

		case valType == "Counter32":
			valI, _ := strconv.Atoi(val)
			pdu := GoSNMPServer.PDUValueControlItem{
				OID:  oid,
				Type: gosnmp.Counter32,
				OnGet: func() (value interface{}, err error) {
					return GoSNMPServer.Asn1Counter32Wrap(uint(valI)), nil
				},
				Document: "....",
			}
			mimicMibs = append(mimicMibs, &pdu)
		case valType == "Counter64":
			valI, _ := strconv.Atoi(val)
			pdu := GoSNMPServer.PDUValueControlItem{
				OID:  oid,
				Type: gosnmp.Counter64,
				OnGet: func() (value interface{}, err error) {
					return GoSNMPServer.Asn1Counter64Wrap(uint64(valI)), nil
				},
				Document: "....",
			}
			mimicMibs = append(mimicMibs, &pdu)
		case valType == "Gauge32":
			valI, _ := strconv.Atoi(val)
			pdu := GoSNMPServer.PDUValueControlItem{
				OID:  oid,
				Type: gosnmp.Gauge32,
				OnGet: func() (value interface{}, err error) {
					return GoSNMPServer.Asn1Gauge32Wrap(uint(valI)), nil
				},
				Document: "....",
			}
			mimicMibs = append(mimicMibs, &pdu)
		case valType == "Hex-STRING":
			pdu := GoSNMPServer.PDUValueControlItem{
				OID:  oid,
				Type: gosnmp.OctetString,
				OnGet: func() (value interface{}, err error) {
					return GoSNMPServer.Asn1OctetStringWrap(val), nil
				},
				Document: "....",
			}
			mimicMibs = append(mimicMibs, &pdu)
		case valType == "IpAddress":
			ip := net.ParseIP(val)
			pdu := GoSNMPServer.PDUValueControlItem{
				OID:  oid,
				Type: gosnmp.IPAddress,
				OnGet: func() (value interface{}, err error) {
					return GoSNMPServer.Asn1IPAddressWrap(ip), nil
				},
				Document: "....",
			}
			mimicMibs = append(mimicMibs, &pdu)
		case valType == "OID":
			pdu := GoSNMPServer.PDUValueControlItem{
				OID:  oid,
				Type: gosnmp.ObjectIdentifier,
				OnGet: func() (value interface{}, err error) {
					return GoSNMPServer.Asn1ObjectIdentifierWrap(val), nil
				},
				Document: "....",
			}
			mimicMibs = append(mimicMibs, &pdu)
		case valType == "STRING":
			val = strings.Replace(val, `"`, "", -1)
			pdu := GoSNMPServer.PDUValueControlItem{
				OID:  oid,
				Type: gosnmp.OctetString,
				OnGet: func() (value interface{}, err error) {
					return GoSNMPServer.Asn1ObjectIdentifierWrap(val), nil
				},
				Document: "....",
			}
			mimicMibs = append(mimicMibs, &pdu)
		case valType == "Timeticks":
			valI, _ := strconv.Atoi(val)
			pdu := GoSNMPServer.PDUValueControlItem{
				OID:  oid,
				Type: gosnmp.TimeTicks,
				OnGet: func() (value interface{}, err error) {
					return GoSNMPServer.Asn1TimeTicksWrap(uint32(valI)), nil
				},
				Document: "....",
			}
			mimicMibs = append(mimicMibs, &pdu)
		}
	}
}

func LoadOids(fname string) {
	if strings.Contains(fname, ".bz2") {
		LoadSNMPRec(fname)
	} else {
		LoadSNMPWalk(fname)
	}
}

func main() {
	app := makeApp()
	app.Run(os.Args)
}

func runServer(c *cli.Context) error {
	logger := GoSNMPServer.NewDefaultLogger()
	switch strings.ToLower(c.String("logLevel")) {
	case "fatal":
		logger.(*GoSNMPServer.DefaultLogger).Level = logrus.FatalLevel
	case "error":
		logger.(*GoSNMPServer.DefaultLogger).Level = logrus.ErrorLevel
	case "info":
		logger.(*GoSNMPServer.DefaultLogger).Level = logrus.InfoLevel
	case "debug":
		logger.(*GoSNMPServer.DefaultLogger).Level = logrus.DebugLevel
	case "trace":
		logger.(*GoSNMPServer.DefaultLogger).Level = logrus.TraceLevel
	}
	mibImps.SetupLogger(logger)
	LoadOids(c.String("OidCaptureFile"))
	master := GoSNMPServer.MasterAgent{
		Logger: logger,
		SecurityConfig: GoSNMPServer.SecurityConfig{
			AuthoritativeEngineBoots: 1,
			Users: []gosnmp.UsmSecurityParameters{
				{
					UserName:                 c.String("v3Username"),
					AuthenticationProtocol:   gosnmp.MD5,
					PrivacyProtocol:          gosnmp.DES,
					AuthenticationPassphrase: c.String("v3AuthenticationPassphrase"),
					PrivacyPassphrase:        c.String("v3PrivacyPassphrase"),
				},
			},
		},
		SubAgents: []*GoSNMPServer.SubAgent{
			{
				CommunityIDs: []string{c.String("community")},
				OIDs:         mimicMibs,
			},
		},
	}
	syncErr := master.SyncConfig()
	if syncErr != nil {
		panic(syncErr)
	}
	logger.Infof("V3 Users:")
	for _, val := range master.SecurityConfig.Users {
		logger.Infof(
			"\tUserName:%v\n\t -- AuthenticationProtocol:%v\n\t -- PrivacyProtocol:%v\n\t -- AuthenticationPassphrase:%v\n\t -- PrivacyPassphrase:%v",
			val.UserName,
			val.AuthenticationProtocol,
			val.PrivacyProtocol,
			val.AuthenticationPassphrase,
			val.PrivacyPassphrase,
		)
	}
	server := GoSNMPServer.NewSNMPServer(master)
	err := server.ListenUDP("udp", c.String("bindTo"))
	if err != nil {
		logger.Errorf("Error in listen: %+v", err)
	}
	server.ServeForever()
	return nil
}
