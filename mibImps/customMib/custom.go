package customMib

import "github.com/slayercat/GoSNMPServer"
import "github.com/slayercat/gosnmp"

func init() {
	g_Logger = GoSNMPServer.NewDiscardLogger()
}

var g_Logger GoSNMPServer.ILogger

//SetupLogger Setups Logger for this mib
func SetupLogger(i GoSNMPServer.ILogger) {
	g_Logger = i
}

func All() []*GoSNMPServer.PDUValueControlItem {
	var result []*GoSNMPServer.PDUValueControlItem
	helloWorldOid := GoSNMPServer.PDUValueControlItem{
		OID:      "1.3.6.1.4.1.571113.1",
		Type:     gosnmp.OctetString,
		OnGet:    HelloWorld,
		Document: "....",
	}
	result = append(result, &helloWorldOid)

	sysOid := GoSNMPServer.PDUValueControlItem{
		OID:      "1.3.6.1.2.1.1.2.0",
		Type:     gosnmp.ObjectIdentifier,
		OnGet:    SysOid,
		Document: "....",
	}
	result = append(result, &sysOid)

	sysDescr := GoSNMPServer.PDUValueControlItem{
		OID:      "1.3.6.1.2.1.1.5.0",
		Type:     gosnmp.OctetString,
		OnGet:    SystemDescription,
		Document: "....",
	}
	result = append(result, &sysDescr)

	return result
}

func HelloWorld() (value interface{}, err error) {
	return GoSNMPServer.Asn1OctetStringWrap("Hello World"), nil
}

func SysOid() (value interface{}, err error) {
	return GoSNMPServer.Asn1ObjectIdentifierWrap("1.3.6.1.4.1.571113"), nil
}

func SystemDescription() (value interface{}, err error) {
	return GoSNMPServer.Asn1OctetStringWrap("My custom go snmp server"), nil
}
