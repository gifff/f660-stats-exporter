package scraper

import (
	"errors"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"

	"github.com/andybalholm/cascadia"
	"golang.org/x/net/html"
	"golang.org/x/net/html/atom"
)

var (
	transferMeaningRegexp = regexp.MustCompile(`\<script language=javascript\>Transfer_meaning\('(.+)','(.+)'\);\<\/script\>`)

	ErrNoTableNodes = errors.New("f660: no table nodes")
)

type LANStat struct {
	Name            string
	LinkType        string
	BytesSent       int64
	BytesReceived   int64
	PacketsSent     int64
	PacketsReceived int64
}

type WANIP struct {
	Address            string
	SubnetMask         string
	Gateway            string
	ConnectionStatus   string
	DisconnectReason   string
	OnlineDuration     int64
	RemainingLeaseTime int64
}

type WANStats struct {
	Type           string
	ConnectionName string
	IPVersion      string
	NATEnabled     bool
	DNSes          []string
	IPv4           WANIP
	MACAddress     string
}

type WLANStat struct {
	Enabled                   bool
	Name                      string
	AuthenticationType        string
	EncryptionType            string
	MACAddress                string
	PacketsReceived           int64
	PacketsSent               int64
	BytesReceived             int64
	BytesSent                 int64
	ErrorPacketsReceived      int64
	ErrorPacketsSent          int64
	DiscardedReceivingPackets int64
	DiscardedSendingPackets   int64
}

func parseLANStats(r io.Reader) ([]LANStat, error) {
	lanTableSelector, err := cascadia.Compile("table#TestContent")
	if err != nil {
		return nil, err
	}

	doc, err := html.Parse(r)
	if err != nil {
		return nil, err
	}

	lanTableNodes := cascadia.QueryAll(doc, lanTableSelector)
	if len(lanTableNodes) == 0 {
		return nil, ErrNoTableNodes
	}

	lanStats := make([]LANStat, 0, len(lanTableNodes))
	for _, lanTableNode := range lanTableNodes {
		stat := LANStat{
			Name:     parseLANData(lanTableNode, 1),
			LinkType: parseLANData(lanTableNode, 2),
		}
		stat.PacketsReceived, stat.BytesReceived = parseLANPacketsBytes(parseLANData(lanTableNode, 5))
		stat.PacketsSent, stat.BytesSent = parseLANPacketsBytes(parseLANData(lanTableNode, 6))

		lanStats = append(lanStats, stat)
	}

	return lanStats, nil
}

func parseLANData(root *html.Node, nthChild int) string {
	selector := cascadia.MustCompile(fmt.Sprintf("tr:nth-child(%d) > td:nth-child(2)", nthChild))
	tdNode := cascadia.Query(root, selector)
	if tdNode == nil || tdNode.DataAtom != atom.Td {
		return ""
	}

	return tdNode.FirstChild.Data
}

func parseLANPacketsBytes(s string) (packets int64, bytes int64) {
	parts := strings.Split(s, "/")

	var err error
	packets, err = strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		// TODO: Log!
		return
	}

	bytes, err = strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		// TODO: Log!
		return
	}

	return
}

func parseWANStats(r io.Reader) (*WANStats, error) {
	wanTableSelector, err := cascadia.Compile("table#TestContent0")
	if err != nil {
		return nil, fmt.Errorf("ParseWANStats: unable to compile wanTableSelector: %w", err)
	}

	doc, err := html.Parse(r)
	if err != nil {
		return nil, err
	}

	tableNode := cascadia.Query(doc, wanTableSelector)
	if tableNode == nil {
		return nil, ErrNoTableNodes
	}

	ws := WANStats{
		Type:           parseTextInputValueByID(tableNode, "TextIPMode0"),
		ConnectionName: parseTextInputValueByID(tableNode, "TextWANCName0"),
		IPVersion:      parseTextInputValueByID(tableNode, "TextIPIpMode0"),
		NATEnabled:     parseTextInputValueByID(tableNode, "TextIPIsNAT0") == "Enabled",
		MACAddress:     parseTextInputValueByID(tableNode, "TextIPWorkIFMac0"),
		DNSes:          strings.Split(parseTextInputValueByID(tableNode, "TextIPDNS0"), "/"),
		IPv4: WANIP{
			Address:            strings.Split(parseTextInputValueByID(tableNode, "TextIPAddress0"), "/")[0],
			SubnetMask:         parseTextInputValueBySelector(tableNode, "tr#TR_IP_SubnetMask > td.tdright > input[type=text].uiNoBorder"),
			Gateway:            parseTextInputValueByID(tableNode, "TextIPGateWay0"),
			ConnectionStatus:   parseTextInputValueByID(tableNode, "TextIPConnStatus0"),
			DisconnectReason:   parseTextInputValueByID(tableNode, "TextIPConnError0"),
			OnlineDuration:     parseSec(parseTextInputValueByID(tableNode, "TextIPUpTime0")),
			RemainingLeaseTime: parseSec(parseTextInputValueByID(tableNode, "TextIPRemainLeaseTime0")),
		},
	}

	return &ws, nil
}

func parseTextInputValueByID(root *html.Node, elementID string) string {
	return parseTextInputValueBySelector(root, "input#"+elementID)
}

func parseTextInputValueBySelector(root *html.Node, selector string) string {
	sel := cascadia.MustCompile(selector)
	targetNode := cascadia.Query(root, sel)
	if targetNode == nil || targetNode.DataAtom != atom.Input {
		return ""
	}

	for _, attr := range targetNode.Attr {
		if attr.Key == "value" {
			return attr.Val
		}
	}

	return ""
}

func parseSec(s string) int64 {
	secIdx := strings.Index(s, " sec")
	if secIdx < 0 {
		return 0
	}

	secStr := s[0:secIdx]
	ret, _ := strconv.ParseInt(secStr, 10, 64)
	// TODO: Log!
	return ret
}

func parseWLANData(s string) map[string]string {
	d := map[string]string{}
	submatches := transferMeaningRegexp.FindAllStringSubmatch(s, -1)
	for _, submatch := range submatches {
		if len(submatch) < 3 {
			// TODO: Log!
			continue
		}

		d[submatch[1]] = submatch[2]
	}

	return d
}

func parseWLANModes(wlanData map[string]string, ssidIndex int) (authMode, cryptMode string) {
	// taken from the showSSIDInfo function in the page
	var (
		beaconType      = wlanData[fmt.Sprintf("BeaconType%d", ssidIndex)]
		n11iAuthMode    = wlanData[fmt.Sprintf("11iAuthMode%d", ssidIndex)]
		n11iEncryptType = wlanData[fmt.Sprintf("11iEncryptType%d", ssidIndex)]
		wepAuthMode     = wlanData[fmt.Sprintf("WEPAuthMode%d", ssidIndex)]
		wpaAuthMode     = wlanData[fmt.Sprintf("WPAAuthMode%d", ssidIndex)]
		wpaEncryptType  = wlanData[fmt.Sprintf("WPAEncryptType%d", ssidIndex)]
	)

	if "None" == beaconType || ("Basic" == beaconType && "None" == wepAuthMode) {
		authMode = "Open System"
	} else if "Basic" == beaconType && "SharedAuthentication" == wepAuthMode {
		authMode = "Shared Key"
	} else if "WPA" == beaconType && "PSKAuthentication" == wpaAuthMode {
		authMode = "WPA-PSK"
	} else if "11i" == beaconType && "PSKAuthentication" == n11iAuthMode {
		authMode = "WPA2-PSK"
	} else if "WPAand11i" == beaconType && "PSKAuthentication" == wpaAuthMode && "PSKAuthentication" == n11iAuthMode {
		authMode = "WPA/WPA2-PSK"
	} else if "WPA" == beaconType && "EAPAuthentication" == wpaAuthMode {
		authMode = "WPA-EAP"
	} else if "11i" == beaconType && "EAPAuthentication" == n11iAuthMode {
		authMode = "WPA2-EAP"
	} else if "WPAand11i" == beaconType && "EAPAuthentication" == wpaAuthMode && "EAPAuthentication" == n11iAuthMode {
		authMode = "WPA/WPA2-EAP"
	}

	if "None" == beaconType {
		cryptMode = "None"
	} else if "Basic" == beaconType {
		cryptMode = "WEP"
	} else if ("WPA" == beaconType && "TKIPEncryption" == wpaEncryptType) || ("11i" == beaconType && "TKIPEncryption" == n11iEncryptType) || ("WPAand11i" == beaconType && "TKIPEncryption" == wpaEncryptType) {
		cryptMode = "TKIP"
	} else if ("WPA" == beaconType && "AESEncryption" == wpaEncryptType) || ("11i" == beaconType && "AESEncryption" == n11iEncryptType) || ("WPAand11i" == beaconType && "AESEncryption" == wpaEncryptType) {
		cryptMode = "AES"
	} else if ("WPA" == beaconType && "TKIPandAESEncryption" == wpaEncryptType) || ("11i" == beaconType && "TKIPandAESEncryption" == n11iEncryptType) || ("WPAand11i" == beaconType && "TKIPandAESEncryption" == wpaEncryptType) {
		cryptMode = "TKIP+AES"
	}

	return authMode, cryptMode
}

func parseInt64(s string) int64 {
	i, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		// TODO: Log!
		return 0
	}

	return i
}
