// Package alipayslim is a slim version of the Alipay API.
package alipayslim

import (
	"context"
	"crypto"
	"crypto/md5"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sort"
	"strings"
	"time"
)

// Client is the client for the Alipay API.
type Client struct {
	appId  string
	md5Key string
	rsaKey *rsa.PrivateKey
	debug  bool
}

// NewClient creates a new client.
func NewClient(appId string) *Client {
	return &Client{
		appId: appId,
	}
}

// WithMD5Key sets the MD5 key and returns the client.
func (c *Client) WithMD5Key(key string) *Client {
	c.md5Key = key
	return c
}

// WithRSAKey sets the RSA key and returns the client and an error if the key is invalid.
func (c *Client) WithRSAKey(key string) (*Client, error) {
	rsaKey, err := parsePrivateKey(key)
	if err != nil {
		return nil, err
	}
	c.rsaKey = rsaKey
	return c, nil
}

// MustWithRSAKey is like WithRSAKey but panics if the key is invalid.
func (c *Client) MustWithRSAKey(key string) *Client {
	c, err := c.WithRSAKey(key)
	if err != nil {
		panic(err)
	}
	return c
}

// WithDebug sets the debug mode and returns the client.
func (c *Client) WithDebug(debug bool) *Client {
	c.debug = debug
	return c
}

// PayParams is the parameters for the Alipay pay.
type PayParams struct {
	client *Client
	Data   map[string]string
}

// WithBody sets the body and returns the PayParams.
func (p *PayParams) WithBody(body string) *PayParams {
	p.Data["body"] = body
	return p
}

// WithNotifyUrl sets the notify URL and returns the PayParams.
func (p *PayParams) WithNotifyUrl(notifyUrl string) *PayParams {
	p.Data["notify_url"] = notifyUrl
	return p
}

// WithOutTradeNo sets the out trade no and returns the PayParams.
func (p *PayParams) WithOutTradeNo(tradeNo string) *PayParams {
	p.Data["out_trade_no"] = tradeNo
	return p
}

// WithTotalFee sets the total fee and returns the PayParams.
func (p *PayParams) WithTotalFee(totalFee string) *PayParams {
	p.Data["total_fee"] = totalFee
	return p
}

// WithReferUrl sets the refer URL and returns the PayParams.
func (p *PayParams) WithReferUrl(referUrl string) *PayParams {
	p.Data["refer_url"] = referUrl
	return p
}

// WithSubject sets the subject and returns the PayParams.
func (p *PayParams) WithSubject(subject string) *PayParams {
	p.Data["subject"] = subject
	return p
}

// OrderString returns the order string for the Alipay HK app pay.
func (p *PayParams) OrderString() (string, error) {
	delete(p.Data, "sign_type")
	delete(p.Data, "sign")
	signature, err := signWithRSA(p.client.rsaKey, paramsToString(p.Data))
	if err != nil {
		return "", err
	}
	p.Data["sign_type"] = "RSA"
	p.Data["sign"] = url.QueryEscape(signature)
	return paramsToString(p.Data), nil
}

// AlipayHKAppPayParams returns a new basic parameters for the AlipayHK app pay.
func (c *Client) AlipayHKAppPayParams() *PayParams {
	return &PayParams{
		client: c,
		Data: map[string]string{
			"service":        "mobile.securitypay.pay",
			"_input_charset": "utf-8",
			"partner":        c.appId,
			"seller_id":      c.appId,
			"payment_type":   "1",
			"currency":       "HKD",
			"forex_biz":      "FP",
			"product_code":   "NEW_WAP_OVERSEAS_SELLER",
			"payment_inst":   "ALIPAYHK",
			"it_b_pay":       "10m",
		},
	}
}

// xmlResponse is the response of the alipay API.
type xmlResponse struct {
	XMLName   xml.Name `xml:"alipay"`
	IsSuccess string   `xml:"is_success"`
	Error     string   `xml:"error,omitempty"`
	Request   struct {
		Params []struct {
			Name  string `xml:"name,attr"`
			Value string `xml:",chardata"`
		} `xml:"param"`
	} `xml:"request,omitempty"`
	Response struct {
		Data []byte `xml:",innerxml"`
	} `xml:"response,omitempty"`
	Sign     string `xml:"sign,omitempty"`
	SignType string `xml:"sign_type,omitempty"`
}

// Time is the time in UTC+8.
type Time struct {
	time.Time
}

var utcPlus8 = time.FixedZone("UTC+8", 8*60*60)

// UnmarshalXML is the method to unmarshal the time from XML.
func (t *Time) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	var v string
	if err := d.DecodeElement(&v, &start); err != nil {
		return err
	}
	parsed, err := time.ParseInLocation("2006-01-02 15:04:05", v, utcPlus8)
	if err != nil {
		return err
	}
	t.Time = parsed
	return nil
}

// MarshalXML is the method to marshal the time to XML.
func (t Time) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	return e.EncodeElement(t.In(utcPlus8).Format("2006-01-02 15:04:05"), start)
}

// TradeQuery is the response of SingleTradeQuery.
type TradeQuery struct {
	// Detailed description about the goods. Special characters are not supported.
	Body string `xml:"body"`

	// Buyer’s Alipay account.
	BuyerEmail string `xml:"buyer_email"`

	// The unique buyer ID assigned by Alipay.
	BuyerID string `xml:"buyer_id"`

	// The discount amount.
	Discount string `xml:"discount"`

	// Indicates whether the trade transaction is locked. If the value is 1, the transaction is locked. If the value is 0, the transaction is not locked.
	FlagTradeLocked string `xml:"flag_trade_locked"`

	// The time when the transaction is created. Format: yyyy-MM-dd HH:mm:ss. Use GMT+8.
	GmtCreate Time `xml:"gmt_create"`

	// The last time when the value of total_fee is modified. Format: yyyy-MM-dd HH:mm:ss. Use GMT +8.
	GmtLastModifiedTime Time `xml:"gmt_last_modified_time"`

	// The time when the transaction is paid by the buyer. Format: yyyy-MM-dd HH:mm:ss. Use GMT+8.
	GmtPayment Time `xml:"gmt_payment"`

	// Indicates whether the total fee is adjusted. The value is T for the adjusted total fee and F for the non-adjusted total fee.
	IsTotalFeeAdjust string `xml:"is_total_fee_adjust"`

	// The operator role, with a value of B for buyers or S for sellers.
	OperatorRole string `xml:"operator_role"`

	// The unique transaction ID that is assigned by the partner.
	OutTradeNo string `xml:"out_trade_no"`

	// The payment type.
	PaymentType string `xml:"payment_type"`

	// Goods prices, which is accurate to 2 digits after the decimal point. The unit is RMB and the value is in the range 0.01 - 100000000.00. The unit is HKD when the buyer paid by Alipay HK.
	Price string `xml:"price"`

	// The quantity of goods.
	Quantity string `xml:"quantity"`

	// Partner Alipay account.
	SellerEmail string `xml:"seller_email"`

	// A unique seller ID assigned by Alipay. This 16-digit number begins with 2088.
	SellerID string `xml:"seller_id"`

	// Brief description of the transaction. Special characters are not supported. Note: The value of this field will be displayed to customers.
	Subject string `xml:"subject"`

	// The accumulative refunded amount paid to the buyer.
	ToBuyerFee string `xml:"to_buyer_fee"`

	// The accumulative amount paid to the seller.
	ToSellerFee string `xml:"to_seller_fee"`

	// The transaction amount in CNY. It is the exact amount that the buyer has paid. Accurate to two decimal places. The transaction amount is in HKD when the buyer paid by Alipay HK.
	TotalFee string `xml:"total_fee"`

	// The unique transaction ID assigned by Alipay, with a length in the range 16 - 64 bits. If out_trade_no and trade_no appear at the same time, trade_no takes precedence.
	TradeNo string `xml:"trade_no"`

	// TradeStatus is used to describe the status of an Online Payment transaction in the specific interfaces. Possible values are:
	// WAIT_BUYER_PAY: The transaction is created and is waiting for the customer to pay.
	// TRADE_FINISHED: The transaction is paid. This status persists even if partial refunds or full refunds occur, or when the refund period is expired.
	// TRADE_CLOSED: The transaction is closed because of payment timeout.
	TradeStatus string `xml:"trade_status"`

	// Indicates whether the Alipay coupon is used in the transaction. The value can be T for a used coupon and F a coupon that is not used.
	UseCoupon string `xml:"use_coupon"`
}

// Return true if the transaction is paid.
func (t TradeQuery) IsPaid() bool {
	return t.TradeStatus == "TRADE_FINISHED"
}

// Call this interface to obtain the information of a particular transaction, such as the transaction ID, out_trade_no, and transaction status.
// https://global.alipay.com/docs/ac/hkapi/single_trade_query
func (c *Client) SingleTradeQuery(ctx context.Context, tradeNo string) (*TradeQuery, error) {
	params := map[string]string{
		"service":        "single_trade_query",
		"_input_charset": "utf-8",
		"partner":        c.appId,
		"out_trade_no":   tradeNo,
	}
	paramString := paramsToString(params)
	signature := signWithMd5(c.md5Key, paramString)
	paramString += "&sign_type=MD5&sign=" + signature
	url := "https://intlmapi.alipay.com/gateway.do?" + paramString
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	if c.debug {
		dump, err := httputil.DumpRequestOut(req, true)
		if err != nil {
			return nil, err
		}
		log.Println(string(dump))
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if c.debug {
		dumpBody := strings.Contains(resp.Header.Get("Content-Type"), "xml")
		dump, err := httputil.DumpResponse(resp, dumpBody)
		if err != nil {
			return nil, err
		}
		log.Println(string(dump))
	}
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var xmlResp xmlResponse
	if err := xml.Unmarshal(b, &xmlResp); err != nil {
		return nil, err
	}
	if xmlResp.IsSuccess != "T" {
		if xmlResp.Error == "" {
			return nil, errors.New("unknown alipay error")
		}
		return nil, errors.New(xmlResp.Error)
	}
	var tradeQuery TradeQuery
	if err := xml.Unmarshal(xmlResp.Response.Data, &tradeQuery); err != nil {
		return nil, err
	}
	return &tradeQuery, nil
}

func paramsToString(params map[string]string) string {
	var keys []string
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var parts []string
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s=%s", k, params[k]))
	}
	return strings.Join(parts, "&")
}

func parsePrivateKey(privateKeyPEM string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(privateKeyPEM))
	if block == nil {
		return nil, errors.New("failed to parse PEM block containing the private key")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return privateKey, nil
}

func signWithMd5(key, data string) string {
	hashed := md5.Sum([]byte(data + key))
	return hex.EncodeToString(hashed[:])
}

func signWithRSA(privateKey *rsa.PrivateKey, data string) (string, error) {
	hashed := sha1.Sum([]byte(data))
	signature, err := rsa.SignPKCS1v15(nil, privateKey, crypto.SHA1, hashed[:])
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(signature), nil
}
