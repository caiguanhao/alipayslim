# alipayslim

## Usage

```go
client := alipayslim.NewClient("2088************")
  WithMD5Key("********************************").
  MustWithRSAKey("-----BEGIN RSA PRIVATE KEY-----\n...\n-----END RSA PRIVATE KEY-----\n").
  WithDebug(false)

ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
defer cancel()
resp, err := configs.DefaultAlipay.SingleTradeQuery(ctx, "MyTradeNo")

params := client.AlipayHKAppPayParams().
  WithBody(paymentTitle).
  WithSubject(paymentTitle).
  WithTotalFee(paymentAmount.String()).
  WithNotifyUrl("https://hippolaundry.com/app").
  WithReferUrl("https://hippolaundry.com/app").
  WithOutTradeNo(tradeNo)
str, err := params.OrderString()
```
