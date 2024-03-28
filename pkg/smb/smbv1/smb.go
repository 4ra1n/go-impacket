package smbv1

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net"

	"github.com/4ra1n/go-impacket/pkg/common"
	"github.com/4ra1n/go-impacket/pkg/encoder"
	"github.com/4ra1n/go-impacket/pkg/ms"
	"github.com/4ra1n/go-impacket/pkg/smb"
)

// 此文件提供smb连接方法

type Client struct {
	common.Client
}

func NewSMBPacket() smb.SMBV1PacketStruct {
	return smb.SMBV1PacketStruct{
		ProtocolId:  []byte(smb.ProtocolSMB),
		Command:     0,
		Status:      0,
		Flags1:      0,
		Flags2:      0,
		ProcessHigh: 0,
		Signature:   0,
		Reserved:    0,
		TreeId:      0,
		ProcessId:   0,
		UserId:      0,
		MultiplexId: 0,
	}
}

// 协商版本请求初始化
func (c *Client) NewNegotiateRequest() smb.SMBV1NegotiateRequestStruct {
	// 初始化
	smbv1Header := NewSMBPacket()
	smbv1Header.Command = smb.SMBV1_NEGOTIATE
	smbv1Header.Status = 0
	smbv1Header.Flags1 = 0x18
	smbv1Header.Flags2 = 0x4801
	smbv1Header.ProcessHigh = 0
	smbv1Header.Signature = 0
	smbv1Header.Reserved = 0
	smbv1Header.TreeId = 0xffff
	smbv1Header.ProcessId = 0xcb98
	smbv1Header.UserId = 0
	smbv1Header.MultiplexId = 0
	return smb.SMBV1NegotiateRequestStruct{
		SMBV1PacketStruct: smbv1Header,
		WCT:               0x00,
		BCC:               0x000c,
		BufferFormat:      0x02,
		Name:              []byte("NT LM 0.12"),
		End:               0x00,
	}
}

// 协商版本响应初始化
func NewNegotiateResponse() smb.SMBV1NegotiateResponseStruct {
	return smb.SMBV1NegotiateResponseStruct{}
}

// 质询请求初始化
//func (c *Client) NewSessionSetupRequest() (smb.SMB2SessionSetupRequestStruct, error) {
//	smb2Header := NewSMBPacket()
//	smb2Header.Command = smb.SMB2_SESSION_SETUP
//	smb2Header.CreditCharge = 1
//	smb2Header.MessageId = c.GetMessageId()
//	smb2Header.SessionId = c.GetSessionId()
//
//	ntlmsspneg := ntlm2.NewNegotiate(c.GetOptions().Domain, c.GetOptions().Workstation)
//	data, err := encoder.Marshal(ntlmsspneg)
//	if err != nil {
//		return smb.SMB2SessionSetupRequestStruct{}, err
//	}
//
//	if c.GetSessionId() != 0 {
//		return smb.SMB2SessionSetupRequestStruct{}, errors.New("Bad session ID for session setup 1 message")
//	}
//
//	// Initial session setup request
//	init, err := gss.NewNegTokenInit()
//	if err != nil {
//		return smb.SMB2SessionSetupRequestStruct{}, err
//	}
//	init.Data.MechToken = data
//
//	return smb.SMB2SessionSetupRequestStruct{
//		SMB2PacketStruct:     smb2Header,
//		StructureSize:        25,
//		Flags:                0x00,
//		SecurityMode:         byte(smb.SecurityModeSigningEnabled),
//		Capabilities:         0,
//		Channel:              0,
//		SecurityBufferOffset: 88,
//		SecurityBufferLength: 0,
//		PreviousSessionID:    0,
//		SecurityBlob:         &init,
//	}, nil
//}

// 质询响应初始化
//
//	func NewSessionSetupResponse() (smb.SMB2SessionSetupResponseStruct, error) {
//		smb2Header := NewSMBPacket()
//		resp, err := gss.NewNegTokenResp()
//		if err != nil {
//			return smb.SMB2SessionSetupResponseStruct{}, err
//		}
//		ret := smb.SMB2SessionSetupResponseStruct{
//			SMB2PacketStruct: smb2Header,
//			SecurityBlob:     &resp,
//		}
//		return ret, nil
//	}
//
// // 认证请求初始化
//
//	func (c *Client) NewSessionSetup2Request() (smb.SMB2SessionSetup2RequestStruct, error) {
//		smb2Header := NewSMBPacket()
//		smb2Header.Command = smb.SMB2_SESSION_SETUP
//		smb2Header.CreditCharge = 1
//		smb2Header.MessageId = c.GetMessageId()
//		smb2Header.SessionId = c.GetSessionId()
//
//		ntlmsspneg := ntlm2.NewNegotiate(c.GetOptions().Domain, c.GetOptions().Workstation)
//		data, err := encoder.Marshal(ntlmsspneg)
//		if err != nil {
//			return smb.SMB2SessionSetup2RequestStruct{}, err
//		}
//
//		if c.GetSessionId() == 0 {
//			return smb.SMB2SessionSetup2RequestStruct{}, errors.New("Bad session ID for session setup 2 message")
//		}
//
//		// Session setup request #2
//		resp, err := gss.NewNegTokenResp()
//		if err != nil {
//			return smb.SMB2SessionSetup2RequestStruct{}, err
//		}
//		resp.ResponseToken = data
//
//		return smb.SMB2SessionSetup2RequestStruct{
//			SMB2PacketStruct:     smb2Header,
//			StructureSize:        25,
//			Flags:                0x00,
//			SecurityMode:         byte(smb.SecurityModeSigningEnabled),
//			Capabilities:         0,
//			Channel:              0,
//			SecurityBufferOffset: 88,
//			SecurityBufferLength: 0,
//			PreviousSessionID:    0,
//			SecurityBlob:         &resp,
//		}, nil
//	}
func (c *Client) NegotiateProtocol() (err error) {
	c.Debug("sending negotiate request", nil)
	negReq := c.NewNegotiateRequest()
	buf, err := c.SMBSend(negReq)
	if err != nil {
		c.Debug("", err)
		return err
	}
	c.Debug("get resp raw:\n"+hex.Dump(buf), err)
	negRes := NewNegotiateResponse()
	if err = encoder.Unmarshal(buf, &negRes); err != nil {
		return err
	}
	if negRes.SMBV1PacketStruct.Status != ms.STATUS_SUCCESS {
		status, _ := ms.StatusMap[negRes.SMBV1PacketStruct.Status]
		return errors.New(status)
	}
	// Check SPNEGO security blob
	//spnegoOID, err := encoder.ObjectIDStrToInt(encoder.SpnegoOid)
	//if err != nil {
	//	c.Debug(err)
	//	return err
	//}
	//oid := negRes.SecurityBlob.OID
	//fmt.Println(oid)
	// 检查是否存在ntlmssp
	//hasNTLMSSP := false
	//ntlmsspOID, err := gss.ObjectIDStrToInt(ntlm2.NTLMSSPMECHTYPEOID)
	//if err != nil {
	//	return err
	//}
	//for _, mechType := range negRes.SecurityBlob.Data.MechTypes {
	//	if mechType.Equal(ntlmsspOID) {
	//		hasNTLMSSP = true
	//		break
	//	}
	//}
	//if !hasNTLMSSP {
	//	return errors.New("Server does not support NTLMSSP")
	//}
	//// 设置会话安全模式
	//c.WithSecurityMode(negRes.SecurityMode)
	//// 设置会话协议
	//c.WithDialect(negRes.DialectRevision)
	//// 签名开启/关闭
	//mode := c.GetSecurityMode()
	//if mode&smb.SecurityModeSigningEnabled > 0 {
	//	if mode&smb.SecurityModeSigningRequired > 0 {
	//		c.IsSigningRequired = true
	//	} else {
	//		c.IsSigningRequired = false
	//	}
	//} else {
	//	c.IsSigningRequired = false
	//}
	// 第二步 发送质询
	//c.Debug("Sending SessionSetup1 request", nil)
	//ssreq, err := c.NewSessionSetupRequest()
	//if err != nil {
	//	c.Debug("", err)
	//	return err
	//}
	//ssres, err := NewSessionSetupResponse()
	//if err != nil {
	//	c.Debug("", err)
	//	return err
	//}
	//buf, err = encoder.Marshal(ssreq)
	//if err != nil {
	//	c.Debug("", err)
	//	return err
	//}
	//
	//buf, err = c.SMBSend(ssreq)
	//if err != nil {
	//	c.Debug("Raw:\n"+hex.Dump(buf), err)
	//	return err
	//}
	//
	//c.Debug("Unmarshalling SessionSetup1 response", nil)
	//if err = encoder.Unmarshal(buf, &ssres); err != nil {
	//	c.Debug("", err)
	//	return err
	//}
	//
	//challenge := ntlm2.NewChallenge()
	//resp := ssres.SecurityBlob
	//if err = encoder.Unmarshal(resp.ResponseToken, &challenge); err != nil {
	//	c.Debug("", err)
	//	return err
	//}
	//
	//if ssres.SMB2PacketStruct.Status != ms.STATUS_MORE_PROCESSING_REQUIRED {
	//	status, _ := ms.StatusMap[negRes.SMB2PacketStruct.Status]
	//	return errors.New(status)
	//}
	//c.WithSessionId(ssres.SMB2PacketStruct.SessionId)
	//
	//c.Debug("Sending SessionSetup2 request", nil)
	//// 第三步 认证
	//ss2req, err := c.NewSessionSetup2Request()
	//if err != nil {
	//	c.Debug("", err)
	//	return err
	//}
	//
	//var auth ntlm2.NTLMv2Authentication
	//if c.GetOptions().Hash != "" {
	//	// Hash present, use it for auth
	//	c.Debug("Performing hash-based authentication", nil)
	//	auth = ntlm2.NewAuthenticateHash(c.GetOptions().Domain, c.GetOptions().User, c.GetOptions().Workstation, c.GetOptions().Hash, challenge)
	//} else {
	//	// No hash, use password
	//	c.Debug("Performing password-based authentication", nil)
	//	auth = ntlm2.NewAuthenticatePass(c.GetOptions().Domain, c.GetOptions().User, c.GetOptions().Workstation, c.GetOptions().Password, challenge)
	//}
	//
	//responseToken, err := encoder.Marshal(auth)
	//if err != nil {
	//	c.Debug("", err)
	//	return err
	//}
	//resp2 := ss2req.SecurityBlob
	//resp2.ResponseToken = responseToken
	//ss2req.SecurityBlob = resp2
	//ss2req.SMB2PacketStruct.CreditRequestResponse = 127
	//buf, err = encoder.Marshal(ss2req)
	//if err != nil {
	//	c.Debug("", err)
	//	return err
	//}
	//
	//buf, err = c.SMBSend(ss2req)
	//if err != nil {
	//	c.Debug("", err)
	//	return err
	//}
	//c.Debug("Unmarshalling SessionSetup2 response", nil)
	//var authResp smb.SMB2PacketStruct
	//if err = encoder.Unmarshal(buf, &authResp); err != nil {
	//	c.Debug("Raw:\n"+hex.Dump(buf), err)
	//	return err
	//}
	//if authResp.Status != ms.STATUS_SUCCESS {
	//	// authResp.Status 十进制表示
	//	status, _ := ms.StatusMap[authResp.Status]
	//	return errors.New(status)
	//}
	//c.IsAuthenticated = true
	//
	//c.Debug("Completed NegotiateProtocol and SessionSetup", nil)
	return nil
}

// SMB2连接封装
func NewSession(opt common.ClientOptions, debug bool) (client *Client, err error) {
	address := fmt.Sprintf("%s:%d", opt.Host, opt.Port)
	conn, err := net.Dial("tcp", address)
	if err != nil {
		return
	}
	client = &Client{}
	client.WithOptions(&opt)
	client.WithConn(conn)
	client.WithDebug(debug)

	err = client.NegotiateProtocol()
	if err != nil {
		return
	}

	return client, nil
}

//
//func (c *Client) Close() {
//	c.Debug("Closing session", nil)
//	trees := c.GetTrees()
//	for k, _ := range trees {
//		c.TreeDisconnect(k)
//	}
//	c.GetConn().Close()
//	c.Debug("Session close completed", nil)
//}
