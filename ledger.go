package main

import (
	"github.com/hiro942/elden-server/model"
	"github.com/hiro942/elden-server/model/request"
	"github.com/hiro942/elden-server/utils/ghttp"
	"github.com/tjfoc/gmsm/sm2"
	"github.com/tjfoc/gmsm/x509"
)

type Ledger struct {
	URL *URL
}

func NewLedger(url *URL) *Ledger {
	return &Ledger{URL: url}
}

func (l *Ledger) RegisterSatellite(satelliteID string, publicKey *sm2.PublicKey) error {
	_, err := ghttp.POST[any](
		l.URL.RegisterSatellite(),
		request.SatelliteRegister{
			ID:        satelliteID,
			PublicKey: x509.WritePublicKeyToHex(publicKey),
		},
	)
	return err
}

func (l *Ledger) QueryClientPublicKey(id string, macAddr string) (keyHex string, err error) {
	key, err := ghttp.GET[string](l.URL.QueryClientPublicKey(id, macAddr))
	if err != nil {
		return "", err
	}
	return key, nil
}

func (l *Ledger) QuerySatellitePublicKey(id string) (keyHex string, err error) {
	key, err := ghttp.GET[string](l.URL.QuerySatellitePublicKey(id))
	if err != nil {
		return "", err
	}
	return key, nil
}

func (l *Ledger) QueryNodeByID(id string) (model.Node, error) {
	node, err := ghttp.GET[model.Node](l.URL.QueryNodeByID(id))
	if err != nil {
		return model.Node{}, err
	}
	return node, nil
}

func (l *Ledger) UpdateClientAuthStatus(clientID string, authStatusCode string) error {
	requestBody := request.ChangeUserAuthStatus{ID: clientID, AuthStatusCode: authStatusCode}
	_, err := ghttp.POST[any](l.URL.UpdateClientAuthStatus(), requestBody)
	return err
}

func (l *Ledger) CreateAccessRecord(record model.CreateAccessRecord) error {
	_, err := ghttp.POST[any](l.URL.CreateAccessRecord(), record)
	return err
}
