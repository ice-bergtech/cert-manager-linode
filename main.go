package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"

	"golang.org/x/oauth2"

	acme "github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	"github.com/cert-manager/cert-manager/pkg/acme/webhook/cmd"
	"github.com/linode/linodego"

	v1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

var (
	ErrDomainNotFound error = errors.New("domain not found")
	ErrRecordNotFound error = errors.New("record not found")
)

var GroupName = os.Getenv("GROUP_NAME")

// Used to fetch api key from a kube secret
var kClientConfig *rest.Config

func main() {
	if GroupName == "" {
		panic("GROUP_NAME must be specified")
	}

	cmd.RunWebhookServer(GroupName, &linodeSolver{})
}

type linodeConfig struct {
	APIKey          string        `json:"apiKey"`
	APISecretKeyRef APISecretKeys `json:"apiKeySecretRef"`
}

type APISecretKeys struct {
	Name string `json:"name"`
	Key  string `json:"json"`
}

type linodeSolver struct{}

func (s *linodeSolver) Name() string {
	return "linode"
}

func (s *linodeSolver) Initialize(kubeClientConfig *rest.Config, stopCh <-chan struct{}) error {
	kClientConfig = kubeClientConfig
	return nil
}

func (s *linodeSolver) Present(ch *acme.ChallengeRequest) error {
	c, err := clientFromRequest(ch)

	if err != nil {
		return err
	}

	domain, record, err := findRecord(c, ch.ResolvedZone, ch.ResolvedFQDN)

	port := 0
	weight := 1
	priority := 0

	if err == nil {
		_, err = c.UpdateDomainRecord(context.Background(), domain.ID, record.ID, linodego.DomainRecordUpdateOptions{
			Type: record.Type,
			Name: record.Name,

			Target: ch.Key,
			Weight: &weight,
			Port:   &port,

			TTLSec:   record.TTLSec,
			Priority: &priority,
		})

		return err
	}

	if domain == nil {
		return errors.New("domain not found")
	}

	_, err = c.CreateDomainRecord(context.Background(), domain.ID, linodego.DomainRecordCreateOptions{
		Type: linodego.RecordTypeTXT,
		Name: strings.TrimRight(ch.ResolvedFQDN, "."),

		Target: ch.Key,
		Weight: &weight,
		Port:   &port,

		TTLSec:   180,
		Priority: &priority,
	})

	return err
}

func (s *linodeSolver) CleanUp(ch *acme.ChallengeRequest) error {
	c, err := clientFromRequest(ch)

	if err != nil {
		return err
	}

	domain, record, err := findRecord(c, ch.ResolvedZone, ch.ResolvedFQDN)

	if err != nil {
		if errors.Is(err, ErrDomainNotFound) || errors.Is(err, ErrRecordNotFound) {
			return nil
		}

		return err
	}

	return c.DeleteDomainRecord(context.Background(), domain.ID, record.ID)
}

func loadConfig(cfgJSON *v1.JSON) (linodeConfig, error) {
	cfg := linodeConfig{}

	if cfgJSON == nil {
		return cfg, nil
	}

	if err := json.Unmarshal(cfgJSON.Raw, &cfg); err != nil {
		return cfg, fmt.Errorf("error decoding solver config: %v", err)
	}

	// If a secret name is set, we'll attempt to fetch the api key from a secret
	if cfg.APISecretKeyRef.Name != "" {
		println("api key secret", cfg.APISecretKeyRef.Name)
		if val, err := apiKeyFromSecret(cfg); err != nil {
			return cfg, fmt.Errorf("kube secret error: %v", err)
		} else {
			cfg.APIKey = val
		}
	}

	return cfg, nil
}

func clientFromRequest(ch *acme.ChallengeRequest) (*linodego.Client, error) {
	cfg, err := loadConfig(ch.Config)

	if err != nil {
		return nil, err
	}

	return clientFromConfig(cfg)
}

// fetches a secret via the kubernetes api based on cfg
func apiKeyFromSecret(cfg linodeConfig) (string, error) {
	//
	kubeClient, err := kubernetes.NewForConfig(kClientConfig)
	if err != nil {
		return "", fmt.Errorf("issue creating kube api client: %v", err)
	}

	// fetch the kube secret
	secret, err := kubeClient.CoreV1().Secrets(cfg.APISecretKeyRef.Name).Get(context.TODO(), cfg.APISecretKeyRef.Key, metav1.GetOptions{})
	if err != nil {
		return "", fmt.Errorf("issue fetching secret: %v", err)
	}

	return string(secret.Data["apiKey"]), nil
}

func clientFromConfig(cfg linodeConfig) (*linodego.Client, error) {
	tokenSource := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: cfg.APIKey})

	tokenClient := &http.Client{
		Transport: &oauth2.Transport{
			Source: tokenSource,
		},
	}

	client := linodego.NewClient(tokenClient)
	return &client, nil
}

func findDomain(c *linodego.Client, name string) (*linodego.Domain, error) {
	name = strings.TrimRight(name, ".")

	println("find domain", name)

	domains, err := c.ListDomains(context.Background(), nil)

	if err != nil {
		return nil, err
	}

	for _, d := range domains {
		domain := d

		if strings.EqualFold(domain.Domain, name) {
			return &domain, nil
		}
	}

	return nil, ErrDomainNotFound
}

func findRecord(c *linodego.Client, zone, name string) (*linodego.Domain, *linodego.DomainRecord, error) {
	println("find record", zone, name)

	name = strings.TrimRight(name, ".")

	domain, err := findDomain(c, zone)

	if err != nil {
		return nil, nil, err
	}

	records, err := c.ListDomainRecords(context.Background(), domain.ID, nil)

	if err != nil {
		return domain, nil, err
	}

	for _, r := range records {
		record := r

		if strings.EqualFold(record.Name, name) && string(record.Type) == "TXT" {
			return domain, &record, nil
		}
	}

	return domain, nil, ErrRecordNotFound
}
