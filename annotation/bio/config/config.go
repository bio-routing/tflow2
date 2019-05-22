package config

import (
	"io/ioutil"

	"github.com/pkg/errors"
	"gopkg.in/yaml.v2"

	bnet "github.com/bio-routing/bio-rd/net"
	"github.com/bio-routing/bmp/protocols/bgp/packet"
)

// Config represents the annotators configuration
type Config struct {
	Agents []Agent `yaml:"agents"`
}

// Agent represents an Flow Agents BGP feeds
type Agent struct {
	Address   string `yaml:"address"`
	IPAddress bnet.IP
	BGPFeeds  []BGPNeighbor `yaml:"bgp-feeds"`
}

// BGPNeighbor represents a BGP session
type BGPNeighbor struct {
	Neighbor    string `yaml:"neighbor"`
	IPNeighbor  *bnet.IP
	LocalASN    uint32   `yaml:"local-as"`
	PeerASN     uint32   `yaml:"peer-as"`
	AFIs        []string `yaml:"afis"`
	NumericAFIs []uint16
}

// LoadConfig loads a config file
func LoadConfig(fp *string) (*Config, error) {
	fc, err := ioutil.ReadFile(*fp)
	if err != nil {
		return nil, errors.Wrap(err, "Unable to read file")
	}

	cfg := &Config{}
	err = yaml.Unmarshal(fc, cfg)
	if err != nil {
		return nil, errors.Wrap(err, "Unable to unmarshal")
	}

	err = cfg.init()
	if err != nil {
		return nil, err
	}

	return cfg, nil
}

func (c *Config) init() error {
	for i := range c.Agents {
		a, err := bnet.IPFromString(c.Agents[i].Address)
		if err != nil {
			return errors.Wrap(err, "Unable to parse IP")
		}

		c.Agents[i].IPAddress = a

		for j := range c.Agents[i].BGPFeeds {
			b, err := bnet.IPFromString(c.Agents[i].BGPFeeds[j].Neighbor)
			if err != nil {
				return errors.Wrap(err, "Unable to parse IP")
			}

			c.Agents[i].BGPFeeds[j].IPNeighbor = &b

			for k := range c.Agents[i].BGPFeeds[j].AFIs {
				switch c.Agents[i].BGPFeeds[j].AFIs[k] {
				case "ipv4":
					c.Agents[i].BGPFeeds[j].NumericAFIs = append(c.Agents[i].BGPFeeds[j].NumericAFIs, uint16(packet.IPv4AFI))
				case "ipv6":
					c.Agents[i].BGPFeeds[j].NumericAFIs = append(c.Agents[i].BGPFeeds[j].NumericAFIs, uint16(packet.IPv6AFI))
				}
			}
		}
	}

	return nil
}
