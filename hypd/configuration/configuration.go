package configuration

import (
	"encoding/json"
	"fmt"
	"os"
)

type HypdConfiguration struct {
	NetworkInterface      string `json:"networkInterface"`
	PreSharedKeyDirectory string `json:"preSharedKeyDirectory"` // hypd will load all *.secret files from this directory
	SuccessAction         string `json:"successAction"`         // The action to take
	TimeoutSeconds        int    `json:"timeoutSeconds"`        // If > 0, once a knock sequence has been successful this value will count down and when it reaches 0, it will perform the TimeoutAction on the client.
	TimeoutAction         string `json:"timeoutAction"`         // The action to take after TimeoutSeconds has elapsed.  only applicable if TimeoutSeconds is > 0

}

// LoadConfiguration opens and parses the configuration file into a HypdConfiguration struct
// If a configFilePath is not specified, it will search in common locations
func LoadConfiguration(configFilePath string) (*HypdConfiguration, error) {
	if configFilePath == "" {
		commonLocations := []string{"hypdconfig.json",
			"~/.hypdconfig.json",
			"~/.config/hyp/hypdConfig.json",
			"/etc/hyp/hypdConfig.json",
			"/usr/local/etc/hyp/hypdConfig.json",
		}

		for _, loc := range commonLocations {
			if _, err := os.Stat(loc); err == nil {
				configFilePath = loc
				break
			}
		}
	}
	// if it's still not found after checking common locations, load default config
	if configFilePath == "" {
		fmt.Println("no configuration file found.  You can generate one with ./hypd generate defaultconfig | tee hypdconfig.json")
		return DefaultConfig(), nil
	}

	// Otherwise if a config is specified, try to load it and error if it fails.
	// I think it's better to error here if a config was intended and failed
	// rather than failing back to default

	b, err := os.ReadFile(configFilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file '%s': %w", configFilePath, err)
	}

	hypdConfiguration := &HypdConfiguration{}
	err = json.Unmarshal(b, hypdConfiguration)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal config file json to HypdConfiguration (is the config file malformed?): %w", err)
	}

	return hypdConfiguration, nil
}

func DefaultConfig() *HypdConfiguration {
	return &HypdConfiguration{
		NetworkInterface:      "enp0s3",
		PreSharedKeyDirectory: "./secrets/",
		SuccessAction:         "iptables -A INPUT -p tcp -s %s --dport 22 -j ACCEPT",
		TimeoutSeconds:        1440,
		TimeoutAction:         "iptables -D INPUT -p tcp -s %s --dport 22 -j ACCEPT",
	}
}
