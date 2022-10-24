package bitward

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"reflect"
	"time"
)

type BW struct {
	session string
}

func New() (*BW, error) {
	var bw BW
	status, err := bw.Status()
	if err != nil {
		return nil, err
	}

	_, clientIdEnvExists := os.LookupEnv("BW_CLIENTID")
	_, clientSecretEnvExists := os.LookupEnv("BW_CLIENTSECRET")
	_, bwPassEnvExists := os.LookupEnv("BW_PASSWORD")

	bwPassEnv := ""
	if bwPassEnvExists {
		// standardizing on BW_PASSWORD since that's what https://bitwarden.com/help/cli/#unlock suggests
		bwPassEnv = " --passwordenv BW_PASSWORD"
	}

	var cmd *exec.Cmd
	switch status.Status {
	case "unlocked":
		_, err = bw.Sync()
		if err != nil {
			return nil, fmt.Errorf("faild sync of unlocked bw, error: %w", err)
		}
		return &bw, nil
	case "locked":
		cmd = exec.Command("/bin/sh", "-c", fmt.Sprintf("bw unlock --raw%s", bwPassEnv))
	case "unauthenticated":
		if clientIdEnvExists && clientSecretEnvExists {
			// bw will read from env as per https://bitwarden.com/help/personal-api-key/#authenticate-using-your-api-key
			cmd = exec.Command("/bin/sh", "-c", fmt.Sprintf("bw login --raw --apikey && bw unlock --raw%s", bwPassEnv))
		} else {
			cmd = exec.Command("bw", "login", "--raw")
		}
	default:
		return nil, fmt.Errorf("unknown vault status `%s`", status.Status)
	}

	cmd.Stdin = os.Stdin
	cmd.Stderr = os.Stderr
	b := bytes.NewBuffer(nil)
	cmd.Stdout = b

	err = cmd.Run()
	if err != nil {
		return nil, err
	}

	bw.session = b.String()
	status, err = bw.Status()
	if err != nil {
		return nil, err
	}
	if status.Status != "unlocked" {
		return nil, fmt.Errorf("authentication failed: vault status `%s`", status.Status)
	}

	_, err = bw.Sync()
	if err != nil {
		return nil, fmt.Errorf("faild sync of unlocked bw, error: %w", err)
	}
	return &bw, nil
}

func (bw *BW) sessionCommand(name string, arg ...string) *exec.Cmd {

	cmd := exec.Command(name, arg...)
	if len(bw.session) > 0 {
		cmd.Args = append(cmd.Args, "--session", bw.session)
	}
	return cmd
}

type StatusMsg struct {
	LastSync  time.Time `json:"lastSync"`
	UserEmail string    `json:"userEmail"`
	UserId    string    `json:"userId"`
	Status    string    `json:"status"`
}

func (bw *BW) Status() (msg StatusMsg, err error) {
	cmd := bw.sessionCommand("bw", "status")
	return msg, output(cmd, &msg)
}

func (bw *BW) Sync() error {
	cmd := bw.sessionCommand("bw", "sync")
	_, err := cmd.Output()
	if err != nil {
		if e, ok := err.(*exec.ExitError); ok {
			err = fmt.Errorf("%w: %s", err, string(e.Stderr))
		}
		return fmt.Errorf("%s: %w", cmd.String(), err)
	}
	return nil
}

type Item struct {
	Object         string      `json:"object"`
	Id             string      `json:"id"`
	OrganizationId string      `json:"organizationId"`
	FolderId       interface{} `json:"folderId"`
	Type           int         `json:"type"`
	RePrompt       int         `json:"reprompt"`
	Name           string      `json:"name"`
	Notes          interface{} `json:"notes"`
	Favorite       bool        `json:"favorite"`
	Fields         []struct {
		Name     string      `json:"name"`
		Value    string      `json:"value"`
		Type     int         `json:"type"`
		LinkedId interface{} `json:"linkedId"`
	} `json:"fields"`
	Login struct {
		Uris []struct {
			Match int    `json:"match"`
			Uri   string `json:"uri"`
		} `json:"uris"`
		Username             string      `json:"username"`
		Password             string      `json:"password"`
		Totp                 interface{} `json:"totp"`
		PasswordRevisionDate interface{} `json:"passwordRevisionDate"`
	} `json:"login"`
	CollectionIds []string  `json:"collectionIds"`
	RevisionDate  time.Time `json:"revisionDate"`
}

func (bw *BW) GetItem(id string) (item Item, err error) {
	cmd := bw.sessionCommand("bw", "get", "item", id)
	return item, output(cmd, &item)
}

func (bw *BW) GetItems(arg ...string) (items []Item, err error) {
	arg = append([]string{"list", "items"}, arg...)
	cmd := bw.sessionCommand("bw", arg...)
	return items, output(cmd, &items)
}

func output(cmd *exec.Cmd, i interface{}) error {
	p, err := cmd.Output()
	if err != nil {
		if e, ok := err.(*exec.ExitError); ok {
			err = fmt.Errorf("%w: %s", err, string(e.Stderr))
		}
		return fmt.Errorf("%s: %w", cmd.String(), err)
	}

	err = json.Unmarshal(p, i)
	if err != nil {
		var s string
		if t := reflect.TypeOf(i); t.Kind() == reflect.Ptr {
			s = t.Elem().Name()
		} else {
			s = t.Name()
		}
		return fmt.Errorf("unable to unmarshall %s: %w", s, err)
	}

	return nil
}
