package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"strings"

	"github.com/otamoe/oauth-client"
	"github.com/otamoe/oauth-client/amazon"
	"github.com/otamoe/oauth-client/baidu"
	"github.com/otamoe/oauth-client/bitbucket"
	"github.com/otamoe/oauth-client/facebook"
	"github.com/otamoe/oauth-client/github"
	"github.com/otamoe/oauth-client/gitlab"
	"github.com/otamoe/oauth-client/google"
	"github.com/otamoe/oauth-client/line"
	"github.com/otamoe/oauth-client/linkedin"
	"github.com/otamoe/oauth-client/microsoft"
	"github.com/otamoe/oauth-client/qq"
	"github.com/otamoe/oauth-client/twitch"
	"github.com/otamoe/oauth-client/twitter"
	"github.com/otamoe/oauth-client/wechat"
	"github.com/otamoe/oauth-client/weibo"
)

func Client(name string) (client oauth.Client) {
	configb, err := ioutil.ReadFile("./config.json")
	if err != nil {
		log.Panicln(err)
	}
	configs := make(map[string]oauth.Config, 0)
	if err := json.Unmarshal(configb, &configs); err != nil {
		log.Panicln(err)
		return
	}
	config, ok := configs[name]
	if !ok {
		log.Panicf("oauth %s does not exist", name)
	}
	switch name {
	case "google":
		config.Endpoint = google.Endpoint
		client = &google.Client{
			OAuth2: oauth.OAuth2{
				Config: config,
			},
		}
	case "facebook":
		config.Endpoint = facebook.Endpoint
		client = &facebook.Client{
			OAuth2: oauth.OAuth2{
				Config: config,
			},
		}
	case "microsoft":
		config.Endpoint = microsoft.Endpoint
		client = &microsoft.Client{
			OAuth2: oauth.OAuth2{
				Config: config,
			},
		}
	case "amazon":
		config.Endpoint = amazon.Endpoint
		client = &amazon.Client{
			OAuth2: oauth.OAuth2{
				Config: config,
			},
		}
	case "linkedin":
		config.Endpoint = linkedin.Endpoint
		client = &linkedin.Client{
			OAuth2: oauth.OAuth2{
				Config: config,
			},
		}
	case "twitter":
		config.Endpoint = twitter.Endpoint
		client = &twitter.Client{
			OAuth1: oauth.OAuth1{
				Config: config,
			},
		}
	case "line":
		config.Endpoint = line.Endpoint
		client = &line.Client{
			OAuth2: oauth.OAuth2{
				Config: config,
			},
		}
	case "github":
		config.Endpoint = github.Endpoint
		client = &github.Client{
			OAuth2: oauth.OAuth2{
				Config: config,
			},
		}
	case "gitlab":
		config.Endpoint = gitlab.Endpoint
		client = &gitlab.Client{
			OAuth2: oauth.OAuth2{
				Config: config,
			},
		}
	case "bitbucket":
		config.Endpoint = bitbucket.Endpoint
		client = &bitbucket.Client{
			OAuth2: oauth.OAuth2{
				Config: config,
			},
		}
	case "twitch":
		config.Endpoint = twitch.Endpoint
		client = &twitch.Client{
			OAuth2: oauth.OAuth2{
				Config: config,
			},
		}
	case "weibo":
		config.Endpoint = weibo.Endpoint
		client = &weibo.Client{
			OAuth2: oauth.OAuth2{
				Config: config,
			},
		}
	case "baidu":
		config.Endpoint = baidu.Endpoint
		client = &baidu.Client{
			OAuth2: oauth.OAuth2{
				Config: config,
			},
		}
	case "qq":
		config.Endpoint = qq.Endpoint
		client = &qq.Client{
			OAuth2: oauth.OAuth2{
				Config: config,
			},
		}
	case "wechat":
		config.Endpoint = wechat.Endpoint
		client = &wechat.Client{
			OAuth2: oauth.OAuth2{
				Config: config,
			},
		}
	default:
		log.Panicf("oauth %s does not exist", name)
	}
	return
}

var browserCommands = map[string]string{
	"windows": "start",
	"darwin":  "open",
	"linux":   "xdg-open",
}

func OpenBrowser(uri string) error {
	run, ok := browserCommands[runtime.GOOS]
	if !ok {
		return fmt.Errorf("don't know how to open things on %s platform", runtime.GOOS)
	}
	cmd := exec.Command(run, uri)
	return cmd.Start()
}

func main() {
	oauth.DEBUG = true
	var err error
	var name string
	var authorize *url.URL
	var callback *url.URL
	var callbackString string
	inputReader := bufio.NewReader(os.Stdin)
	ctx := context.Background()

	var token *oauth.Token

	fmt.Println("Please enter name:")
	if name, err = inputReader.ReadString('\n'); err != nil {
		log.Fatalln(err)
	}
	name = strings.TrimSpace(name)

	client := Client(name)

	var data map[string]interface{}
	if authorize, data, err = client.Authorize(ctx, oauth.RandString(32), nil); err != nil {
		log.Fatalln(err)
	}
	OpenBrowser(authorize.String())

	fmt.Printf("Authorize: %s", authorize.String())
	fmt.Println("")
	fmt.Println("")
	fmt.Println("Please enter callback url:")
	if callbackString, err = inputReader.ReadString('\n'); err != nil {
		log.Fatalln(err)
	}
	if callback, err = url.Parse(strings.TrimSpace(callbackString)); err != nil {
		log.Fatalln(err)
	}
	if token, err = client.Exchange(ctx, callback.Query(), data, nil); err != nil {
		log.Fatalln(err)
	}
	tokenString, _ := json.MarshalIndent(token, "", "    ")
	dataString, _ := json.MarshalIndent(data, "", "    ")
	fmt.Printf("Token: %s", tokenString)
	fmt.Println("")
	fmt.Printf("Data: %s", dataString)
	fmt.Println("")

	var user *oauth.User
	if user, err = client.User(ctx, token); err != nil {
		log.Fatalln(err)
	}
	userString, _ := json.MarshalIndent(user, "", "    ")
	fmt.Printf("User: %s", userString)
	fmt.Println("")

	for {
		fmt.Println("Please enter run method:")
		fmt.Println("user, refresh, revoke, fbexchange, clientcode")
		var method string
		method, err = inputReader.ReadString('\n')
		if err != nil {
			log.Fatalln(err)
		}
		method = strings.TrimSpace(method)
		switch method {
		case "user":
			var user *oauth.User
			if user, err = client.User(ctx, token); err != nil {
				log.Fatalln(err)
			}
			userString, _ := json.MarshalIndent(user, "", "    ")
			fmt.Printf("User: %s", userString)
		case "revoke":
			if err = client.RevokeToken(ctx, token, nil); err != nil {
				log.Fatalln(err)
			}
			fmt.Println("Destroyed")
		case "refresh":
			if token, err = client.RefreshToken(ctx, token, nil); err != nil {
				log.Fatalln(err)
			}
			tokenString, _ := json.MarshalIndent(token, "", "    ")
			fmt.Printf("Refreshed Token: %s", tokenString)
		case "fbexchange":
			if client, ok := client.(*facebook.Client); ok {
				if token, err = client.FbExchangeToken(ctx, token, nil); err != nil {
					log.Fatalln(err)
				}
				tokenString, _ := json.MarshalIndent(token, "", "    ")
				fmt.Printf("Exchange Token: %s", tokenString)
			} else {
				log.Fatalln("Not facebook")
			}
		case "clientcode":
			if client, ok := client.(*facebook.Client); ok {
				var code string
				if code, err = client.ClientCode(ctx, token, nil); err != nil {
					log.Fatalln(err)
				}
				fmt.Printf("Client Code: %s", code)
				fmt.Println("")
				fmt.Println("")

				if token, err = client.AccessToken(ctx, url.Values{"code": {code}}); err != nil {
					log.Fatalln(err)
				}
				tokenString, _ := json.MarshalIndent(token, "", "    ")
				fmt.Printf("Code Token: %s", tokenString)
			} else {
				log.Fatalln("Not facebook")
			}
		}
		fmt.Println("")
		fmt.Println("")
		fmt.Println("")
	}
}
