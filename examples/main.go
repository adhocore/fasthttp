package main

import (
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/adhocore/fasthttp"
	"github.com/adhocore/fasthttp/prefork"
)

func main() {
	app := fasthttp.New()

	usePrefork := len(os.Args) > 1 && os.Args[1] == "-prefork"

	app.Use(func(c *fasthttp.Ctx) error {
		c.Set("X-MW-1", "1")
		return nil
	})

	app.Use(func(c *fasthttp.Ctx) error {
		c.Set("X-MW-2", "2")
		return nil
	})

	app.Get("/", func(c *fasthttp.Ctx) error {
		fmt.Fprint(c, "Hello world!")
		return nil
	}).Name("home")

	app.Post("/gz", func(c *fasthttp.Ctx) error {
		fmt.Println(c.GetReqHeaders())
		// fmt.Fprint(c, "raw: "+fasthttp.B2S(c.BodyRaw()))
		fmt.Fprint(c, "\n")
		// fmt.Fprint(c, "dec: "+fasthttp.B2S(c.Body()))
		return nil
	})

	app.GetPost("/x/:x", func(c *fasthttp.Ctx) error {
		fmt.Println("base", c.BaseURL(), "orig", c.OriginalURL())
		fmt.Print("file x= ")
		fmt.Println(c.FormFile("x"))
		fmt.Println("queries", c.Queries())
		fmt.Println("forms", c.FormParams())
		fmt.Println("form x=", c.FormValues("x"))
		fmt.Println("cookie a=", c.Cookies("a"), "c=", c.Cookies("c"))
		fmt.Println("param x=", c.Params("x"))
		fmt.Println("headers", c.Get("Content-Type"))
		fmt.Println("meth", c.Methods())
		fmt.Println("path", c.Paths())
		fmt.Println("ips", c.IPs(), c.IP())
		fmt.Println("ctx", c.UserContext())
		fmt.Print("url ")
		fmt.Println(c.GetRouteURL("xx", map[string]any{"x": 1}))
		fmt.Println("qryInt", c.QueryInt("i"), c.Query("s"), c.Queries())
		return c.SendStatus(201)
	}).Name("xx")

	app.Get("/num/:num", func(c *fasthttp.Ctx) error {
		fmt.Fprint(c, "/num/:num")
		return nil
	}).Name("num")

	api := app.Group("/api")

	api.Use(func(c *fasthttp.Ctx) error {
		c.Set("X-A-MW-1", "1")
		return nil
	})

	api.Use(func(c *fasthttp.Ctx) error {
		c.Set("X-A-MW-2", "2")
		return nil
	})

	api.Get("", func(c *fasthttp.Ctx) error {
		fmt.Fprint(c, "api /")
		return nil
	}).Name("api_home")

	api.Get("/num/:num", func(c *fasthttp.Ctx) error {
		fmt.Fprint(c, "api /num/:num")
		return nil
	}).Name("api_num")

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM, syscall.SIGABRT)

	if !usePrefork {
		go func() {
			fmt.Println("fasthttp sock on http://fastsock.lvh.me")
			app.ServeUnix("/home/jiten/fast.sock")
		}()
	}
	go func() {
		port := ":8080"
		fmt.Println("fasthttp tcp on http://0.0.0.0" + port + " http://fast.lvh.me")
		if usePrefork {
			prefork.Serve(app, port)
		} else {
			app.Serve(port)
		}
	}()

	var wg sync.WaitGroup
	wg.Add(1)

	go func() {
		<-sig
		app.Server.Shutdown()
		wg.Done()
	}()

	wg.Wait()
}

/*
	echo '{"mydummy": "json"}' | gzip > json.gz
 curl -i --data-binary @json.gz -H "Content-Encoding: gzip" -o - http://fast.lvh.me/gz
*/
