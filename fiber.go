// ⚡️ Fiber is an Express inspired web framework written in Go with ☕️
// 🤖 Github Repository: https://github.com/gofiber/fiber
// 📌 API Documentation: https://docs.gofiber.io
//
// Package fiber is an Express inspired web framework built on top of Fasthttp,
// the fastest HTTP engine for Go. Designed to ease things up for fast
// development with zero memory allocation and performance in mind.
//
// Copied from https://github.com/gofiber/fiber
// See license https://github.com/gofiber/fiber/blob/main/LICENSE
package fasthttp

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/valyala/bytebufferpool"
)

const StatusTooEarly = 425

const (
	schemeHTTP  = "http"
	schemeHTTPS = "https"
)

const (
	StrGzip    = "gzip"
	StrBr      = "br"
	StrDeflate = "deflate"
	StrBrotli  = "brotli"
)

const (
	MIMETextXML         = "text/xml"
	MIMETextHTML        = "text/html"
	MIMETextPlain       = "text/plain"
	MIMETextJavaScript  = "text/javascript"
	MIMEApplicationXML  = "application/xml"
	MIMEApplicationJSON = "application/json"
	// Deprecated: use MIMETextJavaScript instead
	MIMEApplicationJavaScript = "application/javascript"
	MIMEApplicationForm       = "application/x-www-form-urlencoded"
	MIMEOctetStream           = "application/octet-stream"
	MIMEMultipartForm         = "multipart/form-data"

	MIMETextXMLCharsetUTF8         = "text/xml; charset=utf-8"
	MIMETextHTMLCharsetUTF8        = "text/html; charset=utf-8"
	MIMETextPlainCharsetUTF8       = "text/plain; charset=utf-8"
	MIMETextJavaScriptCharsetUTF8  = "text/javascript; charset=utf-8"
	MIMEApplicationXMLCharsetUTF8  = "application/xml; charset=utf-8"
	MIMEApplicationJSONCharsetUTF8 = "application/json; charset=utf-8"
	// Deprecated: use MIMETextJavaScriptCharsetUTF8 instead
	MIMEApplicationJavaScriptCharsetUTF8 = "application/javascript; charset=utf-8"
)

const (
	queryTag  = "query"
	headerTag = "header"
	formTag   = "form"
	paramTag  = "param"
	cookieTag = "cookie"
)

// Errors
var (
	ErrBadRequest                   = NewError(StatusBadRequest)                   // 400
	ErrUnauthorized                 = NewError(StatusUnauthorized)                 // 401
	ErrPaymentRequired              = NewError(StatusPaymentRequired)              // 402
	ErrForbidden                    = NewError(StatusForbidden)                    // 403
	ErrNotFound                     = NewError(StatusNotFound)                     // 404
	ErrMethodNotAllowed             = NewError(StatusMethodNotAllowed)             // 405
	ErrNotAcceptable                = NewError(StatusNotAcceptable)                // 406
	ErrProxyAuthRequired            = NewError(StatusProxyAuthRequired)            // 407
	ErrRequestTimeout               = NewError(StatusRequestTimeout)               // 408
	ErrConflict                     = NewError(StatusConflict)                     // 409
	ErrGone                         = NewError(StatusGone)                         // 410
	ErrLengthRequired               = NewError(StatusLengthRequired)               // 411
	ErrPreconditionFailed           = NewError(StatusPreconditionFailed)           // 412
	ErrRequestEntityTooLarge        = NewError(StatusRequestEntityTooLarge)        // 413
	ErrRequestURITooLong            = NewError(StatusRequestURITooLong)            // 414
	ErrUnsupportedMediaType         = NewError(StatusUnsupportedMediaType)         // 415
	ErrRequestedRangeNotSatisfiable = NewError(StatusRequestedRangeNotSatisfiable) // 416
	ErrExpectationFailed            = NewError(StatusExpectationFailed)            // 417
	ErrTeapot                       = NewError(StatusTeapot)                       // 418
	ErrMisdirectedRequest           = NewError(StatusMisdirectedRequest)           // 421
	ErrUnprocessableEntity          = NewError(StatusUnprocessableEntity)          // 422
	ErrLocked                       = NewError(StatusLocked)                       // 423
	ErrFailedDependency             = NewError(StatusFailedDependency)             // 424
	ErrTooEarly                     = NewError(StatusTooEarly)                     // 425
	ErrUpgradeRequired              = NewError(StatusUpgradeRequired)              // 426
	ErrPreconditionRequired         = NewError(StatusPreconditionRequired)         // 428
	ErrTooManyRequests              = NewError(StatusTooManyRequests)              // 429
	ErrRequestHeaderFieldsTooLarge  = NewError(StatusRequestHeaderFieldsTooLarge)  // 431
	ErrUnavailableForLegalReasons   = NewError(StatusUnavailableForLegalReasons)   // 451

	ErrInternalServerError           = NewError(StatusInternalServerError)           // 500
	ErrNotImplemented                = NewError(StatusNotImplemented)                // 501
	ErrBadGateway                    = NewError(StatusBadGateway)                    // 502
	ErrServiceUnavailable            = NewError(StatusServiceUnavailable)            // 503
	ErrGatewayTimeout                = NewError(StatusGatewayTimeout)                // 504
	ErrHTTPVersionNotSupported       = NewError(StatusHTTPVersionNotSupported)       // 505
	ErrVariantAlsoNegotiates         = NewError(StatusVariantAlsoNegotiates)         // 506
	ErrInsufficientStorage           = NewError(StatusInsufficientStorage)           // 507
	ErrLoopDetected                  = NewError(StatusLoopDetected)                  // 508
	ErrNotExtended                   = NewError(StatusNotExtended)                   // 510
	ErrNetworkAuthenticationRequired = NewError(StatusNetworkAuthenticationRequired) // 511
)

type Ctx = RequestCtx
type ErrorHandler func(*RequestCtx, error)

type Map = map[string]any
type StrMap = map[string]string

// App is application
type App struct {
	*Router
	*Server
	View    *Render
	Start   time.Time
	uses    map[string][]Handle
	usesPos []string
}

// New creates new App
func New() *App {
	return &App{
		Server:  &Server{},
		Router:  NewRouter(),
		Start:   time.Now(),
		uses:    make(map[string][]Handle, 0),
		usesPos: make([]string, 0),
	}
}

// Serve serves over given tcp addr
func (app *App) Serve(addr string) error {
	return app.ServerHandler().ListenAndServe(addr)
}

var sockMode os.FileMode = os.ModeSocket | 0660 // ug+rw

// ServeUnix serves over given unix socket path
func (app *App) ServeUnix(path string) error {
	return app.ServerHandler().ListenAndServeUNIX(path, sockMode)
}

// ServerHandler (re)sets handler for server and returns it
func (app *App) ServerHandler(reset ...bool) *Server {
	if app.Server.Handler == nil || (len(reset) > 0 && reset[0]) {
		app.Server.Handler = app.Handler
	}
	return app.Server
}

// Use registers pre middlewares (that executes before the main handler)
// Middlewares do not match request methods but the request path prefix ONLY
func (app *App) Use(handle Handle) {
	app.use("", handle)
}

func (app *App) use(path string, handle Handle) {
	if _, ok := app.uses[path]; !ok {
		app.uses[path] = []Handle{handle}
		app.usesPos = append(app.usesPos, path)
		return
	}
	app.uses[path] = append(app.uses[path], handle)
}

// GetPost registers same handler for GET and POST methods
func (app *App) GetPost(path string, handle Handle) *Router {
	return app.Get(path, handle).Post(path, handle)
}

const routeNamesKey = "_route_names_"
const viewRendererKey = "_view_renderer_"

// ReqStartTimeKey is request start time key
const ReqStartTimeKey = "_req_start_time_"

// Handler is the entry point of all request handlers
func (app *App) Handler(c *Ctx) {
	c.SetUserValues(Map{
		ReqStartTimeKey:  time.Now(),
		viewRendererKey:  app.View,
		routeNamesKey:    app.Router.names,
		requestServedKey: false,
	})
	if err := app.Router.Serve(c, app.pipeThru); err != nil {
		if err, ok := err.(*Error); ok {
			c.SendError(err)
			return
		}
		if app.PanicHandler != nil {
			app.PanicHandler(c, err)
			return
		}
		c.SendStatus(StatusInternalServerError)
	}
}

// pipeThru runs request through middleware pipes (in order of their registration)
func (app *App) pipeThru(path string, handle Handle, c *Ctx) (err error) {
	for _, p := range app.usesPos {
		if p == path || strings.HasPrefix(path+"/", p+"/") {
			for _, use := range app.uses[p] {
				if err = use(c); err != nil || c.Served() {
					return
				}
			}
		}
	}
	return handle(c)
}

// Group is route subgroup
type Group struct {
	app    *App
	Prefix string
}

// Group creates router subgroup with prefix
func (app *App) Group(prefix string) *Group {
	return &Group{app: app, Prefix: prefix}
}

// GetPost registers same handler for GET and POST methods
func (r *Group) GetPost(path string, handle Handle) *Router {
	r.Get(path, handle) // can't use fluent
	return r.Post(path, handle)
}

// Get is a shortcut Handle(MethodGet, path, handle)
func (r *Group) Get(path string, handle Handle) *Router {
	r.Handle(MethodHead, path, handle)
	return r.Handle(MethodGet, path, handle)
}

// Head is a shortcut handle(MethodHead, path, handle)
func (r *Group) Head(path string, handle Handle) *Router {
	return r.Handle(MethodHead, path, handle)
}

// Options is a shortcut handle(MethodOptions, path, handle)
func (r *Group) Options(path string, handle Handle) *Router {
	return r.Handle(MethodOptions, path, handle)
}

// Post is a shortcut handle(MethodPost, path, handle)
func (r *Group) Post(path string, handle Handle) *Router {
	return r.Handle(MethodPost, path, handle)
}

// Put is a shortcut handle(MethodPut, path, handle)
func (r *Group) Put(path string, handle Handle) *Router {
	return r.Handle(MethodPut, path, handle)
}

// Patch is a shortcut handle(MethodPatch, path, handle)
func (r *Group) Patch(path string, handle Handle) *Router {
	return r.Handle(MethodPatch, path, handle)
}

// Delete is a shortcut handle(MethodDelete, path, handle)
func (r *Group) Delete(path string, handle Handle) *Router {
	return r.Handle(MethodDelete, path, handle)
}

// Handle registers a route
func (r *Group) Handle(method, path string, handle Handle) *Router {
	return r.app.Handle(method, r.Prefix+path, handle)
}

// Use registers pre middlewares (that executes before the main handler)
// Middlewares do not match request methods but the request path prefix ONLY
func (r *Group) Use(handle Handle) {
	r.app.use(r.Prefix, handle)
}

// Error represents an error that occurred while handling a request.
type Error struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// Error makes it compatible with the `error` interface.
func (e *Error) Error() string {
	return e.Message
}

// WithMessage (re)sets the Error message
func (e Error) WithMessage(s string) *Error {
	return &Error{Code: e.Code, Message: s}
}

// NewError creates a new Error instance with an optional message
func NewError(code int, message ...string) *Error {
	err := &Error{
		Code:    code,
		Message: statusMessages[code],
	}
	if len(message) > 0 {
		err.Message = message[0]
	}
	return err
}

// Accepts checks if the specified extensions or content types are acceptable.
func (c *Ctx) Accepts(offers ...string) string {
	if len(offers) == 0 {
		return ""
	}
	header := c.Get(HeaderAccept)
	if header == "" {
		return offers[0]
	}
	for _, offer := range offers {
		// this is insanely simple and imperfect
		if strings.Contains(header, offer) || strings.Contains(header, mime.TypeByExtension(offer)) {
			return offer
		}
	}
	return offers[0]
}

// Append the specified value to the HTTP response header field.
// If the header is not already set, it creates the header with the specified value.
func (c *Ctx) Append(field string, values ...string) {
	if len(values) == 0 {
		return
	}
	h := b2s(c.Response.Header.Peek(field))
	originalH := h
	for _, value := range values {
		if len(h) == 0 {
			h = value
		} else if h != value && !strings.HasPrefix(h, value+",") && !strings.HasSuffix(h, " "+value) &&
			!strings.Contains(h, " "+value+",") {
			h += ", " + value
		}
	}
	if originalH != h {
		c.Set(field, h)
	}
}

// Attachment sets the HTTP response Content-Disposition header field to attachment.
func (c *Ctx) Attachment(filename ...string) {
	if len(filename) > 0 {
		fname := filepath.Base(filename[0])
		c.Type(filepath.Ext(fname))

		c.setCanonical(HeaderContentDisposition, `attachment; filename="`+fname+`"`)
		return
	}
	c.setCanonical(HeaderContentDisposition, "attachment")
}

// BaseURL returns (protocol + host + base path).
func (c *Ctx) BaseURL() string {
	return c.Scheme() + "://" + c.Hostname()
}

// BodyRaw contains the raw body submitted in a POST request.
// Returned value is only valid within the handler. Do not store any references.
// Make copies or use the Immutable setting instead.
func (c *Ctx) BodyRaw() []byte {
	return c.Request.Body()
}

func (c *Ctx) tryDecodeBodyInOrder(
	originalBody *[]byte,
	encodings []string,
) ([]byte, uint8, error) {
	var (
		err             error
		body            []byte
		decodesRealized uint8
	)

	for index, encoding := range encodings {
		decodesRealized++
		switch encoding {
		case StrGzip:
			body, err = c.Request.BodyGunzip()
		case StrDeflate:
			body, err = c.Request.BodyInflate()
		default:
			decodesRealized--
			if len(encodings) == 1 {
				body = c.Request.Body()
			}
			return body, decodesRealized, nil
		}

		if err != nil {
			return nil, decodesRealized, err
		}

		// Only execute body raw update if it has a next iteration to try to decode
		if index < len(encodings)-1 && decodesRealized > 0 {
			if index == 0 {
				tempBody := c.Request.Body()
				*originalBody = make([]byte, len(tempBody))
				copy(*originalBody, tempBody)
			}
			c.Request.SetBodyRaw(body)
		}
	}

	return body, decodesRealized, nil
}

// Body contains the raw body submitted in a POST request.
// This method will decompress the body if the 'Content-Encoding' header is provided.
// It returns the original (or decompressed) body data which is valid only within the handler.
// Don't store direct references to the returned data.
// If you need to keep the body's data later, make a copy or use the Immutable option.
func (c *Ctx) Body() []byte {
	var headerEncoding = strings.ReplaceAll(b2s(c.Request.Header.Peek(HeaderContentEncoding)), " ", "")
	if headerEncoding == "" {
		return c.Request.Body()
	}

	var (
		err                error
		body, originalBody []byte
	)

	// Split and get the encodings list, in order to attend the
	// rule defined at: https://www.rfc-editor.org/rfc/rfc9110#section-8.4-5
	encodingOrder := strings.Split(headerEncoding, ",")
	if len(encodingOrder) == 0 {
		return c.Request.Body()
	}

	var decodesRealized uint8
	body, decodesRealized, err = c.tryDecodeBodyInOrder(&originalBody, encodingOrder)

	// Ensure that the body will be the original
	if originalBody != nil && decodesRealized > 0 {
		c.Request.SetBodyRaw(originalBody)
	}
	if err != nil {
		return []byte(err.Error())
	}

	return body
}

// BodyParser binds the request body to a struct.
// It supports decoding the following content types based on the Content-Type header:
// application/json, application/xml, application/x-www-form-urlencoded, multipart/form-data
// All JSON extenstion mime types are supported (eg. application/problem+json)
// If none of the content types above are matched, it will return a ErrUnprocessableEntity error
func (c *Ctx) BodyParser(out any) error {
	return DefaultBinder.BindBody(c, out)
}

// ClearCookie expires a specific cookie by key on the client side.
// If no key is provided it expires all cookies that came with the request.
func (c *Ctx) ClearCookie(key ...string) {
	if len(key) > 0 {
		for i := range key {
			c.Response.Header.DelClientCookie(key[i])
		}
		return
	}
	c.Request.Header.VisitAllCookie(func(k, v []byte) {
		c.Response.Header.DelClientCookieBytes(k)
	})
}

const userContextKey = "__local_user_context__"

// UserContext returns a context implementation that was set by
// user earlier or returns a non-nil, empty context,if it was not set earlier.
func (c *Ctx) UserContext() context.Context {
	ctx, ok := c.UserValue(userContextKey).(context.Context)
	if !ok {
		ctx = context.Background()
		c.SetUserContext(ctx)
	}

	return ctx
}

// SetUserContext sets a context implementation by user.
func (c *Ctx) SetUserContext(ctx context.Context) {
	c.SetUserValue(userContextKey, ctx)
}

// Range data for c.Range
type Range struct {
	Type   string
	Ranges []RangeSet
}

// RangeSet represents a single content range from a request.
type RangeSet struct {
	Start int
	End   int
}

// Cookiex is a cookie with exported string fields
// Use like c.Cookie(&Cookiex{Name: "...", Value: "..."})
type Cookiex struct {
	Expires     time.Time      `json:"expires"`
	Name        string         `json:"name"`
	Value       string         `json:"value"`
	Path        string         `json:"path"`
	Domain      string         `json:"domain"`
	SameSite    CookieSameSite `json:"same_site"`
	MaxAge      int            `json:"max_age"`
	Secure      bool           `json:"secure"`
	HTTPOnly    bool           `json:"http_only"`
	SessionOnly bool           `json:"session_only"`
}

// Cookie sets a cookie by passing a cookie struct.
// Use like c.Cookie(&Cookiex{Name: "...", Value: "..."})
func (c *Ctx) Cookie(cookie *Cookiex) {
	fcookie := AcquireCookie()
	fcookie.SetKey(cookie.Name)
	fcookie.SetValue(cookie.Value)
	fcookie.SetPath(cookie.Path)
	fcookie.SetDomain(cookie.Domain)
	// only set max age and expiry when SessionOnly is false
	// i.e. cookie supposed to last beyond browser session
	// refer: https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies#define_the_lifetime_of_a_cookie
	if !cookie.SessionOnly {
		fcookie.SetMaxAge(cookie.MaxAge)
		fcookie.SetExpire(cookie.Expires)
	}
	fcookie.SetSecure(cookie.Secure)
	fcookie.SetHTTPOnly(cookie.HTTPOnly)
	fcookie.SetSameSite(cookie.SameSite)

	c.Response.Header.SetCookie(fcookie)
	ReleaseCookie(fcookie)
}

// Cookies are used for getting a cookie value by key.
// Defaults to the empty string "" if the cookie doesn't exist.
// If a default value is given, it will return that value if the cookie doesn't exist.
// The returned value is only valid within the handler. Do not store any references.
// Make copies or use the Immutable setting to use the value outside the Handler.
func (c *Ctx) Cookies(key string, defaultValue ...string) string {
	return defaultString(b2s(c.Request.Header.Cookie(key)), defaultValue)
}

func defaultString(v string, d []string) string {
	if v == "" && len(d) > 0 {
		return d[0]
	}
	return v
}

// CookieParser is used to bind cookies to a struct
func (c *Ctx) CookieParser(out any) error {
	data := make(map[string][]string)
	var err error

	// loop through all cookies
	c.Request.Header.VisitAllCookie(func(key, val []byte) {
		if err != nil {
			return
		}

		k := b2s(key)
		v := b2s(val)

		if strings.Contains(k, "[") {
			k, err = parseParamSquareBrackets(k)
		}

		data[k] = append(data[k], v)
	})
	if err != nil {
		return err
	}

	return DefaultBinder.BindData(out, data, cookieTag)
}

// Download transfers the file from path as an attachment.
// Typically, browsers will prompt the user for download.
// By default, the Content-Disposition header filename= parameter is the filepath (this typically appears in the browser dialog).
// Override this default with the filename parameter.
func (c *Ctx) Download(file string, filename ...string) error {
	var fname string
	if len(filename) > 0 {
		fname = filename[0]
	} else {
		fname = filepath.Base(file)
	}
	c.setCanonical(HeaderContentDisposition, `attachment; filename="`+fname+`"`)
	c.SendFile(file)
	return nil
}

// Format performs content-negotiation on the Accept HTTP header.
// It uses Accepts to select a proper format.
// If the header is not specified or there is no proper format, text/plain is used.
func (c *Ctx) Format(body any) error {
	// Get accepted content type
	accept := c.Accepts("html", "json", "txt", "xml")
	// Set accepted content type
	c.Type(accept)
	// Type convert provided body
	var b string
	switch val := body.(type) {
	case string:
		b = val
	case []byte:
		b = b2s(val)
	default:
		b = fmt.Sprintf("%v", val)
	}

	// Format based on the accept content type
	switch accept {
	case "html":
		return c.SendString("<p>" + b + "</p>")
	case "json":
		return c.JSON(body)
	case "txt":
		return c.SendString(b)
	case "xml":
		return c.XML(body)
	}
	return c.SendString(b)
}

// Get returns the HTTP request header specified by field.
// Field names are case-insensitive
// Returned value is only valid within the handler. Do not store any references.
// Make copies or use the Immutable setting instead.
func (c *Ctx) Get(key string, defaultValue ...string) string {
	return defaultString(b2s(c.Request.Header.Peek(key)), defaultValue)
}

// GetRespHeader returns the HTTP response header specified by field.
// Field names are case-insensitive
// Returned value is only valid within the handler. Do not store any references.
// Make copies or use the Immutable setting instead.
func (c *Ctx) GetRespHeader(key string, defaultValue ...string) string {
	return defaultString(b2s(c.Response.Header.Peek(key)), defaultValue)
}

// GetReqHeaders returns the HTTP request headers.
// Returned value is only valid within the handler. Do not store any references.
// Make copies or use the Immutable setting instead.
func (c *Ctx) GetReqHeaders() map[string][]string {
	headers := make(map[string][]string)
	c.Request.Header.VisitAll(func(k, v []byte) {
		key := b2s(k)
		headers[key] = append(headers[key], b2s(v))
	})

	return headers
}

// GetRespHeaders returns the HTTP response headers.
// Returned value is only valid within the handler. Do not store any references.
// Make copies or use the Immutable setting instead.
func (c *Ctx) GetRespHeaders() map[string][]string {
	headers := make(map[string][]string)
	c.Response.Header.VisitAll(func(k, v []byte) {
		key := b2s(k)
		headers[key] = append(headers[key], b2s(v))
	})

	return headers
}

// Hostname contains the hostname derived from the X-Forwarded-Host or Host HTTP header.
// Returned value is only valid within the handler. Do not store any references.
// Make copies or use the Immutable setting instead.
// Please use Config.EnableTrustedProxyCheck to prevent header spoofing, in case when your app is behind the proxy.
func (c *Ctx) Hostname() string {
	if c.IsProxyTrusted() {
		if host := c.Get(HeaderXForwardedHost); len(host) > 0 {
			commaPos := strings.Index(host, ",")
			if commaPos != -1 {
				return host[:commaPos]
			}
			return host
		}
	}
	return b2s(c.Request.URI().Host())
}

// Port returns the remote port of the request.
func (c *Ctx) Port() string {
	tcpaddr, ok := c.RemoteAddr().(*net.TCPAddr)
	if !ok {
		panic(fmt.Errorf("failed to type-assert to *net.TCPAddr"))
	}
	return strconv.Itoa(tcpaddr.Port)
}

var portRe, _ = regexp.Compile(`:\d+$`)

// IP returns the remote IP address of the request.
// If ProxyHeader and IP Validation is configured, it will parse that header and return the first valid IP address.
// Please use Config.EnableTrustedProxyCheck to prevent header spoofing, in case when your app is behind the proxy.
func (c *Ctx) IP() string {
	return strings.Trim(c.IPs()[0], " ")
}

var localIPs = []string{"127.0.0.1"}

// IPs returns a string slice of IP addresses specified in the X-Forwarded-For request header.
// When IP validation is enabled, only valid IPs are returned.
func (c *Ctx) IPs() (ips []string) {
	ip := c.Get("X-Real-Ip")
	if ip != "" {
		ips = append(ips, ip)
	}
	ip = c.Get("X-Forwarded-For")
	if ip != "" {
		ips = append(ips, strings.Split(ip, ",")...)
	}
	ip = portRe.ReplaceAllLiteralString(c.RemoteIP().String(), "")
	if ip != "" {
		ips = append(ips, ip)
	}
	if len(ips) == 0 {
		return localIPs
	}
	return ips
}

// Is returns the matching content type,
// if the incoming request's Content-Type HTTP header field matches the MIME type specified by the type parameter
func (c *Ctx) Is(extension string) bool {
	extensionHeader := mime.TypeByExtension(extension)
	if extensionHeader == "" {
		return false
	}

	return strings.HasPrefix(
		strings.TrimLeft(b2s(c.Request.Header.ContentType()), " "),
		extensionHeader,
	)
}

// JSON converts any interface or string to JSON.
// Array and slice values encode as JSON arrays,
// except that []byte encodes as a base64-encoded string,
// and a nil slice encodes as the null JSON value.
// If the ctype parameter is given, this method will set the
// Content-Type header equal to ctype. If ctype is not given,
// The Content-Type header will be set to application/json.
func (c *Ctx) JSON(data any, ctype ...string) error {
	raw, err := json.Marshal(data)
	if err != nil {
		return err
	}
	c.Response.SetBodyRaw(raw)
	if len(ctype) > 0 {
		c.Response.Header.SetContentType(ctype[0])
	} else {
		c.Response.Header.SetContentType(MIMEApplicationJSON)
	}
	return nil
}

// JSONP sends a JSON response with JSONP support.
// This method is identical to JSON, except that it opts-in to JSONP callback support.
// By default, the callback name is simply callback.
func (c *Ctx) JSONP(data any, callback ...string) error {
	raw, err := json.Marshal(data)
	if err != nil {
		return err
	}

	var result, cb string

	if len(callback) > 0 {
		cb = callback[0]
	} else {
		cb = "callback"
	}

	result = cb + "(" + b2s(raw) + ");"

	c.setCanonical(HeaderXContentTypeOptions, "nosniff")
	c.Response.Header.SetContentType(MIMETextJavaScriptCharsetUTF8)
	return c.SendString(result)
}

// XML converts any interface or string to XML.
// This method also sets the content header to application/xml.
func (c *Ctx) XML(data any) error {
	raw, err := xml.Marshal(data)
	if err != nil {
		return err
	}
	c.Response.SetBodyRaw(raw)
	c.Response.Header.SetContentType(MIMEApplicationXML)
	return nil
}

// Links joins the links followed by the property to populate the response's Link HTTP header field.
func (c *Ctx) Links(link ...string) {
	if len(link) == 0 {
		return
	}
	bb := bytebufferpool.Get()
	for i := range link {
		if i%2 == 0 {
			_ = bb.WriteByte('<')          //nolint:errcheck // This will never fail
			_, _ = bb.WriteString(link[i]) //nolint:errcheck // This will never fail
			_ = bb.WriteByte('>')          //nolint:errcheck // This will never fail
		} else {
			_, _ = bb.WriteString(`; rel="` + link[i] + `",`) //nolint:errcheck // This will never fail
		}
	}
	c.setCanonical(HeaderLink, strings.TrimRight(b2s(bb.Bytes()), ","))
	bytebufferpool.Put(bb)
}

// Locals makes it possible to pass any values under keys scoped to the request
// and therefore available to all following routes that match the request.
func (c *Ctx) Locals(key any, value ...any) any {
	if len(value) == 0 {
		return c.UserValue(key)
	}
	c.SetUserValue(key, value[0])
	return value[0]
}

// Location sets the response Location HTTP header to the specified path parameter.
func (c *Ctx) Location(path string) {
	c.setCanonical(HeaderLocation, path)
}

// ClientHelloInfo return CHI from context
func (c *Ctx) ClientHelloInfo() *tls.ClientHelloInfo {
	return nil
}

const requestServedKey = "_request_served_"

// Finish marks request as finished to be used by pre middlewares
func (c *Ctx) Finish() error {
	c.SetUserValue(requestServedKey, true)
	return nil
}

// Served tells is request is served already
func (c *Ctx) Served() bool {
	v, ok := c.UserValue(requestServedKey).(bool)
	return v && ok
}

// OriginalURL contains the original request URL.
// Returned value is only valid within the handler. Do not store any references.
// Make copies or use the Immutable setting to use the value outside the Handler.
func (c *Ctx) OriginalURL() string {
	return b2s(c.Request.Header.RequestURI())
}

// Methods gives method string
func (c *Ctx) Methods() string {
	return b2s(c.Method())
}

// Next does nothing, returns nil
func (c *Ctx) Next() error {
	return nil
}

// Paths gives request path string without query
func (c *Ctx) Paths() string {
	return b2s(c.URI().Path())
}

// FormParams give request form params from GET+POST+FILES
func (c *Ctx) FormParams() map[string][]string {
	form := map[string][]string{}
	c.QueryArgs().VisitAll(func(key, value []byte) {
		k := b2s(key)
		form[k] = append(form[k], b2s(value))
	})
	c.PostArgs().VisitAll(func(key, value []byte) {
		k := b2s(key)
		form[k] = append(form[k], b2s(value))
	})
	mf, err := c.MultipartForm()
	if err == nil && mf.Value != nil {
		for k, v := range mf.Value {
			form[k] = v
		}
	}
	return form
}

// FormValues gives form value from request in order GET > POST > FILES
func (c *Ctx) FormValues(key string, defaultValue ...string) string {
	return defaultString(b2s(c.FormValue(key)), defaultValue)
}

// Params is used to get the route parameters.
// Defaults to empty string "" if the param doesn't exist.
// If a default value is given, it will return that value if the param doesn't exist.
// Returned value is only valid within the handler. Do not store any references.
// Make copies or use the Immutable setting to use the value outside the Handler.
func (c *Ctx) Params(key string, defaultValue ...string) (v string) {
	if ps, ok := c.UserValue(routeParamKey).(*Params); ok && ps != nil {
		v = ps.ByName(key)
	}
	return defaultString(v, defaultValue)
}

// AllParams Params is used to get all route parameters.
// Using Params method to get params.
func (c *Ctx) AllParams() map[string]string {
	m := map[string]string{}
	if ps, ok := c.UserValue(routeParamKey).(Params); ok && ps != nil {
		for _, p := range ps {
			m[p.Key] = p.Value
		}
	}
	return m
}

// ParamsParser binds the param string to a struct.
func (c *Ctx) ParamsParser(out any) error {
	return DefaultBinder.BindPathParams(c, out)
}

// ParamsInt is used to get an integer from the route parameters
// it defaults to zero if the parameter is not found or if the
// parameter cannot be converted to an integer
// If a default value is given, it will return that value in case the param
// doesn't exist or cannot be converted to an integer
func (c *Ctx) ParamsInt(key string, defaultValue ...int) (int, error) {
	// Use Atoi to convert the param to an int or return zero and an error
	value, err := strconv.Atoi(c.Params(key))
	if err != nil {
		if len(defaultValue) > 0 {
			return defaultValue[0], nil
		}
		return 0, fmt.Errorf("failed to convert: %w", err)
	}

	return value, nil
}

// Scheme contains the request protocol string: http or https for TLS requests.
// Please use Config.EnableTrustedProxyCheck to prevent header spoofing, in case when your app is behind the proxy.
func (c *Ctx) Scheme() string {
	p := c.Get("X-Forwarded-Proto")
	if len(p) == 0 {
		if p = c.Get("X-Forwarded-Protocol"); len(p) == 0 {
			p = b2s(c.Request.URI().Scheme())
		}
	}
	return p
}

// Query returns the query string parameter in the url.
// Defaults to empty string "" if the query doesn't exist.
// If a default value is given, it will return that value if the query doesn't exist.
// Returned value is only valid within the handler. Do not store any references.
// Make copies or use the Immutable setting to use the value outside the Handler.
func (c *Ctx) Query(key string, defaultValue ...string) string {
	return defaultString(b2s(c.QueryArgs().Peek(key)), defaultValue)
}

// Queries returns a map of query parameters and their values.
//
// GET /?name=alex&wanna_cake=2&id=
// Queries()["name"] == "alex"
// Queries()["wanna_cake"] == "2"
// Queries()["id"] == ""
//
// GET /?field1=value1&field1=value2&field2=value3
// Queries()["field1"] == "value2"
// Queries()["field2"] == "value3"
//
// GET /?list_a=1&list_a=2&list_a=3&list_b[]=1&list_b[]=2&list_b[]=3&list_c=1,2,3
// Queries()["list_a"] == "3"
// Queries()["list_b[]"] == "3"
// Queries()["list_c"] == "1,2,3"
//
// GET /api/search?filters.author.name=John&filters.category.name=Technology&filters[customer][name]=Alice&filters[status]=pending
// Queries()["filters.author.name"] == "John"
// Queries()["filters.category.name"] == "Technology"
// Queries()["filters[customer][name]"] == "Alice"
// Queries()["filters[status]"] == "pending"
func (c *Ctx) Queries() map[string]string {
	m := make(map[string]string, c.QueryArgs().Len())
	c.QueryArgs().VisitAll(func(key, value []byte) {
		m[b2s(key)] = b2s(value)
	})
	return m
}

// QueryInt returns integer value of key string parameter in the url.
// Default to empty or invalid key is 0.
//
//	GET /?name=alex&wanna_cake=2&id=
//	QueryInt("wanna_cake", 1) == 2
//	QueryInt("name", 1) == 1
//	QueryInt("id", 1) == 1
//	QueryInt("id") == 0
func (c *Ctx) QueryInt(key string, defaultValue ...int) int {
	// Use Atoi to convert the param to an int or return zero and an error
	value, err := strconv.Atoi(b2s(c.QueryArgs().Peek(key)))
	if err != nil {
		if len(defaultValue) > 0 {
			return defaultValue[0]
		}
		return 0
	}

	return value
}

// QueryBool returns bool value of key string parameter in the url.
// Default to empty or invalid key is false.
//
//	Get /?name=alex&want_pizza=false&id=
//	QueryBool("want_pizza") == false
//	QueryBool("want_pizza", true) == false
//	QueryBool("name") == false
//	QueryBool("name", true) == true
//	QueryBool("id") == false
//	QueryBool("id", true) == true
func (c *Ctx) QueryBool(key string, defaultValue ...bool) bool {
	value, err := strconv.ParseBool(b2s(c.QueryArgs().Peek(key)))
	if err != nil {
		if len(defaultValue) > 0 {
			return defaultValue[0]
		}
		return false
	}
	return value
}

// QueryFloat returns float64 value of key string parameter in the url.
// Default to empty or invalid key is 0.
//
//	GET /?name=alex&amount=32.23&id=
//	QueryFloat("amount") = 32.23
//	QueryFloat("amount", 3) = 32.23
//	QueryFloat("name", 1) = 1
//	QueryFloat("name") = 0
//	QueryFloat("id", 3) = 3
func (c *Ctx) QueryFloat(key string, defaultValue ...float64) float64 {
	// use strconv.ParseFloat to convert the param to a float or return zero and an error.
	value, err := strconv.ParseFloat(b2s(c.QueryArgs().Peek(key)), 64)
	if err != nil {
		if len(defaultValue) > 0 {
			return defaultValue[0]
		}
		return 0
	}
	return value
}

// QueryParser binds the query string to a struct.
func (c *Ctx) QueryParser(out any) error {
	return DefaultBinder.BindQueryParams(c, out)
}

func parseParamSquareBrackets(k string) (string, error) {
	bb := bytebufferpool.Get()
	defer bytebufferpool.Put(bb)

	kbytes := []byte(k)

	for i, b := range kbytes {
		if b == '[' && kbytes[i+1] != ']' {
			if err := bb.WriteByte('.'); err != nil {
				return "", fmt.Errorf("failed to write: %w", err)
			}
		}

		if b == '[' || b == ']' {
			continue
		}

		if err := bb.WriteByte(b); err != nil {
			return "", fmt.Errorf("failed to write: %w", err)
		}
	}

	return bb.String(), nil
}

// ReqHeaderParser binds the request header strings to a struct.
func (c *Ctx) ReqHeaderParser(out any) error {
	return DefaultBinder.BindHeaders(c, out)
}

var (
	ErrRangeMalformed     = errors.New("range: malformed range header string")
	ErrRangeUnsatisfiable = errors.New("range: unsatisfiable range")
)

// Range returns a struct containing the type and a slice of ranges.
func (c *Ctx) Range(size int) (Range, error) {
	var (
		rangeData Range
		ranges    string
	)
	rangeStr := c.Get(HeaderRange)

	i := strings.IndexByte(rangeStr, '=')
	if i == -1 || strings.Contains(rangeStr[i+1:], "=") {
		return rangeData, ErrRangeMalformed
	}
	rangeData.Type = rangeStr[:i]
	ranges = rangeStr[i+1:]

	var (
		singleRange string
		moreRanges  = ranges
	)
	for moreRanges != "" {
		singleRange = moreRanges
		if i := strings.IndexByte(moreRanges, ','); i >= 0 {
			singleRange = moreRanges[:i]
			moreRanges = moreRanges[i+1:]
		} else {
			moreRanges = ""
		}

		var (
			startStr, endStr string
			i                int
		)
		if i = strings.IndexByte(singleRange, '-'); i == -1 {
			return rangeData, ErrRangeMalformed
		}
		startStr = singleRange[:i]
		endStr = singleRange[i+1:]

		start, startErr := ParseUint(s2b(startStr))
		end, endErr := ParseUint(s2b(endStr))
		if startErr != nil { // -nnn
			start = size - end
			end = size - 1
		} else if endErr != nil { // nnn-
			end = size - 1
		}
		if end > size-1 { // limit last-byte-pos to current length
			end = size - 1
		}
		if start > end || start < 0 {
			continue
		}
		rangeData.Ranges = append(rangeData.Ranges, struct {
			Start int
			End   int
		}{
			start,
			end,
		})
	}
	if len(rangeData.Ranges) < 1 {
		return rangeData, ErrRangeUnsatisfiable
	}

	return rangeData, nil
}

const bindViewMapKey = "_bind_view_map_"

// Bind Add vars to default view var map binding to template engine.
// Variables are read by the Render method and may be overwritten.
func (c *Ctx) Bind(vars Map) error {
	c.SetUserValue(bindViewMapKey, c.mergeBind(vars))
	return nil
}

func (c *Ctx) mergeBind(vars Map) Map {
	if old, ok := c.UserValue(bindViewMapKey).(Map); ok {
		for k, v := range vars {
			old[k] = v
		}
		return old
	}
	return vars
}

// GetRouteURL generates URLs to named routes, with parameters. URLs are relative, for example: "/user/1831"
func (c *Ctx) GetRouteURL(routeName string, params Map) (string, error) {
	if names, ok := c.UserValue(routeNamesKey).(StrMap); ok && names[routeName] != "" {
		uri := names[routeName]
		for k, v := range params {
			uri = strings.Replace(uri, ":"+k, fmt.Sprintf("%v", v), 1)
		}
		return uri, nil
	}
	return "", ErrNotFound
}

// RedirectToRoute to the Route registered in the app with appropriate parameters
// If status is not specified, status defaults to 302 Found.
// If you want to send queries to route, you must add "queries" key typed as map[string]string to params.
func (c *Ctx) RedirectToRoute(routeName string, params Map, status ...int) error {
	uri, err := c.GetRouteURL(routeName, params)
	if err == nil {
		c.Redirects(uri, append(status, StatusFound)[0])
	}
	return err
}

// RedirectBack to the URL to referer
// If status is not specified, status defaults to 302 Found.
func (c *Ctx) RedirectBack(fallback string, status ...int) error {
	location := c.Get(HeaderReferer)
	if location == "" {
		location = fallback
	}
	c.Redirects(location, append(status, StatusFound)[0])
	return nil
}

func (c *Ctx) Redirects(location string, status ...int) error {
	c.redirect(s2b(location), append(status, StatusFound)[0])
	return nil
}

var ErrNoViewRenderer = errors.New("view renderer not configured")

// Render a template with data and sends a text/html response.
// We support the following engines: html, amber, handlebars, mustache, pug
func (c *Ctx) Render(name string, bind Map, layouts ...string) error {
	view, ok := c.UserValue(viewRendererKey).(*Render)
	if !ok || view == nil {
		return ErrNoViewRenderer
	}
	// Get new buffer from pool
	buf := bytebufferpool.Get()
	defer bytebufferpool.Put(buf)

	// Pass global binds
	bind = c.mergeBind(bind)
	if err := view.Render(buf, name, bind, layouts...); err != nil {
		return fmt.Errorf("render view: %w", err)
	}

	c.Response.Header.SetContentType(MIMETextHTMLCharsetUTF8)
	c.Response.SetBody(buf.Bytes())
	return nil
}

// Route returns the matched Route name (returns route path if name not set).
func (c *Ctx) Route() string {
	path, ok := c.UserValue(MatchedRoutePathKey).(string)
	if ok {
		if namePaths, ok := c.UserValue(routeNamesKey).(StrMap); ok {
			for name, pathx := range namePaths {
				if pathx == path {
					return name
				}
			}
		}
	}
	return path
}

// RoutePath is the actual path used in route definition.
func (c *Ctx) RoutePath() string {
	path, _ := c.UserValue(MatchedRoutePathKey).(string)
	return path
}

// SaveFile saves any multipart file to disk.
func (*Ctx) SaveFile(fileheader *multipart.FileHeader, path string) error {
	return SaveMultipartFile(fileheader, path)
}

// Secure returns whether a secure connection was established.
func (c *Ctx) Secure() bool {
	return c.Scheme() == schemeHTTPS
}

// Send sets the HTTP response body without copying it.
// From this point onward the body argument must not be changed.
func (c *Ctx) Send(body []byte) error {
	// Write response body
	c.Response.SetBodyRaw(body)
	return nil
}

// SendStatus sets the HTTP status code and if the response body is empty,
// it sets the correct status message in the body.
func (c *Ctx) SendStatus(status int) error {
	c.Status(status)

	// Only set status body when there is no response body
	if len(c.Response.Body()) == 0 {
		return c.SendString(statusMessages[status])
	}

	return nil
}

// SendError sends HTTP Error
// Use like c.SendError(fasthttp.ErrBadRequest), OR
//
//	c.SendError(fasthttp.ErrBadRequest.WithMessage("can't parse user input"))
func (c *Ctx) SendError(err *Error) {
	c.Error(err.Message, err.Code)
}

// SendString sets the HTTP response body for string types.
// This means no type assertion, recommended for faster performance
func (c *Ctx) SendString(body string) error {
	c.Response.SetBodyString(body)

	return nil
}

// SendStream sets response body stream and optional body size.
func (c *Ctx) SendStream(stream io.Reader, size ...int) error {
	if len(size) > 0 && size[0] >= 0 {
		c.Response.SetBodyStream(stream, size[0])
	} else {
		c.Response.SetBodyStream(stream, -1)
	}

	return nil
}

// Set sets the response's HTTP header field to the specified key, value.
func (c *Ctx) Set(key, val string) {
	c.Response.Header.Set(key, val)
}

// SetUserValues sets many user values using Map
func (c *Ctx) SetUserValues(vals Map) {
	for k, v := range vals {
		c.SetUserValue(k, v)
	}
}

func (c *Ctx) setCanonical(key, val string) {
	c.Response.Header.SetCanonical(s2b(key), s2b(val))
}

// Subdomains returns a string slice of subdomains in the domain name of the request.
// The subdomain offset, which defaults to 2, is used for determining the beginning of the subdomain segments.
func (c *Ctx) Subdomains(offset ...int) []string {
	o := 2
	if len(offset) > 0 {
		o = offset[0]
	}
	subdomains := strings.Split(c.Hostname(), ".")
	l := len(subdomains) - o
	// Check index to avoid slice bounds out of range panic
	if l < 0 {
		l = len(subdomains)
	}
	subdomains = subdomains[:l]
	return subdomains
}

// Status sets the HTTP status for the response.
// This method is chainable.
func (c *Ctx) Status(status int) *Ctx {
	c.Response.SetStatusCode(status)
	return c
}

// Type sets the Content-Type HTTP header to the MIME type specified by the file extension.
func (c *Ctx) Type(extension string, charset ...string) *Ctx {
	if len(charset) > 0 {
		c.Response.Header.SetContentType(mime.TypeByExtension(extension) + "; charset=" + charset[0])
	} else {
		c.Response.Header.SetContentType(mime.TypeByExtension(extension))
	}
	return c
}

// Vary adds the given header field to the Vary response header.
// This will append the header, if not already listed, otherwise leaves it listed in the current location.
func (c *Ctx) Vary(fields ...string) {
	c.Append(HeaderVary, fields...)
}

// Writef appends f & a into response body writer.
func (c *Ctx) Writef(f string, a ...any) (int, error) {
	//nolint:wrapcheck // This must not be wrapped
	return fmt.Fprintf(c.Response.BodyWriter(), f, a...)
}

// XHR returns a Boolean property, that is true, if the request's X-Requested-With header field is XMLHttpRequest,
// indicating that the request was issued by a client library (such as jQuery).
func (c *Ctx) XHR() bool {
	return bytes.EqualFold(c.Request.Header.Peek(HeaderXRequestedWith), []byte("xmlhttprequest"))
}

// IsProxyTrusted (not implemented yet)
func (c *Ctx) IsProxyTrusted() bool {
	return true
}

var localHosts = [...]string{"127.0.0.1", "::1", "@"}

// IsLocalHost will return true if address is a localhost address.
func (*Ctx) isLocalHost(address string) bool {
	for _, h := range localHosts {
		if address == h {
			return true
		}
	}
	return false
}

// IsFromLocal will return true if request came from local.
func (c *Ctx) IsFromLocal() bool {
	return c.isLocalHost(c.RemoteIP().String())
}

// CopyString copies a string
func CopyString(s string) string {
	return string(s2b(s))
}

// CopyBytes copies []byte
func CopyBytes(b []byte) []byte {
	tmp := make([]byte, len(b))
	copy(tmp, b)
	return tmp
}
