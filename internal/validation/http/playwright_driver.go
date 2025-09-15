package http

import (
	"context"
	"fmt"
	"sync"
	"time"
	"github.com/playwright-community/playwright-go"
	"github.com/sirupsen/logrus"
	"github.com/bl4ck0w1/sublynx/pkg/models"
)

type PlaywrightDriver struct {
	pw            *playwright.Playwright
	browser       playwright.Browser
	context       playwright.BrowserContext
	page          playwright.Page
	timeout       time.Duration
	headless      bool
	userAgent     string
	logger        *logrus.Logger
	mu            sync.Mutex
	isInitialized bool
	captureConsole bool
	captureNetwork bool
}

func NewPlaywrightDriver(timeout time.Duration, headless bool, userAgent string, logger *logrus.Logger) *PlaywrightDriver {
	if logger == nil {
		logger = logrus.New()
	}
	if userAgent == "" {
		userAgent = "SubLynx/1.0 Playwright"
	}

	return &PlaywrightDriver{
		timeout:        timeout,
		headless:       headless,
		userAgent:      userAgent,
		logger:         logger,
		captureConsole: false,
		captureNetwork: false,
	}
}

func (p *PlaywrightDriver) Initialize() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.isInitialized {
		return nil
	}

	if err := playwright.Install(); err != nil {
		p.logger.WithError(err).Warn("Playwright browser install failed (continuing if already installed)")
	}

	pw, err := playwright.Run()
	if err != nil {
		return fmt.Errorf("failed to start Playwright: %w", err)
	}
	p.pw = pw
	browser, err := pw.Chromium.Launch(playwright.BrowserTypeLaunchOptions{
		Headless: playwright.Bool(p.headless),
		Args: []string{
			"--disable-web-security",
			"--disable-features=IsolateOrigins,site-per-process",
			"--disable-site-isolation-trials",
			"--disable-setuid-sandbox",
			"--no-sandbox",
			"--disable-dev-shm-usage",
			"--disable-accelerated-2d-canvas",
			"--no-first-run",
			"--no-zygote",
			"--disable-gpu",
			"--window-size=1920,1080",
		},
	})
	if err != nil {
		return fmt.Errorf("failed to launch browser: %w", err)
	}
	p.browser = browser
	ctx, err := browser.NewContext(playwright.BrowserNewContextOptions{
		UserAgent:         &p.userAgent,
		Viewport:          &playwright.Size{Width: 1920, Height: 1080},
		IgnoreHTTPSErrors: playwright.Bool(true),
		JavaScriptEnabled: playwright.Bool(true),
		// Apply a sensible default timeout at the context level
	})
	if err != nil {
		return fmt.Errorf("failed to create browser context: %w", err)
	}
	ctx.SetDefaultTimeout(float64(p.timeout.Milliseconds()))
	ctx.SetDefaultNavigationTimeout(float64(p.timeout.Milliseconds()))
	p.context = ctx
	page, err := ctx.NewPage()
	if err != nil {
		return fmt.Errorf("failed to create page: %w", err)
	}
	p.page = page
	p.isInitialized = true
	p.logger.Info("Playwright driver initialized")
	return nil
}

func (p *PlaywrightDriver) Navigate(ctx context.Context, url string) (*models.BrowserResponse, error) {
	if err := p.Initialize(); err != nil {
		return nil, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()

	resp := &models.BrowserResponse{
		URL:       url,
		StartTime: time.Now(),
	}
	_, err := p.page.Goto(url, playwright.PageGotoOptions{
		WaitUntil: playwright.WaitUntilStateNetworkidle,
		Timeout:   playwright.Float(float64(p.timeout.Milliseconds())),
	})
	if err != nil {
		resp.Error = err.Error()
		resp.Success = false
	} else {
		resp.Success = true
	}
	_ = p.page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{
		State: playwright.LoadStateNetworkidle,
	})

	resp.EndTime = time.Now()
	resp.Duration = resp.EndTime.Sub(resp.StartTime)
	if err := p.extractPageContent(resp); err != nil {
		p.logger.WithError(err).Warn("extractPageContent failed")
	}
	if p.captureConsole {
		resp.ConsoleLogs = []string{"console capture enabled: wire event listeners at initialization"}
	} else {
		resp.ConsoleLogs = []string{}
	}
	if p.captureNetwork {
		resp.NetworkRequests = []string{"network capture enabled: wire event listeners at initialization"}
	} else {
		resp.NetworkRequests = []string{}
	}

	if err := p.takeScreenshot(resp); err != nil {
		p.logger.WithError(err).Warn("screenshot failed")
	}

	return resp, nil
}

func (p *PlaywrightDriver) extractPageContent(response *models.BrowserResponse) error {
	title, err := p.page.Title()
	if err != nil {
		return err
	}
	response.Title = title

	html, err := p.page.Content()
	if err != nil {
		return err
	}
	response.Content = html
	cnt, err := p.page.Locator("body *").Count()
	if err == nil {
		response.ElementCount = cnt
	}
	response.HasForms = p.hasElements("form")
	response.HasInputs = p.hasElements("input")
	response.HasButtons = p.hasElements("button")
	response.HasLinks = p.hasElements("a")

	return nil
}

func (p *PlaywrightDriver) takeScreenshot(response *models.BrowserResponse) error {
	buf, err := p.page.Screenshot(playwright.PageScreenshotOptions{
		FullPage: playwright.Bool(true),
		Type:     playwright.ScreenshotTypePng,
	})
	if err != nil {
		return err
	}
	response.Screenshot = buf
	return nil
}

func (p *PlaywrightDriver) hasElements(selector string) bool {
	n, err := p.page.Locator(selector).Count()
	if err != nil {
		return false
	}
	return n > 0
}

func (p *PlaywrightDriver) ExecuteJavaScript(code string) (interface{}, error) {
	if err := p.Initialize(); err != nil {
		return nil, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()

	return p.page.Evaluate(code)
}

func (p *PlaywrightDriver) FillForm(formSelector string, values map[string]string) error {
	if err := p.Initialize(); err != nil {
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()

	for field, value := range values {
		selector := fmt.Sprintf("%s [name='%s']", formSelector, field)
		if err := p.page.Fill(selector, value); err != nil {
			return err
		}
	}
	return nil
}

func (p *PlaywrightDriver) ClickElement(selector string) error {
	if err := p.Initialize(); err != nil {
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()

	return p.page.Click(selector)
}

func (p *PlaywrightDriver) WaitForNavigation() error {
	if err := p.Initialize(); err != nil {
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()

	return p.page.WaitForNavigation(playwright.PageWaitForNavigationOptions{
		WaitUntil: playwright.WaitUntilStateNetworkidle,
	})
}

func (p *PlaywrightDriver) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.page != nil {
		_ = p.page.Close()
		p.page = nil
	}
	if p.context != nil {
		_ = p.context.Close()
		p.context = nil
	}
	if p.browser != nil {
		if err := p.browser.Close(); err != nil {
			return err
		}
		p.browser = nil
	}
	if p.pw != nil {
		if err := p.pw.Stop(); err != nil {
			return err
		}
		p.pw = nil
	}
	p.isInitialized = false
	return nil
}

func (p *PlaywrightDriver) SetTimeout(timeout time.Duration) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.timeout = timeout
	if p.context != nil {
		p.context.SetDefaultTimeout(float64(timeout.Milliseconds()))
		p.context.SetDefaultNavigationTimeout(float64(timeout.Milliseconds()))
	}
}

func (p *PlaywrightDriver) SetHeadless(headless bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.headless = headless
}
func (p *PlaywrightDriver) SetUserAgent(userAgent string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.userAgent = userAgent
}

func (p *PlaywrightDriver) EnableConsoleCapture(enable bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.captureConsole = enable
}

func (p *PlaywrightDriver) EnableNetworkCapture(enable bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.captureNetwork = enable
}

func (p *PlaywrightDriver) GetStats() map[string]interface{} {
	p.mu.Lock()
	defer p.mu.Unlock()

	return map[string]interface{}{
		"initialized":     p.isInitialized,
		"timeout":         p.timeout.String(),
		"headless":        p.headless,
		"user_agent":      p.userAgent,
		"console_capture": p.captureConsole,
		"network_capture": p.captureNetwork,
	}
}
