package main

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"image/color"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
)

type oliveThemeWrapper struct {
	base fyne.Theme
}

func (g *oliveThemeWrapper) Font(s fyne.TextStyle) fyne.Resource {
	if s.Bold && !s.Italic && !s.Monospace {
		if resourceLabGrotesqueBoldTtf != nil {
			return resourceLabGrotesqueBoldTtf
		}
	}
	return theme.DefaultTheme().Font(s)
}

func (g *oliveThemeWrapper) Color(name fyne.ThemeColorName, variant fyne.ThemeVariant) color.Color {
	switch name {
	case theme.ColorNamePrimary:
		return color.NRGBA{R: 128, G: 128, B: 0, A: 255}
	case theme.ColorNameForegroundOnPrimary:
		return color.NRGBA{R: 255, G: 255, B: 255, A: 255}
	case theme.ColorNameHyperlink:
		return color.NRGBA{R: 128, G: 128, B: 0, A: 255}
	default:
		return g.base.Color(name, variant)
	}
}

func (g *oliveThemeWrapper) Icon(name fyne.ThemeIconName) fyne.Resource {
	return g.base.Icon(name)
}

func (g *oliveThemeWrapper) Size(name fyne.ThemeSizeName) float32 {
	return g.base.Size(name)
}

var ansiRegex = regexp.MustCompile(`\x1B\[[0-9;]*[a-zA-Z]`)

func stripANSI(text string) string {
	return ansiRegex.ReplaceAllString(text, "")
}

const maxOutputLines = 500
const CONFIG_FILE = "nscw.json"

type NymSocks5Config struct {
	ProviderAddress     string `json:"provider_address"`
	UseAnonymousReplies bool   `json:"use_anonymous_replies"`
}

type ClientPanel struct {
	name           string
	outputRich     *widget.RichText
	outputScroll   *container.Scroll
	startBtn       *widget.Button
	stopBtn        *widget.Button
	statusLabel    *widget.Label
	cmd            *exec.Cmd
	isRunning      bool
	clientID       string
	outputMutex    sync.Mutex
	config         NymSocks5Config
	isSocks5Client bool
	appRef         *CombinedApp
}

type CombinedApp struct {
	app            fyne.App
	window         fyne.Window
	socks5Panel    *ClientPanel
	isDarkTheme    bool
	themeSwitch    *widget.Button
	infoBtn        *widget.Button
	configBtn      *widget.Button
	deleteNymOnClose bool
}

func generateRandomID(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

func getNymSocks5ClientPath() (string, error) {
	nymClientName := "nym-socks5-client"
	if runtime.GOOS == "windows" {
		nymClientName = "nym-socks5-client.exe"
	}

	if _, err := os.Stat(nymClientName); err == nil {
		return filepath.Abs(nymClientName)
	}

	if path, err := exec.LookPath(nymClientName); err == nil {
		return path, nil
	}

	if runtime.GOOS == "windows" {
		if _, err := os.Stat("nym-socks5-client"); err == nil {
			return filepath.Abs("nym-socks5-client")
		}
	}

	return "", fmt.Errorf("nym-socks5-client not found in current directory or PATH")
}

func getNymDataDir() (string, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("failed to get home directory: %v", err)
	}
	return filepath.Join(homeDir, ".nym"), nil
}

func DeleteFileSafely(filePath string, passes int) error {
	file, err := os.OpenFile(filePath, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer file.Close()

	stat, err := file.Stat()
	if err != nil {
		return err
	}
	size := stat.Size()
	if size == 0 {
		return os.Remove(filePath)
	}

	for pass := 0; pass < passes; pass++ {
		file.Seek(0, 0)

		var pattern []byte
		switch pass % 3 {
		case 0:
			pattern = make([]byte, 4096)
			rand.Read(pattern)
		case 1:
			pattern = make([]byte, 4096)
			for i := range pattern {
				pattern[i] = 0xFF
			}
		case 2:
			pattern = make([]byte, 4096)
			for i := range pattern {
				if i%2 == 0 {
					pattern[i] = 0xAA
				} else {
					pattern[i] = 0x55
				}
			}
		}

		remaining := size
		for remaining > 0 {
			toWrite := int64(len(pattern))
			if toWrite > remaining {
				toWrite = remaining
			}
			if _, err := file.Write(pattern[:toWrite]); err != nil {
				return err
			}
			remaining -= toWrite
		}
		file.Sync()
	}

	file.Close()

	if runtime.GOOS != "windows" {
		tempName := filePath + ".deleted"
		os.Rename(filePath, tempName)
		filePath = tempName
	}

	return os.Remove(filePath)
}

func DeleteDirectorySafely(dirPath string, passes int) error {
	err := filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if !info.IsDir() {
			criticalExtensions := []string{".pem", ".key", ".nym_address", "config", "database"}
			shouldWipe := false
			for _, ext := range criticalExtensions {
				if strings.Contains(path, ext) {
					shouldWipe = true
					break
				}
			}
			if shouldWipe {
				if err := DeleteFileSafely(path, passes); err != nil {
					os.Remove(path)
				}
			} else {
				if err := DeleteFileSafely(path, 1); err != nil {
					os.Remove(path)
				}
			}
		}
		return nil
	})
	if err != nil {
		return err
	}

	for i := 0; i < 5; i++ {
		err = os.RemoveAll(dirPath)
		if err == nil {
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return err
}

func deleteSpecificSocks5Client(clientID string) error {
	nymDataDir, err := getNymDataDir()
	if err != nil {
		return err
	}
	clientDir := filepath.Join(nymDataDir, "socks5-clients", clientID)
	if _, err := os.Stat(clientDir); os.IsNotExist(err) {
		return nil
	}

	err = DeleteDirectorySafely(clientDir, 3)
	if err != nil {
		time.Sleep(100 * time.Millisecond)
		err = os.RemoveAll(clientDir)
	}
	return err
}

func stopProcess(cmd *exec.Cmd) {
	if cmd == nil || cmd.Process == nil {
		return
	}
	if runtime.GOOS == "windows" {
		taskkill := exec.Command("taskkill", "/PID", fmt.Sprintf("%d", cmd.Process.Pid))
		taskkill.SysProcAttr = getSysProcAttr()
		if err := taskkill.Run(); err == nil {
			done := make(chan bool)
			go func() {
				cmd.Wait()
				done <- true
			}()

			select {
			case <-done:
				return
			case <-time.After(3 * time.Second):
			}
		}

		forceKill := exec.Command("taskkill", "/F", "/PID", fmt.Sprintf("%d", cmd.Process.Pid), "/T")
		forceKill.SysProcAttr = getSysProcAttr()
		forceKill.Run()
	} else {
		cmd.Process.Signal(syscall.SIGTERM)
	}
}

func (p *ClientPanel) appendToOutput(text string) {
	fyne.Do(func() {
		defer func() {
			if r := recover(); r != nil {
				fmt.Printf("Recovered from panic in appendToOutput (%s): %v\n", p.name, r)
			}
		}()

		cleanText := stripANSI(text)

		p.outputMutex.Lock()
		defer p.outputMutex.Unlock()

		p.outputRich.Segments = append(p.outputRich.Segments, &widget.TextSegment{
			Style: widget.RichTextStyle{
				TextStyle: fyne.TextStyle{Monospace: true},
				ColorName: theme.ColorNameForeground,
				Inline:    true,
			},
			Text: cleanText + "\n",
		})

		if len(p.outputRich.Segments) > maxOutputLines {
			p.outputRich.Segments = append(
				p.outputRich.Segments[:1],
				p.outputRich.Segments[len(p.outputRich.Segments)-maxOutputLines+1:]...,
			)
		}

		p.outputRich.Refresh()

		if p.outputScroll != nil {
			contentHeight := p.outputRich.MinSize().Height
			viewportHeight := p.outputScroll.Size().Height
			if contentHeight > viewportHeight {
				p.outputScroll.Offset.Y = contentHeight - viewportHeight
				p.outputScroll.Refresh()
			}
		}
	})
}

func (p *ClientPanel) updateStatus(status string) {
	fyne.Do(func() {
		p.statusLabel.SetText(status)
		p.statusLabel.Refresh()
	})
}

func (c *CombinedApp) loadConfig() error {
	file, err := os.Open(CONFIG_FILE)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	defer file.Close()

	data, err := io.ReadAll(file)
	if err != nil {
		return err
	}

	var config NymSocks5Config
	if err := json.Unmarshal(data, &config); err != nil {
		return err
	}

	c.socks5Panel.config = config
	return nil
}

func (c *CombinedApp) reloadConfig() error {
	file, err := os.Open(CONFIG_FILE)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	defer file.Close()

	data, err := io.ReadAll(file)
	if err != nil {
		return err
	}

	var config NymSocks5Config
	if err := json.Unmarshal(data, &config); err != nil {
		return err
	}

	c.socks5Panel.config = config
	return nil
}

func (c *CombinedApp) saveConfig() error {
	data, err := json.MarshalIndent(c.socks5Panel.config, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(CONFIG_FILE, data, 0644)
}

func (c *CombinedApp) showConfigDialog() {
	providerEntry := widget.NewEntry()
	providerEntry.SetText(c.socks5Panel.config.ProviderAddress)
	providerEntry.PlaceHolder = "Enter Nym provider address"

	anonCheck := widget.NewCheck("Use Anonymous Replies (SURBs)", func(checked bool) {
		c.socks5Panel.config.UseAnonymousReplies = checked
	})
	anonCheck.SetChecked(c.socks5Panel.config.UseAnonymousReplies)

	formItems := []*widget.FormItem{
		{Text: "Provider Address", Widget: providerEntry},
		{Text: "", Widget: anonCheck},
	}

	saveBtn := widget.NewButtonWithIcon("Save", theme.ConfirmIcon(), func() {
		address := providerEntry.Text
		if address == "" {
			dialog.ShowInformation("Error", "Provider address cannot be empty!", c.window)
			return
		}

		c.socks5Panel.config.ProviderAddress = address
		c.socks5Panel.config.UseAnonymousReplies = anonCheck.Checked
		if err := c.saveConfig(); err != nil {
			dialog.ShowError(fmt.Errorf("failed to save configuration: %v", err), c.window)
			return
		}

		c.socks5Panel.appendToOutput("Provider address saved: " + address)
		if anonCheck.Checked {
			c.socks5Panel.appendToOutput("Anonymous replies mode ENABLED (SURBs)")
		} else {
			c.socks5Panel.appendToOutput("Anonymous replies mode DISABLED")
		}

		if overlays := c.window.Canvas().Overlays(); overlays.Top() != nil {
			overlays.Remove(overlays.Top())
		}
		dialog.ShowInformation("Success", "Configuration saved successfully!", c.window)
	})
	saveBtn.Importance = widget.HighImportance

	cancelBtn := widget.NewButtonWithIcon("Cancel", theme.CancelIcon(), func() {
		if overlays := c.window.Canvas().Overlays(); overlays.Top() != nil {
			overlays.Remove(overlays.Top())
		}
	})
	cancelBtn.Importance = widget.HighImportance

	buttons := container.NewHBox(layout.NewSpacer(), saveBtn, cancelBtn, layout.NewSpacer())

	content := container.NewVBox(
		widget.NewLabelWithStyle("Configure Nym Network Requester", fyne.TextAlignCenter, fyne.TextStyle{Bold: true}),
		widget.NewSeparator(),
		widget.NewLabel("Enter the Nym address of the network requester you want to connect to."),
		widget.NewSeparator(),
		widget.NewForm(formItems...),
		widget.NewLabel("When SURBs are enabled, your Nym address will NOT be sent to the provider."),
		widget.NewLabel("Requires provider SURB support."),
		widget.NewSeparator(),
		buttons,
	)

	dialog.ShowCustomWithoutButtons("", content, c.window)
}

func (p *ClientPanel) clearSensitiveData() {
	p.clientID = ""
}

func (p *ClientPanel) cleanupSystemTempFiles() {
	tempDirs := []string{os.TempDir()}
	if runtime.GOOS == "windows" {
		if userTemp := os.Getenv("TEMP"); userTemp != "" {
			tempDirs = append(tempDirs, userTemp)
		}
	}
	for _, tempDir := range tempDirs {
		pattern := filepath.Join(tempDir, "*nym*")
		if matches, err := filepath.Glob(pattern); err == nil {
			for _, match := range matches {
				if info, err := os.Stat(match); err == nil && !info.IsDir() {
					DeleteFileSafely(match, 1)
				}
			}
		}
	}
}

func (p *ClientPanel) startSocks5Client() {
	if p.isRunning {
		p.appendToOutput("Warning: Client is already running")
		return
	}

	if p.config.ProviderAddress == "" {
		p.appendToOutput("Error: No provider address configured.\nPlease click the Config button to set one.")
		return
	}

	go func() {
		defer func() {
			if r := recover(); r != nil {
				p.appendToOutput(fmt.Sprintf("PANIC in client goroutine: %v", r))
				p.updateStatus("Error")
			}
		}()

		p.updateStatus("Starting...")
		p.appendToOutput("=== Nym SOCKS5 Client Ephemeral Session ===")
		p.appendToOutput("")
		p.appendToOutput("NOTE: Only this session's client data will be deleted")
		p.appendToOutput("      Other client IDs in socks5-clients folder remain intact")
		p.appendToOutput("")

		if p.config.UseAnonymousReplies {
			p.appendToOutput("   ANONYMOUS REPLIES MODE ENABLED (SURBs)")
			p.appendToOutput("   Your Nym address will NOT be sent to the provider")
			p.appendToOutput("   Requires provider SURB support")
		} else {
			p.appendToOutput("   STANDARD MODE (no SURBs)")
			p.appendToOutput("   Your Nym address will be visible to the provider")
		}
		p.appendToOutput("")

		nymClientPath, err := getNymSocks5ClientPath()
		if err != nil {
			p.appendToOutput(fmt.Sprintf("Error: %v", err))
			p.updateStatus("Error")
			return
		}
		p.appendToOutput(fmt.Sprintf("Found nym-socks5-client at: %s", nymClientPath))

		clientID, err := generateRandomID(16)
		if err != nil {
			p.appendToOutput(fmt.Sprintf("Failed to generate random ID: %v", err))
			p.updateStatus("Error")
			return
		}
		p.clientID = clientID
		p.appendToOutput(fmt.Sprintf("Generated ephemeral client ID: %s", clientID))

		p.appendToOutput("")
		p.appendToOutput("--- Pre-run cleanup ---")

		nymDataDir, err := getNymDataDir()
		if err == nil {
			clientDir := filepath.Join(nymDataDir, "socks5-clients", clientID)
			if _, err := os.Stat(clientDir); err == nil {
				if err := DeleteDirectorySafely(clientDir, 3); err != nil {
					p.appendToOutput(fmt.Sprintf("  Warning: Failed to clean up existing client data: %v", err))
				} else {
					p.appendToOutput("  Cleaned up existing client data for this ID")
				}
			} else {
				p.appendToOutput("  No existing client data for this ID")
			}
		}

		p.appendToOutput("")
		p.appendToOutput("--- Initializing client ---")
		p.appendToOutput(fmt.Sprintf("Using provider: %s", p.config.ProviderAddress))

		initArgs := []string{"init", "--id", clientID, "--provider", p.config.ProviderAddress}
		if p.config.UseAnonymousReplies {
			initArgs = append(initArgs, "--use-reply-surbs", "true")
			p.appendToOutput("Adding flag: --use-reply-surbs true")
		}

		initCmd := exec.Command(nymClientPath, initArgs...)
		initCmd.SysProcAttr = getSysProcAttr()
		initOutput, err := initCmd.CombinedOutput()
		if err != nil {
			p.appendToOutput(fmt.Sprintf("Failed to initialize client: %v\nOutput: %s", err, string(initOutput)))
			p.updateStatus("Error")
			return
		}
		p.appendToOutput(string(initOutput))

		p.appendToOutput("")
		p.appendToOutput(fmt.Sprintf("--- Running SOCKS5 client (ID: %s) ---", clientID))
		p.appendToOutput("SOCKS5 proxy will be available at 127.0.0.1:1080")
		p.appendToOutput("Press Stop button to stop the client")
		p.appendToOutput("")

		runArgs := []string{"run", "--id", clientID}
		if p.config.UseAnonymousReplies {
			runArgs = append(runArgs, "--use-anonymous-replies", "true")
			p.appendToOutput("Adding flag: --use-anonymous-replies true")
		}

		runCmd := exec.Command(nymClientPath, runArgs...)
		runCmd.SysProcAttr = getSysProcAttr()

		stdout, err := runCmd.StdoutPipe()
		if err != nil {
			p.appendToOutput(fmt.Sprintf("Failed to capture stdout: %v", err))
			p.updateStatus("Error")
			return
		}
		stderr, err := runCmd.StderrPipe()
		if err != nil {
			p.appendToOutput(fmt.Sprintf("Failed to capture stderr: %v", err))
			p.updateStatus("Error")
			return
		}

		if err := runCmd.Start(); err != nil {
			p.appendToOutput(fmt.Sprintf("Failed to start client: %v", err))
			p.updateStatus("Error")
			return
		}

		p.cmd = runCmd
		p.isRunning = true

		if p.config.UseAnonymousReplies {
			p.updateStatus("Running (Anonymous)")
		} else {
			p.updateStatus("Running")
		}

		go func() {
			scanner := bufio.NewScanner(stdout)
			for scanner.Scan() {
				p.appendToOutput(scanner.Text())
			}
		}()

		go func() {
			scanner := bufio.NewScanner(stderr)
			for scanner.Scan() {
				p.appendToOutput(scanner.Text())
			}
		}()

		err = runCmd.Wait()
		p.isRunning = false

		if err != nil {
			if exitErr, ok := err.(*exec.ExitError); ok {
				p.appendToOutput(fmt.Sprintf("Client exited with code: %d", exitErr.ExitCode()))
				if runtime.GOOS != "windows" {
					if status, ok := exitErr.Sys().(syscall.WaitStatus); ok {
						if status.Signaled() {
							p.appendToOutput(fmt.Sprintf("Terminated by signal: %d", status.Signal()))
						}
					}
				}
			} else {
				p.appendToOutput(fmt.Sprintf("Client stopped with error: %v", err))
			}
		} else {
			p.appendToOutput("")
			p.appendToOutput("Client stopped normally")
		}

		p.appendToOutput("")
		p.appendToOutput("--- Post-run cleanup ---")

		if err := deleteSpecificSocks5Client(clientID); err != nil {
			p.appendToOutput(fmt.Sprintf("  Warning during cleanup: %v", err))
		} else {
			p.appendToOutput("Client data deleted (ephemeral session complete)")
		}

		p.cleanupSystemTempFiles()
		p.clearSensitiveData()

		p.appendToOutput("")
		p.appendToOutput("--- Ephemeral session complete ---")
		p.appendToOutput("Client data has been removed from disk")
		p.updateStatus("Stopped")
	}()
}

func (p *ClientPanel) stopClient() {
	if !p.isRunning {
		p.appendToOutput("Warning: No client is running")
		return
	}

	p.appendToOutput("")
	p.appendToOutput("Stopping client...")

	clientID := p.clientID

	stopProcess(p.cmd)
	p.updateStatus("Stopping...")

	go func() {
		time.Sleep(2 * time.Second)

		if p.isRunning && p.cmd != nil && p.cmd.Process != nil {
			if runtime.GOOS == "windows" {
				forceKill := exec.Command("taskkill", "/F", "/PID", fmt.Sprintf("%d", p.cmd.Process.Pid))
				forceKill.SysProcAttr = getSysProcAttr()
				forceKill.Run()
			} else {
				p.cmd.Process.Kill()
			}
			p.appendToOutput("Client force killed")
			p.isRunning = false
		}

		p.appendToOutput(fmt.Sprintf("Deleting client data for ID: %s", clientID))
		if clientID != "" {
			time.Sleep(500 * time.Millisecond)
			if err := deleteSpecificSocks5Client(clientID); err != nil {
				p.appendToOutput(fmt.Sprintf("Warning: Failed to delete client data: %v", err))
			} else {
				p.appendToOutput("Client data deleted successfully")
			}
		} else {
			p.appendToOutput("Warning: No client ID to delete")
		}

		if p.appRef != nil {
			if err := p.appRef.reloadConfig(); err != nil {
				p.appendToOutput(fmt.Sprintf("Warning: Failed to reload config: %v", err))
			} else {
				p.appendToOutput("Configuration reloaded successfully")
			}
		}

		fyne.Do(func() {
			dialog.ShowConfirm("Delete .nym folder?",
				"Do you want to delete the entire .nym folder (including all client data) when the wrapper closes?\n\nThis is recommended for public/Internet café use.",
				func(confirmed bool) {
					p.appRef.deleteNymOnClose = confirmed
					if confirmed {
						p.appendToOutput("")
						p.appendToOutput("Note: .nym folder will be deleted when wrapper closes")
					} else {
						p.appendToOutput("")
						p.appendToOutput("Note: .nym folder will NOT be deleted when wrapper closes")
					}
				},
				p.appRef.window,
			)
		})

		p.updateStatus("Stopped")
	}()
}

func (c *CombinedApp) toggleTheme() {
	fyne.Do(func() {
		c.isDarkTheme = !c.isDarkTheme
		c.themeSwitch.SetText(map[bool]string{true: "🌙", false: "☀️"}[c.isDarkTheme])

		var baseTheme fyne.Theme
		if c.isDarkTheme {
			baseTheme = theme.DarkTheme()
		} else {
			baseTheme = theme.LightTheme()
		}

		oliveTheme := &oliveThemeWrapper{
			base: baseTheme,
		}
		c.app.Settings().SetTheme(oliveTheme)
		c.window.Content().Refresh()
	})
}

func (c *CombinedApp) showInfoPopup() {
	projURL, _ := url.Parse("https://github.com/Ch1ffr3punk/nscw")
	projectLink := widget.NewHyperlink("An Open Source project", projURL)
	okButton := widget.NewButton("OK", func() {
		overlays := c.window.Canvas().Overlays()
		if overlays.Top() != nil {
			overlays.Remove(overlays.Top())
		}
	})
	okButton.Importance = widget.HighImportance
	content := container.NewVBox(
		widget.NewLabelWithStyle("Nym Socks5 Client Wrapper v0.1.0", fyne.TextAlignCenter, fyne.TextStyle{Bold: true}),
		widget.NewSeparator(),
		container.NewHBox(layout.NewSpacer(), projectLink, layout.NewSpacer()),
		widget.NewLabelWithStyle("released under the Apache 2.0 license", fyne.TextAlignCenter, fyne.TextStyle{}),
		widget.NewLabelWithStyle("2026 Ch1ffr3punk", fyne.TextAlignCenter, fyne.TextStyle{}),
		container.NewHBox(layout.NewSpacer(), okButton, layout.NewSpacer()),
	)
	dialog.ShowCustomWithoutButtons("", content, c.window)
}

func createClientPanel(title string, isSocks5 bool, config NymSocks5Config, appRef *CombinedApp) *ClientPanel {
	outputRich := widget.NewRichText()
	outputRich.Wrapping = fyne.TextWrapWord
	outputRich.Segments = []widget.RichTextSegment{
		&widget.TextSegment{
			Style: widget.RichTextStyle{
				TextStyle: fyne.TextStyle{Monospace: true},
				ColorName: theme.ColorNameForeground,
			},
			Text: "Ready",
		},
	}
	outputScroll := container.NewScroll(outputRich)

	statusLabel := widget.NewLabel("Ready")
	statusLabel.TextStyle = fyne.TextStyle{Bold: true}

	panel := &ClientPanel{
		name:           title,
		outputRich:     outputRich,
		outputScroll:   outputScroll,
		statusLabel:    statusLabel,
		isRunning:      false,
		isSocks5Client: isSocks5,
		config:         config,
		appRef:         appRef,
	}

	panel.startBtn = widget.NewButton("Start", func() {
		if !panel.isRunning {
			if isSocks5 {
				go panel.startSocks5Client()
			}
		}
	})
	panel.startBtn.Importance = widget.HighImportance

	panel.stopBtn = widget.NewButton("Stop", func() {
		if panel.isRunning {
			go panel.stopClient()
		}
	})
	panel.stopBtn.Importance = widget.HighImportance

	return panel
}

func (c *CombinedApp) setupUI() {
	c.socks5Panel = createClientPanel("nym-socks5-client wrapper", true, NymSocks5Config{}, c)

	if err := c.loadConfig(); err != nil {
		fmt.Printf("Warning: Failed to load config: %v\n", err)
	}

	socks5Header := container.NewVBox(
		widget.NewLabelWithStyle(c.socks5Panel.name, fyne.TextAlignCenter, fyne.TextStyle{Bold: true}),
	)
	socks5Buttons := container.NewHBox(layout.NewSpacer(), c.socks5Panel.startBtn, c.socks5Panel.stopBtn, layout.NewSpacer())
	socks5Status := container.NewHBox(widget.NewLabel("Status: "), c.socks5Panel.statusLabel, layout.NewSpacer())
	socks5Content := container.NewBorder(
		container.NewVBox(socks5Header, socks5Buttons),
		socks5Status,
		nil, nil,
		c.socks5Panel.outputScroll,
	)

	c.configBtn = widget.NewButtonWithIcon("", theme.SettingsIcon(), c.showConfigDialog)
	c.configBtn.Importance = widget.LowImportance

	c.infoBtn = widget.NewButtonWithIcon("", theme.InfoIcon(), c.showInfoPopup)
	c.infoBtn.Importance = widget.LowImportance

	c.themeSwitch = widget.NewButton("☀️", c.toggleTheme)
	c.themeSwitch.Importance = widget.LowImportance

	globalTopBar := container.NewHBox(
		c.configBtn,
		layout.NewSpacer(),
		c.infoBtn,
		layout.NewSpacer(),
		c.themeSwitch,
	)

	content := container.NewBorder(container.NewVBox(globalTopBar), nil, nil, nil, socks5Content)
	c.window.SetContent(content)
}

func (c *CombinedApp) onWindowClosed() {
	if c.socks5Panel.isRunning {
		stopProcess(c.socks5Panel.cmd)
		time.Sleep(500 * time.Millisecond)
		if c.socks5Panel.clientID != "" {
			deleteSpecificSocks5Client(c.socks5Panel.clientID)
		}
	}

	if c.deleteNymOnClose {
		nymDataDir, err := getNymDataDir()
		if err == nil {
			if _, err := os.Stat(nymDataDir); err == nil {
				DeleteDirectorySafely(nymDataDir, 3)
			}
		}
	}
}

func main() {
	myApp := app.New()
	window := myApp.NewWindow("NSCW")

	myApp.Settings().SetTheme(&oliveThemeWrapper{
		base: theme.DarkTheme(),
	})

	combined := &CombinedApp{
		app:            myApp,
		window:         window,
		isDarkTheme:    true,
		deleteNymOnClose: false,
	}

	combined.setupUI()
	window.SetCloseIntercept(func() {
		combined.onWindowClosed()
		window.Close()
	})

	window.Resize(fyne.NewSize(600, 480))
	window.ShowAndRun()
}
