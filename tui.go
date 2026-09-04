package main

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"charm.land/bubbles/v2/key"
	"charm.land/bubbles/v2/list"
	"charm.land/bubbles/v2/textinput"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
)

const (
	managerDefaultWidth  = 80
	managerDefaultHeight = 24
	managerFieldCount    = 5
)

type managerScreen uint8

const (
	managerListScreen managerScreen = iota
	managerActionScreen
	managerBackendScreen
	managerEditorScreen
	managerSaveConfirmScreen
	managerDeleteConfirmScreen
)

type managerItemKind uint8

const (
	managerCredentialItem managerItemKind = iota
	managerAddItem
	managerQuitItem
)

type managerListItem struct {
	kind        managerItemKind
	record      credentialRecord
	title       string
	description string
}

func (i managerListItem) Title() string       { return i.title }
func (i managerListItem) Description() string { return i.description }
func (i managerListItem) FilterValue() string { return i.title + " " + i.description }

type credentialManagerModel struct {
	stores []managedCredentialStore

	screen managerScreen
	list   list.Model
	width  int
	height int

	selectedRecord credentialRecord
	menuIndex      int
	backendIndex   int

	editorInputs   []textinput.Model
	editorField    int
	editorCreating bool
	editorStore    managedCredentialStore
	editorError    string

	pendingListStatus string
}

var (
	managerTitleStyle = lipgloss.NewStyle().
				Bold(true).
				Foreground(lipgloss.Color("205"))
	managerSubtitleStyle = lipgloss.NewStyle().
				Foreground(lipgloss.Color("241"))
	managerSelectedStyle = lipgloss.NewStyle().
				Bold(true).
				Foreground(lipgloss.Color("212"))
	managerErrorStyle = lipgloss.NewStyle().
				Foreground(lipgloss.Color("196"))
	managerWarningStyle = lipgloss.NewStyle().
				Foreground(lipgloss.Color("214"))
	managerHelpStyle = lipgloss.NewStyle().
				Foreground(lipgloss.Color("241"))
)

func runCredentialManager(stores []managedCredentialStore, startupWarnings ...error) error {
	if len(stores) == 0 && len(startupWarnings) > 0 {
		return fmt.Errorf("no credential storage backend is available: %w", errors.Join(startupWarnings...))
	}
	model, err := newCredentialManagerModel(stores)
	if err != nil {
		return err
	}
	if len(startupWarnings) > 0 {
		warning := safeErrorText(errors.Join(startupWarnings...))
		if model.pendingListStatus != "" {
			model.pendingListStatus += " Warning: " + warning
		} else {
			model.pendingListStatus = "Warning: " + warning
		}
	}
	defer model.clearEditor()

	_, err = tea.NewProgram(
		model,
		tea.WithInput(os.Stdin),
		tea.WithOutput(os.Stderr),
	).Run()
	if errors.Is(err, tea.ErrInterrupted) {
		return nil
	}
	return err
}

func newCredentialManagerModel(stores []managedCredentialStore) (*credentialManagerModel, error) {
	if len(stores) == 0 {
		return nil, errors.New("no credential storage backend is configured")
	}

	delegate := list.NewDefaultDelegate()
	delegate.SetSpacing(0)
	credentialList := list.New(nil, delegate, managerDefaultWidth, managerDefaultHeight)
	credentialList.Title = "Git credential manager"
	credentialList.SetStatusBarItemName("entry", "entries")
	credentialList.StatusMessageLifetime = 5 * time.Second
	credentialList.KeyMap.Quit = key.NewBinding(
		key.WithKeys("q"),
		key.WithHelp("q", "quit"),
	)
	credentialList.AdditionalShortHelpKeys = func() []key.Binding {
		return []key.Binding{
			key.NewBinding(key.WithKeys("enter"), key.WithHelp("enter", "open")),
		}
	}

	model := &credentialManagerModel{
		stores: stores,
		screen: managerListScreen,
		list:   credentialList,
		width:  managerDefaultWidth,
		height: managerDefaultHeight,
	}
	model.pendingListStatus = model.reloadCredentialList()
	return model, nil
}

func (m *credentialManagerModel) Init() tea.Cmd {
	return m.showPendingListStatus()
}

func (m *credentialManagerModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = max(msg.Width, 1)
		m.height = max(msg.Height, 1)
		m.list.SetSize(m.width, m.height)
		m.resizeEditorInputs()
		return m, nil
	case tea.InterruptMsg:
		m.clearEditor()
		return m, tea.Quit
	case tea.KeyPressMsg:
		if msg.String() == "ctrl+c" {
			m.clearEditor()
			return m, tea.Quit
		}
	}

	switch m.screen {
	case managerListScreen:
		return m.updateList(msg)
	case managerActionScreen:
		return m.updateActionMenu(msg)
	case managerBackendScreen:
		return m.updateBackendMenu(msg)
	case managerEditorScreen:
		return m.updateEditor(msg)
	case managerSaveConfirmScreen:
		return m.updateSaveConfirmation(msg)
	case managerDeleteConfirmScreen:
		return m.updateDeleteConfirmation(msg)
	default:
		m.screen = managerListScreen
		return m, nil
	}
}

func (m *credentialManagerModel) View() tea.View {
	var content string
	switch m.screen {
	case managerListScreen:
		content = m.list.View()
	case managerActionScreen:
		content = m.viewActionMenu()
	case managerBackendScreen:
		content = m.viewBackendMenu()
	case managerEditorScreen:
		content = m.viewEditor()
	case managerSaveConfirmScreen:
		content = m.viewSaveConfirmation()
	case managerDeleteConfirmScreen:
		content = m.viewDeleteConfirmation()
	default:
		content = managerErrorStyle.Render("Invalid credential manager state")
	}

	view := tea.NewView(content)
	view.AltScreen = true
	return view
}

func (m *credentialManagerModel) updateList(msg tea.Msg) (tea.Model, tea.Cmd) {
	if keyMsg, ok := msg.(tea.KeyPressMsg); ok && keyMsg.String() == "enter" && !m.list.SettingFilter() {
		selected, ok := m.list.SelectedItem().(managerListItem)
		if !ok {
			return m, nil
		}

		switch selected.kind {
		case managerAddItem:
			m.screen = managerBackendScreen
			m.backendIndex = m.preferredBackendIndex()
			m.menuIndex = 0
			return m, nil
		case managerQuitItem:
			return m, tea.Quit
		case managerCredentialItem:
			m.selectedRecord = selected.record
			m.screen = managerActionScreen
			m.menuIndex = 0
			return m, nil
		}
	}

	var cmd tea.Cmd
	m.list, cmd = m.list.Update(msg)
	return m, cmd
}

func (m *credentialManagerModel) updateActionMenu(msg tea.Msg) (tea.Model, tea.Cmd) {
	keyName, ok := managerKeyName(msg)
	if !ok {
		return m, nil
	}

	switch keyName {
	case "up", "k", "shift+tab":
		m.menuIndex = previousMenuIndex(m.menuIndex, 3)
	case "down", "j", "tab":
		m.menuIndex = nextMenuIndex(m.menuIndex, 3)
	case "esc", "q":
		m.screen = managerListScreen
		return m, nil
	case "enter":
		switch m.menuIndex {
		case 0:
			value := normalizeCredentialForStorage(m.selectedRecord.credential)
			if err := validateCredentialForStorage(value, false); err != nil {
				m.editorError = safeErrorText(fmt.Errorf("cannot safely edit this legacy entry: %w", err))
				return m, nil
			}
			store := m.store(m.selectedRecord.backend)
			if store == nil {
				m.editorError = "Credential backend is unavailable."
				return m, nil
			}
			return m, m.openEditor(value, false, store)
		case 1:
			m.screen = managerDeleteConfirmScreen
			m.menuIndex = 1 // Default to Cancel; deletion must be deliberate.
			m.editorError = ""
			return m, nil
		case 2:
			m.screen = managerListScreen
			return m, nil
		}
	}
	return m, nil
}

func (m *credentialManagerModel) updateBackendMenu(msg tea.Msg) (tea.Model, tea.Cmd) {
	keyName, ok := managerKeyName(msg)
	if !ok {
		return m, nil
	}

	switch keyName {
	case "up", "k", "shift+tab":
		m.backendIndex = previousMenuIndex(m.backendIndex, len(m.stores))
	case "down", "j", "tab":
		m.backendIndex = nextMenuIndex(m.backendIndex, len(m.stores))
	case "esc", "q":
		m.screen = managerListScreen
	case "enter":
		if m.backendIndex < 0 || m.backendIndex >= len(m.stores) {
			return m, nil
		}
		return m, m.openEditor(credential{protocol: "https"}, true, m.stores[m.backendIndex])
	}
	return m, nil
}

func (m *credentialManagerModel) updateEditor(msg tea.Msg) (tea.Model, tea.Cmd) {
	keyName, isKey := managerKeyName(msg)
	if isKey {
		switch keyName {
		case "esc":
			creating := m.editorCreating
			m.clearEditor()
			if creating {
				m.screen = managerBackendScreen
			} else {
				m.screen = managerActionScreen
			}
			return m, nil
		case "up", "shift+tab":
			return m, m.focusEditorField(previousMenuIndex(m.editorField, managerFieldCount))
		case "down", "tab":
			if err := m.validateEditorField(m.editorField); err != nil {
				m.editorError = safeErrorText(err)
				return m, nil
			}
			return m, m.focusEditorField(nextMenuIndex(m.editorField, managerFieldCount))
		case "enter":
			if err := m.validateEditorField(m.editorField); err != nil {
				m.editorError = safeErrorText(err)
				return m, nil
			}
			if m.editorField < managerFieldCount-1 {
				return m, m.focusEditorField(m.editorField + 1)
			}
			return m, m.prepareSave()
		case "ctrl+s":
			return m, m.prepareSave()
		}
	}

	if m.editorField < 0 || m.editorField >= len(m.editorInputs) {
		return m, nil
	}
	oldValue := m.editorInputs[m.editorField].Value()
	var cmd tea.Cmd
	m.editorInputs[m.editorField], cmd = m.editorInputs[m.editorField].Update(msg)
	if err := validateEditorInputSafety(m.editorField, m.editorInputs[m.editorField].Value()); err != nil {
		m.editorInputs[m.editorField].SetValue(oldValue)
		m.editorError = safeErrorText(err)
		return m, cmd
	}
	if isKey {
		m.editorError = ""
	}
	return m, cmd
}

func (m *credentialManagerModel) updateSaveConfirmation(msg tea.Msg) (tea.Model, tea.Cmd) {
	keyName, ok := managerKeyName(msg)
	if !ok {
		return m, nil
	}

	switch keyName {
	case "left", "up", "h", "k", "shift+tab":
		m.menuIndex = previousMenuIndex(m.menuIndex, 2)
	case "right", "down", "l", "j", "tab":
		m.menuIndex = nextMenuIndex(m.menuIndex, 2)
	case "esc", "n":
		m.screen = managerEditorScreen
		m.menuIndex = 0
		return m, m.focusEditorField(m.editorField)
	case "y":
		m.menuIndex = 0
		return m, m.saveEditor()
	case "enter":
		if m.menuIndex == 0 {
			return m, m.saveEditor()
		}
		m.screen = managerEditorScreen
		m.menuIndex = 0
		return m, m.focusEditorField(m.editorField)
	}
	return m, nil
}

func (m *credentialManagerModel) updateDeleteConfirmation(msg tea.Msg) (tea.Model, tea.Cmd) {
	keyName, ok := managerKeyName(msg)
	if !ok {
		return m, nil
	}

	switch keyName {
	case "left", "up", "h", "k", "shift+tab":
		m.menuIndex = previousMenuIndex(m.menuIndex, 2)
	case "right", "down", "l", "j", "tab":
		m.menuIndex = nextMenuIndex(m.menuIndex, 2)
	case "esc", "n":
		m.screen = managerActionScreen
		m.menuIndex = 1
	case "enter":
		if m.menuIndex == 1 {
			m.screen = managerActionScreen
			m.menuIndex = 1
			return m, nil
		}
		store := m.store(m.selectedRecord.backend)
		if store == nil {
			m.editorError = "Credential backend is unavailable."
			m.screen = managerActionScreen
			return m, nil
		}
		if err := store.Delete(m.selectedRecord); err != nil {
			if errors.Is(err, errCredentialChanged) {
				m.pendingListStatus = "Credential storage changed concurrently; the list was reloaded."
				if warning := m.reloadCredentialList(); warning != "" {
					m.pendingListStatus += " Warning: " + warning
				}
				m.screen = managerListScreen
				return m, m.showPendingListStatus()
			}
			m.editorError = safeErrorText(fmt.Errorf("delete credential from %s: %w", store.DisplayName(), err))
			m.screen = managerActionScreen
			return m, nil
		}
		m.pendingListStatus = "Deleted " + displayCredential(m.selectedRecord.credential) + "."
		if warning := m.reloadCredentialList(); warning != "" {
			m.pendingListStatus += " Warning: " + warning
		}
		m.screen = managerListScreen
		return m, m.showPendingListStatus()
	}
	return m, nil
}

func (m *credentialManagerModel) openEditor(initial credential, creating bool, store managedCredentialStore) tea.Cmd {
	m.clearEditor()
	m.editorInputs = newCredentialEditorInputs(initial, creating)
	m.editorField = 0
	m.editorCreating = creating
	m.editorStore = store
	m.editorError = ""
	m.screen = managerEditorScreen
	m.resizeEditorInputs()
	return m.editorInputs[0].Focus()
}

func newCredentialEditorInputs(initial credential, creating bool) []textinput.Model {
	values := []string{initial.protocol, initial.host, initial.path, initial.username, ""}
	placeholders := []string{
		"https",
		"github.com or git.example.com:8443",
		"organization/repository.git (optional)",
		"Git credential username",
		"Password or personal access token",
	}

	inputs := make([]textinput.Model, managerFieldCount)
	for i := range inputs {
		inputs[i] = textinput.New()
		inputs[i].Prompt = "> "
		inputs[i].Placeholder = placeholders[i]
		inputs[i].CharLimit = maxCredentialFieldBytes
		inputs[i].SetValue(values[i])
	}
	inputs[4].EchoMode = textinput.EchoPassword
	if !creating {
		inputs[4].Placeholder = "Leave blank to keep the current secret"
	}
	return inputs
}

func (m *credentialManagerModel) focusEditorField(index int) tea.Cmd {
	if len(m.editorInputs) != managerFieldCount {
		return nil
	}
	if m.editorField >= 0 && m.editorField < len(m.editorInputs) {
		m.editorInputs[m.editorField].Blur()
	}
	m.editorField = index
	m.editorError = ""
	return m.editorInputs[m.editorField].Focus()
}

func (m *credentialManagerModel) prepareSave() tea.Cmd {
	value, err := m.validatedEditorCredential()
	if err != nil {
		m.editorError = safeErrorText(err)
		return nil
	}
	for i := range m.editorInputs {
		m.editorInputs[i].Blur()
	}
	// Keep the validated, normalized non-secret fields visible in confirmation.
	m.editorInputs[0].SetValue(value.protocol)
	m.editorInputs[1].SetValue(value.host)
	m.editorInputs[2].SetValue(value.path)
	m.editorInputs[3].SetValue(value.username)
	m.screen = managerSaveConfirmScreen
	m.menuIndex = 0
	m.editorError = ""
	return nil
}

func (m *credentialManagerModel) saveEditor() tea.Cmd {
	value, err := m.validatedEditorCredential()
	if err != nil {
		m.editorError = safeErrorText(err)
		m.screen = managerEditorScreen
		return m.focusEditorField(m.editorField)
	}
	if m.editorStore == nil {
		m.editorError = "Credential backend is unavailable."
		m.screen = managerEditorScreen
		return m.focusEditorField(m.editorField)
	}

	display := displayCredential(value)
	storeName := safeTerminalText(m.editorStore.DisplayName())
	storeBackend := m.editorStore.Backend()
	if m.editorCreating {
		err = m.editorStore.Add(value)
	} else {
		err = m.editorStore.Update(m.selectedRecord, value)
	}
	value.password = ""
	if err != nil {
		if !m.editorCreating && errors.Is(err, errCredentialChanged) {
			m.clearEditor()
			m.pendingListStatus = "Credential storage changed concurrently; the list was reloaded."
			if warning := m.reloadCredentialList(); warning != "" {
				m.pendingListStatus += " Warning: " + warning
			}
			m.screen = managerListScreen
			return m.showPendingListStatus()
		}
		action := "update"
		if m.editorCreating {
			action = "add"
		}
		m.editorError = safeErrorText(fmt.Errorf("%s credential in %s: %w", action, storeName, err))
		m.screen = managerEditorScreen
		return m.focusEditorField(m.editorField)
	}

	action := "Updated"
	if m.editorCreating {
		action = "Added"
	}
	m.clearEditor()
	m.pendingListStatus = fmt.Sprintf("%s %s in %s.", action, display, storeName)
	if storeBackend == keyringBackend {
		m.pendingListStatus += " Configure the helper with --backend keyring or --backend auto for Git lookups."
	}
	if warning := m.reloadCredentialList(); warning != "" {
		m.pendingListStatus += " Warning: " + warning
	}
	m.screen = managerListScreen
	return m.showPendingListStatus()
}

func (m *credentialManagerModel) editorCredential() credential {
	if len(m.editorInputs) != managerFieldCount {
		return credential{}
	}
	return credential{
		protocol: m.editorInputs[0].Value(),
		host:     m.editorInputs[1].Value(),
		path:     m.editorInputs[2].Value(),
		username: m.editorInputs[3].Value(),
		password: m.editorInputs[4].Value(),
	}
}

func (m *credentialManagerModel) validatedEditorCredential() (credential, error) {
	value := normalizeCredentialForStorage(m.editorCredential())
	if err := validateCredentialForStorage(value, m.editorCreating); err != nil {
		return credential{}, err
	}
	return value, nil
}

func (m *credentialManagerModel) validateEditorField(index int) error {
	value := m.editorCredential()
	switch index {
	case 0:
		return validateCredentialProtocol(value.protocol)
	case 1:
		return validateCredentialHost(value.protocol, value.host)
	case 2:
		return validateCredentialPath(value.path)
	case 3:
		return validateCredentialUsername(value.username)
	case 4:
		return validateCredentialPassword(value.password, m.editorCreating)
	default:
		return errors.New("invalid editor field")
	}
}

func (m *credentialManagerModel) clearEditor() {
	for i := range m.editorInputs {
		m.editorInputs[i].SetValue("")
		m.editorInputs[i].Blur()
	}
	m.editorInputs = nil
	m.editorField = 0
	m.editorCreating = false
	m.editorStore = nil
	m.editorError = ""
}

func (m *credentialManagerModel) reloadCredentialList() string {
	items := make([]list.Item, 0)
	var listErrors []error
	for _, store := range m.stores {
		records, err := store.List()
		if err != nil {
			listErrors = append(listErrors, fmt.Errorf("list %s credentials: %w", store.DisplayName(), err))
		}
		for _, record := range records {
			record.credential.password = ""
			items = append(items, managerListItem{
				kind:        managerCredentialItem,
				record:      record,
				title:       displayCredential(record.credential),
				description: safeTerminalText(store.DisplayName()),
			})
		}
	}

	items = append(items,
		managerListItem{
			kind:        managerAddItem,
			title:       "Add credential…",
			description: "Create a validated credential in the system keyring or credential file",
		},
		managerListItem{
			kind:        managerQuitItem,
			title:       "Quit",
			description: "Exit without changing any other credentials",
		},
	)
	m.list.ResetFilter()
	m.list.SetItems(items)
	m.list.Select(0)

	if len(listErrors) == 0 {
		return ""
	}
	return safeErrorText(errors.Join(listErrors...))
}

func (m *credentialManagerModel) showPendingListStatus() tea.Cmd {
	if m.pendingListStatus == "" {
		return nil
	}
	message := safeTerminalText(m.pendingListStatus)
	m.pendingListStatus = ""
	return m.list.NewStatusMessage(message)
}

func (m *credentialManagerModel) resizeEditorInputs() {
	inputWidth := min(max(m.width-8, 8), 100)
	for i := range m.editorInputs {
		m.editorInputs[i].SetWidth(inputWidth)
	}
}

func (m *credentialManagerModel) preferredBackendIndex() int {
	for i, store := range m.stores {
		if store.Backend() == keyringBackend {
			return i
		}
	}
	return 0
}

func (m *credentialManagerModel) store(backend credentialBackend) managedCredentialStore {
	for _, store := range m.stores {
		if store.Backend() == backend {
			return store
		}
	}
	return nil
}

func (m *credentialManagerModel) viewActionMenu() string {
	store := m.store(m.selectedRecord.backend)
	storeName := string(m.selectedRecord.backend)
	if store != nil {
		storeName = store.DisplayName()
	}
	content := renderManagerMenu(
		"Manage credential",
		displayCredential(m.selectedRecord.credential)+"\n"+safeTerminalText(storeName),
		[]string{"Edit", "Delete", "Back"},
		m.menuIndex,
	)
	return m.withManagerError(content, "↑/↓ move • enter select • esc back • ctrl+c quit")
}

func (m *credentialManagerModel) viewBackendMenu() string {
	options := make([]string, 0, len(m.stores))
	for _, store := range m.stores {
		label := safeTerminalText(store.DisplayName())
		if store.Backend() == keyringBackend {
			label += " (recommended)"
		} else if store.Backend() == fileBackend {
			label += " (plaintext compatibility)"
		}
		options = append(options, label)
	}
	content := renderManagerMenu(
		"Add credential",
		"Choose where the password or token will be stored.\n"+
			"Keyring entries require --backend keyring or --backend auto for Git lookups.",
		options,
		m.backendIndex,
	)
	return managerFrame(content + "\n\n" + managerHelpStyle.Render("↑/↓ move • enter select • esc back • ctrl+c quit"))
}

func (m *credentialManagerModel) viewEditor() string {
	title := "Edit credential"
	secretHelp := "Leave blank to retain the current password or token."
	if m.editorCreating {
		title = "Add credential"
		secretHelp = "Required; the value is masked and never shown in lists or confirmation."
	}
	storeName := ""
	if m.editorStore != nil {
		storeName = "\nStorage: " + safeTerminalText(m.editorStore.DisplayName())
	}

	labels := []string{"Protocol", "Host", "Path scope", "Username", "Password or token"}
	descriptions := []string{
		"URI scheme, usually https.",
		"Hostname and optional port only; do not include a scheme or path.",
		"Optional; for example organization/repository.git.",
		"The HTTP credential username.",
		secretHelp,
	}
	var fields strings.Builder
	firstField := 0
	lastField := len(m.editorInputs)
	compact := m.height < 22
	if compact && len(m.editorInputs) > 0 {
		firstField = m.editorField
		lastField = m.editorField + 1
	}
	for i := firstField; i < lastField; i++ {
		label := labels[i]
		if compact {
			label = fmt.Sprintf("[%d/%d] %s", i+1, managerFieldCount, label)
		}
		if i == m.editorField {
			label = managerSelectedStyle.Render(label)
		} else {
			label = managerSubtitleStyle.Render(label)
		}
		fmt.Fprintf(&fields, "%s\n%s\n%s", label, m.editorInputs[i].View(), managerSubtitleStyle.Render(descriptions[i]))
		if i < lastField-1 {
			fields.WriteString("\n\n")
		}
	}

	content := managerTitleStyle.Render(title) +
		"\n" + managerSubtitleStyle.Render("Structured fields are validated and encoded automatically."+storeName) +
		"\n\n" + fields.String()
	return m.withManagerError(content, "tab/enter next • shift+tab/up previous • ctrl+s review • esc cancel")
}

func (m *credentialManagerModel) viewSaveConfirmation() string {
	value, err := m.validatedEditorCredential()
	description := "Credential fields are no longer valid. Return to the editor."
	if err == nil {
		description = displayCredential(value)
		if value.path == "" {
			description += "\nNo path scope: Git may use this credential for any repository on the host."
		} else {
			description += "\nPath-scoped credentials require Git credential.useHttpPath=true."
		}
	}
	content := renderManagerMenu(
		"Save this credential?",
		description+"\nThe password or token is intentionally not displayed.",
		[]string{"Save", "Cancel"},
		m.menuIndex,
	)
	return managerFrame(content + "\n\n" + managerHelpStyle.Render("←/→ choose • enter confirm • esc cancel • ctrl+c quit"))
}

func (m *credentialManagerModel) viewDeleteConfirmation() string {
	content := renderManagerMenu(
		"Delete this credential?",
		displayCredential(m.selectedRecord.credential)+"\nThe secret cannot be recovered by this application.",
		[]string{"Delete", "Cancel"},
		m.menuIndex,
	)
	return managerFrame(content + "\n\n" + managerWarningStyle.Render("Cancel is selected by default.") +
		"\n" + managerHelpStyle.Render("←/→ choose • enter confirm • esc cancel • ctrl+c quit"))
}

func (m *credentialManagerModel) withManagerError(content, help string) string {
	if m.editorError != "" {
		content += "\n\n" + managerErrorStyle.Render("Error: "+safeTerminalText(m.editorError))
	}
	return managerFrame(content + "\n\n" + managerHelpStyle.Render(help))
}

func managerFrame(content string) string {
	return lipgloss.NewStyle().Padding(1, 2).Render(content)
}

func renderManagerMenu(title, description string, options []string, selected int) string {
	var content strings.Builder
	content.WriteString(managerTitleStyle.Render(title))
	if description != "" {
		content.WriteString("\n")
		content.WriteString(managerSubtitleStyle.Render(description))
	}
	content.WriteString("\n\n")
	for i, option := range options {
		prefix := "  "
		line := safeTerminalText(option)
		if i == selected {
			prefix = "> "
			line = managerSelectedStyle.Render(line)
		}
		content.WriteString(prefix)
		content.WriteString(line)
		if i < len(options)-1 {
			content.WriteByte('\n')
		}
	}
	return content.String()
}

func managerKeyName(msg tea.Msg) (string, bool) {
	keyMsg, ok := msg.(tea.KeyPressMsg)
	if !ok {
		return "", false
	}
	return keyMsg.String(), true
}

func validateEditorInputSafety(index int, value string) error {
	names := []string{"protocol", "host", "path", "username", "password or token"}
	if index < 0 || index >= len(names) {
		return errors.New("invalid editor field")
	}
	return validateCredentialText(names[index], value, true)
}

func previousMenuIndex(index, count int) int {
	if count <= 0 {
		return 0
	}
	return (index - 1 + count) % count
}

func nextMenuIndex(index, count int) int {
	if count <= 0 {
		return 0
	}
	return (index + 1) % count
}

func safeErrorText(err error) string {
	if err == nil {
		return ""
	}
	return strings.TrimSpace(safeTerminalText(err.Error()))
}
