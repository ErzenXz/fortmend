package codexapp

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/ErzenXz/fortmend/internal/reasoner"
)

func safeTemp(t *testing.T) string {
	t.Helper()
	if os.Geteuid() == 0 && runtime.GOOS == "linux" {
		path, err := os.MkdirTemp("/var/lib", "fortmend-codex-test-")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.RemoveAll(path) })
		return path
	}
	path, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return path
}

func mockClient(t *testing.T, scenario string) *Client {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("POSIX fixture executable")
	}
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 fixture required")
	}
	dir := safeTemp(t)
	script := filepath.Join(dir, "codex")
	body := `import sys,json,os,subprocess,time
scenario = ` + fmtPython(scenario) + `
assert os.environ['HOME'] == os.environ['CODEX_HOME']
assert 'OPENAI_API_KEY' not in os.environ
def send(m):
 print(json.dumps(m),flush=True)
for line in sys.stdin:
 q=json.loads(line); method=q.get('method'); ident=q.get('id')
 if method=='initialize':
  if scenario=='hang':
   subprocess.Popen(['sleep','5'],stdout=sys.stdout)
   time.sleep(5)
  send({'id':ident,'result':{}})
 elif method=='account/read':send({'id':ident,'result':{'account':None,'requiresOpenaiAuth':True}})
 elif method=='config/read':send({'id':ident,'result':{'config':{'mcp_servers':{'bad':{'command':'bad'}} if scenario=='mcp' else {}}}})
 elif method=='account/login/start':
  send({'id':ident,'result':{'type':'chatgptDeviceCode','loginId':'login-1','verificationUrl':'https://auth.openai.com/codex/device','userCode':'TEST-CODE'}})
  send({'method':'account/login/completed','params':{'loginId':'login-1','success':True}})
 elif method=='thread/start':
  assert q['params']['sandbox']==('danger-full-access' if scenario=='full' else 'read-only')
  if scenario=='full':
   assert q['params']['cwd']=='/'
   assert 'features.shell_tool=false' not in sys.argv
   assert 'features.unified_exec=false' not in sys.argv
   assert 'features.shell_tool=true' in sys.argv
   assert 'features.unified_exec=true' in sys.argv
   assert 'web_search="live"' in sys.argv
  assert q['params']['approvalPolicy']=='never'
  send({'id':ident,'result':{'thread':{'id':'thread-1'}}})
 elif method=='turn/start':
  if scenario=='full':assert q['params']['sandboxPolicy']['type']=='dangerFullAccess'
  else:assert q['params']['sandboxPolicy']['access']['type']=='restricted'
  send({'id':ident,'result':{'turn':{'id':'turn-1'}}})
  send({'id':99,'method':'item/commandExecution/requestApproval','params':{}})
  reply=json.loads(sys.stdin.readline());assert reply['result']['decision']=='decline'
  send({'method':'item/completed','params':{'threadId':'thread-1','item':{'type':'commandExecution','id':'cmd-1','status':'completed','command':'private args never persisted'}}})
  result={'summary':'PHP finding needs verification','actions':[],'citations':['event-1']}
  if scenario=='malformed':result='not json'
  else:result=json.dumps(result)
  send({'method':'item/completed','params':{'threadId':'other','item':{'type':'agentMessage','text':'ignore'}}})
  send({'method':'item/completed','params':{'threadId':'thread-1','item':{'type':'agentMessage','text':result}}})
  send({'method':'turn/completed','params':{'threadId':'thread-1','turn':{'status':'failed' if scenario=='failed' else 'completed'}}})
`
	if err := os.WriteFile(script, []byte("#!"+python+"\n"+body), 0700); err != nil {
		t.Fatal(err)
	}
	return &Client{Config: Config{Binary: script, Home: filepath.Join(dir, "profile")}}
}
func fmtPython(value string) string { data, _ := json.Marshal(value); return string(data) }

func TestManagedChatGPTAccountAndLogin(t *testing.T) {
	c := mockClient(t, "ok")
	data, err := c.Account(context.Background())
	if err != nil || !strings.Contains(string(data), "requiresOpenaiAuth") {
		t.Fatalf("%s %v", data, err)
	}
	var code string
	if err := c.Login(context.Background(), func(url, value string) {
		if !strings.HasPrefix(url, "https://auth.openai.com/") {
			t.Fatal(url)
		}
		code = value
	}); err != nil || code != "TEST-CODE" {
		t.Fatalf("code=%q error=%v", code, err)
	}
}
func TestInvestigationProtocolDeclinesApprovals(t *testing.T) {
	t.Setenv("OPENAI_API_KEY", "must-not-inherit")
	c := mockClient(t, "ok")
	var activity map[string]string
	c.Config.Activity = func(_ context.Context, a map[string]string) error { activity = a; return nil }
	result, err := c.Turn(context.Background(), reasoner.TurnRequest{Instructions: "security", EvidenceJSON: `{"eventId":"event-1"}`})
	if err != nil || len(result.Citations) != 1 || result.Citations[0] != "event-1" {
		t.Fatalf("%+v %v", result, err)
	}
	if activity["type"] != "commandExecution" || len(activity["recordSHA256"]) != 64 {
		t.Fatalf("missing redacted action audit: %+v", activity)
	}
}

func TestEffectiveMCPConfigurationIsRejected(t *testing.T) {
	c := mockClient(t, "mcp")
	if _, err := c.Turn(context.Background(), reasoner.TurnRequest{EvidenceJSON: `{}`}); err == nil {
		t.Fatal("effective MCP server silently inherited")
	}
}
func TestBadOrFailedModelOutputIsNotSuccess(t *testing.T) {
	for _, scenario := range []string{"failed", "malformed"} {
		t.Run(scenario, func(t *testing.T) {
			c := mockClient(t, scenario)
			if _, err := c.Turn(context.Background(), reasoner.TurnRequest{EvidenceJSON: `{}`}); err == nil {
				t.Fatal("invalid result accepted")
			}
		})
	}
}
func TestCancellationClosesInheritedPipe(t *testing.T) {
	c := mockClient(t, "hang")
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := c.Account(ctx); err == nil {
		t.Fatal("expected cancellation")
	}
	if time.Since(start) > 2*time.Second {
		t.Fatal("process tree or inherited output blocked cancellation")
	}
}
func TestManagedProfileRejectsInjectedConfigAndSymlink(t *testing.T) {
	c := mockClient(t, "ok")
	if err := os.MkdirAll(c.Config.Home, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(c.Config.Home, "config.toml"), []byte("[mcp_servers.bad]\ncommand='bad'"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Account(context.Background()); err == nil {
		t.Fatal("inherited MCP config accepted")
	}
	dir := t.TempDir()
	link := filepath.Join(t.TempDir(), "profile")
	if err := os.Symlink(dir, link); err != nil {
		t.Skip(err)
	}
	c.Config.Home = link
	if _, err := c.Account(context.Background()); err == nil {
		t.Fatal("symlink profile accepted")
	}
}

func TestFullControlRequiresLinuxRoot(t *testing.T) {
	if runtime.GOOS == "linux" && os.Geteuid() == 0 {
		t.Skip("guard tested on nonroot host")
	}
	c := mockClient(t, "ok")
	c.Config.FullControl = true
	if _, err := c.Account(context.Background()); err == nil {
		t.Fatal("full control unexpectedly enabled")
	}
}

func TestFullControlProtocolOnLinuxRoot(t *testing.T) {
	if runtime.GOOS != "linux" || os.Geteuid() != 0 {
		t.Skip("runs in disposable Linux root validation")
	}
	c := mockClient(t, "full")
	c.Config.FullControl = true
	c.Config.WorkDir = "/"
	result, err := c.Turn(context.Background(), reasoner.TurnRequest{EvidenceJSON: `{"eventId":"event-1"}`})
	if err != nil || len(result.Citations) != 1 {
		t.Fatalf("full-control protocol failed: %+v %v", result, err)
	}
}

func TestRootAuthRejectsWritableStateAndExecutable(t *testing.T) {
	if os.Geteuid() != 0 || runtime.GOOS != "linux" {
		t.Skip("root path validation")
	}
	c := mockClient(t, "ok")
	if err := os.Chmod(filepath.Dir(c.Config.Home), 0777); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Account(context.Background()); err == nil {
		t.Fatal("root auth accepted writable state ancestry")
	}
	os.Chmod(filepath.Dir(c.Config.Home), 0700)
	os.Chmod(c.Config.Binary, 0777)
	if _, err := c.Account(context.Background()); err == nil {
		t.Fatal("root accepted writable Codex executable")
	}
}

// This smoke test exercises the installed official protocol without signing in
// or sending inference. It uses an empty, temporary Fortmend-owned profile.
func TestOfficialAppServerAccountSmoke(t *testing.T) {
	if os.Getenv("FORTMEND_CODEX_SMOKE") != "1" {
		t.Skip("opt-in installed Codex smoke")
	}
	binary, err := exec.LookPath("codex")
	if err != nil {
		t.Fatal(err)
	}
	dir := safeTemp(t)
	c := &Client{Config: Config{Binary: binary, Home: filepath.Join(dir, "codex")}}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	data, err := c.Account(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var account struct {
		Account json.RawMessage `json:"account"`
	}
	if json.Unmarshal(data, &account) != nil || string(account.Account) != "null" {
		t.Fatalf("unexpected account metadata %s", data)
	}
	conn, err := c.connect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.close()
	effective, err := conn.call(10, "config/read", map[string]bool{"includeLayers": false})
	if err != nil {
		t.Fatal(err)
	}
	var cfg struct {
		Config map[string]json.RawMessage `json:"config"`
	}
	if json.Unmarshal(effective, &cfg) != nil || cfg.Config == nil {
		t.Fatal("effective configuration protocol failed")
	}
	thread, err := conn.call(11, "thread/start", map[string]any{"cwd": filepath.Join(c.Config.Home, "investigation"), "sandbox": "read-only", "approvalPolicy": "never", "ephemeral": true, "baseInstructions": "Fortmend protocol smoke only; no turn will start."})
	if err != nil {
		t.Fatal(err)
	}
	var started struct {
		Thread struct {
			ID string `json:"id"`
		} `json:"thread"`
	}
	if json.Unmarshal(thread, &started) != nil || started.Thread.ID == "" {
		t.Fatal("official thread/start protocol failed")
	}
}
