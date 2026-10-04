//go:build linux

package service

import (
	"os/user"
	"strings"
	"testing"
)

func TestUnitQuotesUntrustedValues(t *testing.T) {
	a := Account{Name: "pi", Group: "pi", Home: "/home/pi 100%"}
	unit, err := Unit(a, `Kitchen "Pi" 50% $HOME \o/`)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"User=pi\n",
		"Group=pi\n",
		`Environment="HOME=/home/pi 100%%"` + "\n",
		"WorkingDirectory=/home/pi 100%%\n",
		`ExecStart=/usr/local/bin/vims-gadget run --state-dir /var/lib/vims-gadget --socket /run/vims-gadget/control.sock --name "Kitchen \"Pi\" 50%% $$HOME \\o/"` + "\n",
		"StateDirectory=vims-gadget\n",
		"RuntimeDirectory=vims-gadget\n",
		"Restart=always\n",
	} {
		if !strings.Contains(unit, want) {
			t.Errorf("unit lacks %q:\n%s", want, unit)
		}
	}
	for _, bad := range []string{"", strings.Repeat("n", 65), "new\nline"} {
		if _, err := Unit(a, bad); err == nil {
			t.Errorf("name %q accepted", bad)
		}
	}
}

func TestLookupAccount(t *testing.T) {
	me, err := user.Current()
	if err != nil {
		t.Skip(err)
	}
	a, err := LookupAccount(me.Username)
	if err != nil {
		t.Fatal(err)
	}
	if a.Name != me.Username || a.Home != me.HomeDir || a.Group == "" {
		t.Fatalf("account %+v", a)
	}
	if _, err := LookupAccount("no-such-user-vims-gadget"); err == nil {
		t.Fatal("unknown account resolved")
	}
}
