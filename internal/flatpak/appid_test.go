package flatpak

import "testing"

func TestParseFlatpakInfoAppID(t *testing.T) {
	cases := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{
			name: "well-formed",
			input: `[Application]
name=com.discordapp.Discord
runtime=runtime/org.freedesktop.Platform/x86_64/24.08

[Instance]
instance-id=12345
`,
			want: "com.discordapp.Discord",
		},
		{
			name: "name in another section is ignored",
			input: `[Instance]
name=ignored

[Application]
name=com.example.App
`,
			want: "com.example.App",
		},
		{
			name:    "missing application section",
			input:   "[Instance]\ninstance-id=1\n",
			wantErr: true,
		},
		{
			name:    "empty",
			input:   "",
			wantErr: true,
		},
		{
			name: "whitespace-tolerant",
			input: `[Application]
  name = com.foo.Bar
`,
			want: "com.foo.Bar",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseFlatpakInfoAppID([]byte(tc.input))
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got %q", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}
